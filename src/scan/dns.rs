use crate::scan::cache::FETCH_TIMEOUT;
use crate::scan::lens::LensOutcome;
use crate::scan::psl::SuffixList;
use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use hickory_resolver::ResolveError;
use hickory_resolver::lookup::{Lookup, ReverseLookup};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{Resolver, TokioResolver};
use log;
use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

const DNS_SCAN_INTERVAL_SECS: u64 = 60;
const DNS_TIMEOUT_SECS: u64 = 5;
const DEFAULT_DNS_TTL: u32 = 300;
/// Bounds on the TTL-driven re-query: the floor keeps tiny TTLs from hammering the resolver, the
/// ceiling keeps the old once-a-minute refresh for long TTLs.
const DNS_REQUERY_FLOOR: Duration = Duration::from_secs(10);
const DNS_REQUERY_CEILING: Duration = Duration::from_secs(60);
/// The re-query lands this long after the earliest record expires. The stub reports TTLs in whole
/// seconds, so a query at exactly `queried_at + ttl` still hits the cache entry's last second and
/// comes back with TTL 0; one second later the entry is gone and the answer carries a fresh TTL.
const DNS_REQUERY_GRACE: Duration = Duration::from_secs(1);
/// RFC 7489: a DMARC policy record is a TXT record at `_dmarc.<domain>` starting with this tag.
const DMARC_PREFIX: &str = "_dmarc";
const DMARC_VERSION_TAG: &str = "v=DMARC1";
/// RFC 8461 §3.1: the MTA-STS TXT record sits at `_mta-sts.<domain>` and names its policy `id`.
const MTA_STS_PREFIX: &str = "_mta-sts";
const MTA_STS_VERSION: &str = "STSv1";
/// RFC 8460 §3: the TLS-RPT TXT record sits at `_smtp._tls.<domain>` and names where reports go.
const TLS_RPT_PREFIX: &str = "_smtp._tls";
const TLS_RPT_VERSION: &str = "TLSRPTv1";

#[derive(Debug, Clone)]
pub struct DnsRecord<T> {
    pub value: T,
    pub ttl_original: u32,
    pub queried_at: Instant,
}

impl<T> DnsRecord<T> {
    pub fn new(value: T, ttl: u32) -> Self {
        Self {
            value,
            ttl_original: ttl,
            queried_at: Instant::now(),
        }
    }

    pub fn ttl_remaining(&self) -> u32 {
        let elapsed = self.queried_at.elapsed().as_secs() as u32;
        self.ttl_original.saturating_sub(elapsed)
    }

    pub fn is_expired(&self) -> bool {
        self.ttl_remaining() == 0
    }

    /// When the resolver's cached answer runs out: `queried_at + ttl`.
    pub fn expires_at(&self) -> Instant {
        self.queried_at + Duration::from_secs(u64::from(self.ttl_original))
    }
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug, Clone)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

// New record types for SOA and SRV
#[derive(Debug, Clone)]
pub struct SoaRecord {
    pub primary_ns: String,
    pub responsible_email: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// SPF from the apex TXT records, DMARC from `_dmarc.` (RFC 7489), MTA-STS and TLS-RPT from their
/// TXT records at the host itself. DKIM is not here: its records sit at `<selector>._domainkey`,
/// and without a selector there is nothing to query.
#[derive(Debug, Clone)]
pub struct EmailSecurityAnalysis {
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub has_mx: bool,
    pub mx_count: usize,
    /// The MTA-STS record's policy `id`.
    pub mta_sts: LensOutcome<String>,
    /// The TLS-RPT record's `rua`, where reports are sent.
    pub tls_rpt: LensOutcome<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStatus {
    NotQueried,     // Query was not attempted (due to protocol restrictions)
    Success(usize), // Query succeeded with N records
    NoRecords,      // Query succeeded but returned no records
    Failed(String), // Query failed with error message
    Timeout,        // Query timed out
}

impl QueryStatus {
    pub fn was_attempted(&self) -> bool {
        !matches!(self, QueryStatus::NotQueried)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, QueryStatus::Success(_) | QueryStatus::NoRecords)
    }

    pub fn record_count(&self) -> usize {
        match self {
            QueryStatus::Success(count) => *count,
            _ => 0,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct DnsResult {
    pub A: Vec<DnsRecord<Ipv4Addr>>,
    pub AAAA: Vec<DnsRecord<Ipv6Addr>>,
    pub CNAME: Vec<DnsRecord<String>>,
    pub NS: Vec<DnsRecord<String>>,
    pub TXT: Vec<DnsRecord<String>>,
    pub CAA: Vec<DnsRecord<CaaRecord>>,
    pub MX: Vec<DnsRecord<MxRecord>>,
    pub PTR: Vec<DnsRecord<String>>,
    pub SOA: Vec<DnsRecord<SoaRecord>>,
    pub SRV: Vec<DnsRecord<SrvRecord>>,
    pub email_security: Option<EmailSecurityAnalysis>,

    // Query status tracking
    pub A_status: QueryStatus,
    pub AAAA_status: QueryStatus,
    pub MX_status: QueryStatus,
    pub TXT_status: QueryStatus,
    pub NS_status: QueryStatus,
    pub SOA_status: QueryStatus,
    pub SRV_status: QueryStatus,
    pub PTR_status: QueryStatus,
    pub CNAME_status: QueryStatus,
    pub CAA_status: QueryStatus,

    pub response_time: Duration,
    pub queried_at: Instant,
}

impl Default for DnsResult {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResult {
    pub fn new() -> Self {
        Self {
            A: Vec::new(),
            AAAA: Vec::new(),
            CNAME: Vec::new(),
            NS: Vec::new(),
            TXT: Vec::new(),
            CAA: Vec::new(),
            MX: Vec::new(),
            PTR: Vec::new(),
            SOA: Vec::new(),
            SRV: Vec::new(),
            email_security: None,
            A_status: QueryStatus::NotQueried,
            AAAA_status: QueryStatus::NotQueried,
            MX_status: QueryStatus::NotQueried,
            TXT_status: QueryStatus::NotQueried,
            NS_status: QueryStatus::NotQueried,
            SOA_status: QueryStatus::NotQueried,
            SRV_status: QueryStatus::NotQueried,
            PTR_status: QueryStatus::NotQueried,
            CNAME_status: QueryStatus::NotQueried,
            CAA_status: QueryStatus::NotQueried,
            response_time: Duration::from_millis(0),
            queried_at: Instant::now(),
        }
    }

    /// Sort every record set so resolver answer order (round-robin, shuffling) never
    /// changes what the pane shows between scans.
    pub fn sort_records(&mut self) {
        self.A.sort_by_key(|r| r.value);
        self.AAAA.sort_by_key(|r| r.value);
        self.CNAME.sort_by(|a, b| a.value.cmp(&b.value));
        self.NS.sort_by(|a, b| a.value.cmp(&b.value));
        self.TXT.sort_by(|a, b| a.value.cmp(&b.value));
        self.PTR.sort_by(|a, b| a.value.cmp(&b.value));
        self.CAA.sort_by(|a, b| {
            (&a.value.tag, &a.value.value, a.value.flags).cmp(&(&b.value.tag, &b.value.value, b.value.flags))
        });
        self.MX
            .sort_by(|a, b| (a.value.priority, &a.value.exchange).cmp(&(b.value.priority, &b.value.exchange)));
        self.SOA
            .sort_by(|a, b| (&a.value.primary_ns, a.value.serial).cmp(&(&b.value.primary_ns, b.value.serial)));
        self.SRV.sort_by(|a, b| {
            (a.value.priority, a.value.weight, a.value.port, &a.value.target).cmp(&(
                b.value.priority,
                b.value.weight,
                b.value.port,
                &b.value.target,
            ))
        });
    }

    /// True when no forward lookup ran: an IP target, which has only PTR. MX is queried for every
    /// name target whatever the protocol, so its status tells the two apart.
    pub fn is_reverse_only(&self) -> bool {
        !self.MX_status.was_attempted()
    }

    /// When the first record's cached TTL runs out.
    fn earliest_expiry(&self) -> Option<Instant> {
        fn expiries<T>(records: &[DnsRecord<T>]) -> impl Iterator<Item = Instant> + '_ {
            records.iter().map(DnsRecord::expires_at)
        }
        expiries(&self.A)
            .chain(expiries(&self.AAAA))
            .chain(expiries(&self.CNAME))
            .chain(expiries(&self.NS))
            .chain(expiries(&self.TXT))
            .chain(expiries(&self.CAA))
            .chain(expiries(&self.MX))
            .chain(expiries(&self.PTR))
            .chain(expiries(&self.SOA))
            .chain(expiries(&self.SRV))
            .min()
    }

    /// Time from `now` to the earliest record expiry plus `DNS_REQUERY_GRACE`, clamped to
    /// `DNS_REQUERY_FLOOR`..`DNS_REQUERY_CEILING`; `None` when there are no records (NXDOMAIN, every
    /// query failed).
    pub fn requery_delay(&self, now: Instant) -> Option<Duration> {
        let expiry = self.earliest_expiry()?;
        Some(
            (expiry + DNS_REQUERY_GRACE)
                .saturating_duration_since(now)
                .clamp(DNS_REQUERY_FLOOR, DNS_REQUERY_CEILING),
        )
    }

    pub fn update_ttls(&mut self) {
        // TTL updates are handled individually when querying since each record
        // type can have different TTLs and query times
    }
}

pub struct DnsScanner {
    interval: Duration,
    timeout: Duration,
    /// Names the organizational domain for DMARC's fallback query.
    suffix_list: SuffixList,
}

impl Default for DnsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsScanner {
    pub fn new() -> Self {
        log::debug!("[scan::dns] new: interval=60s timeout=5s");
        let client = Client::builder()
            .connect_timeout(FETCH_TIMEOUT)
            .user_agent("scan/1.0")
            .build()
            .expect("Failed to create HTTP client");
        Self {
            interval: Duration::from_secs(DNS_SCAN_INTERVAL_SECS), // ceiling; TTLs drive re-queries
            timeout: Duration::from_secs(DNS_TIMEOUT_SECS),
            suffix_list: SuffixList::new(client),
        }
    }

    /// One `record_type` lookup of `name`, bounded by the per-query timeout. No records and
    /// NXDOMAIN are an empty answer, not a failure.
    async fn timed_lookup(
        &self,
        resolver: &TokioResolver,
        name: &str,
        record_type: RecordType,
    ) -> std::result::Result<Option<Lookup>, QueryStatus> {
        log::debug!("[scan::dns] timed_lookup: name={} type={}", name, record_type);
        match tokio::time::timeout(self.timeout, resolver.lookup(name, record_type)).await {
            Ok(Ok(lookup)) => Ok(Some(lookup)),
            Ok(Err(e)) if is_empty_answer(&e) => {
                log::trace!("[scan::dns] lookup_no_records: name={} type={}", name, record_type);
                Ok(None)
            }
            Ok(Err(e)) => {
                log::debug!(
                    "[scan::dns] lookup_failed: name={} type={} error={}",
                    name,
                    record_type,
                    e
                );
                Err(QueryStatus::Failed(e.to_string()))
            }
            Err(_) => {
                log::warn!(
                    "[scan::dns] lookup_timeout: name={} type={} timeout={}ms",
                    name,
                    record_type,
                    self.timeout.as_millis()
                );
                Err(QueryStatus::Timeout)
            }
        }
    }

    /// CNAME records at `domain`.
    async fn lookup_cname(&self, resolver: &TokioResolver, domain: &str) -> (Vec<DnsRecord<String>>, QueryStatus) {
        log::debug!("[scan::dns] lookup_cname: domain={}", domain);
        let lookup = match self.timed_lookup(resolver, domain, RecordType::CNAME).await {
            Ok(lookup) => lookup,
            Err(status) => return (Vec::new(), status),
        };
        let records: Vec<_> = lookup
            .iter()
            .flat_map(|l| l.record_iter())
            .filter_map(|record| {
                let cname = record.data().as_cname()?;
                Some(DnsRecord::new(cname.0.to_string(), record.ttl()))
            })
            .collect();
        let status = records_status(records.len());
        (records, status)
    }

    /// CAA records at `domain`.
    async fn lookup_caa(&self, resolver: &TokioResolver, domain: &str) -> (Vec<DnsRecord<CaaRecord>>, QueryStatus) {
        log::debug!("[scan::dns] lookup_caa: domain={}", domain);
        let lookup = match self.timed_lookup(resolver, domain, RecordType::CAA).await {
            Ok(lookup) => lookup,
            Err(status) => return (Vec::new(), status),
        };
        let records: Vec<_> = lookup
            .iter()
            .flat_map(|l| l.record_iter())
            .filter_map(|record| {
                let caa = record.data().as_caa()?;
                Some(DnsRecord::new(
                    CaaRecord {
                        flags: caa.flags(),
                        tag: caa.tag().to_string(),
                        value: String::from_utf8_lossy(caa.raw_value()).into_owned(),
                    },
                    record.ttl(),
                ))
            })
            .collect();
        let status = records_status(records.len());
        (records, status)
    }

    /// The TXT strings at `name`, empty when there are none; a timeout or resolver error is the
    /// query's status, never an empty answer.
    async fn txt_at(&self, resolver: &TokioResolver, name: &str) -> std::result::Result<Vec<String>, QueryStatus> {
        Ok(match self.timed_lookup(resolver, name, RecordType::TXT).await? {
            Some(lookup) => lookup
                .record_iter()
                .filter_map(|record| record.data().as_txt().map(txt_text))
                .collect(),
            None => Vec::new(),
        })
    }

    /// The MTA-STS `id` and TLS-RPT `rua` published at `host`, asked concurrently. The host only:
    /// MTA-STS does not inherit to subdomains (RFC 8461 §3.4), and TLS-RPT is found at the policy
    /// domain (RFC 8460 §3).
    async fn lookup_mail_transport(
        &self,
        resolver: &TokioResolver,
        host: &str,
    ) -> (LensOutcome<String>, LensOutcome<String>) {
        let host = host.trim_end_matches('.');
        let (mta_sts, tls_rpt) = (format!("{MTA_STS_PREFIX}.{host}"), format!("{TLS_RPT_PREFIX}.{host}"));
        log::debug!(
            "[scan::dns] lookup_mail_transport: mta_sts={} tls_rpt={}",
            mta_sts,
            tls_rpt
        );
        let (mta_sts, tls_rpt) = tokio::join!(self.txt_at(resolver, &mta_sts), self.txt_at(resolver, &tls_rpt));
        let outcomes = (
            tagged_value(mta_sts, MTA_STS_VERSION, "id"),
            tagged_value(tls_rpt, TLS_RPT_VERSION, "rua"),
        );
        log::debug!(
            "[scan::dns] lookup_mail_transport_done: host={} mta_sts={:?} tls_rpt={:?}",
            host,
            outcomes.0,
            outcomes.1
        );
        outcomes
    }

    /// The `_dmarc.` TXT answer for `host`: `_dmarc.<host>` first, then `_dmarc.<registrable
    /// domain>` (RFC 7489 organizational fallback). Without the suffix list only the host is asked.
    async fn lookup_dmarc(&self, resolver: &TokioResolver, host: &str) -> Vec<String> {
        log::debug!("[scan::dns] lookup_dmarc: host={}", host);
        let deadline = tokio::time::Instant::now() + self.timeout;
        let registrable =
            match tokio::time::timeout_at(deadline, self.suffix_list.registrable_domain(host, deadline)).await {
                Ok(Ok(domain)) => domain,
                Ok(Err(e)) => {
                    log::warn!(
                        "[scan::dns] suffix_list_unavailable_dmarc_host_only: host={} error={:#}",
                        host,
                        e
                    );
                    None
                }
                Err(_) => {
                    log::warn!(
                        "[scan::dns] suffix_list_timeout_dmarc_host_only: host={} timeout={}ms",
                        host,
                        self.timeout.as_millis()
                    );
                    None
                }
            };
        let names = dmarc_names(host, registrable.as_deref());
        for name in &names {
            // DMARC keeps its configured/missing reading: a failed query counts as no record here.
            let answer = self.txt_at(resolver, name).await.unwrap_or_default();
            if dmarc_record(&answer).is_some() {
                log::debug!("[scan::dns] dmarc_found: host={} answered_by={}", host, name);
                return answer;
            }
        }
        log::debug!("[scan::dns] dmarc_not_found: host={} asked={:?}", host, names);
        Vec::new()
    }

    async fn perform_dns_lookup(&self, target: &Target, protocol: Protocol) -> Result<DnsResult> {
        log::debug!(
            "[scan::dns] perform_dns_lookup: target={} domain={:?} protocol={}",
            target.display_name(),
            target.domain,
            protocol.as_str()
        );

        let start_time = Instant::now();
        let mut result = DnsResult::new();

        // Create resolver using system config (which will use system DNS servers)
        let resolver = match Resolver::builder_tokio() {
            Ok(builder) => {
                let r = builder.build();
                log::trace!(
                    "[scan::dns] resolver_created: duration={}μs timeout={}ms protocol={}",
                    start_time.elapsed().as_micros(),
                    self.timeout.as_millis(),
                    protocol.as_str()
                );
                r
            }
            Err(e) => {
                log::error!("[scan::dns] resolver_builder_failed: error={}", e);
                return Err(e).wrap_err("Failed to create DNS resolver");
            }
        };

        // Forward DNS lookups (for domains)
        if let Some(domain) = &target.domain {
            log::debug!(
                "[scan::dns] starting_forward_lookups: domain={} protocol={}",
                domain,
                protocol.as_str()
            );

            // A records (IPv4) - only query if protocol supports IPv4
            if matches!(protocol, Protocol::Ipv4 | Protocol::Both) {
                let a_start = Instant::now();
                match tokio::time::timeout(self.timeout, resolver.ipv4_lookup(domain)).await {
                    Ok(Ok(response)) => {
                        let a_duration = a_start.elapsed();
                        for ip in response.iter() {
                            let ttl = response
                                .as_lookup()
                                .records()
                                .first()
                                .map(|record| record.ttl())
                                .unwrap_or(DEFAULT_DNS_TTL);
                            result.A.push(DnsRecord::new(ip.0, ttl));
                        }
                        result.A_status = if result.A.is_empty() {
                            QueryStatus::NoRecords
                        } else {
                            QueryStatus::Success(result.A.len())
                        };
                        log::trace!(
                            "[scan::dns] a_records_found: domain={} count={} duration={}ms protocol={}",
                            domain,
                            result.A.len(),
                            a_duration.as_millis(),
                            protocol.as_str()
                        );
                    }
                    Ok(Err(e)) => {
                        let a_duration = a_start.elapsed();
                        result.A_status = QueryStatus::Failed(e.to_string());
                        log::trace!(
                            "[scan::dns] a_records_failed: domain={} duration={}ms error={} protocol={}",
                            domain,
                            a_duration.as_millis(),
                            e,
                            protocol.as_str()
                        );
                    }
                    Err(_) => {
                        let a_duration = a_start.elapsed();
                        result.A_status = QueryStatus::Timeout;
                        log::warn!(
                            "[scan::dns] a_records_timeout: domain={} duration={}ms timeout={}ms protocol={}",
                            domain,
                            a_duration.as_millis(),
                            self.timeout.as_millis(),
                            protocol.as_str()
                        );
                    }
                }
            } else {
                result.A_status = QueryStatus::NotQueried;
                log::trace!(
                    "[scan::dns] skipping_a_records: domain={} protocol={}",
                    domain,
                    protocol.as_str()
                );
            }

            // AAAA records (IPv6) - only query if protocol supports IPv6
            if matches!(protocol, Protocol::Ipv6 | Protocol::Both) {
                let aaaa_start = Instant::now();
                match tokio::time::timeout(self.timeout, resolver.ipv6_lookup(domain)).await {
                    Ok(Ok(response)) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        for ip in response.iter() {
                            let ttl = response
                                .as_lookup()
                                .records()
                                .first()
                                .map(|record| record.ttl())
                                .unwrap_or(DEFAULT_DNS_TTL);
                            result.AAAA.push(DnsRecord::new(ip.0, ttl));
                        }
                        result.AAAA_status = if result.AAAA.is_empty() {
                            QueryStatus::NoRecords
                        } else {
                            QueryStatus::Success(result.AAAA.len())
                        };
                        log::trace!(
                            "[scan::dns] aaaa_records_found: domain={} count={} duration={}ms protocol={}",
                            domain,
                            result.AAAA.len(),
                            aaaa_duration.as_millis(),
                            protocol.as_str()
                        );
                    }
                    Ok(Err(e)) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        // Check if this is a "no records" type error vs a real failure
                        let error_str = e.to_string().to_lowercase();
                        if error_str.contains("no records found")
                            || error_str.contains("nxdomain")
                            || error_str.contains("name not found")
                        {
                            result.AAAA_status = QueryStatus::NoRecords;
                            log::trace!(
                                "[scan::dns] aaaa_records_none: domain={} duration={}ms protocol={}",
                                domain,
                                aaaa_duration.as_millis(),
                                protocol.as_str()
                            );
                        } else {
                            result.AAAA_status = QueryStatus::Failed(e.to_string());
                            log::trace!(
                                "[scan::dns] aaaa_records_failed: domain={} duration={}ms error={} protocol={}",
                                domain,
                                aaaa_duration.as_millis(),
                                e,
                                protocol.as_str()
                            );
                        }
                    }
                    Err(_) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        result.AAAA_status = QueryStatus::Timeout;
                        log::warn!(
                            "[scan::dns] aaaa_records_timeout: domain={} duration={}ms timeout={}ms protocol={}",
                            domain,
                            aaaa_duration.as_millis(),
                            self.timeout.as_millis(),
                            protocol.as_str()
                        );
                    }
                }
            } else {
                result.AAAA_status = QueryStatus::NotQueried;
                log::trace!(
                    "[scan::dns] skipping_aaaa_records: domain={} protocol={}",
                    domain,
                    protocol.as_str()
                );
            }

            // MX records (protocol-independent, but log protocol for consistency)
            match resolver.mx_lookup(domain).await {
                Ok(response) => {
                    for mx in response.iter() {
                        let ttl = response
                            .as_lookup()
                            .records()
                            .first()
                            .map(|record| record.ttl())
                            .unwrap_or(DEFAULT_DNS_TTL);
                        result.MX.push(DnsRecord::new(
                            MxRecord {
                                priority: mx.preference(),
                                exchange: mx.exchange().to_string(),
                            },
                            ttl,
                        ));
                    }
                    result.MX_status = if result.MX.is_empty() {
                        QueryStatus::NoRecords
                    } else {
                        QueryStatus::Success(result.MX.len())
                    };
                    log::trace!(
                        "[scan::dns] mx_records_found: domain={} count={} protocol={}",
                        domain,
                        result.MX.len(),
                        protocol.as_str()
                    );
                }
                Err(e) => {
                    result.MX_status = QueryStatus::Failed(e.to_string());
                    log::trace!(
                        "[scan::dns] mx_records_failed: domain={} error={} protocol={}",
                        domain,
                        e,
                        protocol.as_str()
                    );
                }
            }

            // TXT records (protocol-independent, but log protocol for consistency)
            match resolver.txt_lookup(domain).await {
                Ok(response) => {
                    for txt in response.iter() {
                        let ttl = response
                            .as_lookup()
                            .records()
                            .first()
                            .map(|record| record.ttl())
                            .unwrap_or(DEFAULT_DNS_TTL);
                        let txt_string = txt
                            .iter()
                            .map(|bytes| String::from_utf8_lossy(bytes))
                            .collect::<Vec<_>>()
                            .join("");
                        result.TXT.push(DnsRecord::new(txt_string, ttl));
                    }
                    result.TXT_status = if result.TXT.is_empty() {
                        QueryStatus::NoRecords
                    } else {
                        QueryStatus::Success(result.TXT.len())
                    };
                    log::trace!(
                        "[scan::dns] txt_records_found: domain={} count={} protocol={}",
                        domain,
                        result.TXT.len(),
                        protocol.as_str()
                    );
                }
                Err(e) => {
                    result.TXT_status = QueryStatus::Failed(e.to_string());
                    log::trace!(
                        "[scan::dns] txt_records_failed: domain={} error={} protocol={}",
                        domain,
                        e,
                        protocol.as_str()
                    );
                }
            }

            // NS records (protocol-independent, but log protocol for consistency)
            match resolver.ns_lookup(domain).await {
                Ok(response) => {
                    for ns in response.iter() {
                        let ttl = response
                            .as_lookup()
                            .records()
                            .first()
                            .map(|record| record.ttl())
                            .unwrap_or(DEFAULT_DNS_TTL);
                        result.NS.push(DnsRecord::new(ns.0.to_string(), ttl));
                    }
                    result.NS_status = if result.NS.is_empty() {
                        QueryStatus::NoRecords
                    } else {
                        QueryStatus::Success(result.NS.len())
                    };
                    log::trace!(
                        "[scan::dns] ns_records_found: domain={} count={} protocol={}",
                        domain,
                        result.NS.len(),
                        protocol.as_str()
                    );
                }
                Err(e) => {
                    result.NS_status = QueryStatus::Failed(e.to_string());
                    log::trace!(
                        "[scan::dns] ns_records_failed: domain={} error={} protocol={}",
                        domain,
                        e,
                        protocol.as_str()
                    );
                }
            }

            // SOA records (protocol-independent, but log protocol for consistency)
            match resolver.lookup(domain, RecordType::SOA).await {
                Ok(response) => {
                    for record in response.record_iter() {
                        if let Some(soa) = record.data().as_soa() {
                            result.SOA.push(DnsRecord::new(
                                SoaRecord {
                                    primary_ns: soa.mname().to_string(),
                                    responsible_email: soa.rname().to_string(),
                                    serial: soa.serial(),
                                    refresh: soa.refresh() as u32,
                                    retry: soa.retry() as u32,
                                    expire: soa.expire() as u32,
                                    minimum_ttl: soa.minimum(),
                                },
                                record.ttl(),
                            ));
                        }
                    }
                    result.SOA_status = if result.SOA.is_empty() {
                        QueryStatus::NoRecords
                    } else {
                        QueryStatus::Success(result.SOA.len())
                    };
                    log::trace!(
                        "[scan::dns] soa_records_found: domain={} count={} protocol={}",
                        domain,
                        result.SOA.len(),
                        protocol.as_str()
                    );
                }
                Err(e) => {
                    result.SOA_status = QueryStatus::Failed(e.to_string());
                    log::trace!(
                        "[scan::dns] soa_records_failed: domain={} error={} protocol={}",
                        domain,
                        e,
                        protocol.as_str()
                    );
                }
            }

            // SRV records (protocol-independent, but log protocol for consistency)
            let srv_services = vec![
                "_http._tcp",
                "_https._tcp",
                "_ftp._tcp",
                "_smtp._tcp",
                "_imap._tcp",
                "_pop3._tcp",
                "_xmpp-server._tcp",
                "_sip._tcp",
            ];

            let mut srv_queries_attempted = 0;
            let mut srv_queries_successful = 0;
            let mut srv_errors = Vec::new();

            for service in srv_services {
                let srv_domain = format!("{}.{}", service, domain);
                srv_queries_attempted += 1;
                match resolver.lookup(&srv_domain, RecordType::SRV).await {
                    Ok(response) => {
                        srv_queries_successful += 1;
                        for record in response.record_iter() {
                            if let Some(srv) = record.data().as_srv() {
                                result.SRV.push(DnsRecord::new(
                                    SrvRecord {
                                        priority: srv.priority(),
                                        weight: srv.weight(),
                                        port: srv.port(),
                                        target: srv.target().to_string(),
                                    },
                                    record.ttl(),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        srv_errors.push(format!("{}: {}", service, e));
                    }
                }
            }

            // Set SRV status based on overall results
            result.SRV_status = if srv_queries_attempted == 0 {
                QueryStatus::NotQueried
            } else if !result.SRV.is_empty() {
                QueryStatus::Success(result.SRV.len())
            } else if srv_queries_successful > 0 {
                QueryStatus::NoRecords
            } else {
                QueryStatus::Failed(format!(
                    "All {} SRV queries failed: {:?}",
                    srv_queries_attempted, srv_errors
                ))
            };

            if !result.SRV.is_empty() {
                log::trace!(
                    "[scan::dns] srv_records_found: domain={} count={} protocol={}",
                    domain,
                    result.SRV.len(),
                    protocol.as_str()
                );
            } else {
                log::trace!(
                    "[scan::dns] srv_records_none: domain={} attempted={} successful={} protocol={}",
                    domain,
                    srv_queries_attempted,
                    srv_queries_successful,
                    protocol.as_str()
                );
            }

            let (cname, cname_status) = self.lookup_cname(&resolver, domain).await;
            result.CNAME = cname;
            result.CNAME_status = cname_status;
            let (caa, caa_status) = self.lookup_caa(&resolver, domain).await;
            result.CAA = caa;
            result.CAA_status = caa_status;

            let (dmarc_txt, (mta_sts, tls_rpt)) = tokio::join!(
                self.lookup_dmarc(&resolver, domain),
                self.lookup_mail_transport(&resolver, domain)
            );
            let mut email_security = analyze_email_security(&result.TXT, &result.MX, &dmarc_txt);
            email_security.mta_sts = mta_sts;
            email_security.tls_rpt = tls_rpt;
            result.email_security = Some(email_security);
            log::trace!(
                "[scan::dns] email_security_analyzed: domain={} protocol={}",
                domain,
                protocol.as_str()
            );
        }

        // Reverse DNS lookups (for IP addresses) - filter by protocol
        let target_ips = target.ips_for_protocol(protocol);

        if target_ips.is_empty() {
            result.PTR_status = QueryStatus::NotQueried;
            log::trace!("[scan::dns] no_ips_for_protocol: protocol={}", protocol.as_str());
        } else {
            let mut answers = Vec::with_capacity(target_ips.len());
            for ip in &target_ips {
                log::trace!("[scan::dns] reverse_lookup: ip={} protocol={}", ip, protocol.as_str());

                // Create resolver using system config
                let resolver = Resolver::builder_tokio()
                    .wrap_err("Failed to create DNS resolver")?
                    .build();

                let answer = ptr_answer(*ip, resolver.reverse_lookup(*ip).await);
                log::trace!(
                    "[scan::dns] ptr_answer: ip={} answer={:?} protocol={}",
                    ip,
                    answer,
                    protocol.as_str()
                );
                answers.push(answer);
            }

            let (records, status) = ptr_records_and_status(answers);
            result.PTR = records;
            result.PTR_status = status;
        }

        result.sort_records();
        result.response_time = start_time.elapsed();
        result.queried_at = start_time;

        log::debug!(
            "[scan::dns] dns_lookup_completed: target={} protocol={} duration={}ms a_status={:?} aaaa_status={:?} mx_status={:?} txt_status={:?} cname_status={:?} caa_status={:?} ptr_status={:?}",
            target.display_name(),
            protocol.as_str(),
            result.response_time.as_millis(),
            result.A_status,
            result.AAAA_status,
            result.MX_status,
            result.TXT_status,
            result.CNAME_status,
            result.CAA_status,
            result.PTR_status
        );

        Ok(result)
    }
}

#[async_trait]
impl Scanner for DnsScanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!(
            "[scan::dns] scan: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        let scan_start = Instant::now();
        match self.perform_dns_lookup(target, protocol).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!(
                    "[scan::dns] dns_scan_completed: target={} protocol={} duration={}ms response_time={}ms records_found=A:{} AAAA:{} MX:{} TXT:{} NS:{}",
                    target.display_name(),
                    protocol.as_str(),
                    scan_duration.as_millis(),
                    result.response_time.as_millis(),
                    result.A.len(),
                    result.AAAA.len(),
                    result.MX.len(),
                    result.TXT.len(),
                    result.NS.len()
                );
                Ok(ScanResult::Dns(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!(
                    "[scan::dns] dns_scan_failed: target={} protocol={} duration={}ms error={}",
                    target.display_name(),
                    protocol.as_str(),
                    scan_duration.as_millis(),
                    e
                );
                Err(e.wrap_err("DNS lookup failed"))
            }
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "dns"
    }

    /// Re-query 1s after the first cached record expires (10s..60s), so the answer carries a fresh TTL.
    fn next_delay(&self, result: &ScanResult) -> Option<Duration> {
        let ScanResult::Dns(dns) = result else {
            return None;
        };
        let delay = dns.requery_delay(Instant::now());
        log::debug!("[scan::dns] next_delay: delay={:?}", delay);
        delay
    }
}

/// No records and NXDOMAIN are an answer with nothing in it, not a failed query.
fn is_empty_answer(error: &ResolveError) -> bool {
    error.is_no_records_found() || error.is_nx_domain()
}

/// One address's reverse lookup, classified.
#[derive(Debug)]
enum PtrAnswer {
    Names(Vec<DnsRecord<String>>),
    /// The resolver answered: this address has no PTR record.
    Empty,
    Failed(String),
}

/// Classifies one `reverse_lookup` outcome. No records and NXDOMAIN are `Empty`, exactly as
/// `timed_lookup` treats them for forward queries.
fn ptr_answer(ip: IpAddr, lookup: std::result::Result<ReverseLookup, ResolveError>) -> PtrAnswer {
    match lookup {
        Ok(response) => {
            let ttl = response
                .as_lookup()
                .records()
                .first()
                .map(|record| record.ttl())
                .unwrap_or(DEFAULT_DNS_TTL);
            let names: Vec<_> = response
                .iter()
                .map(|ptr| DnsRecord::new(ptr.to_string(), ttl))
                .collect();
            if names.is_empty() { PtrAnswer::Empty } else { PtrAnswer::Names(names) }
        }
        Err(e) if is_empty_answer(&e) => PtrAnswer::Empty,
        Err(e) => PtrAnswer::Failed(format!("{}: {}", ip, e)),
    }
}

/// Every address's PTR names and the section's status: `Success` with any name, `NoRecords` when
/// at least one lookup answered and none had a name, `Failed` only when every lookup failed.
fn ptr_records_and_status(answers: Vec<PtrAnswer>) -> (Vec<DnsRecord<String>>, QueryStatus) {
    let attempted = answers.len();
    let mut records = Vec::new();
    let mut answered = 0;
    let mut errors = Vec::new();
    for answer in answers {
        match answer {
            PtrAnswer::Names(names) => {
                answered += 1;
                records.extend(names);
            }
            PtrAnswer::Empty => answered += 1,
            PtrAnswer::Failed(error) => errors.push(error),
        }
    }
    let status = if attempted == 0 {
        QueryStatus::NotQueried
    } else if !records.is_empty() {
        QueryStatus::Success(records.len())
    } else if answered > 0 {
        QueryStatus::NoRecords
    } else {
        QueryStatus::Failed(format!("All {} PTR queries failed: {:?}", attempted, errors))
    };
    (records, status)
}

/// `Success(n)` for an answer with records, `NoRecords` for an empty one.
fn records_status(count: usize) -> QueryStatus {
    if count == 0 { QueryStatus::NoRecords } else { QueryStatus::Success(count) }
}

/// One TXT record's character strings, joined.
fn txt_text(txt: &hickory_resolver::proto::rr::rdata::TXT) -> String {
    txt.iter()
        .map(|bytes| String::from_utf8_lossy(bytes))
        .collect::<Vec<_>>()
        .join("")
}

/// Where DMARC is looked up for `host`, in order: `_dmarc.<host>`, then `_dmarc.<registrable>`
/// when that is a different name.
fn dmarc_names(host: &str, registrable: Option<&str>) -> Vec<String> {
    let host = host.trim_end_matches('.');
    let mut names = vec![format!("{}.{}", DMARC_PREFIX, host)];
    if let Some(domain) = registrable
        && !domain.eq_ignore_ascii_case(host)
    {
        names.push(format!("{}.{}", DMARC_PREFIX, domain));
    }
    names
}

/// The DMARC policy record in a `_dmarc.` TXT answer.
fn dmarc_record(answer: &[String]) -> Option<String> {
    answer
        .iter()
        .find(|txt| txt.trim_start().starts_with(DMARC_VERSION_TAG))
        .cloned()
}

/// The `key` tag of the record in a TXT answer whose `v=` tag is `version` (`v=STSv1; id=...`,
/// `v=TLSRPTv1; rua=...`). No such record is `Absent`; a failed query is `Failed`, never `Absent`.
fn tagged_value(
    answer: std::result::Result<Vec<String>, QueryStatus>,
    version: &str,
    key: &str,
) -> LensOutcome<String> {
    let records = match answer {
        Ok(records) => records,
        Err(QueryStatus::Timeout) => return LensOutcome::Failed("timed out".to_string()),
        Err(QueryStatus::Failed(reason)) => return LensOutcome::Failed(reason),
        Err(other) => return LensOutcome::Failed(format!("{other:?}")),
    };
    let tags = |record: &str| -> Vec<(String, String)> {
        record
            .split(';')
            .filter_map(|tag| tag.split_once('='))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect()
    };
    records
        .iter()
        .map(|record| tags(record))
        .find(|tags| {
            tags.first()
                .is_some_and(|(name, value)| name == "v" && value == version)
        })
        .and_then(|tags| tags.into_iter().find(|(name, _)| name == key).map(|(_, value)| value))
        .filter(|value| !value.is_empty())
        .map_or(LensOutcome::Absent, LensOutcome::Present)
}

/// SPF from the apex TXT records; DMARC only from the `_dmarc.` answer, since a `v=DMARC1` record
/// at the apex is not where receivers look. MTA-STS and TLS-RPT start `Absent` and are filled in
/// from their own queries.
fn analyze_email_security(
    txt_records: &[DnsRecord<String>],
    mx_records: &[DnsRecord<MxRecord>],
    dmarc_answer: &[String],
) -> EmailSecurityAnalysis {
    log::debug!(
        "[scan::dns] analyze_email_security: txt_count={} mx_count={} dmarc_answer_count={}",
        txt_records.len(),
        mx_records.len(),
        dmarc_answer.len()
    );
    let analysis = EmailSecurityAnalysis {
        spf_record: txt_records
            .iter()
            .map(|record| &record.value)
            .find(|txt| txt.starts_with("v=spf1"))
            .cloned(),
        dmarc_record: dmarc_record(dmarc_answer),
        has_mx: !mx_records.is_empty(),
        mx_count: mx_records.len(),
        mta_sts: LensOutcome::Absent,
        tls_rpt: LensOutcome::Absent,
    };
    log::debug!(
        "[scan::dns] email_security_analysis: spf={} dmarc={} mx_count={}",
        analysis.spf_record.is_some(),
        analysis.dmarc_record.is_some(),
        analysis.mx_count
    );
    analysis
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scanner whose suffix list is unreachable and uncached, so tests neither fetch the
    /// published list nor write the user's cache; DMARC is then asked at the host only.
    async fn test_scanner() -> DnsScanner {
        DnsScanner {
            suffix_list: SuffixList {
                url: crate::scan::testing::dead_http_url().await,
                cache_dir: None,
                ..SuffixList::new(Client::new())
            },
            ..DnsScanner::new()
        }
    }

    fn txt(values: &[&str]) -> Vec<DnsRecord<String>> {
        values.iter().map(|v| DnsRecord::new(v.to_string(), 300)).collect()
    }

    /// Item 4: DMARC comes from the `_dmarc.` answer.
    #[test]
    fn email_security_takes_dmarc_from_the_dmarc_answer() {
        let answer = vec!["v=DMARC1; p=reject; rua=mailto:d@example.com".to_string()];
        let analysis = analyze_email_security(&txt(&["v=spf1 -all"]), &[], &answer);
        assert_eq!(
            analysis.dmarc_record.as_deref(),
            Some("v=DMARC1; p=reject; rua=mailto:d@example.com")
        );
        assert_eq!(analysis.spf_record.as_deref(), Some("v=spf1 -all"));
    }

    /// Item 4: a `v=DMARC1` string among the apex TXT records is not where receivers look.
    #[test]
    fn apex_only_dmarc_txt_is_not_dmarc() {
        let analysis = analyze_email_security(&txt(&["v=DMARC1; p=none", "v=spf1 -all"]), &[], &[]);
        assert!(analysis.dmarc_record.is_none(), "{analysis:?}");
    }

    /// A `_dmarc.` answer without a `v=DMARC1` record (a stray verification string) is no policy.
    #[test]
    fn dmarc_answer_without_a_policy_record_is_not_dmarc() {
        let answer = vec!["some-verification=abc".to_string()];
        assert!(analyze_email_security(&[], &[], &answer).dmarc_record.is_none());
    }

    /// RFC 7489 organizational fallback: the host first, then its registrable domain when different.
    #[test]
    fn dmarc_is_asked_at_the_host_then_the_registrable_domain() {
        assert_eq!(
            dmarc_names("www.tatari.tv", Some("tatari.tv")),
            vec!["_dmarc.www.tatari.tv", "_dmarc.tatari.tv"]
        );
        assert_eq!(
            dmarc_names("google.com.", Some("google.com")),
            vec!["_dmarc.google.com"]
        );
        assert_eq!(dmarc_names("Google.com", Some("google.com")), vec!["_dmarc.Google.com"]);
        assert_eq!(dmarc_names("www.tatari.tv", None), vec!["_dmarc.www.tatari.tv"]);
    }

    fn expiring_in(secs: u32, now: Instant) -> DnsRecord<Ipv4Addr> {
        DnsRecord {
            value: Ipv4Addr::new(192, 0, 2, 1),
            ttl_original: secs,
            queried_at: now,
        }
    }

    /// Item 1: the re-query lands 1s after the earliest expiry, so the stub's cache entry is gone
    /// and the answer carries a fresh TTL; clamped to 10s..60s.
    #[test]
    fn requery_delay_is_one_second_past_the_earliest_expiry_clamped_to_10s_60s() {
        let now = Instant::now();
        for (ttl, expected) in [(4, 10), (30, 31), (300, 60)] {
            let mut result = DnsResult::new();
            result.A.push(expiring_in(ttl, now));
            assert_eq!(
                result.requery_delay(now),
                Some(Duration::from_secs(expected)),
                "ttl {ttl}s"
            );
        }
    }

    #[test]
    fn requery_delay_takes_the_earliest_record_across_types() {
        let now = Instant::now();
        let mut result = DnsResult::new();
        result.A.push(expiring_in(300, now));
        result.TXT.push(DnsRecord {
            value: "v=spf1 -all".to_string(),
            ttl_original: 25,
            queried_at: now,
        });
        result.PTR.push(DnsRecord {
            value: "host.example.".to_string(),
            ttl_original: 45,
            queried_at: now,
        });
        assert_eq!(result.requery_delay(now), Some(Duration::from_secs(26)));
        // 20s later the TXT record has 5s left: the floor holds.
        assert_eq!(
            result.requery_delay(now + Duration::from_secs(20)),
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn requery_delay_without_records_is_none() {
        assert_eq!(DnsResult::new().requery_delay(Instant::now()), None);
    }

    #[tokio::test]
    async fn next_delay_reads_a_dns_result_and_ignores_others() {
        let scanner = DnsScanner::new();
        let mut result = DnsResult::new();
        result.A.push(expiring_in(30, Instant::now()));
        let delay = scanner.next_delay(&ScanResult::Dns(result)).unwrap();
        assert!(
            delay <= Duration::from_secs(31) && delay >= Duration::from_secs(30),
            "{delay:?}"
        );
        assert_eq!(scanner.next_delay(&ScanResult::Dns(DnsResult::new())), None);
        assert_eq!(
            scanner.next_delay(&ScanResult::Ping(crate::scan::ping::PingResult::new())),
            None
        );
    }

    /// A resolver's "no records" answer for `code` (NOERROR with an empty answer, or NXDOMAIN).
    fn no_records_error(code: hickory_resolver::proto::op::ResponseCode) -> ResolveError {
        hickory_resolver::proto::ProtoError::nx_error(
            Box::new(hickory_resolver::proto::op::Query::new()),
            None,
            None,
            None,
            code,
            false,
            None,
        )
        .into()
    }

    /// Item 2: an address with no PTR record is an empty answer, not a failure, exactly as
    /// `timed_lookup` treats forward queries.
    #[test]
    fn ptr_without_a_record_is_no_records_never_failed() {
        use hickory_resolver::proto::op::ResponseCode;
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let answer = ptr_answer(ip, Err(no_records_error(code)));
            assert!(matches!(answer, PtrAnswer::Empty), "{code:?}: {answer:?}");
            let (records, status) = ptr_records_and_status(vec![answer]);
            assert!(records.is_empty());
            assert_eq!(status, QueryStatus::NoRecords, "{code:?}");
        }
    }

    #[test]
    fn ptr_resolver_error_still_fails() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let answer = ptr_answer(ip, Err(ResolveError::from("connection refused")));
        assert!(
            matches!(answer, PtrAnswer::Failed(ref e) if e.contains("192.0.2.1")),
            "{answer:?}"
        );
        let (_, status) = ptr_records_and_status(vec![answer]);
        assert!(matches!(status, QueryStatus::Failed(_)), "{status:?}");
    }

    #[test]
    fn ptr_status_is_failed_only_when_every_lookup_failed() {
        let names = PtrAnswer::Names(vec![DnsRecord::new("host.example.".to_string(), 300)]);
        let (records, status) = ptr_records_and_status(vec![names, PtrAnswer::Failed("x".to_string())]);
        assert_eq!(records.len(), 1);
        assert_eq!(status, QueryStatus::Success(1));
        let (_, status) = ptr_records_and_status(vec![PtrAnswer::Empty, PtrAnswer::Failed("x".to_string())]);
        assert_eq!(status, QueryStatus::NoRecords);
        assert_eq!(ptr_records_and_status(Vec::new()).1, QueryStatus::NotQueried);
    }

    #[test]
    fn ip_target_result_is_reverse_only() {
        let mut result = DnsResult::new();
        assert!(result.is_reverse_only());
        result.MX_status = QueryStatus::NoRecords;
        assert!(!result.is_reverse_only());
    }

    /// Live: google.com publishes DMARC at `_dmarc.google.com`, not at the apex.
    #[tokio::test]
    async fn google_dmarc_is_found_at_dmarc() {
        let scanner = test_scanner().await;
        let target = Target::parse("google.com").expect("Failed to parse target");
        let Ok(ScanResult::Dns(result)) = scanner.scan(&target, Protocol::Both).await else {
            panic!("DNS scan of google.com failed");
        };
        let dmarc = result.email_security.and_then(|e| e.dmarc_record);
        assert!(dmarc.as_deref().is_some_and(|d| d.starts_with("v=DMARC1")), "{dmarc:?}");
    }

    #[test]
    fn test_sort_records_is_order_independent() {
        let ns = |names: &[&str]| -> DnsResult {
            let mut r = DnsResult::new();
            for n in names {
                r.NS.push(DnsRecord::new(n.to_string(), 300));
            }
            r.A.push(DnsRecord::new(Ipv4Addr::new(9, 9, 9, 9), 60));
            r.A.push(DnsRecord::new(Ipv4Addr::new(1, 1, 1, 1), 60));
            r.sort_records();
            r
        };
        let one = ns(&["b.ns.example.", "a.ns.example.", "c.ns.example."]);
        let two = ns(&["c.ns.example.", "b.ns.example.", "a.ns.example."]);
        let values = |r: &DnsResult| r.NS.iter().map(|x| x.value.clone()).collect::<Vec<_>>();
        assert_eq!(values(&one), values(&two));
        assert_eq!(values(&one), vec!["a.ns.example.", "b.ns.example.", "c.ns.example."]);
        assert_eq!(one.A[0].value, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn test_sort_records_mx_by_priority() {
        let mut r = DnsResult::new();
        for (p, e) in [(20, "b."), (10, "z."), (10, "a.")] {
            r.MX.push(DnsRecord::new(
                MxRecord {
                    priority: p,
                    exchange: e.to_string(),
                },
                60,
            ));
        }
        r.sort_records();
        let got: Vec<_> =
            r.MX.iter()
                .map(|m| (m.value.priority, m.value.exchange.clone()))
                .collect();
        assert_eq!(
            got,
            vec![(10, "a.".to_string()), (10, "z.".to_string()), (20, "b.".to_string())]
        );
    }

    #[test]
    fn test_dns_record_ttl() {
        let record = DnsRecord::new("test.com".to_string(), 300);
        assert_eq!(record.ttl_original, 300);
        assert!(record.ttl_remaining() <= 300);
        assert!(!record.is_expired());
    }

    #[test]
    fn test_mx_record() {
        let mx = MxRecord {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        assert_eq!(mx.priority, 10);
        assert_eq!(mx.exchange, "mail.example.com");
    }

    #[test]
    fn test_soa_record() {
        let soa = SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            responsible_email: "admin.example.com".to_string(),
            serial: 2024010101,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum_ttl: 86400,
        };
        assert_eq!(soa.serial, 2024010101);
        assert_eq!(soa.refresh, 3600);
    }

    #[test]
    fn test_srv_record() {
        let srv = SrvRecord {
            priority: 10,
            weight: 20,
            port: 443,
            target: "server.example.com".to_string(),
        };
        assert_eq!(srv.priority, 10);
        assert_eq!(srv.port, 443);
    }

    #[test]
    fn test_caa_record() {
        let caa = CaaRecord {
            flags: 0,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };
        assert_eq!(caa.flags, 0);
        assert_eq!(caa.tag, "issue");
    }

    #[test]
    fn test_dns_scanner_creation() {
        let scanner = DnsScanner::new();
        assert_eq!(scanner.interval(), Duration::from_secs(DNS_SCAN_INTERVAL_SECS));
        assert_eq!(scanner.name(), "dns");
    }

    #[tokio::test]
    async fn test_dns_lookup_google() {
        let scanner = test_scanner().await;
        let target = Target::parse("google.com").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Both).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // Google should have A records
            assert!(!dns_result.A.is_empty());
            // Should have email security analysis for a domain
            assert!(dns_result.email_security.is_some());
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup() {
        let scanner = test_scanner().await;
        let target = Target::parse("8.8.8.8").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Both).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // 8.8.8.8 should have PTR records
            assert!(!dns_result.PTR.is_empty());
        }
    }

    #[test]
    fn test_email_security_analysis() {
        let analysis = EmailSecurityAnalysis {
            spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=quarantine;".to_string()),
            has_mx: true,
            mx_count: 2,
            mta_sts: LensOutcome::Absent,
            tls_rpt: LensOutcome::Absent,
        };

        assert!(analysis.spf_record.is_some());
        assert!(analysis.dmarc_record.is_some());
        assert!(analysis.has_mx);
        assert_eq!(analysis.mx_count, 2);
    }

    #[test]
    fn test_dns_record_ttl_expiration() {
        let mut record = DnsRecord::new("test.com".to_string(), 1);

        // Initially should not be expired
        assert!(!record.is_expired());

        // Manually set queried_at to past to simulate expiration
        record.queried_at = Instant::now() - Duration::from_secs(2);
        assert!(record.is_expired());
    }

    #[test]
    fn test_dns_result_update_ttls() {
        let mut result = DnsResult::new();

        // Add records with different TTLs
        result.A.push(DnsRecord::new("127.0.0.1".parse().unwrap(), 300));
        result.TXT.push(DnsRecord::new("v=spf1 -all".to_string(), 600));

        // Simulate time passing
        std::thread::sleep(Duration::from_millis(10));

        result.update_ttls();

        // TTL should have decreased (but might not be noticeable with such small sleep)
        assert!(result.A[0].ttl_remaining() <= 300);
        assert!(result.TXT[0].ttl_remaining() <= 600);
    }

    #[tokio::test]
    async fn test_dns_lookup_failure() {
        let scanner = test_scanner().await;
        let target = Target::parse("nonexistent-domain-12345.invalid").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Both).await;

        // Should handle DNS lookup failures gracefully
        match result {
            Ok(ScanResult::Dns(dns_result)) => {
                // Even if lookup fails, we should get an empty result
                assert!(dns_result.A.is_empty());
                assert!(dns_result.AAAA.is_empty());
            }
            Ok(_) => panic!("Expected Dns result"),
            Err(_) => {
                // It's also okay if it returns an error for invalid domains
            }
        }
    }

    #[test]
    fn test_soa_record_complete() {
        let soa = SoaRecord {
            primary_ns: "ns1.example.com".to_string(),
            responsible_email: "admin.example.com".to_string(),
            serial: 2024010101,
            refresh: 3600,
            retry: 1800,
            expire: 604800,
            minimum_ttl: 86400,
        };

        assert_eq!(soa.primary_ns, "ns1.example.com");
        assert_eq!(soa.responsible_email, "admin.example.com");
        assert_eq!(soa.serial, 2024010101);
        assert_eq!(soa.refresh, 3600);
        assert_eq!(soa.retry, 1800);
        assert_eq!(soa.expire, 604800);
        assert_eq!(soa.minimum_ttl, 86400);
    }

    #[test]
    fn test_srv_record_complete() {
        let srv = SrvRecord {
            priority: 10,
            weight: 20,
            port: 443,
            target: "server.example.com".to_string(),
        };

        assert_eq!(srv.priority, 10);
        assert_eq!(srv.weight, 20);
        assert_eq!(srv.port, 443);
        assert_eq!(srv.target, "server.example.com");
    }

    #[test]
    fn test_caa_record_complete() {
        let caa = CaaRecord {
            flags: 128,
            tag: "issue".to_string(),
            value: "letsencrypt.org".to_string(),
        };

        assert_eq!(caa.flags, 128);
        assert_eq!(caa.tag, "issue");
        assert_eq!(caa.value, "letsencrypt.org");
    }

    #[test]
    fn test_email_security_analysis_edge_cases() {
        // Test with no email security records
        let empty_analysis = EmailSecurityAnalysis {
            spf_record: None,
            dmarc_record: None,
            has_mx: false,
            mx_count: 0,
            mta_sts: LensOutcome::Absent,
            tls_rpt: LensOutcome::Absent,
        };

        assert!(empty_analysis.spf_record.is_none());
        assert!(empty_analysis.dmarc_record.is_none());
        assert!(!empty_analysis.has_mx);
        assert_eq!(empty_analysis.mx_count, 0);

        // Test with malformed SPF
        let malformed_analysis = EmailSecurityAnalysis {
            spf_record: Some("invalid spf record".to_string()),
            dmarc_record: Some("v=DMARC1; p=none;".to_string()),
            has_mx: true,
            mx_count: 1,
            mta_sts: LensOutcome::Absent,
            tls_rpt: LensOutcome::Absent,
        };

        assert!(malformed_analysis.spf_record.is_some());
    }

    #[tokio::test]
    async fn test_ipv6_dns_lookup() {
        let scanner = test_scanner().await;
        let target = Target::parse("google.com").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Both).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // Google should have both A and AAAA records
            assert!(!dns_result.A.is_empty());
            assert!(!dns_result.AAAA.is_empty());
        }
    }

    #[tokio::test]
    async fn test_protocol_aware_ipv4_only() {
        let scanner = test_scanner().await;
        let target = Target::parse("google.com").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Ipv4).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // Should have A records (IPv4)
            assert!(!dns_result.A.is_empty());
            // Should NOT have AAAA records (IPv6) when IPv4-only
            assert!(dns_result.AAAA.is_empty());
            // Should still have protocol-independent records
            assert!(dns_result.email_security.is_some());
        }
    }

    #[tokio::test]
    async fn test_protocol_aware_ipv6_only() {
        let scanner = test_scanner().await;
        let target = Target::parse("google.com").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Ipv6).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // Should NOT have A records (IPv4) when IPv6-only
            assert!(dns_result.A.is_empty());
            // Should have AAAA records (IPv6)
            assert!(!dns_result.AAAA.is_empty());
            // Should still have protocol-independent records
            assert!(dns_result.email_security.is_some());
        }
    }

    #[tokio::test]
    async fn test_protocol_aware_reverse_lookup() {
        let scanner = test_scanner().await;

        // Test IPv4 reverse lookup
        let ipv4_target = Target::parse("8.8.8.8").expect("Failed to parse IPv4 target");
        let ipv4_result = scanner.scan(&ipv4_target, Protocol::Ipv4).await;
        assert!(ipv4_result.is_ok());

        // Test IPv6 reverse lookup (using Google's IPv6 DNS)
        let ipv6_target = Target::parse("2001:4860:4860::8888").expect("Failed to parse IPv6 target");
        let ipv6_result = scanner.scan(&ipv6_target, Protocol::Ipv6).await;
        assert!(ipv6_result.is_ok());

        if let Ok(ScanResult::Dns(_dns_result)) = ipv6_result {
            // Should have PTR records for reverse lookup
            // Note: This might be empty if the reverse lookup fails, which is okay
            // The important thing is that it doesn't crash
        }
    }

    /// A DNS server on loopback that answers TXT queries for `records` (name, TXT string) and
    /// NXDOMAIN for everything else.
    async fn fake_dns(records: Vec<(&'static str, &'static str)>) -> u16 {
        use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
        use hickory_resolver::proto::rr::rdata::TXT;
        use hickory_resolver::proto::rr::{RData, Record};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut response = Message::new();
                response
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(query.op_code())
                    .set_recursion_desired(query.recursion_desired())
                    .set_recursion_available(true)
                    .add_queries(query.queries().to_vec());
                for question in query.queries() {
                    let name = question.name().to_ascii();
                    let answers: Vec<_> = records
                        .iter()
                        .filter(|(owner, _)| name.trim_end_matches('.').eq_ignore_ascii_case(owner))
                        .filter(|_| question.query_type() == RecordType::TXT)
                        .map(|(_, text)| {
                            Record::from_rdata(
                                question.name().clone(),
                                300,
                                RData::TXT(TXT::new(vec![text.to_string()])),
                            )
                        })
                        .collect();
                    if answers.is_empty() {
                        response.set_response_code(ResponseCode::NXDomain);
                    }
                    response.add_answers(answers);
                }
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        port
    }

    /// A resolver that asks only the server on `port` at 127.0.0.1.
    fn resolver_at(port: u16) -> TokioResolver {
        use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
        use hickory_resolver::name_server::TokioConnectionProvider;
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["127.0.0.1".parse().unwrap()], port, true),
        );
        Resolver::builder_with_config(config, TokioConnectionProvider::default()).build()
    }

    #[tokio::test]
    async fn mta_sts_and_tls_rpt_are_read_at_the_host_from_a_dns_fixture() {
        let port = fake_dns(vec![
            ("_mta-sts.site.test", "v=STSv1; id=20210803T010101;"),
            ("_smtp._tls.site.test", "v=TLSRPTv1;rua=mailto:sts-reports@site.test"),
            // A parent's record is never read for a subdomain (RFC 8461 §3.4).
            ("_mta-sts.test", "v=STSv1; id=parent"),
        ])
        .await;
        let scanner = test_scanner().await;
        let resolver = resolver_at(port);

        let (mta_sts, tls_rpt) = scanner.lookup_mail_transport(&resolver, "site.test.").await;
        assert_eq!(mta_sts, LensOutcome::Present("20210803T010101".to_string()));
        assert_eq!(
            tls_rpt,
            LensOutcome::Present("mailto:sts-reports@site.test".to_string())
        );

        let (mta_sts, tls_rpt) = scanner.lookup_mail_transport(&resolver, "www.site.test").await;
        assert_eq!(mta_sts, LensOutcome::Absent, "no parent-domain fallback");
        assert_eq!(tls_rpt, LensOutcome::Absent);
    }

    /// A resolver that never answers is a failed query, never an empty answer.
    #[tokio::test]
    async fn a_dns_failure_reads_failed_never_none() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = silent.local_addr().unwrap().port();
        let scanner = DnsScanner {
            timeout: Duration::from_millis(300),
            ..test_scanner().await
        };
        let resolver = resolver_at(port);

        assert_eq!(
            scanner.txt_at(&resolver, "_mta-sts.site.test").await,
            Err(QueryStatus::Timeout)
        );
        let (mta_sts, tls_rpt) = scanner.lookup_mail_transport(&resolver, "site.test").await;
        assert_eq!(mta_sts, LensOutcome::Failed("timed out".to_string()));
        assert_eq!(tls_rpt, LensOutcome::Failed("timed out".to_string()));
        drop(silent);
    }

    #[test]
    fn tagged_value_reads_the_versioned_record_and_keeps_failures() {
        let answer = |records: &[&str]| Ok(records.iter().map(|r| r.to_string()).collect());
        assert_eq!(
            tagged_value(
                answer(&["google-site-verification=x", "v=STSv1; id=abc"]),
                "STSv1",
                "id"
            ),
            LensOutcome::Present("abc".to_string())
        );
        assert_eq!(
            tagged_value(answer(&[" v=TLSRPTv1 ; RUA=mailto:a@b.c ; "]), "TLSRPTv1", "rua"),
            LensOutcome::Present("mailto:a@b.c".to_string())
        );
        assert_eq!(tagged_value(answer(&[]), "STSv1", "id"), LensOutcome::Absent);
        assert_eq!(
            tagged_value(answer(&["id=abc; v=STSv1"]), "STSv1", "id"),
            LensOutcome::Absent
        );
        assert_eq!(
            tagged_value(answer(&["v=STSv1; id="]), "STSv1", "id"),
            LensOutcome::Absent
        );
        assert_eq!(
            tagged_value(
                Err(QueryStatus::Failed("connection refused".to_string())),
                "STSv1",
                "id"
            ),
            LensOutcome::Failed("connection refused".to_string())
        );
        assert_eq!(
            tagged_value(Err(QueryStatus::Timeout), "TLSRPTv1", "rua"),
            LensOutcome::Failed("timed out".to_string())
        );
    }
}
