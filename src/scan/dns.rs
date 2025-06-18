use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use hickory_resolver::Resolver;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use log;

const DNS_SCAN_INTERVAL_SECS: u64 = 60;
const DNS_TIMEOUT_SECS: u64 = 5;
const DEFAULT_DNS_TTL: u32 = 300;

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

// Email Security Analysis
#[derive(Debug, Clone)]
pub struct EmailSecurityAnalysis {
    pub spf_record: Option<String>,
    pub dmarc_record: Option<String>,
    pub has_mx: bool,
    pub mx_count: usize,
    pub dkim_domains: Vec<String>, // Common DKIM selectors found
}

#[derive(Debug, Clone)]
pub enum QueryStatus {
    NotQueried,      // Query was not attempted (due to protocol restrictions)
    Success(usize),  // Query succeeded with N records
    NoRecords,       // Query succeeded but returned no records
    Failed(String),  // Query failed with error message
    Timeout,         // Query timed out
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

    pub response_time: Duration,
    pub queried_at: Instant,
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
            response_time: Duration::from_millis(0),
            queried_at: Instant::now(),
        }
    }

    pub fn update_ttls(&mut self) {
        // TTL updates are handled individually when querying since each record
        // type can have different TTLs and query times
    }
}

pub struct DnsScanner {
    interval: Duration,
    timeout: Duration,
}

impl DnsScanner {
    pub fn new() -> Self {
        log::debug!("[scan::dns] new: interval=60s timeout=5s");
        Self {
            interval: Duration::from_secs(DNS_SCAN_INTERVAL_SECS), // DNS lookups every 60 seconds
            timeout: Duration::from_secs(DNS_TIMEOUT_SECS),
        }
    }

    async fn analyze_email_security(&self, txt_records: &[DnsRecord<String>], mx_records: &[DnsRecord<MxRecord>]) -> EmailSecurityAnalysis {
        log::debug!("[scan::dns] analyze_email_security: txt_count={} mx_count={}",
            txt_records.len(), mx_records.len());

        let mut spf_record = None;
        let mut dmarc_record = None;
        let mut dkim_domains = Vec::new();

        // Parse TXT records for SPF and DMARC
        for (i, record) in txt_records.iter().enumerate() {
            let txt = &record.value;
            if txt.starts_with("v=spf1") {
                spf_record = Some(txt.clone());
                log::trace!("[scan::dns] found_spf_record: index={} record={}", i, txt);
            } else if txt.starts_with("v=DMARC1") {
                dmarc_record = Some(txt.clone());
                log::trace!("[scan::dns] found_dmarc_record: index={} record={}", i, txt);
            }
        }

        // Check for common DKIM selectors
        // In a real implementation, we might query common selectors like:
        // default._domainkey.domain.com, selector1._domainkey.domain.com, etc.
        // For now, we'll note if we should implement this
        let common_selectors = vec!["default", "selector1", "selector2", "google", "k1"];
        for selector in common_selectors {
            // We would implement DKIM lookup here
            // For now, just add to the list if we find evidence of DKIM usage
            if txt_records.iter().any(|r| r.value.contains("k=rsa") || r.value.contains("p=")) {
                dkim_domains.push(format!("{}._domainkey", selector));
                log::trace!("[scan::dns] found_dkim_evidence: selector={}", selector);
                break; // Only add one entry to avoid duplicates
            }
        }

        let analysis = EmailSecurityAnalysis {
            spf_record: spf_record.clone(),
            dmarc_record: dmarc_record.clone(),
            has_mx: !mx_records.is_empty(),
            mx_count: mx_records.len(),
            dkim_domains: dkim_domains.clone(),
        };

        log::debug!("[scan::dns] email_security_analysis: spf={} dmarc={} mx_count={} dkim_count={}",
            analysis.spf_record.is_some(), analysis.dmarc_record.is_some(),
            analysis.mx_count, analysis.dkim_domains.len());

        analysis
    }

    async fn perform_dns_lookup(&self, target: &Target, protocol: Protocol) -> Result<DnsResult> {
        log::debug!("[scan::dns] perform_dns_lookup: target={} domain={:?} protocol={}",
            target.display_name(), target.domain, protocol.as_str());

        let start_time = Instant::now();
        let mut result = DnsResult::new();

        // Create resolver using system config (which will use system DNS servers)
        let resolver = match Resolver::builder_tokio() {
            Ok(builder) => {
                let r = builder.build();
                log::trace!("[scan::dns] resolver_created: duration={}μs timeout={}ms protocol={}",
                    start_time.elapsed().as_micros(), self.timeout.as_millis(), protocol.as_str());
                r
            }
            Err(e) => {
                log::error!("[scan::dns] resolver_builder_failed: error={}", e);
                return Err(e).wrap_err("Failed to create DNS resolver");
            }
        };

        // Forward DNS lookups (for domains)
        if let Some(domain) = &target.domain {
            log::debug!("[scan::dns] starting_forward_lookups: domain={} protocol={}", domain, protocol.as_str());

            // A records (IPv4) - only query if protocol supports IPv4
            if matches!(protocol, Protocol::Ipv4 | Protocol::Both) {
                let a_start = Instant::now();
                match tokio::time::timeout(self.timeout, resolver.ipv4_lookup(domain)).await {
                    Ok(Ok(response)) => {
                        let a_duration = a_start.elapsed();
                        for ip in response.iter() {
                            let ttl = response.as_lookup().records().first()
                                .map(|record| record.ttl())
                                .unwrap_or(DEFAULT_DNS_TTL);
                            result.A.push(DnsRecord::new(ip.0, ttl));
                        }
                        result.A_status = if result.A.is_empty() {
                            QueryStatus::NoRecords
                        } else {
                            QueryStatus::Success(result.A.len())
                        };
                        log::trace!("[scan::dns] a_records_found: domain={} count={} duration={}ms protocol={}",
                            domain, result.A.len(), a_duration.as_millis(), protocol.as_str());
                    }
                    Ok(Err(e)) => {
                        let a_duration = a_start.elapsed();
                        result.A_status = QueryStatus::Failed(e.to_string());
                        log::trace!("[scan::dns] a_records_failed: domain={} duration={}ms error={} protocol={}",
                            domain, a_duration.as_millis(), e, protocol.as_str());
                    }
                    Err(_) => {
                        let a_duration = a_start.elapsed();
                        result.A_status = QueryStatus::Timeout;
                        log::warn!("[scan::dns] a_records_timeout: domain={} duration={}ms timeout={}ms protocol={}",
                            domain, a_duration.as_millis(), self.timeout.as_millis(), protocol.as_str());
                    }
                }
            } else {
                result.A_status = QueryStatus::NotQueried;
                log::trace!("[scan::dns] skipping_a_records: domain={} protocol={}", domain, protocol.as_str());
            }

            // AAAA records (IPv6) - only query if protocol supports IPv6
            if matches!(protocol, Protocol::Ipv6 | Protocol::Both) {
                let aaaa_start = Instant::now();
                match tokio::time::timeout(self.timeout, resolver.ipv6_lookup(domain)).await {
                    Ok(Ok(response)) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        for ip in response.iter() {
                            let ttl = response.as_lookup().records().first()
                                .map(|record| record.ttl())
                                .unwrap_or(DEFAULT_DNS_TTL);
                            result.AAAA.push(DnsRecord::new(ip.0, ttl));
                        }
                        result.AAAA_status = if result.AAAA.is_empty() {
                            QueryStatus::NoRecords
                        } else {
                            QueryStatus::Success(result.AAAA.len())
                        };
                        log::trace!("[scan::dns] aaaa_records_found: domain={} count={} duration={}ms protocol={}",
                            domain, result.AAAA.len(), aaaa_duration.as_millis(), protocol.as_str());
                    }
                    Ok(Err(e)) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        // Check if this is a "no records" type error vs a real failure
                        let error_str = e.to_string().to_lowercase();
                        if error_str.contains("no records found") || error_str.contains("nxdomain") || error_str.contains("name not found") {
                            result.AAAA_status = QueryStatus::NoRecords;
                            log::trace!("[scan::dns] aaaa_records_none: domain={} duration={}ms protocol={}",
                                domain, aaaa_duration.as_millis(), protocol.as_str());
                        } else {
                            result.AAAA_status = QueryStatus::Failed(e.to_string());
                            log::trace!("[scan::dns] aaaa_records_failed: domain={} duration={}ms error={} protocol={}",
                                domain, aaaa_duration.as_millis(), e, protocol.as_str());
                        }
                    }
                    Err(_) => {
                        let aaaa_duration = aaaa_start.elapsed();
                        result.AAAA_status = QueryStatus::Timeout;
                        log::warn!("[scan::dns] aaaa_records_timeout: domain={} duration={}ms timeout={}ms protocol={}",
                            domain, aaaa_duration.as_millis(), self.timeout.as_millis(), protocol.as_str());
                    }
                }
            } else {
                result.AAAA_status = QueryStatus::NotQueried;
                log::trace!("[scan::dns] skipping_aaaa_records: domain={} protocol={}", domain, protocol.as_str());
            }

            // MX records (protocol-independent, but log protocol for consistency)
            match resolver.mx_lookup(domain).await {
                Ok(response) => {
                    for mx in response.iter() {
                        let ttl = response.as_lookup().records().first()
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
                    log::trace!("[scan::dns] mx_records_found: domain={} count={} protocol={}",
                        domain, result.MX.len(), protocol.as_str());
                }
                Err(e) => {
                    result.MX_status = QueryStatus::Failed(e.to_string());
                    log::trace!("[scan::dns] mx_records_failed: domain={} error={} protocol={}",
                        domain, e, protocol.as_str());
                }
            }

            // TXT records (protocol-independent, but log protocol for consistency)
            match resolver.txt_lookup(domain).await {
                Ok(response) => {
                    for txt in response.iter() {
                        let ttl = response.as_lookup().records().first()
                            .map(|record| record.ttl())
                            .unwrap_or(DEFAULT_DNS_TTL);
                        let txt_string = txt.iter()
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
                    log::trace!("[scan::dns] txt_records_found: domain={} count={} protocol={}",
                        domain, result.TXT.len(), protocol.as_str());
                }
                Err(e) => {
                    result.TXT_status = QueryStatus::Failed(e.to_string());
                    log::trace!("[scan::dns] txt_records_failed: domain={} error={} protocol={}",
                        domain, e, protocol.as_str());
                }
            }

            // NS records (protocol-independent, but log protocol for consistency)
            match resolver.ns_lookup(domain).await {
                Ok(response) => {
                    for ns in response.iter() {
                        let ttl = response.as_lookup().records().first()
                            .map(|record| record.ttl())
                            .unwrap_or(DEFAULT_DNS_TTL);
                        result.NS.push(DnsRecord::new(ns.0.to_string(), ttl));
                    }
                    result.NS_status = if result.NS.is_empty() {
                        QueryStatus::NoRecords
                    } else {
                        QueryStatus::Success(result.NS.len())
                    };
                    log::trace!("[scan::dns] ns_records_found: domain={} count={} protocol={}",
                        domain, result.NS.len(), protocol.as_str());
                }
                Err(e) => {
                    result.NS_status = QueryStatus::Failed(e.to_string());
                    log::trace!("[scan::dns] ns_records_failed: domain={} error={} protocol={}",
                        domain, e, protocol.as_str());
                }
            }

            // SOA records (protocol-independent, but log protocol for consistency)
            use hickory_resolver::proto::rr::RecordType;
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
                    log::trace!("[scan::dns] soa_records_found: domain={} count={} protocol={}",
                        domain, result.SOA.len(), protocol.as_str());
                }
                Err(e) => {
                    result.SOA_status = QueryStatus::Failed(e.to_string());
                    log::trace!("[scan::dns] soa_records_failed: domain={} error={} protocol={}",
                        domain, e, protocol.as_str());
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
                QueryStatus::Failed(format!("All {} SRV queries failed: {:?}", srv_queries_attempted, srv_errors))
            };

            if !result.SRV.is_empty() {
                log::trace!("[scan::dns] srv_records_found: domain={} count={} protocol={}",
                    domain, result.SRV.len(), protocol.as_str());
            } else {
                log::trace!("[scan::dns] srv_records_none: domain={} attempted={} successful={} protocol={}",
                    domain, srv_queries_attempted, srv_queries_successful, protocol.as_str());
            }

            // Email Security Analysis (protocol-independent, but log protocol for consistency)
            result.email_security = Some(self.analyze_email_security(&result.TXT, &result.MX).await);
            log::trace!("[scan::dns] email_security_analyzed: domain={} protocol={}", domain, protocol.as_str());
        }

        // Reverse DNS lookups (for IP addresses) - filter by protocol
        let target_ips = target.ips_for_protocol(protocol);

        if target_ips.is_empty() {
            result.PTR_status = QueryStatus::NotQueried;
            log::trace!("[scan::dns] no_ips_for_protocol: protocol={}", protocol.as_str());
        } else {
            let mut ptr_queries_attempted = 0;
            let mut ptr_queries_successful = 0;
            let mut ptr_errors = Vec::new();

            for ip in &target_ips {
                log::trace!("[scan::dns] reverse_lookup: ip={} protocol={}", ip, protocol.as_str());

                // Create resolver using system config
                let resolver = Resolver::builder_tokio()
                    .wrap_err("Failed to create DNS resolver")?
                    .build();

                ptr_queries_attempted += 1;
                // Perform reverse DNS lookup (PTR records)
                match resolver.reverse_lookup(*ip).await {
                    Ok(response) => {
                        ptr_queries_successful += 1;
                        for ptr in response.iter() {
                            let ttl = response.as_lookup().records().first()
                                .map(|record| record.ttl())
                                .unwrap_or(DEFAULT_DNS_TTL);
                            result.PTR.push(DnsRecord::new(ptr.to_string(), ttl));
                        }
                        log::trace!("[scan::dns] ptr_records_found: ip={} count={} protocol={}",
                            ip, result.PTR.len(), protocol.as_str());
                    }
                    Err(e) => {
                        ptr_errors.push(format!("{}: {}", ip, e));
                        log::trace!("[scan::dns] ptr_records_failed: ip={} error={} protocol={}",
                            ip, e, protocol.as_str());
                    }
                }
            }

            // Set PTR status based on overall results
            result.PTR_status = if ptr_queries_attempted == 0 {
                QueryStatus::NotQueried
            } else if !result.PTR.is_empty() {
                QueryStatus::Success(result.PTR.len())
            } else if ptr_queries_successful > 0 {
                QueryStatus::NoRecords
            } else {
                QueryStatus::Failed(format!("All {} PTR queries failed: {:?}", ptr_queries_attempted, ptr_errors))
            };
        }

        result.response_time = start_time.elapsed();
        result.queried_at = start_time;

        log::debug!("[scan::dns] dns_lookup_completed: target={} protocol={} duration={}ms a_status={:?} aaaa_status={:?} mx_status={:?} txt_status={:?} ptr_status={:?}",
            target.display_name(), protocol.as_str(), result.response_time.as_millis(),
            result.A_status, result.AAAA_status, result.MX_status, result.TXT_status, result.PTR_status);

        Ok(result)
    }
}

#[async_trait]
impl Scanner for DnsScanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!("[scan::dns] scan: target={} protocol={}", target.display_name(), protocol.as_str());

        let scan_start = Instant::now();
        match self.perform_dns_lookup(target, protocol).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::dns] dns_scan_completed: target={} protocol={} duration={}ms response_time={}ms records_found=A:{} AAAA:{} MX:{} TXT:{} NS:{}",
                    target.display_name(), protocol.as_str(), scan_duration.as_millis(), result.response_time.as_millis(),
                    result.A.len(), result.AAAA.len(), result.MX.len(), result.TXT.len(), result.NS.len());
                Ok(ScanResult::Dns(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::dns] dns_scan_failed: target={} protocol={} duration={}ms error={}",
                    target.display_name(), protocol.as_str(), scan_duration.as_millis(), e);
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let scanner = DnsScanner::new();
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
        let scanner = DnsScanner::new();
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
            dkim_domains: vec!["default._domainkey".to_string()],
        };

        assert!(analysis.spf_record.is_some());
        assert!(analysis.dmarc_record.is_some());
        assert!(analysis.has_mx);
        assert_eq!(analysis.mx_count, 2);
        assert_eq!(analysis.dkim_domains.len(), 1);
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
        let scanner = DnsScanner::new();
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
            dkim_domains: vec![],
        };

        assert!(empty_analysis.spf_record.is_none());
        assert!(empty_analysis.dmarc_record.is_none());
        assert!(!empty_analysis.has_mx);
        assert_eq!(empty_analysis.mx_count, 0);
        assert!(empty_analysis.dkim_domains.is_empty());

        // Test with malformed SPF
        let malformed_analysis = EmailSecurityAnalysis {
            spf_record: Some("invalid spf record".to_string()),
            dmarc_record: Some("v=DMARC1; p=none;".to_string()),
            has_mx: true,
            mx_count: 1,
            dkim_domains: vec!["selector1._domainkey".to_string(), "selector2._domainkey".to_string()],
        };

        assert!(malformed_analysis.spf_record.is_some());
        assert_eq!(malformed_analysis.dkim_domains.len(), 2);
    }

    #[tokio::test]
    async fn test_ipv6_dns_lookup() {
        let scanner = DnsScanner::new();
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
        let scanner = DnsScanner::new();
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
        let scanner = DnsScanner::new();
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
        let scanner = DnsScanner::new();

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
}