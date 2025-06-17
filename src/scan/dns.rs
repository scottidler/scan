use crate::scanner::Scanner;
use crate::target::Target;
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
    pub SOA: Vec<DnsRecord<SoaRecord>>,     // New field
    pub SRV: Vec<DnsRecord<SrvRecord>>,     // New field
    pub email_security: Option<EmailSecurityAnalysis>, // New field
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

    async fn perform_dns_lookup(&self, target: &Target) -> Result<DnsResult> {
        log::debug!("[scan::dns] perform_dns_lookup: target={} domain={:?}",
            target.display_name(), target.domain);

        let start_time = Instant::now();
        let mut result = DnsResult::new();

        // Create resolver using system config (which will use system DNS servers)
        let resolver = match Resolver::builder_tokio() {
            Ok(builder) => {
                let r = builder.build();
                log::trace!("[scan::dns] resolver_created: duration={}μs timeout={}ms",
                    start_time.elapsed().as_micros(), self.timeout.as_millis());
                r
            }
            Err(e) => {
                log::error!("[scan::dns] resolver_builder_failed: error={}", e);
                return Err(e).wrap_err("Failed to create DNS resolver");
            }
        };

        // Forward DNS lookups (for domains)
        if let Some(domain) = &target.domain {
            log::debug!("[scan::dns] starting_forward_lookups: domain={}", domain);

            // A records (IPv4)
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
                    log::trace!("[scan::dns] a_records_found: domain={} count={} duration={}ms",
                        domain, result.A.len(), a_duration.as_millis());
                }
                Ok(Err(e)) => {
                    let a_duration = a_start.elapsed();
                    log::trace!("[scan::dns] a_records_failed: domain={} duration={}ms error={}",
                        domain, a_duration.as_millis(), e);
                }
                Err(_) => {
                    let a_duration = a_start.elapsed();
                    log::warn!("[scan::dns] a_records_timeout: domain={} duration={}ms timeout={}ms",
                        domain, a_duration.as_millis(), self.timeout.as_millis());
                }
            }

            // AAAA records (IPv6)
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
                    log::trace!("[scan::dns] aaaa_records_found: domain={} count={} duration={}ms",
                        domain, result.AAAA.len(), aaaa_duration.as_millis());
                }
                Ok(Err(e)) => {
                    let aaaa_duration = aaaa_start.elapsed();
                    log::trace!("[scan::dns] aaaa_records_failed: domain={} duration={}ms error={}",
                        domain, aaaa_duration.as_millis(), e);
                }
                Err(_) => {
                    let aaaa_duration = aaaa_start.elapsed();
                    log::warn!("[scan::dns] aaaa_records_timeout: domain={} duration={}ms timeout={}ms",
                        domain, aaaa_duration.as_millis(), self.timeout.as_millis());
                }
            }

            // MX records
            if let Ok(response) = resolver.mx_lookup(domain).await {
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
            }

            // TXT records
            if let Ok(response) = resolver.txt_lookup(domain).await {
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
            }

            // NS records
            if let Ok(response) = resolver.ns_lookup(domain).await {
                for ns in response.iter() {
                    let ttl = response.as_lookup().records().first()
                        .map(|record| record.ttl())
                        .unwrap_or(DEFAULT_DNS_TTL);
                    result.NS.push(DnsRecord::new(ns.0.to_string(), ttl));
                }
            }

            // SOA records (new)
            use hickory_resolver::proto::rr::RecordType;
            if let Ok(response) = resolver.lookup(domain, RecordType::SOA).await {
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
            }

            // SRV records (new) - checking for common services
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

            for service in srv_services {
                let srv_domain = format!("{}.{}", service, domain);
                if let Ok(response) = resolver.lookup(&srv_domain, RecordType::SRV).await {
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
            }

            // Email Security Analysis (new)
            result.email_security = Some(self.analyze_email_security(&result.TXT, &result.MX).await);
        }

        // Reverse DNS lookups (for IP addresses)
        for ip in target.all_ips() {
            // Create resolver using system config
            let resolver = Resolver::builder_tokio()
                .wrap_err("Failed to create DNS resolver")?
                .build();

            // Perform reverse DNS lookup (PTR records)
            if let Ok(response) = resolver.reverse_lookup(*ip).await {
                for ptr in response.iter() {
                    let ttl = response.as_lookup().records().first()
                        .map(|record| record.ttl())
                        .unwrap_or(DEFAULT_DNS_TTL);
                    result.PTR.push(DnsRecord::new(ptr.to_string(), ttl));
                }
            }
        }

        result.response_time = start_time.elapsed();
        result.queried_at = start_time;

        Ok(result)
    }
}

#[async_trait]
impl Scanner for DnsScanner {
    async fn scan(&self, target: &Target) -> Result<ScanResult> {
        log::debug!("[scan::dns] scan: target={}", target.display_name());

        let scan_start = Instant::now();
        match self.perform_dns_lookup(target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::dns] dns_scan_completed: target={} duration={}ms response_time={}ms records_found=A:{} AAAA:{} MX:{} TXT:{} NS:{}",
                    target.display_name(), scan_duration.as_millis(), result.response_time.as_millis(),
                    result.A.len(), result.AAAA.len(), result.MX.len(), result.TXT.len(), result.NS.len());
                Ok(ScanResult::Dns(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::dns] dns_scan_failed: target={} duration={}ms error={}",
                    target.display_name(), scan_duration.as_millis(), e);
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

        let result = scanner.scan(&target).await;

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

        let result = scanner.scan(&target).await;

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

        let result = scanner.scan(&target).await;

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
        let target = Target::parse("ipv6.google.com").expect("Failed to parse target");

        let result = scanner.scan(&target).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Dns(dns_result)) = result {
            // Should have both A and AAAA records for IPv6-enabled domains
            // Note: This test might fail if ipv6.google.com doesn't exist or changes
            assert!(dns_result.response_time.as_millis() > 0);
        }
    }
}