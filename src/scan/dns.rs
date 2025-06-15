use crate::scanner::Scanner;
use crate::types::ScanResult;
use crate::target::{Target, TargetType};
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct DnsResult {
    pub A: Vec<DnsRecord<Ipv4Addr>>,
    pub AAAA: Vec<DnsRecord<Ipv6Addr>>,
    pub CNAME: Vec<DnsRecord<String>>,
    pub MX: Vec<DnsRecord<MxRecord>>,
    pub TXT: Vec<DnsRecord<String>>,
    pub NS: Vec<DnsRecord<String>>,
    pub CAA: Vec<DnsRecord<CaaRecord>>,
    pub PTR: Vec<DnsRecord<String>>, // For reverse DNS
    pub response_time: Duration,
    pub queried_at: Instant,
}

impl DnsResult {
    pub fn new() -> Self {
        Self {
            A: Vec::new(),
            AAAA: Vec::new(),
            CNAME: Vec::new(),
            MX: Vec::new(),
            TXT: Vec::new(),
            NS: Vec::new(),
            CAA: Vec::new(),
            PTR: Vec::new(),
            response_time: Duration::from_millis(0),
            queried_at: Instant::now(),
        }
    }
    
    pub fn update_ttls(&mut self) {
        // TTLs are calculated on-demand via ttl_remaining() method
        // This method exists for potential future TTL refresh logic
        // Currently, no action needed since TTL calculation is done dynamically
    }
}

pub struct DnsScanner {
    interval: Duration,
    timeout: Duration,
}

impl DnsScanner {
    pub fn new(interval: Duration, timeout: Duration) -> Self {
        Self { interval, timeout }
    }
}

impl Default for DnsScanner {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(60), // Query DNS every minute
            Duration::from_secs(5),  // 5 second timeout
        )
    }
}

#[async_trait]
impl Scanner for DnsScanner {
    fn name(&self) -> &'static str {
        "dns"
    }
    
    fn interval(&self) -> Duration {
        self.interval
    }
    
    async fn scan(&self, target: &Target) -> Result<ScanResult, eyre::Error> {
        let start_time = Instant::now();
        
        let mut result = match &target.target_type {
            TargetType::IpAddress(ip) => {
                // For IP addresses, do reverse DNS lookup
                self.scan_reverse_dns(*ip).await
                    .wrap_err_with(|| format!("Failed reverse DNS lookup for {}", ip))?
            }
            TargetType::Domain(_) | TargetType::Url(_) => {
                let domain = target.domain.as_ref()
                    .ok_or_else(|| eyre::eyre!("No domain found for DNS scan"))?;
                
                self.scan_forward_dns(domain).await
                    .wrap_err_with(|| format!("Failed DNS lookup for {}", domain))?
            }
        };
        
        result.response_time = start_time.elapsed();
        Ok(ScanResult::Dns(result))
    }
}

impl DnsScanner {
    async fn scan_forward_dns(&self, domain: &str) -> Result<DnsResult> {
        let mut result = DnsResult::new();
        
        // Create resolver using system config (which will use system DNS servers)
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .wrap_err("Failed to create DNS resolver")?;
        
        // A records (IPv4)
        if let Ok(lookup) = resolver.ipv4_lookup(domain).await {
            for ip in lookup.iter() {
                // Get TTL from the first record (they should all have the same TTL)
                let ttl = lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300); // Default 5 minutes if no TTL found
                result.A.push(DnsRecord::new(ip.0, ttl));
            }
        }
        
        // AAAA records (IPv6)  
        if let Ok(lookup) = resolver.ipv6_lookup(domain).await {
            for ip in lookup.iter() {
                let ttl = lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300);
                result.AAAA.push(DnsRecord::new(ip.0, ttl));
            }
        }
        
        // MX records
        if let Ok(mx_lookup) = resolver.mx_lookup(domain).await {
            for mx in mx_lookup.iter() {
                let ttl = mx_lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300);
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
        if let Ok(txt_lookup) = resolver.txt_lookup(domain).await {
            for txt in txt_lookup.iter() {
                let ttl = txt_lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300);
                let txt_data = txt.txt_data()
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                    .collect::<Vec<_>>()
                    .join("");
                result.TXT.push(DnsRecord::new(txt_data, ttl));
            }
        }
        
        // NS records
        if let Ok(ns_lookup) = resolver.ns_lookup(domain).await {
            for ns in ns_lookup.iter() {
                let ttl = ns_lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300);
                result.NS.push(DnsRecord::new(ns.to_string(), ttl));
            }
        }
        
        // TODO: Add CNAME and CAA lookups when hickory-resolver supports them directly
        // For now, we'll skip these to keep the implementation working
        
        Ok(result)
    }
    
    async fn scan_reverse_dns(&self, ip: IpAddr) -> Result<DnsResult> {
        let mut result = DnsResult::new();
        
        // Create resolver using system config
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .wrap_err("Failed to create DNS resolver")?;
        
        // Perform reverse DNS lookup (PTR records)
        if let Ok(ptr_lookup) = resolver.reverse_lookup(ip).await {
            for ptr in ptr_lookup.iter() {
                let ttl = ptr_lookup.as_lookup().records().first()
                    .map(|record| record.ttl())
                    .unwrap_or(300);
                result.PTR.push(DnsRecord::new(ptr.to_string(), ttl));
            }
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_dns_record_ttl() {
        let record = DnsRecord::new("test.com".to_string(), 300);
        
        // Initially should have full TTL
        assert!(record.ttl_remaining() <= 300);
        assert!(!record.is_expired());
        
        // Test TTL calculation logic
        let mut test_record = DnsRecord {
            value: "test.com".to_string(),
            ttl_original: 10,
            queried_at: Instant::now() - Duration::from_secs(5),
        };
        
        assert_eq!(test_record.ttl_remaining(), 5);
        
        // Test expiration
        test_record.queried_at = Instant::now() - Duration::from_secs(15);
        assert_eq!(test_record.ttl_remaining(), 0);
        assert!(test_record.is_expired());
    }
    
    #[test]
    fn test_mx_record() {
        let mx = MxRecord {
            priority: 10,
            exchange: "mail.google.com".to_string(),
        };
        
        assert_eq!(mx.priority, 10);
        assert_eq!(mx.exchange, "mail.google.com");
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
        assert_eq!(caa.value, "letsencrypt.org");
    }
    
    #[test]
    fn test_dns_result_creation() {
        let result = DnsResult::new();
        
        assert!(result.A.is_empty());
        assert!(result.AAAA.is_empty());
        assert!(result.CNAME.is_empty());
        assert!(result.MX.is_empty());
        assert!(result.TXT.is_empty());
        assert!(result.NS.is_empty());
        assert!(result.CAA.is_empty());
        assert!(result.PTR.is_empty());
    }
    
    #[tokio::test]
    async fn test_dns_scanner_creation() {
        let scanner = DnsScanner::default();
        assert_eq!(scanner.name(), "dns");
        assert_eq!(scanner.interval(), Duration::from_secs(60));
    }
    
    #[tokio::test]
    async fn test_dns_scanner_with_domain_target() {
        let scanner = DnsScanner::default();
        let target = Target::parse("google.com").unwrap();
        
        // This test will actually perform DNS lookups, so we need network access
        match scanner.scan(&target).await {
            Ok(ScanResult::Dns(result)) => {
                println!("DNS scan successful: {:?}", result);
                // We can't assert specific values since DNS can change, 
                // but we can check the structure is correct
                assert!(result.response_time > Duration::from_millis(0));
            }
            Err(e) => {
                // DNS lookups might fail in CI environments, so we log but don't fail
                eprintln!("DNS lookup failed (expected in some environments): {}", e);
            }
            _ => panic!("Expected DNS scan result"),
        }
    }
    
    #[tokio::test]
    async fn test_dns_scanner_with_ip_target() {
        let scanner = DnsScanner::default();
        let target = Target::parse("8.8.8.8").unwrap();
        
        // Test reverse DNS lookup
        match scanner.scan(&target).await {
            Ok(ScanResult::Dns(result)) => {
                println!("Reverse DNS scan successful: {:?}", result);
                assert!(result.response_time > Duration::from_millis(0));
                // 8.8.8.8 should have PTR records
                if !result.PTR.is_empty() {
                    println!("PTR records found: {:?}", result.PTR);
                }
            }
            Err(e) => {
                eprintln!("Reverse DNS lookup failed (expected in some environments): {}", e);
            }
            _ => panic!("Expected DNS scan result"),
        }
    }
    
    #[test]
    fn test_multiple_dns_records() {
        let mut result = DnsResult::new();
        
        // Add some test records
        result.A.push(DnsRecord::new(Ipv4Addr::new(1, 1, 1, 1), 300));
        result.A.push(DnsRecord::new(Ipv4Addr::new(8, 8, 8, 8), 300));
        
        result.AAAA.push(DnsRecord::new(
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), 
            3600
        ));
        
        result.MX.push(DnsRecord::new(
            MxRecord {
                priority: 10,
                exchange: "mail.google.com".to_string(),
            },
            1800,
        ));
        
        result.TXT.push(DnsRecord::new(
            "v=spf1 include:_spf.google.com ~all".to_string(),
            3600,
        ));
        
        assert_eq!(result.A.len(), 2);
        assert_eq!(result.AAAA.len(), 1);
        assert_eq!(result.MX.len(), 1);
        assert_eq!(result.TXT.len(), 1);
        
        // Test TTL functionality
        for record in &result.A {
            assert!(record.ttl_remaining() <= 300);
            assert!(!record.is_expired());
        }
    }
    
    #[test]
    fn test_dns_record_types_structure() {
        // Test that our record structures have the expected fields
        let _mx = MxRecord {
            priority: 10,
            exchange: "test.com".to_string(),
        };
        
        let _caa = CaaRecord {
            flags: 0,
            tag: "issue".to_string(),
            value: "ca.example.com".to_string(),
        };
        
        let _dns_record = DnsRecord::new("test.com".to_string(), 300);
        
        // If this compiles, our structure is correct
        assert!(true);
    }
} 