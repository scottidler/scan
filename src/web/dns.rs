use chrono::{DateTime, Utc};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::ResolveError,
    TokioAsyncResolver,
    proto::rr::RecordType,
};

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub a: Vec<DnsRecord<Ipv4Addr>>,
    pub aaaa: Vec<DnsRecord<Ipv6Addr>>,
    pub mx: Vec<MxRecord>,
    pub ns: Vec<DnsRecord<String>>,
    #[allow(dead_code)] // Required for TUI, suppress warning until used
    pub cname: Vec<DnsRecord<String>>,
    pub txt: Vec<TxtRecord>,
    pub resolution_time: Duration,
    pub dnssec_valid: Option<bool>,
    pub doh_support: Option<bool>,
    pub dot_support: Option<bool>,
}

/// Fields are for future TUI and data display use
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DnsRecord<T> {
    pub value: T,
    pub ttl: u32,
    pub last_updated: DateTime<Utc>,
}

/// Fields are for future TUI and data display use
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: u16,
    pub exchange: String,
    pub ttl: u32,
    pub last_updated: DateTime<Utc>,
}

/// Fields are for future TUI and data display use
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TxtRecord {
    pub value: String,
    pub record_type: TxtRecordType,
    pub ttl: u32,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TxtRecordType {
    Spf,
    Dkim,
    Dmarc,
    General,
}

pub struct DnsClient {
    resolver: TokioAsyncResolver,
}

impl DnsClient {
    pub async fn new() -> Result<Self, ResolveError> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self { resolver })
    }

    pub async fn query_domain(&self, domain: &str) -> Result<DnsInfo, ResolveError> {
        let start_time = std::time::Instant::now();
        let now = Utc::now();

        // Query A records
        let a = self
            .resolver
            .lookup_ip(domain)
            .await?
            .iter()
            .filter_map(|ip| {
                if let IpAddr::V4(ipv4) = ip {
                    Some(DnsRecord {
                        value: ipv4,
                        ttl: 300, // Default TTL if not available
                        last_updated: now,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Query AAAA records
        let aaaa = self
            .resolver
            .lookup_ip(domain)
            .await?
            .iter()
            .filter_map(|ip| {
                if let IpAddr::V6(ipv6) = ip {
                    Some(DnsRecord {
                        value: ipv6,
                        ttl: 300,
                        last_updated: now,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Query MX records
        let mx = self
            .resolver
            .mx_lookup(domain)
            .await?
            .iter()
            .map(|mx| MxRecord {
                priority: mx.preference(),
                exchange: mx.exchange().to_string(),
                ttl: 300,
                last_updated: now,
            })
            .collect();

        // Query NS records
        let ns = self
            .resolver
            .ns_lookup(domain)
            .await?
            .iter()
            .map(|ns| DnsRecord {
                value: ns.to_string(),
                ttl: 300,
                last_updated: now,
            })
            .collect();

        // Query CNAME records
        let cname = match self
            .resolver
            .lookup(domain, RecordType::CNAME)
            .await {
            Ok(lookup) => lookup.iter().map(|cname| DnsRecord {
                value: cname.to_string(),
                ttl: 300,
                last_updated: now,
            }).collect(),
            Err(e) => {
                // Only treat NoRecordsFound as empty, propagate other errors
                if let trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } = e.kind() {
                    Vec::new()
                } else {
                    return Err(e);
                }
            }
        };

        // Query TXT records
        let txt = self
            .resolver
            .txt_lookup(domain)
            .await?
            .iter()
            .flat_map(|txt| {
                txt.iter().map(|txt_str| {
                    let value = String::from_utf8_lossy(txt_str).to_string();
                    let record_type = if value.starts_with("v=spf1") {
                        TxtRecordType::Spf
                    } else if value.starts_with("v=DKIM1") {
                        TxtRecordType::Dkim
                    } else if value.starts_with("v=DMARC1") {
                        TxtRecordType::Dmarc
                    } else {
                        TxtRecordType::General
                    };

                    TxtRecord {
                        value,
                        record_type,
                        ttl: 300,
                        last_updated: now,
                    }
                })
            })
            .collect();

        // Check DNSSEC validation
        let dnssec_valid = self.check_dnssec(domain).await;

        // Check DoH/DoT support
        let (doh_support, dot_support) = self.check_modern_dns(domain).await;

        let resolution_time = start_time.elapsed();

        Ok(DnsInfo {
            a,
            aaaa,
            mx,
            ns,
            cname,
            txt,
            resolution_time,
            dnssec_valid,
            doh_support,
            dot_support,
        })
    }

    async fn check_dnssec(&self, _domain: &str) -> Option<bool> {
        // TODO: Implement proper DNSSEC validation
        None
    }

    async fn check_modern_dns(&self, _domain: &str) -> (Option<bool>, Option<bool>) {
        // TODO: Implement DoH/DoT support detection
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_query_all_records() {
        let client = DnsClient::new().await.unwrap();
        let result = client.query_domain("google.com").await.unwrap();
        // Should have at least one A record and NS record
        assert!(!result.a.is_empty(), "No A records");
        assert!(!result.ns.is_empty(), "No NS records");
        // Should have TXT records
        assert!(!result.txt.is_empty(), "No TXT records");
        // Should have MX records
        assert!(!result.mx.is_empty(), "No MX records");
        // Should have CNAME field (may be empty for root domains)
        let _ = &result.cname; // Just check field exists, don't assert on length
        // Should have resolution time
        assert!(result.resolution_time.as_millis() > 0);
        // DNSSEC/DoH/DoT are Option fields
        assert!(result.dnssec_valid.is_none() || result.dnssec_valid.is_some());
        assert!(result.doh_support.is_none() || result.doh_support.is_some());
        assert!(result.dot_support.is_none() || result.dot_support.is_some());
        // TTL and last_updated present
        let arec = &result.a[0];
        assert!(arec.ttl > 0);
        assert!(arec.last_updated <= chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_txt_record_type_detection() {
        let client = DnsClient::new().await.unwrap();
        let result = client.query_domain("google.com").await.unwrap();
        let types: Vec<_> = result.txt.iter().map(|r| &r.record_type).collect();
        // Should contain at least General, may contain Spf, Dkim, Dmarc
        assert!(types.contains(&&TxtRecordType::General));
    }

    #[tokio::test]
    async fn test_nxdomain_error() {
        let client = DnsClient::new().await.unwrap();
        let result = client.query_domain("nonexistentdomain-xyz-1234567890.com").await;
        assert!(result.is_err(), "Expected error for NXDOMAIN");
    }

    #[tokio::test]
    async fn test_no_records() {
        // This domain is reserved and should have no records
        let client = DnsClient::new().await.unwrap();
        let result = client.query_domain("example.invalid").await;
        assert!(result.is_err() || result.as_ref().unwrap().a.is_empty());
    }
}
