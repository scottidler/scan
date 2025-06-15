use std::net::IpAddr;
use url::Url;
use eyre::{Result, WrapErr};
use tokio::net::lookup_host;

#[derive(Debug, Clone)]
pub struct Target {
    pub original: String,
    pub target_type: TargetType,
    pub domain: Option<String>,      // Extracted domain for DNS scans
    pub port: Option<u16>,           // Extracted/default port
    pub scheme: Option<String>,      // http/https for URL targets
    resolved_ips: Vec<IpAddr>,       // Cached resolution results
}

#[derive(Debug, Clone)]
pub enum TargetType {
    Url(Url),
    Domain(String), 
    IpAddress(IpAddr),
}

impl Target {
    pub fn parse(input: &str) -> Result<Self> {
        // Try URL first (must have scheme)
        if input.contains("://") {
            if let Ok(url) = Url::parse(input) {
                // Get port from URL, or use default for scheme
                let port = url.port().or_else(|| {
                    match url.scheme() {
                        "http" => Some(80),
                        "https" => Some(443),
                        "ftp" => Some(21),
                        _ => None,
                    }
                });
                
                return Ok(Self {
                    original: input.to_string(),
                    target_type: TargetType::Url(url.clone()),
                    domain: url.host_str().map(String::from),
                    port,
                    scheme: Some(url.scheme().to_string()),
                    resolved_ips: Vec::new(),
                });
            }
        }
        
        // Try IP address
        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self {
                original: input.to_string(),
                target_type: TargetType::IpAddress(ip),
                domain: None,
                port: None,
                scheme: None,
                resolved_ips: vec![ip],
            });
        }
        
        // Assume domain (with optional port)
        let (domain, port) = if let Some((d, p)) = input.split_once(':') {
            (d.to_string(), p.parse::<u16>().ok())
        } else {
            (input.to_string(), None)
        };
        
        Ok(Self {
            original: input.to_string(),
            target_type: TargetType::Domain(domain.clone()),
            domain: Some(domain),
            port,
            scheme: None,
            resolved_ips: Vec::new(),
        })
    }
    
    pub async fn resolve(&mut self) -> Result<&[IpAddr]> {
        if self.resolved_ips.is_empty() && self.domain.is_some() {
            self.resolved_ips = self.resolve_domain().await
                .wrap_err("Failed to resolve domain to IP addresses")?;
        }
        Ok(&self.resolved_ips)
    }
    
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.resolved_ips.first().copied()
    }
    
    pub fn all_ips(&self) -> &[IpAddr] {
        &self.resolved_ips
    }
    
    /// Get the hostname/domain for display purposes
    pub fn display_name(&self) -> &str {
        match &self.target_type {
            TargetType::Url(url) => url.host_str().unwrap_or(&self.original),
            TargetType::Domain(domain) => domain,
            TargetType::IpAddress(_) => &self.original,
        }
    }
    
    /// Get the target for ping/network commands (IP or domain)
    pub fn network_target(&self) -> String {
        if let Some(ip) = self.primary_ip() {
            ip.to_string()
        } else if let Some(domain) = &self.domain {
            domain.clone()
        } else {
            self.original.clone()
        }
    }
    
    async fn resolve_domain(&self) -> Result<Vec<IpAddr>> {
        let domain = self.domain.as_ref()
            .ok_or_else(|| eyre::eyre!("No domain to resolve"))?;
        
        // Use port 80 as default for resolution if no port specified
        let port = self.port.unwrap_or(80);
        let lookup_addr = format!("{}:{}", domain, port);
        
        let mut ips = Vec::new();
        let addresses = lookup_host(&lookup_addr).await
            .wrap_err_with(|| format!("DNS resolution failed for {}", domain))?;
            
        for addr in addresses {
            ips.push(addr.ip());
        }
        
        if ips.is_empty() {
            eyre::bail!("No IP addresses found for domain: {}", domain);
        }
        
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_parse_ip_address() {
        let target = Target::parse("192.168.1.1").unwrap();
        assert!(matches!(target.target_type, TargetType::IpAddress(_)));
        assert_eq!(target.domain, None);
        assert_eq!(target.port, None);
        assert_eq!(target.primary_ip(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }
    
    #[test]
    fn test_parse_domain() {
        let target = Target::parse("google.com").unwrap();
        assert!(matches!(target.target_type, TargetType::Domain(_)));
        assert_eq!(target.domain, Some("google.com".to_string()));
        assert_eq!(target.port, None);
    }
    
    #[test]
    fn test_parse_domain_with_port() {
        let target = Target::parse("google.com:8080").unwrap();
        assert!(matches!(target.target_type, TargetType::Domain(_)));
        assert_eq!(target.domain, Some("google.com".to_string()));
        assert_eq!(target.port, Some(8080));
    }
    
    #[test]
    fn test_parse_url() {
        let target = Target::parse("https://google.com:443/path").unwrap();
        assert!(matches!(target.target_type, TargetType::Url(_)));
        assert_eq!(target.domain, Some("google.com".to_string()));
        assert_eq!(target.port, Some(443));
        assert_eq!(target.scheme, Some("https".to_string()));
    }
    
    #[test]
    fn test_parse_ipv6() {
        let target = Target::parse("2001:db8::1").unwrap();
        assert!(matches!(target.target_type, TargetType::IpAddress(_)));
        assert_eq!(target.domain, None);
        assert_eq!(target.primary_ip(), Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }
} 