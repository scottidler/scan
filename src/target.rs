use std::net::IpAddr;
use url::Url;
use eyre::{Result, WrapErr};
use tokio::net::lookup_host;
use tokio::time::Instant;

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
        log::debug!("[target] parse: input={}", input);
        
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
                
                let target = Self {
                    original: input.to_string(),
                    target_type: TargetType::Url(url.clone()),
                    domain: url.host_str().map(String::from),
                    port,
                    scheme: Some(url.scheme().to_string()),
                    resolved_ips: Vec::new(),
                };
                
                log::debug!("[target] parsed_as_url: domain={:?} port={:?} scheme={:?}", 
                    target.domain, target.port, target.scheme);
                return Ok(target);
            }
        }
        
        // Try IP address
        if let Ok(ip) = input.parse::<IpAddr>() {
            let target = Self {
                original: input.to_string(),
                target_type: TargetType::IpAddress(ip),
                domain: None,
                port: None,
                scheme: None,
                resolved_ips: vec![ip],
            };
            
            log::debug!("[target] parsed_as_ip: ip={}", ip);
            return Ok(target);
        }
        
        // Assume domain (with optional port)
        let (domain, port) = if let Some((d, p)) = input.split_once(':') {
            (d.to_string(), p.parse::<u16>().ok())
        } else {
            (input.to_string(), None)
        };
        
        let target = Self {
            original: input.to_string(),
            target_type: TargetType::Domain(domain.clone()),
            domain: Some(domain.clone()),
            port,
            scheme: None,
            resolved_ips: Vec::new(),
        };
        
        log::debug!("[target] parsed_as_domain: domain={} port={:?}", domain, port);
        Ok(target)
    }
    
    pub async fn resolve(&mut self) -> Result<&[IpAddr]> {
        log::debug!("[target] resolve: domain={:?} cached_ips={}", 
            self.domain, self.resolved_ips.len());
        
        if self.resolved_ips.is_empty() && self.domain.is_some() {
            let resolve_start = Instant::now();
            match self.resolve_domain().await {
                Ok(ips) => {
                    let resolve_duration = resolve_start.elapsed();
                    self.resolved_ips = ips;
                    log::trace!("[target] DNS resolution completed: domain={:?} ips={:?} duration={}ms", 
                        self.domain, self.resolved_ips, resolve_duration.as_millis());
                }
                Err(e) => {
                    let resolve_duration = resolve_start.elapsed();
                    log::error!("[target] DNS resolution failed: domain={:?} duration={}ms error={}", 
                        self.domain, resolve_duration.as_millis(), e);
                    return Err(e.wrap_err("Failed to resolve domain to IP addresses"));
                }
            }
        }
        
        log::debug!("[target] resolve_result: ip_count={}", self.resolved_ips.len());
        Ok(&self.resolved_ips)
    }
    
    pub fn primary_ip(&self) -> Option<IpAddr> {
        let ip = self.resolved_ips.first().copied();
        log::debug!("[target] primary_ip: {:?}", ip);
        ip
    }
    
    pub fn all_ips(&self) -> &[IpAddr] {
        log::debug!("[target] all_ips: count={}", self.resolved_ips.len());
        &self.resolved_ips
    }
    
    /// Get the hostname/domain for display purposes
    pub fn display_name(&self) -> &str {
        let name = match &self.target_type {
            TargetType::Url(url) => url.host_str().unwrap_or(&self.original),
            TargetType::Domain(domain) => domain,
            TargetType::IpAddress(_) => &self.original,
        };
        log::debug!("[target] display_name: {}", name);
        name
    }
    
    /// Get the target for ping/network commands (IP or domain)
    pub fn network_target(&self) -> String {
        let target = if let Some(ip) = self.primary_ip() {
            ip.to_string()
        } else if let Some(domain) = &self.domain {
            domain.clone()
        } else {
            self.original.clone()
        };
        log::debug!("[target] network_target: {}", target);
        target
    }
    
    /// Update resolved IPs from DNS scanner results
    pub fn update_resolved_ips(&mut self, ips: Vec<IpAddr>) {
        log::debug!("[target] update_resolved_ips: old_count={} new_count={}", 
            self.resolved_ips.len(), ips.len());
        self.resolved_ips = ips;
        log::trace!("[target] updated_ips: {:?}", self.resolved_ips);
    }
    
    /// Add additional resolved IPs
    pub fn add_resolved_ips(&mut self, mut ips: Vec<IpAddr>) {
        let old_count = self.resolved_ips.len();
        log::debug!("[target] add_resolved_ips: existing_count={} adding_count={}", 
            old_count, ips.len());
        
        self.resolved_ips.append(&mut ips);
        // Remove duplicates
        self.resolved_ips.sort();
        self.resolved_ips.dedup();
        
        let new_count = self.resolved_ips.len();
        log::debug!("[target] add_resolved_ips_result: final_count={} added={}", 
            new_count, new_count - old_count);
        log::trace!("[target] final_ips: {:?}", self.resolved_ips);
    }
    
    async fn resolve_domain(&self) -> Result<Vec<IpAddr>> {
        let domain = self.domain.as_ref()
            .ok_or_else(|| eyre::eyre!("No domain to resolve"))?;
        
        log::debug!("[target] resolve_domain: domain={} port={:?}", domain, self.port);
        
        // Use port 80 as default for resolution if no port specified
        let port = self.port.unwrap_or(80);
        let lookup_addr = format!("{}:{}", domain, port);
        
        log::trace!("[target] DNS lookup starting: lookup_addr={}", lookup_addr);
        
        let lookup_start = Instant::now();
        let addresses = match lookup_host(&lookup_addr).await {
            Ok(addrs) => {
                let lookup_duration = lookup_start.elapsed();
                log::trace!("[target] DNS lookup succeeded: duration={}ms", lookup_duration.as_millis());
                addrs
            }
            Err(e) => {
                let lookup_duration = lookup_start.elapsed();
                log::error!("[target] DNS lookup failed: domain={} duration={}ms error={}", 
                    domain, lookup_duration.as_millis(), e);
                return Err(e).wrap_err_with(|| format!("DNS resolution failed for {}", domain));
            }
        };
        
        let mut ips = Vec::new();
        for addr in addresses {
            ips.push(addr.ip());
        }
        
        if ips.is_empty() {
            log::error!("[target] DNS resolution returned no IPs: domain={}", domain);
            eyre::bail!("No IP addresses found for domain: {}", domain);
        }
        
        log::trace!("[target] DNS resolution successful: domain={} ips={:?}", domain, ips);
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