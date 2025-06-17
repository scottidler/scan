use crate::scanner::Scanner;
use crate::target::Target;
use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use log;

#[derive(Debug, Clone)]
pub struct GeoIpScanner {
    interval: Duration,
    service: Arc<GeoIpService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub target_ip: IpAddr,
    pub location: Option<GeoLocation>,
    pub network_info: Option<NetworkInfo>,
    pub scan_duration: Duration,
    pub data_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub region_code: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub isp: String,
    pub organization: String,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub network_range: Option<String>,
}

// Shared GeoIP service for use by other scanners
#[derive(Debug)]
pub struct GeoIpService {
    client: Client,
    cache: RwLock<HashMap<IpAddr, CachedGeoData>>,
    rate_limiter: RwLock<RateLimiter>,
}

#[derive(Debug, Clone)]
struct CachedGeoData {
    location: Option<GeoLocation>,
    network_info: Option<NetworkInfo>,
    data_source: String,
    cached_at: Instant,
    ttl: Duration,
}

#[derive(Debug)]
struct RateLimiter {
    last_request: Instant,
    requests_this_minute: u32,
    minute_start: Instant,
}

// API response structures
#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    region: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[serde(rename = "as")]
    asn_info: Option<String>,
    query: String,
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    ip: String,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    loc: Option<String>, // "lat,lon" format
    org: Option<String>, // "AS#### Organization Name" format
    timezone: Option<String>,
}

impl Default for GeoIpScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpScanner {
    pub fn new() -> Self {
        log::debug!("[scan::geoip] new: interval=600s");
        Self {
            interval: Duration::from_secs(10 * 60), // 10 minutes
            service: Arc::new(GeoIpService::new()),
        }
    }

    pub fn service(&self) -> Arc<GeoIpService> {
        self.service.clone()
    }

    async fn perform_geoip_lookup(&self, target: &Target) -> Result<GeoIpResult> {
        log::debug!("[scan::geoip] perform_geoip_lookup: target={}", target.display_name());
        
        let start_time = Instant::now();
        
        // Get target IP
        let target_ip = if let Some(ip) = target.primary_ip() {
            ip
        } else {
            log::error!("[scan::geoip] no_ip_available: target={}", target.display_name());
            return Err(eyre::eyre!("No IP address available for GeoIP lookup"));
        };
        
        log::debug!("[scan::geoip] looking_up_ip: target={} ip={}", target.display_name(), target_ip);
        
        let lookup_start = Instant::now();
        match self.service.lookup_ip(target_ip).await {
            Ok((location, network_info, data_source)) => {
                let lookup_duration = lookup_start.elapsed();
                let scan_duration = start_time.elapsed();
                
                let result = GeoIpResult {
                    target_ip,
                    location: location.clone(),
                    network_info: network_info.clone(),
                    scan_duration,
                    data_source: data_source.clone(),
                };
                
                log::trace!("[scan::geoip] geoip_lookup_completed: target={} ip={} duration={}ms source={} has_location={} has_network_info={}", 
                    target.display_name(), target_ip, lookup_duration.as_millis(), data_source, 
                    location.is_some(), network_info.is_some());
                
                if let Some(loc) = &location {
                    log::trace!("[scan::geoip] location_found: target={} country={} city={} lat={} lon={}", 
                        target.display_name(), loc.country, loc.city, loc.latitude, loc.longitude);
                }
                
                if let Some(net) = &network_info {
                    log::trace!("[scan::geoip] network_info_found: target={} isp={} org={} asn={:?}", 
                        target.display_name(), net.isp, net.organization, net.asn);
                }
                
                Ok(result)
            }
            Err(e) => {
                let lookup_duration = lookup_start.elapsed();
                log::error!("[scan::geoip] geoip_lookup_failed: target={} ip={} duration={}ms error={}", 
                    target.display_name(), target_ip, lookup_duration.as_millis(), e);
                Err(e)
            }
        }
    }
}

impl GeoIpService {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("scan-tool/1.0")
                .build()
                .expect("Failed to create HTTP client"),
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(RateLimiter {
                last_request: Instant::now() - Duration::from_secs(60),
                requests_this_minute: 0,
                minute_start: Instant::now(),
            }),
        }
    }

    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<(Option<GeoLocation>, Option<NetworkInfo>, String)> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&ip) {
                if cached.cached_at.elapsed() < cached.ttl {
                    return Ok((
                        cached.location.clone(),
                        cached.network_info.clone(),
                        format!("{} (cached)", cached.data_source),
                    ));
                }
            }
        }

        // Try ip-api.com first (free, no auth required)
        match self.lookup_ip_api(ip).await {
            Ok((location, network_info)) => {
                self.cache_result(ip, location.clone(), network_info.clone(), "ip-api.com".to_string()).await;
                Ok((location, network_info, "ip-api.com".to_string()))
            }
            Err(_) => {
                // Fallback to ipinfo.io
                match self.lookup_ipinfo(ip).await {
                    Ok((location, network_info)) => {
                        self.cache_result(ip, location.clone(), network_info.clone(), "ipinfo.io".to_string()).await;
                        Ok((location, network_info, "ipinfo.io".to_string()))
                    }
                    Err(e) => Err(e.wrap_err("All GeoIP providers failed")),
                }
            }
        }
    }

    async fn lookup_ip_api(&self, ip: IpAddr) -> Result<(Option<GeoLocation>, Option<NetworkInfo>)> {
        // Check rate limit (45 requests per minute)
        self.check_rate_limit(45).await?;

        let url = format!("http://ip-api.com/json/{}?fields=status,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query", ip);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to send request to ip-api.com")?;

        let api_response: IpApiResponse = response
            .json()
            .await
            .wrap_err("Failed to parse ip-api.com response")?;

        if api_response.status != "success" {
            return Err(eyre::eyre!("ip-api.com returned failure status"));
        }

        let location = if api_response.country.is_some() {
            Some(GeoLocation {
                country: api_response.country.unwrap_or_default(),
                country_code: api_response.country_code.unwrap_or_default(),
                region: api_response.region_name.unwrap_or_default(),
                region_code: api_response.region.unwrap_or_default(),
                city: api_response.city.unwrap_or_default(),
                latitude: api_response.lat.unwrap_or(0.0),
                longitude: api_response.lon.unwrap_or(0.0),
                timezone: api_response.timezone.unwrap_or_default(),
            })
        } else {
            None
        };

        let network_info = if api_response.isp.is_some() || api_response.org.is_some() {
            let (asn, asn_name) = api_response.asn_info
                .as_ref()
                .and_then(|s| parse_asn_info(s))
                .unwrap_or((None, None));

            Some(NetworkInfo {
                isp: api_response.isp.unwrap_or_default(),
                organization: api_response.org.unwrap_or_default(),
                asn,
                asn_name,
                network_range: None, // ip-api doesn't provide this
            })
        } else {
            None
        };

        Ok((location, network_info))
    }

    async fn lookup_ipinfo(&self, ip: IpAddr) -> Result<(Option<GeoLocation>, Option<NetworkInfo>)> {
        // Check rate limit (50,000 requests per month, ~1600 per day, ~67 per hour, ~1 per minute)
        self.check_rate_limit(50).await?;

        let url = format!("https://ipinfo.io/{}/json", ip);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .wrap_err("Failed to send request to ipinfo.io")?;

        let api_response: IpInfoResponse = response
            .json()
            .await
            .wrap_err("Failed to parse ipinfo.io response")?;

        let location = if api_response.city.is_some() || api_response.country.is_some() {
            let (lat, lon) = api_response.loc
                .as_ref()
                .and_then(|s| parse_coordinates(s))
                .unwrap_or((0.0, 0.0));

            let country = api_response.country.clone().unwrap_or_default();
            let region = api_response.region.clone().unwrap_or_default();

            Some(GeoLocation {
                country: country.clone(),
                country_code: country, // ipinfo uses 2-letter codes
                region: region.clone(),
                region_code: region,
                city: api_response.city.unwrap_or_default(),
                latitude: lat,
                longitude: lon,
                timezone: api_response.timezone.unwrap_or_default(),
            })
        } else {
            None
        };

        let network_info = if let Some(org) = api_response.org {
            let (asn, asn_name) = parse_org_info(&org);
            Some(NetworkInfo {
                isp: asn_name.clone().unwrap_or_else(|| org.clone()),
                organization: org,
                asn,
                asn_name,
                network_range: None, // ipinfo doesn't provide this in free tier
            })
        } else {
            None
        };

        Ok((location, network_info))
    }

    async fn check_rate_limit(&self, max_per_minute: u32) -> Result<()> {
        let mut limiter = self.rate_limiter.write().await;
        
        let now = Instant::now();
        
        // Reset counter if a new minute has started
        if now.duration_since(limiter.minute_start) >= Duration::from_secs(60) {
            limiter.requests_this_minute = 0;
            limiter.minute_start = now;
        }
        
        // Check if we're over the limit
        if limiter.requests_this_minute >= max_per_minute {
            let wait_time = Duration::from_secs(60) - now.duration_since(limiter.minute_start);
            return Err(eyre::eyre!("Rate limit exceeded, need to wait {:?}", wait_time));
        }
        
        // Ensure minimum delay between requests (1 second)
        let time_since_last = now.duration_since(limiter.last_request);
        if time_since_last < Duration::from_secs(1) {
            let wait_time = Duration::from_secs(1) - time_since_last;
            tokio::time::sleep(wait_time).await;
        }
        
        limiter.requests_this_minute += 1;
        limiter.last_request = Instant::now();
        
        Ok(())
    }

    async fn cache_result(
        &self,
        ip: IpAddr,
        location: Option<GeoLocation>,
        network_info: Option<NetworkInfo>,
        data_source: String,
    ) {
        let mut cache = self.cache.write().await;
        cache.insert(ip, CachedGeoData {
            location,
            network_info,
            data_source,
            cached_at: Instant::now(),
            ttl: Duration::from_secs(24 * 60 * 60), // Cache for 24 hours
        });
        
        // Limit cache size to prevent memory bloat
        if cache.len() > 1000 {
            // Remove oldest entries (simple approach - in production might use LRU)
            let oldest_time = Instant::now() - Duration::from_secs(48 * 60 * 60);
            cache.retain(|_, v| v.cached_at > oldest_time);
        }
    }

    // Public method for other scanners to use
    pub async fn lookup_multiple_ips(&self, ips: Vec<IpAddr>) -> HashMap<IpAddr, (Option<GeoLocation>, Option<NetworkInfo>, String)> {
        let mut results = HashMap::new();
        
        for ip in ips {
            if let Ok((location, network_info, source)) = self.lookup_ip(ip).await {
                results.insert(ip, (location, network_info, source));
            }
            
            // Small delay between requests to be respectful
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        results
    }
}

// Helper functions
fn parse_asn_info(asn_str: &str) -> Option<(Option<u32>, Option<String>)> {
    // Format: "AS15169 Google LLC"
    if let Some(space_pos) = asn_str.find(' ') {
        let asn_part = &asn_str[..space_pos];
        let name_part = &asn_str[space_pos + 1..];
        
        if let Some(asn_num_str) = asn_part.strip_prefix("AS") {
            if let Ok(asn_num) = asn_num_str.parse::<u32>() {
                return Some((Some(asn_num), Some(name_part.to_string())));
            }
        }
    }
    None
}

fn parse_coordinates(loc_str: &str) -> Option<(f64, f64)> {
    // Format: "37.4056,-122.0775"
    let parts: Vec<&str> = loc_str.split(',').collect();
    if parts.len() == 2 {
        if let (Ok(lat), Ok(lon)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
            return Some((lat, lon));
        }
    }
    None
}

fn parse_org_info(org_str: &str) -> (Option<u32>, Option<String>) {
    // Format: "AS15169 Google LLC"
    if let Some(space_pos) = org_str.find(' ') {
        let asn_part = &org_str[..space_pos];
        let name_part = &org_str[space_pos + 1..];
        
        if let Some(asn_num_str) = asn_part.strip_prefix("AS") {
            if let Ok(asn_num) = asn_num_str.parse::<u32>() {
                return (Some(asn_num), Some(name_part.to_string()));
            }
        }
    }
    (None, Some(org_str.to_string()))
}

#[async_trait]
impl Scanner for GeoIpScanner {
    async fn scan(&self, target: &Target) -> Result<ScanResult> {
        log::debug!("[scan::geoip] scan: target={}", target.display_name());
        
        let scan_start = Instant::now();
        match self.perform_geoip_lookup(target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::geoip] geoip_scan_completed: target={} duration={}ms ip={} source={} has_location={} has_network_info={}", 
                    target.display_name(), scan_duration.as_millis(), result.target_ip, 
                    result.data_source, result.location.is_some(), result.network_info.is_some());
                Ok(ScanResult::GeoIp(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::geoip] geoip_scan_failed: target={} duration={}ms error={}", 
                    target.display_name(), scan_duration.as_millis(), e);
                Err(e.wrap_err("GeoIP scan failed"))
            }
        }
    }
    
    fn interval(&self) -> Duration {
        self.interval
    }
    
    fn name(&self) -> &'static str {
        "geoip"
    }
    
    async fn run(&self, target: Target, state: Arc<AppState>) {
        loop {
            // Update scan state to running
            let scan_state = ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            };
            state.scanners.insert(self.name().to_string(), scan_state);
            
            // Perform scan
            match self.scan(&target).await {
                Ok(result) => {
                    let mut scan_state = state.scanners.get_mut(self.name()).unwrap();
                    scan_state.result = Some(result);
                    scan_state.error = None;
                    scan_state.status = ScanStatus::Complete;
                    scan_state.last_updated = Instant::now();
                    
                    // Add to history
                    let timestamp = Instant::now();
                    let result_clone = scan_state.result.clone();
                    if let Some(result) = result_clone {
                        scan_state.history.push_back(crate::types::TimestampedResult {
                            timestamp,
                            result,
                        });
                        
                        // Keep only last 10 results
                        while scan_state.history.len() > 10 {
                            scan_state.history.pop_front();
                        }
                    }
                }
                Err(e) => {
                    let mut scan_state = state.scanners.get_mut(self.name()).unwrap();
                    scan_state.result = None;
                    scan_state.error = Some(e);
                    scan_state.status = ScanStatus::Failed;
                    scan_state.last_updated = Instant::now();
                }
            }
            
            // Wait for next scan
            sleep(self.interval()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_geoip_scanner_creation() {
        let scanner = GeoIpScanner::new();
        assert_eq!(scanner.name(), "geoip");
        assert_eq!(scanner.interval(), Duration::from_secs(10 * 60));
    }
    
    #[test]
    fn test_parse_asn_info() {
        let (asn, name) = parse_asn_info("AS15169 Google LLC").unwrap();
        assert_eq!(asn, Some(15169));
        assert_eq!(name, Some("Google LLC".to_string()));
        
        assert!(parse_asn_info("Invalid format").is_none());
    }
    
    #[test]
    fn test_parse_coordinates() {
        let (lat, lon) = parse_coordinates("37.4056,-122.0775").unwrap();
        assert!((lat - 37.4056).abs() < 0.0001);
        assert!((lon - (-122.0775)).abs() < 0.0001);
        
        assert!(parse_coordinates("invalid").is_none());
    }
    
    #[test]
    fn test_parse_org_info() {
        let (asn, name) = parse_org_info("AS15169 Google LLC");
        assert_eq!(asn, Some(15169));
        assert_eq!(name, Some("Google LLC".to_string()));
        
        let (asn2, name2) = parse_org_info("Some Organization");
        assert_eq!(asn2, None);
        assert_eq!(name2, Some("Some Organization".to_string()));
    }
    
    #[tokio::test]
    async fn test_geoip_service_creation() {
        let service = GeoIpService::new();
        // Just test that it creates without panicking
        assert!(service.cache.read().await.is_empty());
    }
    
    #[tokio::test]
    async fn test_rate_limiter() {
        let service = GeoIpService::new();
        
        // First request should succeed
        assert!(service.check_rate_limit(2).await.is_ok());
        
        // Second request should succeed
        assert!(service.check_rate_limit(2).await.is_ok());
        
        // Third request should fail (over limit of 2)
        assert!(service.check_rate_limit(2).await.is_err());
    }
    
    #[tokio::test]
    async fn test_geoip_scan_no_ip() {
        let scanner = GeoIpScanner::new();
        let target = Target::parse("nonexistent.invalid").unwrap();
        
        // Should fail because no IP is resolved
        assert!(scanner.scan(&target).await.is_err());
    }
} 