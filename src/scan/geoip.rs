use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use log;

const GEOIP_SCAN_INTERVAL_SECS: u64 = 10 * 60; // 10 minutes
const GEOIP_HTTP_TIMEOUT_SECS: u64 = 10;
const RATE_LIMITER_WINDOW_SECS: u64 = 60;
const MIN_REQUEST_INTERVAL_SECS: u64 = 1;
const GEOIP_CACHE_TTL_SECS: u64 = 24 * 60 * 60; // 24 hours
const MAX_CACHE_SIZE: usize = 1000;
const CACHE_CLEANUP_THRESHOLD_SECS: u64 = 48 * 60 * 60; // 48 hours
const MULTI_IP_DELAY_MS: u64 = 100;
const IP_API_RATE_LIMIT: u32 = 45;

#[derive(Debug, Clone)]
pub struct GeoIpScanner {
    interval: Duration,
    service: Arc<GeoIpService>,
}

// Dual-protocol GeoIP result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub ipv4_result: Option<GeoIpData>,
    pub ipv6_result: Option<GeoIpData>,
    pub ipv4_status: GeoIpStatus,
    pub ipv6_status: GeoIpStatus,
    pub total_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpData {
    pub target_ip: IpAddr,
    pub location: Option<GeoLocation>,
    pub network_info: Option<NetworkInfo>,
    pub scan_duration: Duration,
    pub data_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeoIpStatus {
    Success,              // GeoIP lookup succeeded
    Failed(String),       // GeoIP lookup failed with error message
    NoAddress,           // No address available for this protocol
    NotQueried,          // Query was not attempted
}

impl GeoIpResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: GeoIpStatus::NotQueried,
            ipv6_status: GeoIpStatus::NotQueried,
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn get_primary_result(&self) -> Option<&GeoIpData> {
        // Prefer IPv4, then IPv6
        self.ipv4_result.as_ref().or(self.ipv6_result.as_ref())
    }

    pub fn has_any_success(&self) -> bool {
        matches!(self.ipv4_status, GeoIpStatus::Success) ||
        matches!(self.ipv6_status, GeoIpStatus::Success)
    }

    pub fn get_all_locations(&self) -> Vec<&GeoLocation> {
        let mut locations = Vec::new();
        if let Some(ipv4_data) = &self.ipv4_result {
            if let Some(location) = &ipv4_data.location {
                locations.push(location);
            }
        }
        if let Some(ipv6_data) = &self.ipv6_result {
            if let Some(location) = &ipv6_data.location {
                locations.push(location);
            }
        }
        locations
    }

    pub fn get_all_network_info(&self) -> Vec<&NetworkInfo> {
        let mut network_infos = Vec::new();
        if let Some(ipv4_data) = &self.ipv4_result {
            if let Some(network_info) = &ipv4_data.network_info {
                network_infos.push(network_info);
            }
        }
        if let Some(ipv6_data) = &self.ipv6_result {
            if let Some(network_info) = &ipv6_data.network_info {
                network_infos.push(network_info);
            }
        }
        network_infos
    }
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
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
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
        log::debug!("[scan::geoip] new: interval={}s", GEOIP_SCAN_INTERVAL_SECS);
        Self {
            interval: Duration::from_secs(GEOIP_SCAN_INTERVAL_SECS), // 10 minutes
            service: Arc::new(GeoIpService::new()),
        }
    }

    pub fn service(&self) -> Arc<GeoIpService> {
        self.service.clone()
    }

    async fn geoip_protocol(&self, target: &Target, protocol: Protocol) -> Result<GeoIpData> {
        log::debug!("[scan::geoip] geoip_protocol: target={} protocol={}", target.display_name(), protocol.as_str());

        // Check if target supports this protocol
        if !target.supports_protocol(protocol) {
            log::warn!("[scan::geoip] no_address_for_protocol: target={} protocol={}",
                target.display_name(), protocol.as_str());
            return Err(eyre::eyre!("No {} address available for target: {}", protocol.as_str(), target.display_name()));
        }

        // Get protocol-specific IP address
        let target_ip = match target.primary_ip_for_protocol(protocol) {
            Some(ip) => ip,
            None => {
                log::warn!("[scan::geoip] no_ip_for_protocol: target={} protocol={}",
                    target.display_name(), protocol.as_str());
                return Err(eyre::eyre!("No {} IP address available for target: {}", protocol.as_str(), target.display_name()));
            }
        };

        log::debug!("[scan::geoip] protocol_target: {} -> {} ({})",
            target.display_name(), target_ip, protocol.as_str());

        let geoip_data = self.perform_geoip_lookup_for_ip(target, target_ip).await?;
        Ok(geoip_data)
    }

    async fn perform_geoip_lookup_for_ip(&self, target: &Target, target_ip: IpAddr) -> Result<GeoIpData> {
        log::debug!("[scan::geoip] perform_geoip_lookup: target={}", target.display_name());

        let start_time = Instant::now();

        log::debug!("[scan::geoip] looking_up_ip: target={} ip={}", target.display_name(), target_ip);

        let lookup_start = Instant::now();
        match self.service.lookup_ip(target_ip).await {
            Ok((location, network_info, data_source)) => {
                let lookup_duration = lookup_start.elapsed();
                let scan_duration = start_time.elapsed();

                let result = GeoIpData {
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
                .timeout(Duration::from_secs(GEOIP_HTTP_TIMEOUT_SECS))
                .user_agent("scan-tool/1.0")
                .build()
                .expect("Failed to create HTTP client"),
            cache: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(RateLimiter {
                last_request: Instant::now() - Duration::from_secs(RATE_LIMITER_WINDOW_SECS),
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
        self.check_rate_limit(IP_API_RATE_LIMIT).await?;

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
        if now.duration_since(limiter.minute_start) >= Duration::from_secs(RATE_LIMITER_WINDOW_SECS) {
            limiter.requests_this_minute = 0;
            limiter.minute_start = now;
        }

        // Check if we're over the limit
        if limiter.requests_this_minute >= max_per_minute {
            let wait_time = Duration::from_secs(RATE_LIMITER_WINDOW_SECS) - now.duration_since(limiter.minute_start);
            return Err(eyre::eyre!("Rate limit exceeded, need to wait {:?}", wait_time));
        }

        // Ensure minimum delay between requests (1 second)
        let time_since_last = now.duration_since(limiter.last_request);
        if time_since_last < Duration::from_secs(MIN_REQUEST_INTERVAL_SECS) {
            let wait_time = Duration::from_secs(MIN_REQUEST_INTERVAL_SECS) - time_since_last;
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
            ttl: Duration::from_secs(GEOIP_CACHE_TTL_SECS), // Cache for 24 hours
        });

        // Limit cache size to prevent memory bloat
        if cache.len() > MAX_CACHE_SIZE {
            // Remove oldest entries (simple approach - in production might use LRU)
            let oldest_time = Instant::now() - Duration::from_secs(CACHE_CLEANUP_THRESHOLD_SECS);
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
            tokio::time::sleep(Duration::from_millis(MULTI_IP_DELAY_MS)).await;
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
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!("[scan::geoip] scan: target={} protocol={}", target.display_name(), protocol.as_str());

        let scan_start = Instant::now();
        let mut result = GeoIpResult::new();

        match protocol {
            Protocol::Ipv4 => {
                match self.geoip_protocol(target, Protocol::Ipv4).await {
                    Ok(data) => {
                        result.ipv4_result = Some(data.clone());
                        result.ipv4_status = GeoIpStatus::Success;
                        log::trace!("[scan::geoip] ipv4_geoip_completed: target={} ip={} source={} has_location={} has_network_info={}",
                            target.display_name(), data.target_ip, data.data_source, data.location.is_some(), data.network_info.is_some());
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv4_status = GeoIpStatus::NoAddress;
                            log::warn!("[scan::geoip] ipv4_geoip_no_address: target={}", target.display_name());
                        } else {
                            result.ipv4_status = GeoIpStatus::Failed(error_str);
                            log::error!("[scan::geoip] ipv4_geoip_failed: target={} error={}", target.display_name(), e);
                        }
                    }
                }
            }
            Protocol::Ipv6 => {
                match self.geoip_protocol(target, Protocol::Ipv6).await {
                    Ok(data) => {
                        result.ipv6_result = Some(data.clone());
                        result.ipv6_status = GeoIpStatus::Success;
                        log::trace!("[scan::geoip] ipv6_geoip_completed: target={} ip={} source={} has_location={} has_network_info={}",
                            target.display_name(), data.target_ip, data.data_source, data.location.is_some(), data.network_info.is_some());
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv6_status = GeoIpStatus::NoAddress;
                            log::warn!("[scan::geoip] ipv6_geoip_no_address: target={}", target.display_name());
                        } else {
                            result.ipv6_status = GeoIpStatus::Failed(error_str);
                            log::error!("[scan::geoip] ipv6_geoip_failed: target={} error={}", target.display_name(), e);
                        }
                    }
                }
            }
            Protocol::Both => {
                // Run both IPv4 and IPv6 GeoIP lookups concurrently
                let (ipv4_result, ipv6_result) = tokio::join!(
                    self.geoip_protocol(target, Protocol::Ipv4),
                    self.geoip_protocol(target, Protocol::Ipv6)
                );

                match ipv4_result {
                    Ok(data) => {
                        result.ipv4_result = Some(data.clone());
                        result.ipv4_status = GeoIpStatus::Success;
                        log::trace!("[scan::geoip] ipv4_geoip_completed: target={} ip={} source={} has_location={} has_network_info={}",
                            target.display_name(), data.target_ip, data.data_source, data.location.is_some(), data.network_info.is_some());
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv4_status = GeoIpStatus::NoAddress;
                            log::warn!("[scan::geoip] ipv4_geoip_no_address: target={}", target.display_name());
                        } else {
                            result.ipv4_status = GeoIpStatus::Failed(error_str);
                            log::error!("[scan::geoip] ipv4_geoip_failed: target={} error={}", target.display_name(), e);
                        }
                    }
                }

                match ipv6_result {
                    Ok(data) => {
                        result.ipv6_result = Some(data.clone());
                        result.ipv6_status = GeoIpStatus::Success;
                        log::trace!("[scan::geoip] ipv6_geoip_completed: target={} ip={} source={} has_location={} has_network_info={}",
                            target.display_name(), data.target_ip, data.data_source, data.location.is_some(), data.network_info.is_some());
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv6_status = GeoIpStatus::NoAddress;
                            log::warn!("[scan::geoip] ipv6_geoip_no_address: target={}", target.display_name());
                        } else {
                            result.ipv6_status = GeoIpStatus::Failed(error_str);
                            log::error!("[scan::geoip] ipv6_geoip_failed: target={} error={}", target.display_name(), e);
                        }
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if any protocol succeeded
        if result.has_any_success() {
            log::debug!("[scan::geoip] scan_completed: target={} protocol={} duration={}ms ipv4_status={:?} ipv6_status={:?}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(),
                result.ipv4_status, result.ipv6_status);
            Ok(ScanResult::GeoIp(result))
        } else {
            let error_msg = format!("All GeoIP protocols failed: IPv4={:?}, IPv6={:?}",
                result.ipv4_status, result.ipv6_status);
            log::error!("[scan::geoip] scan_failed: target={} protocol={} duration={}ms error={}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(), error_msg);
            Err(eyre::eyre!(error_msg))
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "geoip"
    }
}

#[cfg(test)]
mod tests {
    use super::*;


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
        assert!(scanner.scan(&target, Protocol::Both).await.is_err());
    }

    #[test]
    fn test_geo_location_structure() {
        let location = GeoLocation {
            country: "United States".to_string(),
            country_code: "US".to_string(),
            region: "California".to_string(),
            region_code: "CA".to_string(),
            city: "Mountain View".to_string(),
            latitude: 37.4056,
            longitude: -122.0775,
            timezone: "America/Los_Angeles".to_string(),
        };

        assert_eq!(location.country, "United States");
        assert_eq!(location.country_code, "US");
        assert_eq!(location.city, "Mountain View");
        assert!((location.latitude - 37.4056).abs() < 0.0001);
        assert!((location.longitude - (-122.0775)).abs() < 0.0001);
    }

    #[test]
    fn test_network_info_structure() {
        let network_info = NetworkInfo {
            isp: "Google LLC".to_string(),
            organization: "Google LLC".to_string(),
            asn: Some(15169),
            asn_name: Some("GOOGLE".to_string()),
            network_range: Some("8.8.8.0/24".to_string()),
        };

        assert_eq!(network_info.isp, "Google LLC");
        assert_eq!(network_info.asn, Some(15169));
        assert!(network_info.asn_name.is_some());
        assert!(network_info.network_range.is_some());
    }

    #[test]
    fn test_coordinate_parsing_edge_cases() {
        // Valid coordinates
        assert!(parse_coordinates("37.4056,-122.0775").is_some());
        assert!(parse_coordinates("0.0,0.0").is_some());
        assert!(parse_coordinates("-90.0,180.0").is_some());

        // Invalid coordinates
        assert!(parse_coordinates("invalid,coords").is_none());
        assert!(parse_coordinates("37.4056").is_none()); // Missing longitude
        assert!(parse_coordinates("37.4056,-122.0775,extra").is_none()); // Too many parts
        assert!(parse_coordinates("").is_none());
    }

    #[test]
    fn test_asn_parsing_edge_cases() {
        // Valid ASN formats
        let (asn, name) = parse_asn_info("AS15169 Google LLC").unwrap();
        assert_eq!(asn, Some(15169));
        assert_eq!(name, Some("Google LLC".to_string()));

        let (asn2, name2) = parse_asn_info("AS0 Test ASN").unwrap();
        assert_eq!(asn2, Some(0));
        assert_eq!(name2, Some("Test ASN".to_string()));

        // Invalid ASN formats
        assert!(parse_asn_info("15169 Google LLC").is_none()); // Missing AS prefix
        assert!(parse_asn_info("AS Google LLC").is_none()); // Non-numeric ASN
        assert!(parse_asn_info("ASinvalid Name").is_none());
        assert!(parse_asn_info("").is_none());
        assert!(parse_asn_info("AS15169").is_none()); // No name part
    }

    #[test]
    fn test_org_info_parsing() {
        // With ASN
        let (asn, name) = parse_org_info("AS15169 Google LLC");
        assert_eq!(asn, Some(15169));
        assert_eq!(name, Some("Google LLC".to_string()));

        // Without ASN
        let (asn2, name2) = parse_org_info("Some Organization");
        assert_eq!(asn2, None);
        assert_eq!(name2, Some("Some Organization".to_string()));

        // Edge cases
        let (asn3, name3) = parse_org_info("AS Invalid Organization");
        assert_eq!(asn3, None);
        assert_eq!(name3, Some("AS Invalid Organization".to_string()));
    }

    #[tokio::test]
    async fn test_geoip_result_structure() {
        let mut result = GeoIpResult::new();
        result.ipv4_result = Some(GeoIpData {
            target_ip: "8.8.8.8".parse().unwrap(),
            location: Some(GeoLocation {
                country: "United States".to_string(),
                country_code: "US".to_string(),
                region: "California".to_string(),
                region_code: "CA".to_string(),
                city: "Mountain View".to_string(),
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles".to_string(),
            }),
            network_info: Some(NetworkInfo {
                isp: "Google LLC".to_string(),
                organization: "Google LLC".to_string(),
                asn: Some(15169),
                asn_name: Some("GOOGLE".to_string()),
                network_range: Some("8.8.8.0/24".to_string()),
            }),
            scan_duration: Duration::from_millis(100),
            data_source: "ip-api.com".to_string(),
        });
        result.ipv4_status = GeoIpStatus::Success;
        result.total_duration = Duration::from_millis(100);

        assert!(result.has_any_success());
        if let Some(ipv4_data) = &result.ipv4_result {
            assert!(ipv4_data.location.is_some());
            assert!(ipv4_data.network_info.is_some());
            assert_eq!(ipv4_data.data_source, "ip-api.com");
            assert!(ipv4_data.scan_duration.as_millis() > 0);
        }
        assert!(result.total_duration.as_millis() > 0);
    }

    #[tokio::test]
    async fn test_rate_limiter_edge_cases() {
        let service = GeoIpService::new();

        // Test rate limiting with different limits
        assert!(service.check_rate_limit(10).await.is_ok());
        assert!(service.check_rate_limit(10).await.is_ok());

        // Fill up the rate limit
        for _ in 0..8 {
            let _ = service.check_rate_limit(10).await;
        }

        // Should now be rate limited
        assert!(service.check_rate_limit(10).await.is_err());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let service = GeoIpService::new();
        let test_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();

        // Cache a result
        service.cache_result(
            test_ip,
            Some(GeoLocation {
                country: "US".to_string(),
                country_code: "US".to_string(),
                region: "CA".to_string(),
                region_code: "CA".to_string(),
                city: "Mountain View".to_string(),
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles".to_string(),
            }),
            None,
            "test".to_string(),
        ).await;

        // Verify cache contains the entry
        let cache = service.cache.read().await;
        assert!(cache.contains_key(&test_ip));
    }

    #[tokio::test]
    async fn test_multiple_ip_lookup() {
        let service = GeoIpService::new();
        let ips = vec![
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];

        let results = service.lookup_multiple_ips(ips).await;

        // Should return results for both IPs (though they might be errors for test environment)
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_geoip_status_enum() {
        let success = GeoIpStatus::Success;
        let failed = GeoIpStatus::Failed("Network error".to_string());
        let no_address = GeoIpStatus::NoAddress;
        let not_queried = GeoIpStatus::NotQueried;

        // Test enum variants exist and can be created
        match success {
            GeoIpStatus::Success => assert!(true),
            _ => assert!(false, "Expected Success variant"),
        }

        match failed {
            GeoIpStatus::Failed(msg) => assert_eq!(msg, "Network error"),
            _ => assert!(false, "Expected Failed variant"),
        }

        match no_address {
            GeoIpStatus::NoAddress => assert!(true),
            _ => assert!(false, "Expected NoAddress variant"),
        }

        match not_queried {
            GeoIpStatus::NotQueried => assert!(true),
            _ => assert!(false, "Expected NotQueried variant"),
        }
    }

    #[test]
    fn test_geoip_result_helper_methods() {
        let mut result = GeoIpResult::new();

        // Test initial state
        assert!(!result.has_any_success());
        assert!(result.get_primary_result().is_none());
        assert!(result.get_all_locations().is_empty());
        assert!(result.get_all_network_info().is_empty());

        // Add IPv4 result
        result.ipv4_result = Some(GeoIpData {
            target_ip: "8.8.8.8".parse().unwrap(),
            location: Some(GeoLocation {
                country: "United States".to_string(),
                country_code: "US".to_string(),
                region: "California".to_string(),
                region_code: "CA".to_string(),
                city: "Mountain View".to_string(),
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles".to_string(),
            }),
            network_info: Some(NetworkInfo {
                isp: "Google LLC".to_string(),
                organization: "Google LLC".to_string(),
                asn: Some(15169),
                asn_name: Some("GOOGLE".to_string()),
                network_range: Some("8.8.8.0/24".to_string()),
            }),
            scan_duration: Duration::from_millis(100),
            data_source: "ip-api.com".to_string(),
        });
        result.ipv4_status = GeoIpStatus::Success;

        // Test with IPv4 success
        assert!(result.has_any_success());
        assert!(result.get_primary_result().is_some());
        assert_eq!(result.get_all_locations().len(), 1);
        assert_eq!(result.get_all_network_info().len(), 1);

        // Add IPv6 result
        result.ipv6_result = Some(GeoIpData {
            target_ip: "2001:4860:4860::8888".parse().unwrap(),
            location: Some(GeoLocation {
                country: "United States".to_string(),
                country_code: "US".to_string(),
                region: "California".to_string(),
                region_code: "CA".to_string(),
                city: "Mountain View".to_string(),
                latitude: 37.4056,
                longitude: -122.0775,
                timezone: "America/Los_Angeles".to_string(),
            }),
            network_info: Some(NetworkInfo {
                isp: "Google LLC".to_string(),
                organization: "Google LLC".to_string(),
                asn: Some(15169),
                asn_name: Some("GOOGLE".to_string()),
                network_range: Some("2001:4860:4860::/48".to_string()),
            }),
            scan_duration: Duration::from_millis(120),
            data_source: "ipinfo.io".to_string(),
        });
        result.ipv6_status = GeoIpStatus::Success;

        // Test with both IPv4 and IPv6 success
        assert!(result.has_any_success());
        assert!(result.get_primary_result().is_some());
        assert_eq!(result.get_all_locations().len(), 2);
        assert_eq!(result.get_all_network_info().len(), 2);

        // Primary result should prefer IPv4
        let primary = result.get_primary_result().unwrap();
        assert!(primary.target_ip.is_ipv4());
    }
}