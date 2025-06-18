use dashmap::DashMap;
use std::collections::VecDeque;
use std::time::Instant;
use crate::target::Protocol;

pub struct AppState {
    pub target: String,
    pub scanners: DashMap<String, ScanState>,
    pub protocol: Protocol,
}

impl AppState {
    pub fn new(target: String) -> Self {
        Self {
            target,
            scanners: DashMap::new(),
            protocol: Protocol::Both, // Default to scanning both IPv4 and IPv6
        }
    }

    /// Switch to the next protocol in the cycle: Both -> Ipv4 -> Ipv6 -> Both
    pub fn cycle_protocol(&mut self) {
        self.protocol = match self.protocol {
            Protocol::Both => Protocol::Ipv4,
            Protocol::Ipv4 => Protocol::Ipv6,
            Protocol::Ipv6 => Protocol::Both,
        };
    }

    /// Get the current protocol as a display string
    pub fn protocol_display(&self) -> &'static str {
        self.protocol.as_str()
    }
}

pub struct ScanState {
    pub result: Option<ScanResult>,
    pub error: Option<eyre::Error>,
    pub status: ScanStatus,
    pub last_updated: Instant,
    pub history: VecDeque<TimestampedResult>,
}

#[derive(Debug, Clone)]
pub enum ScanStatus {
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TimestampedResult {
    pub timestamp: Instant,
    pub result: ScanResult,
}

#[derive(Debug, Clone)]
pub enum ScanResult {
    Ping(crate::scan::ping::PingResult),
    Dns(crate::scan::dns::DnsResult),
    Tls(crate::scan::tls::TlsResult),
    Http(crate::scan::http::HttpResult),
    Whois(crate::scan::whois::WhoisResult),
    Traceroute(crate::scan::traceroute::TracerouteResult),
    GeoIp(crate::scan::geoip::GeoIpResult),
    Port(crate::scan::port::PortResult),
}