use dashmap::DashMap;
use std::collections::VecDeque;
use std::time::Instant;

pub struct AppState {
    pub target: String,
    pub scanners: DashMap<String, ScanState>,
}

impl AppState {
    pub fn new(target: String) -> Self {
        Self {
            target,
            scanners: DashMap::new(),
        }
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
    // TODO: Add other scanner result types
    // Http(crate::scan::http::HttpResult),
    // Port(crate::scan::port::PortResult),
    // Whois(crate::scan::whois::WhoisResult),
} 