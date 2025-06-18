pub mod ping;
pub mod dns;
pub mod tls;
pub mod http;
pub mod whois;
pub mod traceroute;
pub mod geoip;
pub mod port;

pub use ping::{PingScanner, PingResult};
pub use dns::{DnsScanner, DnsResult};
pub use tls::{TlsScanner, TlsResult};
pub use http::{HttpScanner, HttpResult};
pub use whois::{WhoisScanner, WhoisResult};
pub use traceroute::{TracerouteScanner, TracerouteResult};
pub use geoip::{GeoIpScanner, GeoIpResult};
pub use port::{PortScanner, PortResult};

use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use std::sync::Arc;
use std::time::Duration;

const PING_SCANNER_INTERVAL_SECS: u64 = 60;
const PING_SCANNER_TIMEOUT_SECS: u64 = 5;
const PING_SCANNER_RETRY_COUNT: u8 = 3;

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    log::debug!("[scan] create_default_scanners: creating scanner instances");

    let scanners: Vec<Box<dyn Scanner + Send + Sync>> = vec![
        Box::new(PingScanner::new(Duration::from_secs(PING_SCANNER_INTERVAL_SECS), Duration::from_secs(PING_SCANNER_TIMEOUT_SECS), PING_SCANNER_RETRY_COUNT)),
        Box::new(DnsScanner::new()),
        Box::new(TlsScanner::new()),
        Box::new(HttpScanner::default()),
        Box::new(WhoisScanner::default()),
        Box::new(TracerouteScanner::new()),
        Box::new(GeoIpScanner::new()),
        Box::new(PortScanner::new()),
    ];

    log::debug!("[scan] scanners_created: count={}", scanners.len());
    scanners
}

pub async fn spawn_scanner_tasks(
    scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    target: Target,
    protocol: Protocol,
    state: Arc<crate::types::AppState>,
) {
    log::debug!("[scan] spawn_scanner_tasks: scanner_count={} target={} protocol={}",
        scanners.len(), target.display_name(), protocol.as_str());

    for scanner in scanners {
        let scanner_name = scanner.name();
        let target_clone = target.clone();
        let state_clone = state.clone();

        log::debug!("[scan] spawning_scanner_task: scanner={} protocol={}", 
            scanner_name, protocol.as_str());

        tokio::spawn(async move {
            log::debug!("[scan] scanner_task_started: scanner={} protocol={}", 
                scanner_name, protocol.as_str());
            scanner.run(target_clone, protocol, state_clone).await;
            log::debug!("[scan] scanner_task_ended: scanner={} protocol={}", 
                scanner_name, protocol.as_str());
        });
    }

    log::debug!("[scan] all_scanner_tasks_spawned: protocol={}", protocol.as_str());
}