pub mod dns;
pub mod geoip;
pub mod http;
pub mod ping;
pub mod port;
pub mod tls;
pub mod traceroute;
pub mod whois;

pub use dns::{DnsResult, DnsScanner};
pub use geoip::{GeoIpResult, GeoIpScanner};
pub use http::{HttpResult, HttpScanner};
pub use ping::{PingResult, PingScanner};
pub use port::{PortResult, PortScanner};
pub use tls::{TlsResult, TlsScanner};
pub use traceroute::{TracerouteResult, TracerouteScanner};
pub use whois::{WhoisResult, WhoisScanner};

use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use std::sync::{Arc, Mutex};

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    log::debug!("[scan] create_default_scanners: creating scanner instances");

    let scanners: Vec<Box<dyn Scanner + Send + Sync>> = vec![
        Box::new(PingScanner::default()),
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
    state: Arc<Mutex<crate::types::AppState>>,
) {
    log::debug!(
        "[scan] spawn_scanner_tasks: scanner_count={} target={} protocol={}",
        scanners.len(),
        target.display_name(),
        protocol.as_str()
    );

    for scanner in scanners {
        let scanner_name = scanner.name();
        let target_clone = target.clone();
        let state_clone = state.clone();

        log::debug!(
            "[scan] spawning_scanner_task: scanner={} protocol={}",
            scanner_name,
            protocol.as_str()
        );

        tokio::spawn(async move {
            log::debug!(
                "[scan] scanner_task_started: scanner={} protocol={}",
                scanner_name,
                protocol.as_str()
            );
            scanner.run(target_clone, protocol, state_clone).await;
            log::debug!(
                "[scan] scanner_task_ended: scanner={} protocol={}",
                scanner_name,
                protocol.as_str()
            );
        });
    }

    log::debug!("[scan] all_scanner_tasks_spawned: protocol={}", protocol.as_str());
}
