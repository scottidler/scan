pub mod ping;
pub mod dns;
pub mod tls;
pub mod http;
pub mod whois;
pub mod traceroute;
pub mod geoip;

pub use ping::{PingScanner, PingResult};
pub use dns::{DnsScanner, DnsResult};
pub use tls::{TlsScanner, TlsResult};
pub use http::{HttpScanner, HttpResult};
pub use whois::{WhoisScanner, WhoisResult};
pub use traceroute::{TracerouteScanner, TracerouteResult};
pub use geoip::{GeoIpScanner, GeoIpResult};

use crate::scanner::Scanner;
use crate::target::Target;
use std::sync::Arc;

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    vec![
        Box::new(PingScanner::default()),
        Box::new(DnsScanner::new()),
        Box::new(TlsScanner::new()),
        Box::new(HttpScanner::default()),
        Box::new(WhoisScanner::default()),
        Box::new(TracerouteScanner::new()),
        Box::new(GeoIpScanner::new()),
        // TODO: Add other scanners as they're implemented
    ]
}

pub async fn spawn_scanner_tasks(
    scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    target: Target,
    state: Arc<crate::types::AppState>,
) {
    for scanner in scanners {
        let target_clone = target.clone();
        let state_clone = state.clone();
        
        tokio::spawn(async move {
            scanner.run(target_clone, state_clone).await;
        });
    }
} 