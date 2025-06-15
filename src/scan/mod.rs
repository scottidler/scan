pub mod ping;
pub mod dns;
pub mod tls;

pub use ping::{PingScanner, PingResult};
pub use dns::{DnsScanner, DnsResult};
pub use tls::{TlsScanner, TlsResult};

use crate::scanner::Scanner;
use crate::target::Target;
use std::sync::Arc;

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    vec![
        Box::new(PingScanner::default()),
        Box::new(DnsScanner::new()),
        Box::new(TlsScanner::new()),
        // TODO: Add other scanners as they're implemented
        // Box::new(HttpScanner::default()),
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