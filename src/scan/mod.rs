pub mod ping;

pub use ping::{PingScanner, PingResult};

use crate::scanner::Scanner;
use std::sync::Arc;

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    vec![
        Box::new(PingScanner::default()),
        // TODO: Add other scanners as they're implemented
        // Box::new(DnsScanner::default()),
        // Box::new(HttpScanner::default()),
    ]
}

pub async fn spawn_scanner_tasks(
    scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    target: String,
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