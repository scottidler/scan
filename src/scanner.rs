use async_trait::async_trait;
use eyre::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::types::{AppState, ScanResult, ScanState, ScanStatus, TimestampedResult};

#[async_trait]
pub trait Scanner {
    /// Scanner identifier for state storage
    fn name(&self) -> &'static str;
    
    /// How frequently this scanner should run
    fn interval(&self) -> Duration;
    
    /// Perform the actual scan operation
    async fn scan(&self, target: &str) -> Result<ScanResult, eyre::Error>;
    
    /// Default implementation of the scanner loop
    async fn run(&self, target: String, state: Arc<AppState>) {
        let mut ticker = tokio::time::interval(self.interval());
        
        loop {
            ticker.tick().await;
            
            // Update status to running
            {
                let scan_state = ScanState {
                    result: None,
                    error: None,
                    status: ScanStatus::Running,
                    last_updated: Instant::now(),
                    history: VecDeque::new(),
                };
                state.scanners.insert(self.name().to_string(), scan_state);
            }
            
            // Perform scan
            match self.scan(&target).await {
                Ok(result) => {
                    let timestamp = Instant::now();
                    let timestamped = TimestampedResult {
                        timestamp,
                        result: result.clone(),
                    };
                    
                    if let Some(mut scan_state) = state.scanners.get_mut(self.name()) {
                        scan_state.result = Some(result);
                        scan_state.error = None;
                        scan_state.status = ScanStatus::Complete;
                        scan_state.last_updated = timestamp;
                        scan_state.history.push_back(timestamped);
                        
                        // Keep last 100 results
                        if scan_state.history.len() > 100 {
                            scan_state.history.pop_front();
                        }
                    }
                }
                Err(error) => {
                    if let Some(mut scan_state) = state.scanners.get_mut(self.name()) {
                        scan_state.error = Some(error);
                        scan_state.status = ScanStatus::Failed;
                        scan_state.last_updated = Instant::now();
                    }
                }
            }
        }
    }
} 