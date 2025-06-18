use async_trait::async_trait;
use eyre::Result;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::types::{AppState, ScanResult, ScanState, ScanStatus, TimestampedResult};
use crate::target::{Target, Protocol};

const DEFAULT_MAX_HISTORY_RESULTS: usize = 10;

#[async_trait]
pub trait Scanner {
    /// Scanner identifier for state storage
    fn name(&self) -> &'static str;

    /// How frequently this scanner should run
    fn interval(&self) -> Duration;

    /// Maximum number of historical results to keep
    fn max_history(&self) -> usize {
        DEFAULT_MAX_HISTORY_RESULTS
    }

    /// Perform the actual scan operation with protocol specification
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult, eyre::Error>;

    /// Default implementation of the scanner loop
    async fn run(&self, target: Target, protocol: Protocol, state: Arc<Mutex<AppState>>) {
        log::debug!("[scanner] run: scanner={} target={} protocol={} interval={}ms",
            self.name(), target.display_name(), protocol.as_str(), self.interval().as_millis());

        let mut ticker = tokio::time::interval(self.interval());
        let mut scan_count = 0u64;

        loop {
            ticker.tick().await;
            scan_count += 1;

            log::debug!("[scanner] scan_cycle_starting: scanner={} count={} protocol={}",
                self.name(), scan_count, protocol.as_str());

            // Update status to running
            {
                let scan_state = ScanState {
                    result: None,
                    error: None,
                    status: ScanStatus::Running,
                    last_updated: Instant::now(),
                    history: VecDeque::new(),
                };
                #[allow(unused_mut)]
                let mut state_guard = state.lock().unwrap();
                state_guard.scanners.insert(self.name().to_string(), scan_state);
                log::debug!("[scanner] status_updated: scanner={} status=Running protocol={}", 
                    self.name(), protocol.as_str());
            }

            // Perform scan
            let scan_start = Instant::now();
            match self.scan(&target, protocol).await {
                Ok(result) => {
                    let scan_duration = scan_start.elapsed();
                    let timestamp = Instant::now();
                    let timestamped = TimestampedResult {
                        timestamp,
                        result: result.clone(),
                    };

                    log::trace!("[scanner] scan_completed: scanner={} protocol={} duration={}ms result={:#?}",
                        self.name(), protocol.as_str(), scan_duration.as_millis(), result);

                    {
                        #[allow(unused_mut)]
                        let mut state_guard = state.lock().unwrap();
                        if let Some(mut scan_state) = state_guard.scanners.get_mut(self.name()) {
                            let old_history_len = scan_state.history.len();

                            scan_state.result = Some(result);
                            scan_state.error = None;
                            scan_state.status = ScanStatus::Complete;
                            scan_state.last_updated = timestamp;
                            scan_state.history.push_back(timestamped);

                            // Keep last N results (configurable per scanner)
                            while scan_state.history.len() > self.max_history() {
                                scan_state.history.pop_front();
                            }

                            log::debug!("[scanner] state_updated: scanner={} protocol={} status=Complete history_len={}",
                                self.name(), protocol.as_str(), scan_state.history.len());

                            if old_history_len >= self.max_history() {
                                log::trace!("[scanner] history_trimmed: scanner={} protocol={} old_len={} new_len={}",
                                    self.name(), protocol.as_str(), old_history_len + 1, scan_state.history.len());
                            }
                        } else {
                            log::warn!("[scanner] state_not_found: scanner={} protocol={} - could not update scan state",
                                self.name(), protocol.as_str());
                        }
                    }
                }
                Err(error) => {
                    let scan_duration = scan_start.elapsed();
                    log::error!("[scanner] scan_failed: scanner={} protocol={} duration={}ms error={}",
                        self.name(), protocol.as_str(), scan_duration.as_millis(), error);

                    {
                        #[allow(unused_mut)]
                        let mut state_guard = state.lock().unwrap();
                        if let Some(mut scan_state) = state_guard.scanners.get_mut(self.name()) {
                            scan_state.error = Some(error);
                            scan_state.status = ScanStatus::Failed;
                            scan_state.last_updated = Instant::now();

                            log::debug!("[scanner] state_updated: scanner={} protocol={} status=Failed", 
                                self.name(), protocol.as_str());
                        } else {
                            log::warn!("[scanner] state_not_found: scanner={} protocol={} - could not update error state",
                                self.name(), protocol.as_str());
                        }
                    }
                }
            }

            log::debug!("[scanner] scan_cycle_completed: scanner={} count={} protocol={}",
                self.name(), scan_count, protocol.as_str());
        }
    }
}