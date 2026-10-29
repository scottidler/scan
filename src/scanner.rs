use async_trait::async_trait;
use eyre::Result;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::target::{Protocol, Target};
use crate::types::{AppState, ScanResult, ScanState, ScanStatus, TimestampedResult};

const DEFAULT_MAX_HISTORY_RESULTS: usize = 10;

#[allow(clippy::double_must_use)] // async_trait expansion trips newer clippy
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
        log::debug!(
            "[scanner] run: scanner={} target={} protocol={} interval={}ms",
            self.name(),
            target.display_name(),
            protocol.as_str(),
            self.interval().as_millis()
        );

        let mut ticker = tokio::time::interval(self.interval());
        let mut scan_count = 0u64;

        loop {
            ticker.tick().await;
            scan_count += 1;

            log::debug!(
                "[scanner] scan_cycle_starting: scanner={} count={} protocol={}",
                self.name(),
                scan_count,
                protocol.as_str()
            );

            // Flip to Running in place: the previous result, error and history stay visible
            {
                let state_guard = state.lock().unwrap();
                match state_guard.scanners.get_mut(self.name()) {
                    Some(mut scan_state) => {
                        scan_state.status = ScanStatus::Running;
                    }
                    None => {
                        state_guard.scanners.insert(
                            self.name().to_string(),
                            ScanState {
                                result: None,
                                error: None,
                                status: ScanStatus::Running,
                                last_updated: Instant::now(),
                                history: VecDeque::new(),
                            },
                        );
                    }
                }
                log::debug!(
                    "[scanner] status_updated: scanner={} status=Running protocol={}",
                    self.name(),
                    protocol.as_str()
                );
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

                    log::trace!(
                        "[scanner] scan_completed: scanner={} protocol={} duration={}ms result={:#?}",
                        self.name(),
                        protocol.as_str(),
                        scan_duration.as_millis(),
                        result
                    );

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

                            log::debug!(
                                "[scanner] state_updated: scanner={} protocol={} status=Complete history_len={}",
                                self.name(),
                                protocol.as_str(),
                                scan_state.history.len()
                            );

                            if old_history_len >= self.max_history() {
                                log::trace!(
                                    "[scanner] history_trimmed: scanner={} protocol={} old_len={} new_len={}",
                                    self.name(),
                                    protocol.as_str(),
                                    old_history_len + 1,
                                    scan_state.history.len()
                                );
                            }
                        } else {
                            log::warn!(
                                "[scanner] state_not_found: scanner={} protocol={} - could not update scan state",
                                self.name(),
                                protocol.as_str()
                            );
                        }
                    }
                }
                Err(error) => {
                    let scan_duration = scan_start.elapsed();
                    log::error!(
                        "[scanner] scan_failed: scanner={} protocol={} duration={}ms error={}",
                        self.name(),
                        protocol.as_str(),
                        scan_duration.as_millis(),
                        error
                    );

                    {
                        #[allow(unused_mut)]
                        let mut state_guard = state.lock().unwrap();
                        if let Some(mut scan_state) = state_guard.scanners.get_mut(self.name()) {
                            scan_state.error = Some(error);
                            scan_state.status = ScanStatus::Failed;
                            scan_state.last_updated = Instant::now();

                            log::debug!(
                                "[scanner] state_updated: scanner={} protocol={} status=Failed",
                                self.name(),
                                protocol.as_str()
                            );
                        } else {
                            log::warn!(
                                "[scanner] state_not_found: scanner={} protocol={} - could not update error state",
                                self.name(),
                                protocol.as_str()
                            );
                        }
                    }
                }
            }

            log::debug!(
                "[scanner] scan_cycle_completed: scanner={} count={} protocol={}",
                self.name(),
                scan_count,
                protocol.as_str()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ping::PingResult;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, PartialEq)]
    struct Snapshot {
        status_running: bool,
        has_result: bool,
        history_len: usize,
    }

    struct StubScanner {
        calls: AtomicUsize,
        state: Arc<Mutex<AppState>>,
        snapshots: Arc<Mutex<Vec<Snapshot>>>,
        fail_on_call: Option<usize>,
    }

    #[async_trait]
    impl Scanner for StubScanner {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn interval(&self) -> Duration {
            Duration::from_millis(20)
        }

        async fn scan(&self, _target: &Target, _protocol: Protocol) -> Result<ScanResult, eyre::Error> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let snapshot = {
                let guard = self.state.lock().unwrap();
                guard.scanners.get("stub").map(|s| Snapshot {
                    status_running: matches!(s.status, ScanStatus::Running),
                    has_result: s.result.is_some(),
                    history_len: s.history.len(),
                })
            };
            if let Some(snapshot) = snapshot {
                self.snapshots.lock().unwrap().push(snapshot);
            }
            if self.fail_on_call == Some(call) {
                return Err(eyre::eyre!("stub failure"));
            }
            Ok(ScanResult::Ping(PingResult::new()))
        }
    }

    async fn run_until<F: Fn(&AppState) -> bool>(scanner: Arc<StubScanner>, state: Arc<Mutex<AppState>>, done: F) {
        let target = Target::parse("example.com").unwrap();
        let handle = {
            let state = state.clone();
            tokio::spawn(async move { scanner.run(target, Protocol::Both, state).await })
        };
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if done(&state.lock().unwrap()) {
                break;
            }
        }
        handle.abort();
    }

    type StubParts = (Arc<StubScanner>, Arc<Mutex<AppState>>, Arc<Mutex<Vec<Snapshot>>>);

    fn stub(fail_on_call: Option<usize>) -> StubParts {
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let scanner = Arc::new(StubScanner {
            calls: AtomicUsize::new(0),
            state: state.clone(),
            snapshots: snapshots.clone(),
            fail_on_call,
        });
        (scanner, state, snapshots)
    }

    #[tokio::test]
    async fn second_cycle_keeps_result_and_history_while_running() {
        let (scanner, state, snapshots) = stub(None);
        run_until(scanner, state.clone(), |s| {
            s.scanners.get("stub").is_some_and(|x| x.history.len() >= 2)
        })
        .await;

        let snaps = snapshots.lock().unwrap();
        assert_eq!(
            snaps[0],
            Snapshot {
                status_running: true,
                has_result: false,
                history_len: 0
            },
            "first cycle: Running, nothing retained yet"
        );
        assert_eq!(
            snaps[1],
            Snapshot {
                status_running: true,
                has_result: true,
                history_len: 1
            },
            "second cycle: Running while retaining result and history"
        );
        let guard = state.lock().unwrap();
        let after = guard.scanners.get("stub").unwrap();
        assert_eq!(after.history.len(), 2);
        assert!(matches!(after.status, ScanStatus::Complete));
    }

    #[tokio::test]
    async fn failed_cycle_keeps_result_and_history() {
        let (scanner, state, _snapshots) = stub(Some(2));
        run_until(scanner, state.clone(), |s| {
            s.scanners
                .get("stub")
                .is_some_and(|x| matches!(x.status, ScanStatus::Failed))
        })
        .await;

        let guard = state.lock().unwrap();
        let after = guard.scanners.get("stub").unwrap();
        assert!(matches!(after.status, ScanStatus::Failed));
        assert!(after.error.is_some());
        assert!(after.result.is_some(), "last good result survives a failed cycle");
        assert_eq!(after.history.len(), 1);
    }

    #[tokio::test]
    async fn history_is_capped_at_max_history() {
        struct Capped(StubScanner);
        #[async_trait]
        impl Scanner for Capped {
            fn name(&self) -> &'static str {
                "stub"
            }
            fn interval(&self) -> Duration {
                Duration::from_millis(5)
            }
            fn max_history(&self) -> usize {
                2
            }
            async fn scan(&self, t: &Target, p: Protocol) -> Result<ScanResult, eyre::Error> {
                self.0.scan(t, p).await
            }
        }
        let (inner, state, _snapshots) = stub(None);
        let scanner = Arc::new(Capped(Arc::try_unwrap(inner).ok().unwrap()));
        let target = Target::parse("example.com").unwrap();
        let handle = {
            let state = state.clone();
            tokio::spawn(async move { scanner.run(target, Protocol::Both, state).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.abort();
        let guard = state.lock().unwrap();
        assert_eq!(guard.scanners.get("stub").unwrap().history.len(), 2);
    }
}
