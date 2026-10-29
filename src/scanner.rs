use async_trait::async_trait;
use eyre::Result;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

use crate::target::{Protocol, Target};
use crate::types::{AppState, ScanResult, ScanState, ScanStatus, TimestampedResult};

const DEFAULT_MAX_HISTORY_RESULTS: usize = 10;
const DEFAULT_SCAN_DEADLINE: Duration = Duration::from_secs(30);

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

    /// Longest a single scan may run before it is dropped and recorded as timed out
    fn deadline(&self) -> Duration {
        DEFAULT_SCAN_DEADLINE
    }

    /// Whether the protocol selection changes what this scanner does; `false` ignores protocol changes
    fn uses_protocol(&self) -> bool {
        true
    }

    /// Default implementation of the scanner loop.
    ///
    /// Waits on the interval tick or a protocol change, then scans. A protocol change while a scan
    /// is in flight drops that scan and starts a new one with the new protocol; either way the
    /// interval restarts from the change. Every scan is bounded by `deadline()`.
    async fn run(&self, target: Target, mut protocol_rx: watch::Receiver<Protocol>, state: Arc<Mutex<AppState>>) {
        let mut follow_protocol = self.uses_protocol();
        log::debug!(
            "[scanner] run: scanner={} target={} protocol={} interval={}ms deadline={}s follow_protocol={}",
            self.name(),
            target.display_name(),
            protocol_rx.borrow().as_str(),
            self.interval().as_millis(),
            self.deadline().as_secs(),
            follow_protocol
        );

        let mut ticker = tokio::time::interval(self.interval());
        let mut scan_count = 0u64;

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                changed = protocol_rx.changed(), if follow_protocol => {
                    if changed.is_err() {
                        follow_protocol = false;
                        log::debug!("[scanner] protocol_sender_dropped: scanner={} - continuing on ticks only", self.name());
                        continue;
                    }
                    ticker.reset();
                    log::debug!(
                        "[scanner] protocol_changed_while_idle: scanner={} protocol={}",
                        self.name(),
                        protocol_rx.borrow().as_str()
                    );
                }
            }

            // Scan until one completes without being superseded by a protocol change
            loop {
                let protocol = *protocol_rx.borrow_and_update();
                scan_count += 1;
                log::debug!(
                    "[scanner] scan_cycle_starting: scanner={} count={} protocol={}",
                    self.name(),
                    scan_count,
                    protocol.as_str()
                );
                mark_running(self.name(), &state);

                let deadline = self.deadline();
                let scan_start = Instant::now();
                let mut scan = Box::pin(tokio::time::timeout(deadline, self.scan(&target, protocol)));
                let outcome = loop {
                    tokio::select! {
                        outcome = &mut scan => break Some(outcome),
                        changed = protocol_rx.changed(), if follow_protocol => {
                            if changed.is_err() {
                                follow_protocol = false;
                                log::debug!("[scanner] protocol_sender_dropped: scanner={} - finishing in-flight scan", self.name());
                                continue;
                            }
                            break None;
                        }
                    }
                };

                let Some(outcome) = outcome else {
                    drop(scan);
                    ticker.reset();
                    log::debug!(
                        "[scanner] scan_cancelled: scanner={} count={} old_protocol={} new_protocol={} after={}ms",
                        self.name(),
                        scan_count,
                        protocol.as_str(),
                        protocol_rx.borrow().as_str(),
                        scan_start.elapsed().as_millis()
                    );
                    continue;
                };

                let result = outcome.unwrap_or_else(|_| Err(eyre::eyre!("timed out after {}s", deadline.as_secs())));
                record_outcome(self.name(), self.max_history(), protocol, scan_start, result, &state);
                log::debug!(
                    "[scanner] scan_cycle_completed: scanner={} count={} protocol={}",
                    self.name(),
                    scan_count,
                    protocol.as_str()
                );
                break;
            }
        }
    }
}

/// Flip the scanner's state to Running in place: the previous result, error and history stay visible.
fn mark_running(name: &str, state: &Arc<Mutex<AppState>>) {
    let state_guard = state.lock().unwrap();
    match state_guard.scanners.get_mut(name) {
        Some(mut scan_state) => {
            scan_state.status = ScanStatus::Running;
        }
        None => {
            state_guard.scanners.insert(
                name.to_string(),
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
    log::debug!("[scanner] status_updated: scanner={} status=Running", name);
}

/// Store a finished scan: a result is pushed to history (capped), an error keeps the last good result.
pub(crate) fn record_outcome(
    name: &str,
    max_history: usize,
    protocol: Protocol,
    scan_start: Instant,
    outcome: Result<ScanResult, eyre::Error>,
    state: &Arc<Mutex<AppState>>,
) {
    let scan_duration = scan_start.elapsed();
    let state_guard = state.lock().unwrap();
    let Some(mut scan_state) = state_guard.scanners.get_mut(name) else {
        log::warn!(
            "[scanner] state_not_found: scanner={} protocol={} - could not update scan state",
            name,
            protocol.as_str()
        );
        return;
    };

    match outcome {
        Ok(result) => {
            log::trace!(
                "[scanner] scan_completed: scanner={} protocol={} duration={}ms result={:#?}",
                name,
                protocol.as_str(),
                scan_duration.as_millis(),
                result
            );
            let timestamp = Instant::now();
            let old_history_len = scan_state.history.len();
            scan_state.history.push_back(TimestampedResult {
                timestamp,
                result: result.clone(),
            });
            scan_state.result = Some(result);
            scan_state.error = None;
            scan_state.status = ScanStatus::Complete;
            scan_state.last_updated = timestamp;

            // Keep last N results (configurable per scanner)
            while scan_state.history.len() > max_history {
                scan_state.history.pop_front();
            }
            log::debug!(
                "[scanner] state_updated: scanner={} protocol={} status=Complete history_len={}",
                name,
                protocol.as_str(),
                scan_state.history.len()
            );
            if old_history_len >= max_history {
                log::trace!(
                    "[scanner] history_trimmed: scanner={} protocol={} old_len={} new_len={}",
                    name,
                    protocol.as_str(),
                    old_history_len + 1,
                    scan_state.history.len()
                );
            }
        }
        Err(error) => {
            log::error!(
                "[scanner] scan_failed: scanner={} protocol={} duration={}ms error={}",
                name,
                protocol.as_str(),
                scan_duration.as_millis(),
                error
            );
            scan_state.error = Some(error);
            scan_state.status = ScanStatus::Failed;
            scan_state.last_updated = Instant::now();
            log::debug!(
                "[scanner] state_updated: scanner={} protocol={} status=Failed",
                name,
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

    /// A receiver whose sender is already gone: the loop runs on ticks only.
    fn fixed_protocol() -> watch::Receiver<Protocol> {
        watch::channel(Protocol::Both).1
    }

    async fn run_until<F: Fn(&AppState) -> bool>(scanner: Arc<StubScanner>, state: Arc<Mutex<AppState>>, done: F) {
        let target = Target::parse("example.com").unwrap();
        let handle = {
            let state = state.clone();
            tokio::spawn(async move { scanner.run(target, fixed_protocol(), state).await })
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
            tokio::spawn(async move { scanner.run(target, fixed_protocol(), state).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.abort();
        let guard = state.lock().unwrap();
        assert_eq!(guard.scanners.get("stub").unwrap().history.len(), 2);
    }

    /// A scan observed by a test: which protocol it was asked for and when (tokio clock) it started.
    type Call = (Protocol, tokio::time::Instant);

    /// Stub for the protocol and deadline tests. `scan()` reports each call, then sleeps `scan_time`
    /// (or never returns when `None`).
    struct ProtocolStub {
        calls: tokio::sync::mpsc::UnboundedSender<Call>,
        scan_time: Option<Duration>,
        uses_protocol: bool,
    }

    #[async_trait]
    impl Scanner for ProtocolStub {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn interval(&self) -> Duration {
            Duration::from_secs(3600)
        }
        fn uses_protocol(&self) -> bool {
            self.uses_protocol
        }
        async fn scan(&self, _target: &Target, protocol: Protocol) -> Result<ScanResult, eyre::Error> {
            self.calls.send((protocol, tokio::time::Instant::now())).unwrap();
            match self.scan_time {
                Some(scan_time) => tokio::time::sleep(scan_time).await,
                None => std::future::pending::<()>().await,
            }
            Ok(ScanResult::Ping(PingResult::new()))
        }
    }

    struct ProtocolHarness {
        tx: watch::Sender<Protocol>,
        calls: tokio::sync::mpsc::UnboundedReceiver<Call>,
        state: Arc<Mutex<AppState>>,
        handle: tokio::task::JoinHandle<()>,
    }

    fn spawn_protocol_stub(scan_time: Option<Duration>, uses_protocol: bool) -> ProtocolHarness {
        let (calls_tx, calls) = tokio::sync::mpsc::unbounded_channel();
        let (tx, rx) = watch::channel(Protocol::Both);
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        let scanner = ProtocolStub {
            calls: calls_tx,
            scan_time,
            uses_protocol,
        };
        let target = Target::parse("example.com").unwrap();
        let handle = {
            let state = state.clone();
            tokio::spawn(async move { scanner.run(target, rx, state).await })
        };
        ProtocolHarness {
            tx,
            calls,
            state,
            handle,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn protocol_change_mid_scan_restarts_scan_with_new_protocol_immediately() {
        let mut h = spawn_protocol_stub(Some(Duration::from_secs(60)), true);
        let (first_protocol, first_at) = h.calls.recv().await.unwrap();
        assert_eq!(first_protocol, Protocol::Both);

        h.tx.send(Protocol::Ipv4).unwrap();
        let (second_protocol, second_at) = h.calls.recv().await.unwrap();

        assert_eq!(second_protocol, Protocol::Ipv4);
        assert_eq!(second_at, first_at, "rescan started without the clock advancing");
        {
            let guard = h.state.lock().unwrap();
            let stub = guard.scanners.get("stub").unwrap();
            assert!(matches!(stub.status, ScanStatus::Running));
            assert!(stub.history.is_empty(), "the cancelled scan recorded nothing");
        }
        h.handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn protocol_change_while_idle_scans_immediately_and_resets_interval() {
        let mut h = spawn_protocol_stub(Some(Duration::ZERO), true);
        h.calls.recv().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1800)).await;

        let changed_at = tokio::time::Instant::now();
        h.tx.send(Protocol::Ipv6).unwrap();
        let (protocol, at) = h.calls.recv().await.unwrap();
        assert_eq!(protocol, Protocol::Ipv6);
        assert_eq!(at, changed_at);

        let (_, next_tick_at) = h.calls.recv().await.unwrap();
        assert_eq!(
            next_tick_at - changed_at,
            Duration::from_secs(3600),
            "next tick is a full interval after the change, not the original schedule"
        );
        h.handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn scan_past_deadline_records_timeout() {
        let mut h = spawn_protocol_stub(None, true);
        h.calls.recv().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        {
            let guard = h.state.lock().unwrap();
            let stub = guard.scanners.get("stub").unwrap();
            assert!(matches!(stub.status, ScanStatus::Failed));
            assert_eq!(stub.error.as_ref().unwrap().to_string(), "timed out after 30s");
        }
        h.handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn protocol_agnostic_scanner_is_not_rescanned_on_change() {
        let mut h = spawn_protocol_stub(Some(Duration::ZERO), false);
        h.calls.recv().await.unwrap();

        h.tx.send(Protocol::Ipv4).unwrap();
        let rescan = tokio::time::timeout(Duration::from_secs(60), h.calls.recv()).await;
        assert!(rescan.is_err(), "uses_protocol() == false must ignore the change");
        h.handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_sender_keeps_scanning_on_ticks() {
        let mut h = spawn_protocol_stub(Some(Duration::ZERO), true);
        h.calls.recv().await.unwrap();
        drop(h.tx);

        let (protocol, _) = h.calls.recv().await.unwrap();
        assert_eq!(protocol, Protocol::Both, "next tick still scans with the last protocol");
        assert!(!h.handle.is_finished());
        h.handle.abort();
    }

    #[test]
    fn default_deadline_and_protocol_use() {
        let (scanner, _, _) = stub(None);
        assert_eq!(scanner.deadline(), Duration::from_secs(30));
        assert!(scanner.uses_protocol());
    }
}
