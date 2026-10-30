pub mod connectivity;
pub mod dns;
pub mod geoip;
pub mod http;
pub mod layout;
pub mod pane;
pub mod ports;
pub mod security;
pub mod sparkline;
pub mod status;
pub mod target;
#[cfg(test)]
pub mod testing;
pub mod text;
pub mod traceroute;
pub mod whois;

pub use connectivity::ConnectivityPane;
pub use dns::DnsPane;
pub use geoip::GeoIpPane;
pub use http::HttpPane;
pub use layout::PaneLayout;
pub use pane::{Detail, Pane, PaneConfig, PanePosition};
pub use ports::PortsPane;
pub use security::SecurityPane;
pub use sparkline::SparklineData;
pub use status::{failure_text, status_label};
pub use target::TargetPane;
pub use traceroute::TraceroutePane;
pub use whois::WhoisPane;

use crate::target::Protocol;
use crate::types::AppState;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use log;
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

const TUI_TICK_RATE_MS: u64 = 250;
const FRAME_STATS_LOG_INTERVAL: u64 = 100;
const FALLBACK_TIMEOUT_SECS: u64 = 0;

/// Cycle `AppState.protocol` (Both -> IPv4 -> IPv6 -> Both) and send the new value to the scanners.
/// Returns the protocol now in effect.
pub fn switch_protocol(state: &Mutex<AppState>, protocol_tx: &watch::Sender<Protocol>) -> Protocol {
    let (old_protocol, new_protocol) = {
        let mut state_guard = state.lock().unwrap();
        let old = state_guard.protocol;
        state_guard.cycle_protocol();
        (old, state_guard.protocol)
    };
    match protocol_tx.send(new_protocol) {
        Ok(()) => log::info!(
            "[tui] protocol_changed: {} -> {} (scanners notified)",
            old_protocol.as_str(),
            new_protocol.as_str()
        ),
        Err(_) => log::error!(
            "[tui] protocol_change_not_delivered: {} -> {} - no scanner is listening",
            old_protocol.as_str(),
            new_protocol.as_str()
        ),
    }
    new_protocol
}

/// Wait up to `timeout` for a key press from the terminal.
fn read_key_press(timeout: Duration) -> io::Result<Option<event::KeyEvent>> {
    if crossterm::event::poll(timeout)?
        && let Event::Key(key) = event::read()?
        && key.kind == KeyEventKind::Press
    {
        return Ok(Some(key));
    }
    Ok(None)
}

/// Main TUI application
pub struct TuiApp {
    layout: PaneLayout,
    should_quit: bool,
    last_tick: Instant,
    tick_rate: Duration,
    /// When the process started, so the first-render log reports startup latency.
    startup: Instant,
}

impl TuiApp {
    /// Create a new TUI application with default layout
    pub fn new() -> io::Result<Self> {
        log::debug!("[tui] new: creating TUI application with default layout");

        // Initialize layout with default dashboard
        let mut layout = PaneLayout::default_dashboard();

        // Add panes to the layout
        log::trace!("[tui] adding_panes: setting up 3x4 dashboard layout");
        layout.add_pane(Box::new(TargetPane::new()), PaneConfig::new(0, 0));
        layout.add_pane(Box::new(ConnectivityPane::new()), PaneConfig::new(0, 1));
        layout.add_pane(Box::new(WhoisPane::new()), PaneConfig::new(1, 0));
        layout.add_pane(Box::new(HttpPane::new()), PaneConfig::new(1, 1));
        layout.add_pane(Box::new(PortsPane::new()), PaneConfig::new(1, 2));
        layout.add_pane(Box::new(GeoIpPane::new()), PaneConfig::new(1, 3));
        layout.add_pane(Box::new(DnsPane::new()), PaneConfig::new(2, 0));
        layout.add_pane(Box::new(TraceroutePane::new()), PaneConfig::new(2, 1));
        layout.add_pane(Box::new(SecurityPane::new()), PaneConfig::new(2, 2));

        // Set initial focus on the security pane
        layout.set_focus(Some("security".to_string()));
        log::debug!("[tui] initial_focus_set: pane=security");

        log::debug!("[tui] tui_app_created: tick_rate=250ms panes=9");
        Ok(Self {
            layout,
            should_quit: false,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(TUI_TICK_RATE_MS), // 4 FPS
            startup: Instant::now(),
        })
    }

    /// Measure `First TUI render completed` from `startup` (the process start) instead of from `new`.
    pub fn with_startup(mut self, startup: Instant) -> Self {
        self.startup = startup;
        self
    }

    /// Run the TUI event loop. `protocol_tx` is lent by `main`, which owns it; `p` sends on it.
    pub fn run<B: Backend>(
        self,
        terminal: &mut Terminal<B>,
        state: Arc<Mutex<AppState>>,
        protocol_tx: &watch::Sender<Protocol>,
    ) -> io::Result<()> {
        self.run_with_keys(terminal, state, protocol_tx, read_key_press)
    }

    /// The event loop with its key source injected: `next_key(timeout)` waits up to `timeout` for a
    /// key press.
    fn run_with_keys<B: Backend>(
        mut self,
        terminal: &mut Terminal<B>,
        state: Arc<Mutex<AppState>>,
        protocol_tx: &watch::Sender<Protocol>,
        mut next_key: impl FnMut(Duration) -> io::Result<Option<event::KeyEvent>>,
    ) -> io::Result<()> {
        log::debug!("[tui] run: starting TUI event loop");

        let mut frame_count = 0;
        let start_time = Instant::now();

        loop {
            self.ingest(&state);

            // Draw the UI
            let draw_start = Instant::now();
            terminal.draw(|f| self.ui(f, &state))?;
            let draw_duration = draw_start.elapsed();

            frame_count += 1;
            if frame_count == 1 {
                log::info!(
                    "[tui] First TUI render completed: startup_to_render={}ms",
                    self.startup.elapsed().as_millis()
                );
            }
            if frame_count % FRAME_STATS_LOG_INTERVAL == 0 {
                log::trace!(
                    "[tui] frame_stats: frames={} avg_draw_time={}μs uptime={}s",
                    frame_count,
                    draw_duration.as_micros(),
                    start_time.elapsed().as_secs()
                );
            }

            // Handle events
            let timeout = self
                .tick_rate
                .checked_sub(self.last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(FALLBACK_TIMEOUT_SECS));

            if let Some(key) = next_key(timeout)? {
                self.handle_key(key, &state, protocol_tx);
            }

            // Check if we should quit
            if self.should_quit {
                log::debug!(
                    "[tui] exiting_event_loop: frames_rendered={} uptime={}s",
                    frame_count,
                    start_time.elapsed().as_secs()
                );
                break;
            }

            // Update tick
            if self.last_tick.elapsed() >= self.tick_rate {
                self.last_tick = Instant::now();
            }
        }

        Ok(())
    }

    /// Act on one key press. Esc leaves zoom, and quits only from the grid; `q` and Ctrl-C always
    /// quit. Enter zooms the focused pane; Tab/Right and BackTab/Left move focus, which carries the
    /// zoom with it.
    fn handle_key(
        &mut self,
        key: event::KeyEvent,
        state: &Arc<Mutex<AppState>>,
        protocol_tx: &watch::Sender<Protocol>,
    ) {
        log::debug!(
            "[tui] key_event: key={:?} modifiers={:?} zoomed={}",
            key.code,
            key.modifiers,
            self.layout.is_zoomed()
        );
        match key.code {
            KeyCode::Char('q') => {
                log::debug!("[tui] quit_requested: key={:?}", key.code);
                self.should_quit = true;
            }
            KeyCode::Esc if self.layout.is_zoomed() => self.layout.unzoom(),
            KeyCode::Esc => {
                log::debug!("[tui] quit_requested: key={:?}", key.code);
                self.should_quit = true;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                log::debug!("[tui] quit_requested: ctrl_c");
                self.should_quit = true;
            }
            KeyCode::Enter => {
                self.layout.zoom();
            }
            KeyCode::Tab | KeyCode::Right => self.focus_next_pane(),
            KeyCode::BackTab | KeyCode::Left => self.focus_prev_pane(),
            KeyCode::Char('p') => {
                switch_protocol(state, protocol_tx);
            }
            // Scrolling for the focused pane
            _ => {
                let state_guard = state.lock().unwrap();
                let handled = self.layout.handle_key_event(key, &state_guard);
                log::trace!("[tui] key_handled_by_pane: key={:?} handled={}", key.code, handled);
            }
        }
    }

    /// The per-tick step that feeds every pane new scanner data, separate from drawing so a pane
    /// that is not drawn (zoom on another pane) still loses no scan results.
    fn ingest(&self, state: &Arc<Mutex<AppState>>) {
        let state_guard = state.lock().unwrap();
        self.layout.ingest(&state_guard);
    }

    /// Draw the UI
    fn ui(&mut self, frame: &mut ratatui::Frame, state: &Arc<Mutex<AppState>>) {
        let size = frame.area();
        log::trace!("[tui] ui_render: area={}x{}", size.width, size.height);

        // Render the layout with all panes
        let state_guard = state.lock().unwrap();
        self.layout.render(frame, size, &state_guard);
    }

    /// Check if the application should quit
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Set the quit flag
    pub fn quit(&mut self) {
        log::debug!("[tui] quit: setting quit flag");
        self.should_quit = true;
    }

    /// Focus the next pane in the layout
    fn focus_next_pane(&mut self) {
        let current = self.layout.focused_pane().map(|s| s.as_str());
        if let Some(next_pane) = self.layout.next_focusable_pane(current) {
            log::debug!("[tui] focus_next_pane: old={:?} new={}", current, next_pane);
            self.layout.set_focus(Some(next_pane));
        }
    }

    /// Focus the previous pane in the layout
    fn focus_prev_pane(&mut self) {
        let current = self.layout.focused_pane().map(|s| s.as_str());
        if let Some(prev_pane) = self.layout.prev_focusable_pane(current) {
            log::debug!("[tui] focus_prev_pane: old={:?} new={}", current, prev_pane);
            self.layout.set_focus(Some(prev_pane));
        }
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new().expect("Failed to create TuiApp")
    }
}

/// Initialize the terminal for TUI mode
pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    log::debug!("[tui] init_terminal: enabling raw mode and alternate screen");

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;

    log::debug!("[tui] terminal_initialized: backend=crossterm");
    Ok(terminal)
}

/// Restore the terminal after TUI mode
pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    log::debug!("[tui] restore_terminal: disabling raw mode and restoring screen");

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    log::debug!("[tui] terminal_restored:");
    Ok(())
}

/// Create the default pane layout for the dashboard
pub fn create_default_layout() -> PaneLayout {
    // This function is deprecated - use TuiApp::new() instead
    // Kept for test compatibility
    let mut layout = PaneLayout::default_dashboard();

    // Row 0: TARGET, CONNECTIVITY
    layout.add_pane(Box::new(TargetPane::new()), PaneConfig::new(0, 0));

    layout.add_pane(Box::new(ConnectivityPane::new()), PaneConfig::new(0, 1));

    // Row 1: WHOIS, HTTP, PORTS, GEOIP
    layout.add_pane(Box::new(WhoisPane::new()), PaneConfig::new(1, 0));

    layout.add_pane(Box::new(HttpPane::new()), PaneConfig::new(1, 1));

    layout.add_pane(Box::new(PortsPane::new()), PaneConfig::new(1, 2));

    layout.add_pane(Box::new(GeoIpPane::new()), PaneConfig::new(1, 3));

    // Row 2: DNS, TRACEROUTE, SECURITY
    layout.add_pane(Box::new(DnsPane::new()), PaneConfig::new(2, 0));

    layout.add_pane(Box::new(TraceroutePane::new()), PaneConfig::new(2, 1));

    layout.add_pane(Box::new(SecurityPane::new()), PaneConfig::new(2, 2));

    layout
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tui_app_creation() {
        let app = TuiApp::new().expect("Failed to create TuiApp");
        assert!(!app.should_quit());
        assert_eq!(app.tick_rate, Duration::from_millis(TUI_TICK_RATE_MS));

        // Check that panes were added
        let pane_ids = app.layout.pane_ids();
        assert!(pane_ids.contains(&"target".to_string()));
        assert!(pane_ids.contains(&"connectivity".to_string()));
        assert!(pane_ids.contains(&"security".to_string()));
        assert!(pane_ids.contains(&"whois".to_string()));
        assert!(pane_ids.contains(&"dns".to_string()));
        assert!(pane_ids.contains(&"http".to_string()));
        assert!(pane_ids.contains(&"ports".to_string()));
        assert!(pane_ids.contains(&"traceroute".to_string()));
        assert!(pane_ids.contains(&"geoip".to_string()));
    }

    #[test]
    fn test_quit_functionality() {
        let mut app = TuiApp::new().expect("Failed to create TuiApp");
        assert!(!app.should_quit());

        app.quit();
        assert!(app.should_quit());
    }

    #[test]
    fn test_default_layout_creation() {
        let layout = create_default_layout();
        let pane_ids = layout.pane_ids();

        // Should have the implemented panes
        assert!(!pane_ids.is_empty());
        assert!(pane_ids.contains(&"target".to_string()));
        assert!(pane_ids.contains(&"connectivity".to_string()));
        assert!(pane_ids.contains(&"security".to_string()));
        assert!(pane_ids.contains(&"whois".to_string()));
        assert!(pane_ids.contains(&"dns".to_string()));
        assert!(pane_ids.contains(&"http".to_string()));
        assert!(pane_ids.contains(&"ports".to_string()));
        assert!(pane_ids.contains(&"traceroute".to_string()));
        assert!(pane_ids.contains(&"geoip".to_string()));
    }

    #[test]
    fn switch_protocol_cycles_state_and_notifies_scanners() {
        let state = Mutex::new(AppState::new("example.com".to_string()));
        let (tx, mut rx) = watch::channel(Protocol::Both);

        assert_eq!(switch_protocol(&state, &tx), Protocol::Ipv4);
        assert_eq!(state.lock().unwrap().protocol, Protocol::Ipv4);
        assert!(rx.has_changed().unwrap(), "scanners see the change");
        assert_eq!(*rx.borrow_and_update(), Protocol::Ipv4);

        assert_eq!(switch_protocol(&state, &tx), Protocol::Ipv6);
        assert_eq!(*rx.borrow_and_update(), Protocol::Ipv6);
        assert_eq!(switch_protocol(&state, &tx), Protocol::Both);
        assert_eq!(*rx.borrow_and_update(), Protocol::Both);
    }

    #[test]
    fn switch_protocol_without_listeners_still_updates_state() {
        let state = Mutex::new(AppState::new("example.com".to_string()));
        let (tx, rx) = watch::channel(Protocol::Both);
        drop(rx);

        assert_eq!(switch_protocol(&state, &tx), Protocol::Ipv4);
        assert_eq!(state.lock().unwrap().protocol, Protocol::Ipv4);
    }

    #[test]
    fn test_key_modifiers_import() {
        // Test that KeyModifiers is properly imported and accessible
        let ctrl_modifier = KeyModifiers::CONTROL;
        assert_eq!(ctrl_modifier, KeyModifiers::CONTROL);
    }

    use crate::scan::ping::{PingResult, PingStatus};
    use crate::types::{ScanResult, ScanState, ScanStatus};
    use std::collections::VecDeque;

    /// Publish one ping result the way the scanner loop does.
    fn publish_ping(state: &Arc<Mutex<AppState>>, cycle: u64) {
        {
            let guard = state.lock().unwrap();
            guard.scanners.entry("ping".to_string()).or_insert_with(|| ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: VecDeque::new(),
            });
        }
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Success(Duration::from_millis(10 + cycle));
        ping.ipv6_status = PingStatus::Success(Duration::from_millis(20 + cycle));
        ping.queried_at = Instant::now() + Duration::from_secs(cycle);
        crate::scanner::record_outcome(
            "ping",
            10,
            Protocol::Both,
            Instant::now(),
            Ok(ScanResult::Ping(ping)),
            state,
        );
    }

    fn connectivity_samples(app: &mut TuiApp) -> (usize, usize) {
        app.layout
            .pane_mut("connectivity")
            .expect("connectivity pane")
            .as_any_mut()
            .downcast_mut::<ConnectivityPane>()
            .expect("ConnectivityPane")
            .sample_counts()
    }

    #[test]
    fn ping_results_published_while_connectivity_is_not_drawn_are_all_sampled() {
        const N: usize = 7;
        let mut app = TuiApp::new().expect("app");
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        for cycle in 0..N {
            publish_ping(&state, cycle as u64);
            app.ingest(&state);
        }
        assert_eq!(connectivity_samples(&mut app), (N, N), "no frame was drawn");
    }

    #[test]
    fn ping_results_published_between_two_ticks_are_all_sampled() {
        const N: usize = 4;
        let mut app = TuiApp::new().expect("app");
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        app.ingest(&state);
        for cycle in 0..N {
            publish_ping(&state, cycle as u64);
        }
        app.ingest(&state);
        app.ingest(&state);
        assert_eq!(connectivity_samples(&mut app), (N, N));
    }

    use std::sync::atomic::{AtomicBool, Ordering};

    /// Captures `log` records so a test can see what was logged, and when.
    struct CaptureLogger;
    static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static LOGGER: CaptureLogger = CaptureLogger;

    impl log::Log for CaptureLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            CAPTURED.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    #[test]
    fn first_render_is_logged_before_any_key_is_read() {
        log::set_logger(&LOGGER).expect("no other test installs a logger");
        log::set_max_level(log::LevelFilter::Info);

        let app = TuiApp::new().expect("app");
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).expect("terminal");
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        let (tx, _rx) = watch::channel(Protocol::Both);
        let logged_before_first_key = AtomicBool::new(false);
        app.run_with_keys(&mut terminal, state, &tx, |_timeout| {
            let logged = CAPTURED
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("First TUI render completed"));
            logged_before_first_key.store(logged, Ordering::SeqCst);
            Ok(Some(event::KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)))
        })
        .expect("run");
        assert!(
            logged_before_first_key.load(Ordering::SeqCst),
            "first render not logged before the first key read"
        );
    }
}
