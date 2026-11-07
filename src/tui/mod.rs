pub mod cert;
pub mod connectivity;
pub mod dns;
pub mod geoip;
pub mod http;
pub mod layout;
pub mod mail;
pub mod overlay;
pub mod pane;
pub mod ports;
pub mod security;
pub mod sparkline;
pub mod status;
pub mod target;
#[cfg(test)]
pub mod testing;
pub mod text;
pub mod theme;
pub mod traceroute;
pub mod whois;

pub use cert::CertPane;
pub use connectivity::ConnectivityPane;
pub use dns::DnsPane;
pub use geoip::GeoIpPane;
pub use http::HttpPane;
pub use layout::PaneLayout;
pub use mail::MailPane;
pub use overlay::{KEY_HELP, MenuItem, Overlay};
pub use pane::{Detail, Pane, PaneConfig, PanePosition};
pub use ports::PortsPane;
pub use security::SecurityPane;
pub use sparkline::SparklineData;
pub use status::{failure_text, no_address, status_label};
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
    layout::Rect,
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
    /// The menu or help box drawn over the dashboard, if one is open.
    overlay: Overlay,
    /// The frame area last drawn, so help's scroll keys clamp against the box as it was drawn.
    frame_area: Rect,
}

impl TuiApp {
    /// Create a new TUI application with default layout
    pub fn new() -> io::Result<Self> {
        log::debug!("[tui] new: creating TUI application with default layout");

        let mut layout = create_default_layout();

        // Set initial focus on the security pane
        layout.set_focus(Some("security".to_string()));
        log::debug!("[tui] initial_focus_set: pane=security");

        log::debug!(
            "[tui] tui_app_created: tick_rate=250ms panes={}",
            layout.pane_ids().len()
        );
        Ok(Self {
            layout,
            should_quit: false,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(TUI_TICK_RATE_MS), // 4 FPS
            startup: Instant::now(),
            overlay: Overlay::None,
            frame_area: Rect::default(),
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

    /// Act on one key press. `q` and Ctrl-C always quit. Otherwise an open menu or help box takes
    /// the key; with none open, the dashboard does.
    fn handle_key(
        &mut self,
        key: event::KeyEvent,
        state: &Arc<Mutex<AppState>>,
        protocol_tx: &watch::Sender<Protocol>,
    ) {
        log::debug!(
            "[tui] key_event: key={:?} modifiers={:?} zoomed={} overlay={:?}",
            key.code,
            key.modifiers,
            self.layout.is_zoomed(),
            self.overlay
        );
        let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Char('q') || ctrl_c {
            log::debug!("[tui] quit_requested: key={:?} ctrl_c={}", key.code, ctrl_c);
            self.should_quit = true;
            return;
        }
        match self.overlay {
            Overlay::Menu { selected } => self.handle_menu_key(key, selected),
            Overlay::Help { scroll } => self.handle_help_key(key, scroll),
            Overlay::None => self.handle_dashboard_key(key, state, protocol_tx),
        }
    }

    /// A key with no box open. Esc leaves zoom, or opens the menu from the grid; `?` opens help;
    /// Enter zooms the focused pane; Tab/Right/l and BackTab/Left/h move focus, which carries the
    /// zoom with it. `?` is matched on its code alone: crossterm reports it with SHIFT set.
    fn handle_dashboard_key(
        &mut self,
        key: event::KeyEvent,
        state: &Arc<Mutex<AppState>>,
        protocol_tx: &watch::Sender<Protocol>,
    ) {
        match key.code {
            KeyCode::Esc if self.layout.is_zoomed() => self.layout.unzoom(),
            KeyCode::Esc => self.open(Overlay::Menu { selected: 0 }),
            KeyCode::Char('?') => self.open(Overlay::Help { scroll: 0 }),
            KeyCode::Enter => {
                self.layout.zoom();
            }
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.focus_next_pane(),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => self.focus_prev_pane(),
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

    /// A key with the menu open: Up/k and Down/j move the selection, Home selects the first entry,
    /// Enter activates it, `?` goes to help, Esc closes. Every other key is ignored.
    fn handle_menu_key(&mut self, key: event::KeyEvent, selected: usize) {
        let last = overlay::MENU_ITEMS.len() - 1;
        match key.code {
            KeyCode::Esc => self.open(Overlay::None),
            KeyCode::Up | KeyCode::Char('k') => {
                self.overlay = Overlay::Menu {
                    selected: selected.saturating_sub(1),
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.overlay = Overlay::Menu {
                    selected: (selected + 1).min(last),
                }
            }
            KeyCode::Home => self.overlay = Overlay::Menu { selected: 0 },
            KeyCode::Char('?') => self.open(Overlay::Help { scroll: 0 }),
            KeyCode::Enter => match overlay::MENU_ITEMS[selected.min(last)] {
                MenuItem::Help => self.open(Overlay::Help { scroll: 0 }),
                MenuItem::Quit => {
                    log::debug!("[tui] quit_requested: menu");
                    self.should_quit = true;
                }
            },
            _ => log::trace!("[tui] menu_key_ignored: key={:?}", key.code),
        }
    }

    /// A key with help open: Up/k, Down/j and Home scroll it, Esc or `?` closes it. Every other
    /// key is ignored. Down stops at the last row of the box as it was last drawn.
    fn handle_help_key(&mut self, key: event::KeyEvent, scroll: u16) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') => self.open(Overlay::None),
            KeyCode::Up | KeyCode::Char('k') => {
                self.overlay = Overlay::Help {
                    scroll: scroll.saturating_sub(1),
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = overlay::help_max_scroll(self.frame_area);
                self.overlay = Overlay::Help {
                    scroll: scroll.saturating_add(1).min(max),
                };
            }
            KeyCode::Home => self.overlay = Overlay::Help { scroll: 0 },
            _ => log::trace!("[tui] help_key_ignored: key={:?}", key.code),
        }
    }

    /// Open `overlay` in place of the current one; `Overlay::None` closes it.
    fn open(&mut self, overlay: Overlay) {
        log::debug!("[tui] overlay_changed: old={:?} new={:?}", self.overlay, overlay);
        self.overlay = overlay;
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

        frame
            .buffer_mut()
            .set_style(size, ratatui::style::Style::default().bg(theme::BACKGROUND));
        self.frame_area = size;
        let state_guard = state.lock().unwrap();
        self.layout.render(frame, size, &state_guard);
        overlay::render(frame, size, &mut self.overlay);
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

/// Every dashboard pane and its grid cell, in focus order: the one pane table.
fn panes() -> Vec<(Box<dyn Pane>, PaneConfig)> {
    vec![
        // Row 0: target 30, connectivity 40, cert 30
        (Box::new(TargetPane::new()), PaneConfig::new(0, 0)),
        (Box::new(ConnectivityPane::new()), PaneConfig::new(0, 1)),
        (Box::new(CertPane::new()), PaneConfig::new(0, 2)),
        // Row 1: whois, http, ports, geoip, mail, 20 each
        (Box::new(WhoisPane::new()), PaneConfig::new(1, 0)),
        (Box::new(HttpPane::new()), PaneConfig::new(1, 1)),
        (Box::new(PortsPane::new()), PaneConfig::new(1, 2)),
        (Box::new(GeoIpPane::new()), PaneConfig::new(1, 3)),
        (Box::new(MailPane::new()), PaneConfig::new(1, 4)),
        // Row 2: dns 33, traceroute 33, security 34
        (Box::new(DnsPane::new()), PaneConfig::new(2, 0)),
        (Box::new(TraceroutePane::new()), PaneConfig::new(2, 1)),
        (Box::new(SecurityPane::new()), PaneConfig::new(2, 2)),
    ]
}

/// The dashboard layout with every pane from [`panes`] placed in its cell.
pub fn create_default_layout() -> PaneLayout {
    let mut layout = PaneLayout::default_dashboard();
    for (pane, config) in panes() {
        layout.add_pane(pane, config);
    }
    log::debug!("[tui] create_default_layout: panes={}", layout.pane_ids().len());
    layout
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pane in grid order, focus order and the one table.
    const PANE_IDS: [&str; 11] = [
        "target",
        "connectivity",
        "cert",
        "whois",
        "http",
        "ports",
        "geoip",
        "mail",
        "dns",
        "traceroute",
        "security",
    ];

    #[test]
    fn test_tui_app_creation() {
        let app = TuiApp::new().expect("Failed to create TuiApp");
        assert!(!app.should_quit());
        assert_eq!(app.tick_rate, Duration::from_millis(TUI_TICK_RATE_MS));
        assert_eq!(app.layout.pane_ids(), PANE_IDS);
        assert_eq!(app.layout.focused_pane().map(String::as_str), Some("security"));
    }

    #[test]
    fn test_quit_functionality() {
        let mut app = TuiApp::new().expect("Failed to create TuiApp");
        assert!(!app.should_quit());

        app.quit();
        assert!(app.should_quit());
    }

    /// The app and the default layout are both built from the one pane table.
    #[test]
    fn the_app_and_the_default_layout_place_the_same_panes_in_the_same_cells() {
        let app = TuiApp::new().expect("app");
        let layout = create_default_layout();
        assert_eq!(layout.pane_ids(), PANE_IDS);
        for id in PANE_IDS {
            let (a, b) = (app.layout.get_config(id).expect(id), layout.get_config(id).expect(id));
            assert_eq!(
                (a.position.row, a.position.col),
                (b.position.row, b.position.col),
                "{id}"
            );
        }
        let cell = |id: &str| {
            let config = layout.get_config(id).expect(id);
            (config.position.row, config.position.col)
        };
        assert_eq!(cell("cert"), (0, 2));
        assert_eq!(cell("mail"), (1, 4));
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

    #[test]
    fn every_cell_of_the_frame_is_painted_with_the_theme_background() {
        let mut app = TuiApp::new().expect("app");
        let state = Arc::new(Mutex::new(AppState::new("example.com".to_string())));
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(120, 40)).expect("terminal");
        terminal.draw(|frame| app.ui(frame, &state)).expect("draw");
        let buffer = terminal.backend().buffer();
        let unpainted: Vec<ratatui::layout::Position> = buffer
            .area
            .positions()
            .filter(|&position| buffer[position].bg != theme::BACKGROUND)
            // The cell behind a double-width glyph is never drawn: the glyph covers it.
            .filter(|position| {
                position.x == 0 || ratatui::text::Span::raw(buffer[(position.x - 1, position.y)].symbol()).width() < 2
            })
            .collect();
        assert!(
            unpainted.is_empty(),
            "cells left on the terminal background: {unpainted:?}"
        );
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
