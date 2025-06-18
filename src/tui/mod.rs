pub mod pane;
pub mod layout;
pub mod scrollable;
pub mod target;
pub mod connectivity;
pub mod security;
pub mod whois;
pub mod dns;
pub mod http;
pub mod ports;
pub mod traceroute;
pub mod geoip;

pub use pane::{Pane, PaneConfig, PanePosition};
pub use layout::PaneLayout;
pub use scrollable::ScrollablePane;
pub use target::TargetPane;
pub use connectivity::ConnectivityPane;
pub use security::SecurityPane;
pub use whois::WhoisPane;
pub use dns::DnsPane;
pub use http::HttpPane;
pub use ports::PortsPane;
pub use traceroute::TraceroutePane;
pub use geoip::GeoIpPane;

use crate::types::AppState;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log;

const TUI_TICK_RATE_MS: u64 = 250;
const FRAME_STATS_LOG_INTERVAL: u64 = 100;
const FALLBACK_TIMEOUT_SECS: u64 = 0;

/// Main TUI application
pub struct TuiApp {
    layout: PaneLayout,
    should_quit: bool,
    last_tick: Instant,
    tick_rate: Duration,
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
        })
    }

    /// Run the TUI application
    pub fn run<B: Backend>(mut self, terminal: &mut Terminal<B>, state: Arc<Mutex<AppState>>) -> io::Result<()> {
        log::debug!("[tui] run: starting TUI event loop");

        let mut frame_count = 0;
        let start_time = Instant::now();

        loop {
            // Draw the UI
            let draw_start = Instant::now();
            terminal.draw(|f| self.ui(f, &state))?;
            let draw_duration = draw_start.elapsed();

            frame_count += 1;
            if frame_count % FRAME_STATS_LOG_INTERVAL == 0 {
                log::trace!("[tui] frame_stats: frames={} avg_draw_time={}μs uptime={}s",
                    frame_count, draw_duration.as_micros(), start_time.elapsed().as_secs());
            }

            // Handle events
            let timeout = self.tick_rate
                .checked_sub(self.last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(FALLBACK_TIMEOUT_SECS));

            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        log::debug!("[tui] key_event: key={:?} modifiers={:?}", key.code, key.modifiers);

                        match key.code {
                            // Quit on 'q' or Escape key
                            KeyCode::Char('q') | KeyCode::Esc => {
                                log::debug!("[tui] quit_requested: key={:?}", key.code);
                                self.should_quit = true;
                            }
                            // Quit on Ctrl+C
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                log::debug!("[tui] quit_requested: ctrl_c");
                                self.should_quit = true;
                            }
                            KeyCode::Tab | KeyCode::Right => {
                                // Cycle forward through focusable panes
                                self.focus_next_pane();
                            }
                            KeyCode::BackTab | KeyCode::Left => {
                                // Cycle backward through focusable panes
                                self.focus_prev_pane();
                            }
                            KeyCode::Char('p') => {
                                // Cycle through protocols: Both -> IPv4 -> IPv6 -> Both
                                let (old_protocol, new_protocol) = {
                                    let mut state_guard = state.lock().unwrap();
                                    let old = state_guard.protocol;
                                    state_guard.cycle_protocol();
                                    let new = state_guard.protocol;
                                    (old, new)
                                };
                                log::info!("[tui] protocol_changed: {} -> {} (scanner restart needed)",
                                    old_protocol.as_str(), new_protocol.as_str());
                                // TODO: Implement scanner restart when protocol changes
                            }
                            // Handle scrolling and navigation for focused pane
                            _ => {
                                // We need to calculate pane areas for proper scroll bounds
                                // This is a bit of a hack, but we'll create a temporary frame to get areas
                                let size = terminal.size()?;
                                let area = ratatui::layout::Rect::new(0, 0, size.width, size.height);
                                let grid_areas = self.layout.create_grid_layout_public(area);

                                // Let the layout handle pane-specific events
                                let state_guard = state.lock().unwrap();
                                let handled = self.layout.handle_key_event(key, &*state_guard, &grid_areas);
                                if handled {
                                    log::trace!("[tui] key_handled_by_pane: key={:?}", key.code);
                                } else {
                                    log::trace!("[tui] key_unhandled: key={:?}", key.code);
                                }
                            }
                        }
                    }
                }
            }

            // Check if we should quit
            if self.should_quit {
                log::debug!("[tui] exiting_event_loop: frames_rendered={} uptime={}s",
                    frame_count, start_time.elapsed().as_secs());
                break;
            }

            // Update tick
            if self.last_tick.elapsed() >= self.tick_rate {
                self.last_tick = Instant::now();
            }
        }

        Ok(())
    }

    /// Draw the UI
    fn ui(&mut self, frame: &mut ratatui::Frame, state: &Arc<Mutex<AppState>>) {
        let size = frame.area();
        log::trace!("[tui] ui_render: area={}x{}", size.width, size.height);

        // Render the layout with all panes
        let state_guard = state.lock().unwrap();
        self.layout.render(frame, size, &*state_guard);
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
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    log::debug!("[tui] terminal_restored:");
    Ok(())
}

/// Create the default pane layout for the dashboard
pub fn create_default_layout() -> PaneLayout {
    let mut layout = PaneLayout::default_dashboard();

    // Row 0: TARGET, CONNECTIVITY
    layout.add_pane(
        Box::new(TargetPane::new()),
        PaneConfig::new(0, 0)
    );

    layout.add_pane(
        Box::new(ConnectivityPane::new()),
        PaneConfig::new(0, 1)
    );

    // Row 1: WHOIS, HTTP, PORTS, GEOIP
    layout.add_pane(
        Box::new(WhoisPane::new()),
        PaneConfig::new(1, 0)
    );

    layout.add_pane(
        Box::new(HttpPane::new()),
        PaneConfig::new(1, 1)
    );

    layout.add_pane(
        Box::new(PortsPane::new()),
        PaneConfig::new(1, 2)
    );

    layout.add_pane(
        Box::new(GeoIpPane::new()),
        PaneConfig::new(1, 3)
    );

    // Row 2: DNS, TRACEROUTE, SECURITY (bigger panes on bottom)
    layout.add_pane(
        Box::new(DnsPane::new()),
        PaneConfig::new(2, 0)
    );

    layout.add_pane(
        Box::new(TraceroutePane::new()),
        PaneConfig::new(2, 1)
    );

    layout.add_pane(
        Box::new(SecurityPane::new()),
        PaneConfig::new(2, 2)
    );

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
    fn test_key_modifiers_import() {
        // Test that KeyModifiers is properly imported and accessible
        let ctrl_modifier = KeyModifiers::CONTROL;
        assert_eq!(ctrl_modifier, KeyModifiers::CONTROL);
    }
}
