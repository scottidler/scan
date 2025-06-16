pub mod pane;
pub mod layout;
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
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Main TUI application
pub struct TuiApp {
    layout: PaneLayout,
    should_quit: bool,
    last_tick: Instant,
    tick_rate: Duration,
}

impl TuiApp {
    /// Create a new TUI application with default layout
    pub fn new() -> Self {
        let mut layout = PaneLayout::default_dashboard();
        
        // Row 0: TARGET, CONNECTIVITY, SECURITY
        layout.add_pane(
            Box::new(TargetPane::new()),
            PaneConfig::new(0, 0)
        );
        
        layout.add_pane(
            Box::new(ConnectivityPane::new()),
            PaneConfig::new(0, 1)
        );
        
        layout.add_pane(
            Box::new(SecurityPane::new()),
            PaneConfig::new(0, 2)
        );
        
        // Row 1: DNS, HTTP, PORTS
        layout.add_pane(
            Box::new(DnsPane::new()),
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
        
        // Row 2: WHOIS, TRACEROUTE, GEOIP
        layout.add_pane(
            Box::new(WhoisPane::new()),
            PaneConfig::new(2, 0)
        );
        
        layout.add_pane(
            Box::new(TraceroutePane::new()),
            PaneConfig::new(2, 1)
        );
        
        layout.add_pane(
            Box::new(GeoIpPane::new()),
            PaneConfig::new(2, 2)
        );
        
        Self {
            layout,
            should_quit: false,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250), // 4 FPS
        }
    }
    
    /// Run the TUI application
    pub fn run<B: Backend>(mut self, terminal: &mut Terminal<B>, state: Arc<AppState>) -> io::Result<()> {
        loop {
            // Draw the UI
            terminal.draw(|f| self.ui(f, &state))?;
            
            // Handle events
            let timeout = self.tick_rate
                .checked_sub(self.last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));
            
            if crossterm::event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            // Quit on 'q' or Escape key
                            KeyCode::Char('q') | KeyCode::Esc => {
                                self.should_quit = true;
                            }
                            // Quit on Ctrl+C
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.should_quit = true;
                            }
                            KeyCode::Tab => {
                                // TODO: Cycle through focusable panes
                            }
                            KeyCode::Char('h') | KeyCode::Left => {
                                // TODO: Navigate left
                            }
                            KeyCode::Char('l') | KeyCode::Right => {
                                // TODO: Navigate right
                            }
                            KeyCode::Char('j') | KeyCode::Down => {
                                // TODO: Navigate down
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                // TODO: Navigate up
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            // Check if we should quit
            if self.should_quit {
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
    fn ui(&mut self, frame: &mut ratatui::Frame, state: &AppState) {
        let size = frame.area();
        
        // Render the layout with all panes
        self.layout.render(frame, size, state);
    }
    
    /// Check if the application should quit
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }
    
    /// Set the quit flag
    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

impl Default for TuiApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the terminal for TUI mode
pub fn init_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore the terminal after TUI mode
pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Create the default pane layout for the dashboard
pub fn create_default_layout() -> PaneLayout {
    let mut layout = PaneLayout::default_dashboard();
    
    // Row 0: TARGET, CONNECTIVITY, SECURITY
    layout.add_pane(
        Box::new(TargetPane::new()),
        PaneConfig::new(0, 0)
    );
    
    layout.add_pane(
        Box::new(ConnectivityPane::new()),
        PaneConfig::new(0, 1)
    );
    
    layout.add_pane(
        Box::new(SecurityPane::new()),
        PaneConfig::new(0, 2)
    );
    
    // Row 1: DNS, HTTP, PORTS
    layout.add_pane(
        Box::new(DnsPane::new()),
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
    
    // Row 2: WHOIS, TRACEROUTE, GEOIP
    layout.add_pane(
        Box::new(WhoisPane::new()),
        PaneConfig::new(2, 0)
    );
    
    layout.add_pane(
        Box::new(TraceroutePane::new()),
        PaneConfig::new(2, 1)
    );
    
    layout.add_pane(
        Box::new(GeoIpPane::new()),
        PaneConfig::new(2, 2)
    );
    
    layout
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tui_app_creation() {
        let app = TuiApp::new();
        assert!(!app.should_quit());
        assert_eq!(app.tick_rate, Duration::from_millis(250));
        
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
        let mut app = TuiApp::new();
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