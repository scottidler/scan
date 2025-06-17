use scan::types::{AppState, ScanState, ScanStatus};
use scan::tui::{TuiApp, init_terminal, restore_terminal};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a test application state
    let state = Arc::new(AppState::new("example.com".to_string()));
    
    // Add some mock scanner states for testing
    state.scanners.insert("ping".to_string(), ScanState {
        result: None,
        error: None,
        status: ScanStatus::Complete,
        last_updated: Instant::now(),
        history: Default::default(),
    });
    
    state.scanners.insert("dns".to_string(), ScanState {
        result: None,
        error: None,
        status: ScanStatus::Running,
        last_updated: Instant::now(),
        history: Default::default(),
    });
    
    state.scanners.insert("http".to_string(), ScanState {
        result: None,
        error: Some(eyre::eyre!("Connection timeout")),
        status: ScanStatus::Failed,
        last_updated: Instant::now(),
        history: Default::default(),
    });
    
    // Initialize terminal
    let mut terminal = init_terminal()?;
    
    // Create and run TUI app
    let app = TuiApp::new()?;
    let result = app.run(&mut terminal, state);
    
    // Restore terminal
    restore_terminal(&mut terminal)?;
    
    // Handle any errors
    result?;
    
    println!("TUI test completed successfully!");
    Ok(())
} 