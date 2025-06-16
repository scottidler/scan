use std::sync::Arc;
use std::time::Duration;
use eyre::Result;

mod cli;
mod types;
mod scanner;
mod scan;
mod target;
mod pretty;
// mod tui; // TODO: Implement TUI module

use types::AppState;
use target::Target;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = cli::parse();
    
    if cli.verbose {
        env_logger::init();
    }

    // Parse the target
    let mut target = Target::parse(&cli.target)?;
    
    // Resolve the target if it's a domain
    match target.target_type {
        target::TargetType::Domain(_) => {
            println!("Resolving domain: {}", target.display_name());
            target.resolve().await?;
            if let Some(ip) = target.primary_ip() {
                println!("Resolved to: {}", ip);
            }
        }
        _ => {}
    }

    // Initialize shared application state
    let state = Arc::new(AppState::new(cli.target.clone()));
    
    // Create and spawn scanner tasks
    let scanners = scan::create_default_scanners();
    scan::spawn_scanner_tasks(scanners, target.clone(), state.clone()).await;
    
    if !cli.no_tui && !cli.debug {
        // TODO: Run the TUI application
        // let mut app = tui::App::new(state, Duration::from_millis(cli.refresh_rate));
        // app.run().await?;
        
        // For now, just run indefinitely until TUI is implemented
        println!("TUI mode not yet implemented. Use --debug for debug output or --no-tui for debug mode.");
        println!("Press Ctrl+C to exit");
        
        // Keep the application running silently
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
        }
    } else {
        // Debug mode: pretty print scan results to stdout
        pretty::print_header(&cli.target);
        println!("Debug mode enabled. Press Ctrl+C to exit");
        pretty::print_separator();
        
        // Keep the application running and print scanner state periodically
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            
            // Clear screen for better readability (optional)
            if cli.debug {
                print!("\x1B[2J\x1B[1;1H"); // ANSI escape codes to clear screen
                pretty::print_header(&cli.target);
            }
            
            // Print current scanner states using pretty printing
            let mut scanner_names: Vec<String> = state.scanners.iter()
                .map(|entry| entry.key().clone())
                .collect();
            scanner_names.sort();
            
            for scanner_name in scanner_names {
                if let Some(scan_state) = state.scanners.get(&scanner_name) {
                    pretty::print_scan_state(&scanner_name, &scan_state);
                }
            }
            
            if cli.debug {
                pretty::print_separator();
                println!("Refreshing every 5 seconds...");
            }
        }
    }
}
