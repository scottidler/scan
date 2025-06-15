use std::sync::Arc;
use std::time::Duration;
use eyre::Result;

mod cli;
mod types;
mod scanner;
mod scan;
mod target;
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
    
    // TODO: Run the TUI application
    // let mut app = tui::App::new(state, Duration::from_millis(cli.refresh_rate));
    // app.run().await?;
    
    // For now, just run indefinitely to test scanners
    println!("Scanning target: {}", cli.target);
    println!("Press Ctrl+C to exit");
    
    // Keep the application running and print scanner state periodically
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        
        // Print current scanner states
        for entry in state.scanners.iter() {
            let (scanner_name, scan_state) = entry.pair();
            println!("{}: {:?} - Last updated: {:?}", 
                scanner_name, 
                scan_state.status,
                scan_state.last_updated
            );
            
            if let Some(result) = &scan_state.result {
                println!("  Result: {:?}", result);
            }
            
            if let Some(error) = &scan_state.error {
                println!("  Error: {}", error);
            }
        }
        println!("---");
    }
}
