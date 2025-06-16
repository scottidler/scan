use clap::Parser;
use eyre::Result;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[command(name = "scan")]
#[command(about = "A comprehensive network scanner")]
struct Args {
    /// Target to scan (domain, IP, or URL)
    target: String,
    
    /// Enable debug mode with pretty printing
    #[arg(long)]
    debug: bool,
    
    /// Disable TUI mode (use debug output instead)
    #[arg(long)]
    no_tui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging first
    if let Err(e) = scan::init_logging() {
        eprintln!("Warning: Failed to initialize logging: {}", e);
    }
    
    // Add a gigantic divider to separate runs
    log::info!("================================================================================");
    log::info!("🚀 NEW SCAN SESSION STARTING");
    log::info!("================================================================================");
    
    let args = Args::parse();
    
    // Parse the target
    let mut target = scan::target::Target::parse(&args.target)?;
    println!("Resolving domain: {}", target.display_name());
    
    // Resolve the target to get IP addresses
    target.resolve().await?;
    if let Some(ip) = target.primary_ip() {
        println!("Resolved to: {}", ip);
    }
    
    // Create shared application state
    let state = Arc::new(scan::types::AppState::new(args.target.clone()));
    
    // Create and start all scanners
    let scanners = scan::scan::create_default_scanners();
    let mut scanner_handles = Vec::new();
    
    for scanner in scanners {
        let target_clone = target.clone();
        let state_clone = Arc::clone(&state);
        
        let handle = tokio::spawn(async move {
            scanner.run(target_clone, state_clone).await;
        });
        
        scanner_handles.push(handle);
    }
    
    // Choose between TUI and debug mode
    if args.no_tui || args.debug {
        // Debug mode - pretty print results
        println!("🎯 Scanning: {}", args.target);
        println!("────────────────────────────────────────────────────────────────────────────────");
        
        if args.debug {
            println!("Debug mode enabled. Press Ctrl+C to exit");
        }
        
        // Print results every 5 seconds
        loop {
            println!("🎯 Scanning: {}", args.target);
            println!("────────────────────────────────────────────────────────────────────────────────");
            
            // Print scanner results using the pretty print function
            for scanner_state in state.scanners.iter() {
                let scanner_name = scanner_state.key();
                let scan_state = scanner_state.value();
                
                scan::pretty::print_scan_state(scanner_name, &scan_state);
            }
            
            println!("────────────────────────────────────────────────────────────────────────────────");
            
            if args.debug {
                println!("Refreshing every 5 seconds...");
                println!();
            }
            
            sleep(Duration::from_secs(5)).await;
        }
    } else {
        // TUI mode
        let mut terminal = scan::tui::init_terminal()?;
        let app = scan::tui::TuiApp::new()?;
        
        // Run the TUI application
        let result = app.run(&mut terminal, state);
        
        // Restore terminal
        scan::tui::restore_terminal(&mut terminal)?;
        
        // Handle any TUI errors
        result?;
    }
    
    Ok(())
}
