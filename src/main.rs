use clap::Parser;
use eyre::Result;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant, sleep};

// Built-in version from build.rs via env!("GIT_DESCRIBE")

const DEBUG_REFRESH_INTERVAL_SECS: u64 = 5;

fn get_after_help() -> String {
    let log_path = scan::get_log_file_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "Unable to determine log file path".to_string());

    format!("Logs are written to: {}", log_path)
}

#[derive(Parser)]
#[command(name = "scan")]
#[command(about = "A comprehensive network scanner")]
#[command(version = env!("GIT_DESCRIBE"))]
#[command(after_help = get_after_help())]
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

/// glibc arenas a process may create. Every scanner allocates short-lived buffers from its own
/// worker thread, and the default (8 per core) let RSS climb ~3 MB per 4 minutes on a 64-core host
/// while live data stayed flat: `MALLOC_ARENA_MAX=1` held +200 KB over the same window.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const MALLOC_ARENA_MAX: libc::c_int = 2;

/// Must run before the runtime starts its worker threads, so their first allocations already see
/// the cap.
fn cap_malloc_arenas() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt only adjusts allocator tuning; called before any other thread exists.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, MALLOC_ARENA_MAX);
    }
}

fn main() -> Result<()> {
    cap_malloc_arenas();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    let app_start = Instant::now();

    // Initialize logging first
    if let Err(e) = scan::init_logging() {
        eprintln!("Warning: Failed to initialize logging: {}", e);
    }

    // Add a gigantic divider to separate runs
    log::info!("================================================================================");
    log::info!("🚀 NEW SCAN SESSION STARTING");
    log::info!("================================================================================");

    let args = Args::parse();
    log::debug!(
        "[main] main: target={} debug={} no_tui={}",
        args.target,
        args.debug,
        args.no_tui
    );

    // Parse the target
    let mut target = scan::target::Target::parse(&args.target)?;
    log::debug!("[main] target_parsed: {}", target.display_name());

    // Only show resolution messages in debug/no-tui mode
    if args.debug || args.no_tui {
        println!("Resolving domain: {}", target.display_name());
    }

    // Resolve the target to get IP addresses
    let resolve_start = Instant::now();
    target.resolve().await?;
    let resolve_duration = resolve_start.elapsed();
    log::debug!("[main] target_resolved: duration={}ms", resolve_duration.as_millis());

    // Show resolved addresses in debug/no-tui mode
    if args.debug || args.no_tui {
        if let Some(ipv4) = target.primary_ipv4() {
            println!("IPv4: {}", ipv4);
        }
        if let Some(ipv6) = target.primary_ipv6() {
            println!("IPv6: {}", ipv6);
        } else if target.has_ipv4() {
            println!("IPv6: no address");
        }
    }

    if let Some(ip) = target.primary_ip() {
        log::debug!("[main] primary_ip: {}", ip);
    }

    // Create shared application state (wrapped in Mutex for protocol changes)
    let mut app_state = scan::types::AppState::new(args.target.clone());
    app_state.resolved_ips = target.all_ips().to_vec();
    log::debug!(
        "[main] app_state_created: target={} resolved_ips={:?}",
        args.target,
        app_state.resolved_ips
    );
    let state = Arc::new(Mutex::new(app_state));

    // Create and start all scanners using the protocol from app state
    let scanners = scan::scan::create_default_scanners();
    log::debug!("[main] scanners_created: count={}", scanners.len());

    // Use the protocol from app state (defaults to Both, but user can change it)
    let protocol = {
        let state_guard = state.lock().unwrap();
        state_guard.protocol
    };
    // main owns the sender for the process lifetime: the TUI borrows it to switch protocol on `p`,
    // debug mode holds it and never sends, so no scanner ever sees the channel close.
    let (protocol_tx, protocol_rx) = tokio::sync::watch::channel(protocol);
    scan::scan::spawn_scanner_tasks(scanners, target.clone(), protocol_rx, Arc::clone(&state)).await;
    log::debug!("[main] all_scanners_started: protocol={}", protocol.as_str());

    // Choose between TUI and debug mode
    if args.no_tui || args.debug {
        log::info!("[main] Starting debug mode output");

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
            {
                let state_guard = state.lock().unwrap();
                for scanner_state in state_guard.scanners.iter() {
                    let scanner_name = scanner_state.key();
                    let scan_state = scanner_state.value();

                    scan::pretty::print_scan_state(scanner_name, scan_state);
                }
            }

            println!("────────────────────────────────────────────────────────────────────────────────");

            if args.debug {
                println!("Refreshing every 5 seconds...");
                println!();
            }

            sleep(Duration::from_secs(DEBUG_REFRESH_INTERVAL_SECS)).await;
        }
    } else {
        log::info!("[main] Starting TUI mode");

        // TUI mode
        let terminal_init_start = Instant::now();
        let mut terminal = scan::tui::init_terminal()?;
        let terminal_init_duration = terminal_init_start.elapsed();
        log::debug!(
            "[main] terminal_initialized: duration={}ms",
            terminal_init_duration.as_millis()
        );

        let app_create_start = Instant::now();
        let app = scan::tui::TuiApp::new()?.with_startup(app_start.into_std());
        let app_create_duration = app_create_start.elapsed();
        log::debug!("[main] tui_app_created: duration={}ms", app_create_duration.as_millis());

        // Run the TUI application
        let tui_start = Instant::now();
        let result = app.run(&mut terminal, state, &protocol_tx);
        let tui_duration = tui_start.elapsed();

        // Restore terminal
        let restore_start = Instant::now();
        scan::tui::restore_terminal(&mut terminal)?;
        let restore_duration = restore_start.elapsed();
        log::debug!("[main] terminal_restored: duration={}ms", restore_duration.as_millis());

        log::debug!(
            "[main] tui_session_completed: total_duration={}ms",
            tui_duration.as_millis()
        );

        // Handle any TUI errors
        result?;
    }

    let total_duration = app_start.elapsed();
    log::info!(
        "[main] Scan session completed: total_duration={}ms",
        total_duration.as_millis()
    );
    log::info!("================================================================================");
    log::info!("🏁 SCAN SESSION ENDED");
    log::info!("================================================================================");

    Ok(())
}
