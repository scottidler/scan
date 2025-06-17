use clap::Parser;

const DEFAULT_REFRESH_RATE_MS: &str = "250";

#[derive(Parser)]
#[command(name = "scan")]
#[command(about = "A network scanning TUI application")]
pub struct Cli {
    /// Target URL, domain, or IP address to scan
    pub target: String,
    
    /// Refresh rate in milliseconds
    #[arg(short, long, default_value = DEFAULT_REFRESH_RATE_MS)]
    pub refresh_rate: u64,
    
    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Enable debug output (pretty print scan results to stdout)
    #[arg(short, long)]
    pub debug: bool,
    
    /// Disable TUI mode (run in debug mode instead)
    #[arg(long)]
    pub no_tui: bool,
}

pub fn parse() -> Cli {
    Cli::parse()
} 