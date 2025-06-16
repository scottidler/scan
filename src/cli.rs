use clap::Parser;

#[derive(Parser)]
#[command(name = "scan")]
#[command(about = "A network scanning TUI application")]
pub struct Cli {
    /// Target URL, domain, or IP address to scan
    pub target: String,
    
    /// Refresh rate in milliseconds
    #[arg(short, long, default_value = "250")]
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