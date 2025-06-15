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
}

pub fn parse() -> Cli {
    Cli::parse()
} 