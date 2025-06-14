use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Show dashboard with summary panes for areas
    Dashboard {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Show target domain/URL and scan summary
    Target {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Query DNS records and resolution info
    Dns {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Monitor network latency and connectivity (ping)
    Ping {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Analyze HTTP/HTTPS status, redirects, and headers
    Http {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Inspect TLS/SSL certificate and connection security
    Tls {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Check web/email security headers and DNS policies
    Security {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Show geolocation, ISP, and hosting info for IPs
    Geo {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Display domain registration and ownership (WHOIS)
    Whois {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Scan for open ports and detect running services
    Ports {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Check email deliverability (SPF, DKIM, DMARC, MX)
    Mail {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
    /// Show scan status, errors, and logs
    Status {
        /// Target domains, URLs, or IPs to scan
        targets: Vec<String>,
    },
}
