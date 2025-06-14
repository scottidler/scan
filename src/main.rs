mod cli;
mod web;
mod tui;

use clap::Parser;
use cli::{Cli, Commands};
use web::dns::DnsClient;
use web::http::HttpClient;
use web::ping::{PingData, PingMethod, ping_target, determine_ping_method};
use std::net::IpAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dashboard { targets } => {
            println!("Dashboard command with targets: {:?}", targets);
        }
        Commands::Target { targets } => {
            println!("Target command with targets: {:?}", targets);
        }
        Commands::Dns { targets } => {
            let client = DnsClient::new().await?;
            for target in targets {
                match client.query_domain(&target).await {
                    Ok(dns_info) => {
                        println!("DNS information for {}:", target);
                        println!("A: {:?}", dns_info.a);
                        println!("AAAA: {:?}", dns_info.aaaa);
                        println!("MX: {:?}", dns_info.mx);
                        println!("NS: {:?}", dns_info.ns);
                        println!("CNAME: {:?}", dns_info.cname);
                        println!("TXT: {:?}", dns_info.txt);
                        println!("Resolution Time: {:?}", dns_info.resolution_time);
                        println!("DNSSEC Valid: {:?}", dns_info.dnssec_valid);
                        println!("DoH Support: {:?}", dns_info.doh_support);
                        println!("DoT Support: {:?}", dns_info.dot_support);
                    }
                    Err(e) => eprintln!("Error querying DNS for {}: {}", target, e),
                }
            }
        }
        Commands::Ping { targets } => {
            for target in targets {
                println!("\nPinging {}...", target);
                // First resolve the domain to IP
                let client = DnsClient::new().await?;
                let dns_info = client.query_domain(&target).await?;
                // Get all IPs (both IPv4 and IPv6)
                let mut ips = Vec::new();
                ips.extend(dns_info.a.iter().map(|r| IpAddr::V4(r.value)));
                ips.extend(dns_info.aaaa.iter().map(|r| IpAddr::V6(r.value)));
                if ips.is_empty() {
                    eprintln!("No IP addresses found for {}", target);
                    continue;
                }
                // Create ping data structure
                let mut ping_data = PingData::new(ips.clone());
                // Try each IP with different methods
                for ip in ips {
                    println!("\nTrying IP: {}", ip);
                    // Determine best ping method
                    let method = determine_ping_method(ip).await;
                    println!("Using method: {:?}", method);
                    // Perform ping
                    let _result = ping_target(ip, method).await;
                    // Update stats
                    ping_data.update_stats().await;
                    // Print results
                    let stats_opt = if ip.is_ipv4() {
                        &ping_data.ipv4_stats
                    } else {
                        &ping_data.ipv6_stats
                    };
                    if let Some(stats) = stats_opt {
                        println!("\nPing Statistics:");
                        if let Some(avg) = stats.average {
                            println!("Average Latency: {} ms", avg.as_millis());
                        }
                        if let Some((min, max)) = stats.min_max {
                            println!("Min Latency: {} ms", min.as_millis());
                            println!("Max Latency: {} ms", max.as_millis());
                        }
                        if let Some(jitter) = stats.jitter {
                            println!("Jitter: {} ms", jitter.as_millis());
                        }
                        println!("Packet Loss: {:.1}%", stats.packet_loss);
                        println!("Success Rate: {:.1}%", stats.success_rate);
                    }
                }
            }
        }
        Commands::Http { targets } => {
            let client = HttpClient::new()?;
            for target in targets {
                match client.analyze_url(&target).await {
                    Ok(http_data) => {
                        println!("HTTP information for {}:", target);
                        
                        if let Some(http_stats) = http_data.http_stats {
                            println!("\nHTTP Stats:");
                            println!("Current Response Time: {:?}", http_stats.current_response_time);
                            println!("Average Response Time: {:?}", http_stats.average_response_time);
                            println!("Status Code: {:?}", http_stats.current_status);
                            println!("Availability: {:.1}%", http_stats.availability * 100.0);
                        }
                        
                        if let Some(https_stats) = http_data.https_stats {
                            println!("\nHTTPS Stats:");
                            println!("Current Response Time: {:?}", https_stats.current_response_time);
                            println!("Average Response Time: {:?}", https_stats.average_response_time);
                            println!("Status Code: {:?}", https_stats.current_status);
                            println!("Availability: {:.1}%", https_stats.availability * 100.0);
                        }
                        
                        println!("\nRedirect Chain:");
                        for (i, hop) in http_data.redirect_chain.iter().enumerate() {
                            println!("{}. {} -> {} ({} ms)", 
                                i + 1,
                                hop.from_url,
                                hop.to_url,
                                hop.response_time.as_millis()
                            );
                        }
                        
                        println!("\nFinal URL: {}", http_data.final_url);
                        
                        println!("\nServer Info:");
                        if let Some(server) = http_data.server_info.detected_server {
                            println!("Server Type: {:?}", server);
                        }
                        if let Some(powered_by) = http_data.server_info.powered_by {
                            println!("Powered By: {}", powered_by);
                        }
                        
                        println!("\nSupported HTTP Versions:");
                        for version in http_data.supported_versions {
                            println!("- {:?}", version);
                        }
                        
                        println!("\nResponse Headers:");
                        for (name, value) in http_data.headers {
                            println!("{}: {}", name, value);
                        }
                    }
                    Err(e) => eprintln!("Error analyzing HTTP for {}: {}", target, e),
                }
            }
        }
        Commands::Tls { targets } => {
            println!("TLS command with targets: {:?}", targets);
        }
        Commands::Security { targets } => {
            println!("Security command with targets: {:?}", targets);
        }
        Commands::Geo { targets } => {
            println!("Geo command with targets: {:?}", targets);
        }
        Commands::Whois { targets } => {
            println!("Whois command with targets: {:?}", targets);
        }
        Commands::Ports { targets } => {
            println!("Ports command with targets: {:?}", targets);
        }
        Commands::Mail { targets } => {
            println!("Mail command with targets: {:?}", targets);
        }
        Commands::Status { targets } => {
            println!("Status command with targets: {:?}", targets);
        }
    }

    Ok(())
}
