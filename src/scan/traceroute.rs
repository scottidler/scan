use crate::scanner::Scanner;
use crate::target::Target;
use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct TracerouteScanner {
    interval: Duration,
    timeout: Duration,
    max_hops: u8,
    probes_per_hop: u8,
}

#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub hops: Vec<TracerouteHop>,
    pub destination_reached: bool,
    pub total_hops: u8,
    pub max_hops: u8,
    pub target_ip: IpAddr,
    pub scan_duration: Duration,
    pub ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub responses: Vec<HopResponse>,
    pub best_rtt: Option<Duration>,
    pub avg_rtt: Option<Duration>,
    pub worst_rtt: Option<Duration>,
    pub packet_loss: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone)]
pub struct HopResponse {
    pub ip_address: Option<IpAddr>,
    pub rtt: Option<Duration>,
    pub timeout: bool,
}

impl Default for TracerouteScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TracerouteScanner {
    pub fn new() -> Self {
        Self {
            interval: Duration::from_secs(15 * 60), // 15 minutes
            timeout: Duration::from_secs(60),       // 60 seconds total
            max_hops: 20,
            probes_per_hop: 3,
        }
    }

    async fn perform_traceroute(&self, target: &Target) -> Result<TracerouteResult> {
        let start_time = Instant::now();
        
        // Determine target IP and whether to use IPv6
        let (target_ip, use_ipv6) = self.determine_target_ip(target)?;
        
        // Build traceroute command
        let mut cmd = Command::new("traceroute");
        
        if use_ipv6 {
            cmd.arg("-6");
        }
        
        cmd.args([
            "-n",                                    // Numeric output
            "-w", "3",                              // 3 second timeout per probe
            "-q", &self.probes_per_hop.to_string(), // Probes per hop
            "-m", &self.max_hops.to_string(),       // Max hops
        ]);
        
        // Add target
        match target_ip {
            IpAddr::V4(ip) => { cmd.arg(ip.to_string()); },
            IpAddr::V6(ip) => { cmd.arg(ip.to_string()); },
        }
        
        // Execute command with timeout
        let output = tokio::time::timeout(self.timeout, async {
            let result = tokio::task::spawn_blocking(move || cmd.output()).await;
            match result {
                Ok(output) => output.wrap_err("Failed to execute traceroute command"),
                Err(e) => Err(eyre::eyre!("Failed to spawn traceroute command: {}", e)),
            }
        })
        .await
        .wrap_err("Traceroute command timed out")??;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(eyre::eyre!("Traceroute failed: {}", stderr));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_traceroute_output(&stdout, target_ip, use_ipv6, start_time.elapsed())
    }
    
    fn determine_target_ip(&self, target: &Target) -> Result<(IpAddr, bool)> {
        // Get primary IP from target
        if let Some(ip) = target.primary_ip() {
            let use_ipv6 = ip.is_ipv6();
            return Ok((ip, use_ipv6));
        }
        
        // If no resolved IP, try to use the domain directly
        if let Some(domain) = &target.domain {
            // For now, default to IPv4. In a real implementation, we might
            // want to check if the domain has AAAA records first
            return Err(eyre::eyre!("No resolved IP available for domain: {}", domain));
        }
        
        Err(eyre::eyre!("No valid target IP found"))
    }
    
    fn parse_traceroute_output(
        &self,
        output: &str,
        target_ip: IpAddr,
        ipv6: bool,
        scan_duration: Duration,
    ) -> Result<TracerouteResult> {
        let mut hops = Vec::new();
        let mut destination_reached = false;
        let mut total_hops = 0;
        
        for line in output.lines() {
            let line = line.trim();
            
            // Skip header line
            if line.starts_with("traceroute to") {
                continue;
            }
            
            // Parse hop line
            if let Some(hop) = self.parse_hop_line(line)? {
                total_hops = hop.hop_number;
                
                // Check if this hop reached the destination
                if let Some(response) = hop.responses.first() {
                    if let Some(ip) = response.ip_address {
                        if ip == target_ip {
                            destination_reached = true;
                        }
                    }
                }
                
                hops.push(hop);
            }
        }
        
        Ok(TracerouteResult {
            hops,
            destination_reached,
            total_hops,
            max_hops: self.max_hops,
            target_ip,
            scan_duration,
            ipv6,
        })
    }
    
    fn parse_hop_line(&self, line: &str) -> Result<Option<TracerouteHop>> {
        // Skip empty lines
        if line.is_empty() {
            return Ok(None);
        }
        
        // Parse hop number at the start of the line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(None);
        }
        
        let hop_number = match parts[0].parse::<u8>() {
            Ok(num) => num,
            Err(_) => return Ok(None), // Not a hop line
        };
        
        let mut responses = Vec::new();
        let mut i = 1;
        
        // Parse responses for this hop
        while i < parts.len() {
            if parts[i] == "*" {
                // Timeout response
                responses.push(HopResponse {
                    ip_address: None,
                    rtt: None,
                    timeout: true,
                });
                i += 1;
            } else if i + 2 < parts.len() && parts[i + 2] == "ms" {
                // Response with IP and RTT: "192.168.1.1 2.345 ms"
                let ip_str = parts[i];
                let rtt_str = parts[i + 1];
                
                let ip_address = ip_str.parse::<IpAddr>().ok();
                let rtt = rtt_str.parse::<f64>().ok()
                    .map(|ms| Duration::from_micros((ms * 1000.0) as u64));
                
                responses.push(HopResponse {
                    ip_address,
                    rtt,
                    timeout: false,
                });
                
                i += 3; // Skip IP, RTT, "ms"
            } else if i + 1 < parts.len() && parts[i + 1] == "ms" {
                // Additional RTT for same IP: "2.345 ms"
                let rtt_str = parts[i];
                let rtt = rtt_str.parse::<f64>().ok()
                    .map(|ms| Duration::from_micros((ms * 1000.0) as u64));
                
                // Use the same IP as the previous response
                let ip_address = responses.last()
                    .and_then(|r| r.ip_address);
                
                responses.push(HopResponse {
                    ip_address,
                    rtt,
                    timeout: false,
                });
                
                i += 2; // Skip RTT, "ms"
            } else {
                i += 1; // Skip unknown token
            }
        }
        
        // Calculate statistics
        let rtts: Vec<Duration> = responses.iter()
            .filter_map(|r| r.rtt)
            .collect();
        
        let best_rtt = rtts.iter().min().copied();
        let worst_rtt = rtts.iter().max().copied();
        let avg_rtt = if !rtts.is_empty() {
            let total_micros: u64 = rtts.iter().map(|d| d.as_micros() as u64).sum();
            Some(Duration::from_micros(total_micros / rtts.len() as u64))
        } else {
            None
        };
        
        let packet_loss = if responses.is_empty() {
            1.0
        } else {
            responses.iter().filter(|r| r.timeout).count() as f32 / responses.len() as f32
        };
        
        Ok(Some(TracerouteHop {
            hop_number,
            responses,
            best_rtt,
            avg_rtt,
            worst_rtt,
            packet_loss,
        }))
    }
}

#[async_trait]
impl Scanner for TracerouteScanner {
    async fn scan(&self, target: &Target) -> Result<ScanResult> {
        let result = self.perform_traceroute(target).await
            .wrap_err("Traceroute scan failed")?;
        
        Ok(ScanResult::Traceroute(result))
    }
    
    fn interval(&self) -> Duration {
        self.interval
    }
    
    fn name(&self) -> &'static str {
        "traceroute"
    }
    
    async fn run(&self, target: Target, state: Arc<AppState>) {
        loop {
            // Update scan state to running
            let scan_state = ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            };
            state.scanners.insert(self.name().to_string(), scan_state);
            
            // Perform scan
            let start_time = Instant::now();
            match self.scan(&target).await {
                Ok(result) => {
                    let mut scan_state = state.scanners.get_mut(self.name()).unwrap();
                    scan_state.result = Some(result);
                    scan_state.error = None;
                    scan_state.status = ScanStatus::Complete;
                    scan_state.last_updated = Instant::now();
                    
                    // Add to history
                    let timestamp = Instant::now();
                    let result_clone = scan_state.result.clone();
                    if let Some(result) = result_clone {
                        scan_state.history.push_back(crate::types::TimestampedResult {
                            timestamp,
                            result,
                        });
                        
                        // Keep only last 10 results
                        while scan_state.history.len() > 10 {
                            scan_state.history.pop_front();
                        }
                    }
                }
                Err(e) => {
                    let mut scan_state = state.scanners.get_mut(self.name()).unwrap();
                    scan_state.result = None;
                    scan_state.error = Some(e);
                    scan_state.status = ScanStatus::Failed;
                    scan_state.last_updated = Instant::now();
                }
            }
            
            // Wait for next scan
            sleep(self.interval()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_traceroute_scanner_creation() {
        let scanner = TracerouteScanner::new();
        assert_eq!(scanner.name(), "traceroute");
        assert_eq!(scanner.max_hops, 20);
        assert_eq!(scanner.probes_per_hop, 3);
    }
    
    #[test]
    fn test_parse_hop_line_with_responses() {
        let scanner = TracerouteScanner::new();
        let line = " 1  192.168.10.1  2.390 ms  2.250 ms  2.203 ms";
        
        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 1);
        assert_eq!(hop.responses.len(), 3);
        
        // Check first response
        let response = &hop.responses[0];
        assert_eq!(response.ip_address, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1))));
        assert!(!response.timeout);
        assert!(response.rtt.is_some());
        
        // Check statistics
        assert!(hop.best_rtt.is_some());
        assert!(hop.avg_rtt.is_some());
        assert!(hop.worst_rtt.is_some());
        assert_eq!(hop.packet_loss, 0.0);
    }
    
    #[test]
    fn test_parse_hop_line_with_timeouts() {
        let scanner = TracerouteScanner::new();
        let line = " 3  * * *";
        
        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 3);
        assert_eq!(hop.responses.len(), 3);
        
        // All responses should be timeouts
        for response in &hop.responses {
            assert!(response.timeout);
            assert!(response.ip_address.is_none());
            assert!(response.rtt.is_none());
        }
        
        assert_eq!(hop.packet_loss, 1.0);
        assert!(hop.best_rtt.is_none());
    }
    
    #[test]
    fn test_parse_hop_line_mixed_responses() {
        let scanner = TracerouteScanner::new();
        let line = " 2  192.168.7.1  4.929 ms  * 8.298 ms";
        
        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 2);
        assert_eq!(hop.responses.len(), 3);
        
        // First response should have IP and RTT
        assert_eq!(hop.responses[0].ip_address, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1))));
        assert!(!hop.responses[0].timeout);
        
        // Second response should be timeout
        assert!(hop.responses[1].timeout);
        
        // Third response should have RTT (same IP as first)
        assert!(!hop.responses[2].timeout);
        assert!(hop.responses[2].rtt.is_some());
        
        // Packet loss should be 1/3
        assert!((hop.packet_loss - 0.333).abs() < 0.01);
    }
    
    #[test]
    fn test_parse_ipv6_hop() {
        let scanner = TracerouteScanner::new();
        let line = " 1  2001:db8::1  15.234 ms  14.567 ms  16.123 ms";
        
        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 1);
        
        let expected_ip = "2001:db8::1".parse::<IpAddr>().unwrap();
        assert_eq!(hop.responses[0].ip_address, Some(expected_ip));
    }
    
    #[test]
    fn test_parse_invalid_hop_line() {
        let scanner = TracerouteScanner::new();
        
        // Empty line
        assert!(scanner.parse_hop_line("").unwrap().is_none());
        
        // Header line
        assert!(scanner.parse_hop_line("traceroute to 8.8.8.8 (8.8.8.8), 30 hops max").unwrap().is_none());
        
        // Invalid format
        assert!(scanner.parse_hop_line("not a hop line").unwrap().is_none());
    }
    
    #[tokio::test]
    async fn test_traceroute_scan_localhost() {
        let scanner = TracerouteScanner::new();
        let target = Target::parse("127.0.0.1").unwrap();
        
        // This test requires traceroute to be installed
        // Skip if not available
        if std::process::Command::new("which").arg("traceroute").output().is_err() {
            return;
        }
        
        match scanner.scan(&target).await {
            Ok(ScanResult::Traceroute(result)) => {
                assert!(!result.hops.is_empty());
                assert_eq!(result.target_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                assert!(!result.ipv6);
            }
            Ok(_) => panic!("Expected TracerouteResult"),
            Err(e) => {
                // Traceroute might fail in some environments (containers, etc.)
                println!("Traceroute test skipped due to error: {}", e);
            }
        }
    }
} 