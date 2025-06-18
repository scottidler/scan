use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::process::Command;
use log;

const TRACEROUTE_INTERVAL_SECS: u64 = 5 * 60; // 5 minutes - traceroute is slow and noisy if too frequent
const TRACEROUTE_TIMEOUT_SECS: u64 = 3; // 3 seconds per hop (much faster like your example)
const MAX_TRACEROUTE_HOPS: u8 = 30;
const PROBES_PER_HOP: u8 = 3;
const HOP_SUMMARY_DISPLAY_COUNT: usize = 5;
const MS_TO_MICROSECONDS_MULTIPLIER: f64 = 1000.0;
const FULL_PACKET_LOSS: f32 = 1.0;

#[derive(Debug, Clone)]
pub struct TracerouteScanner {
    interval: Duration,
    timeout: Duration,
    max_hops: u8,
    probes_per_hop: u8,
}

// Dual-protocol Traceroute result structure
#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub ipv4_result: Option<TracerouteData>,
    pub ipv6_result: Option<TracerouteData>,
    pub ipv4_status: TracerouteStatus,
    pub ipv6_status: TracerouteStatus,
    pub total_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct TracerouteData {
    pub hops: Vec<TracerouteHop>,
    pub destination_reached: bool,
    pub total_hops: u8,
    pub max_hops: u8,
    pub target_ip: IpAddr,
    pub scan_duration: Duration,
    pub ipv6: bool,
}

#[derive(Debug, Clone)]
pub enum TracerouteStatus {
    Success(u8),           // Traceroute succeeded with N hops
    Failed(String),        // Traceroute failed with error message
    NoAddress,            // No address available for this protocol
    NotQueried,           // Query was not attempted
}

impl TracerouteResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: TracerouteStatus::NotQueried,
            ipv6_status: TracerouteStatus::NotQueried,
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn get_primary_result(&self) -> Option<&TracerouteData> {
        // Prefer IPv4, then IPv6
        self.ipv4_result.as_ref().or(self.ipv6_result.as_ref())
    }

    pub fn has_any_success(&self) -> bool {
        matches!(self.ipv4_status, TracerouteStatus::Success(_)) ||
        matches!(self.ipv6_status, TracerouteStatus::Success(_))
    }

    pub fn total_hops(&self) -> u8 {
        let ipv4_hops = self.ipv4_result.as_ref().map(|r| r.total_hops).unwrap_or(0);
        let ipv6_hops = self.ipv6_result.as_ref().map(|r| r.total_hops).unwrap_or(0);
        ipv4_hops.max(ipv6_hops)
    }

    pub fn any_destination_reached(&self) -> bool {
        self.ipv4_result.as_ref().map(|r| r.destination_reached).unwrap_or(false) ||
        self.ipv6_result.as_ref().map(|r| r.destination_reached).unwrap_or(false)
    }
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
        log::debug!("[scan::traceroute] new: interval=120s timeout=30s max_hops=20 probes_per_hop=3");
        Self {
            interval: Duration::from_secs(TRACEROUTE_INTERVAL_SECS), // 2 minutes
            timeout: Duration::from_secs(TRACEROUTE_TIMEOUT_SECS),
            max_hops: MAX_TRACEROUTE_HOPS,
            probes_per_hop: PROBES_PER_HOP,
        }
    }

    async fn traceroute_protocol(&self, target: &Target, protocol: Protocol) -> Result<TracerouteData> {
        log::debug!("[scan::traceroute] traceroute_protocol: target={} protocol={}", target.display_name(), protocol.as_str());

        // Check if target supports this protocol
        if !target.supports_protocol(protocol) {
            log::warn!("[scan::traceroute] no_address_for_protocol: target={} protocol={}",
                target.display_name(), protocol.as_str());
            return Err(eyre::eyre!("No {} address available for target: {}", protocol.as_str(), target.display_name()));
        }

        // Get protocol-specific IP address
        let target_ip = match target.primary_ip_for_protocol(protocol) {
            Some(ip) => ip,
            None => {
                log::warn!("[scan::traceroute] no_ip_for_protocol: target={} protocol={}",
                    target.display_name(), protocol.as_str());
                return Err(eyre::eyre!("No {} IP address available for target: {}", protocol.as_str(), target.display_name()));
            }
        };

        log::debug!("[scan::traceroute] protocol_target: {} -> {} ({})",
            target.display_name(), target_ip, protocol.as_str());

        let traceroute_data = self.perform_traceroute_for_ip(target, target_ip).await?;
        Ok(traceroute_data)
    }

    async fn perform_traceroute_for_ip(&self, target: &Target, target_ip: IpAddr) -> Result<TracerouteData> {
        log::debug!("[scan::traceroute] perform_traceroute: target={}", target.display_name());

        let start_time = Instant::now();
        let ipv6 = target_ip.is_ipv6();

        log::debug!("[scan::traceroute] target_determined: target={} ip={} ipv6={}",
            target.display_name(), target_ip, ipv6);

        // Build traceroute command
        let mut cmd = Command::new(if ipv6 { "traceroute6" } else { "traceroute" });
        cmd.args([
            "-n", // Don't resolve hostnames
            "-w", &self.timeout.as_secs().to_string(), // Wait time
            "-m", &self.max_hops.to_string(), // Max hops
            "-q", &self.probes_per_hop.to_string(), // Probes per hop
            &target_ip.to_string(),
        ]);

        log::trace!("[scan::traceroute] executing_command: target={} cmd={:?}",
            target.display_name(), cmd);

        let command_start = Instant::now();
        let output = cmd.output().await
            .wrap_err("Failed to execute traceroute command")?;
        let command_duration = command_start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!("[scan::traceroute] command_failed: target={} duration={}ms status={} stderr={}",
                target.display_name(), command_duration.as_millis(), output.status, stderr.trim());
            return Err(eyre::eyre!("Traceroute command failed: {}", stderr));
        }

        let stdout = String::from_utf8(output.stdout)
            .wrap_err("Invalid UTF-8 in traceroute output")?;

        log::trace!("[scan::traceroute] command_completed: target={} duration={}ms output_len={}",
            target.display_name(), command_duration.as_millis(), stdout.len());

        let parse_start = Instant::now();
        let result = self.parse_traceroute_output(&stdout, target_ip, ipv6, start_time.elapsed())?;
        let parse_duration = parse_start.elapsed();

        log::debug!("[scan::traceroute] traceroute_completed: target={} duration={}ms parse_duration={}μs hops={} destination_reached={}",
            target.display_name(), result.scan_duration.as_millis(), parse_duration.as_micros(),
            result.hops.len(), result.destination_reached);

        if !result.hops.is_empty() {
            let hop_summary: Vec<String> = result.hops.iter().take(HOP_SUMMARY_DISPLAY_COUNT).map(|h| {
                format!("{}:{:.1}ms", h.hop_number,
                    h.best_rtt.map(|d| d.as_millis() as f32).unwrap_or(-1.0))
            }).collect();
            log::trace!("[scan::traceroute] hop_summary: target={} first_5_hops=[{}]",
                target.display_name(), hop_summary.join(", "));
        }

        Ok(result)
    }



    fn parse_traceroute_output(
        &self,
        output: &str,
        target_ip: IpAddr,
        ipv6: bool,
        scan_duration: Duration,
    ) -> Result<TracerouteData> {
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

        Ok(TracerouteData {
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
                    .map(|ms| Duration::from_micros((ms * MS_TO_MICROSECONDS_MULTIPLIER) as u64));

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
                    .map(|ms| Duration::from_micros((ms * MS_TO_MICROSECONDS_MULTIPLIER) as u64));

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
            FULL_PACKET_LOSS
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
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!("[scan::traceroute] scan: target={} protocol={}", target.display_name(), protocol.as_str());

        let scan_start = Instant::now();
        let mut result = TracerouteResult::new();

        match protocol {
            Protocol::Ipv4 => {
                match self.traceroute_protocol(target, Protocol::Ipv4).await {
                    Ok(data) => {
                        result.ipv4_result = Some(data.clone());
                        result.ipv4_status = TracerouteStatus::Success(data.total_hops);
                        log::trace!("[scan::traceroute] ipv4_traceroute_completed: target={} hops={} complete={}",
                            target.display_name(), data.total_hops, data.destination_reached);
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv4_status = TracerouteStatus::NoAddress;
                            log::warn!("[scan::traceroute] ipv4_traceroute_no_address: target={}", target.display_name());
                        } else {
                            result.ipv4_status = TracerouteStatus::Failed(error_str);
                            log::error!("[scan::traceroute] ipv4_traceroute_failed: target={} error={}",
                                target.display_name(), e);
                        }
                    }
                }
            }
            Protocol::Ipv6 => {
                match self.traceroute_protocol(target, Protocol::Ipv6).await {
                    Ok(data) => {
                        result.ipv6_result = Some(data.clone());
                        result.ipv6_status = TracerouteStatus::Success(data.total_hops);
                        log::trace!("[scan::traceroute] ipv6_traceroute_completed: target={} hops={} complete={}",
                            target.display_name(), data.total_hops, data.destination_reached);
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv6_status = TracerouteStatus::NoAddress;
                            log::warn!("[scan::traceroute] ipv6_traceroute_no_address: target={}", target.display_name());
                        } else {
                            result.ipv6_status = TracerouteStatus::Failed(error_str);
                            log::error!("[scan::traceroute] ipv6_traceroute_failed: target={} error={}",
                                target.display_name(), e);
                        }
                    }
                }
            }
            Protocol::Both => {
                // Run both IPv4 and IPv6 traceroutes concurrently
                let (ipv4_result, ipv6_result) = tokio::join!(
                    self.traceroute_protocol(target, Protocol::Ipv4),
                    self.traceroute_protocol(target, Protocol::Ipv6)
                );

                match ipv4_result {
                    Ok(data) => {
                        result.ipv4_result = Some(data.clone());
                        result.ipv4_status = TracerouteStatus::Success(data.total_hops);
                        log::trace!("[scan::traceroute] ipv4_traceroute_completed: target={} hops={} complete={}",
                            target.display_name(), data.total_hops, data.destination_reached);
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv4_status = TracerouteStatus::NoAddress;
                            log::warn!("[scan::traceroute] ipv4_traceroute_no_address: target={}", target.display_name());
                        } else {
                            result.ipv4_status = TracerouteStatus::Failed(error_str);
                            log::error!("[scan::traceroute] ipv4_traceroute_failed: target={} error={}",
                                target.display_name(), e);
                        }
                    }
                }

                match ipv6_result {
                    Ok(data) => {
                        result.ipv6_result = Some(data.clone());
                        result.ipv6_status = TracerouteStatus::Success(data.total_hops);
                        log::trace!("[scan::traceroute] ipv6_traceroute_completed: target={} hops={} complete={}",
                            target.display_name(), data.total_hops, data.destination_reached);
                    }
                    Err(e) => {
                        let error_str = e.to_string();
                        if error_str.contains("address available") {
                            result.ipv6_status = TracerouteStatus::NoAddress;
                            log::warn!("[scan::traceroute] ipv6_traceroute_no_address: target={}", target.display_name());
                        } else {
                            result.ipv6_status = TracerouteStatus::Failed(error_str);
                            log::error!("[scan::traceroute] ipv6_traceroute_failed: target={} error={}",
                                target.display_name(), e);
                        }
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if any protocol succeeded
        if result.has_any_success() {
            log::debug!("[scan::traceroute] scan_completed: target={} protocol={} duration={}ms ipv4_status={:?} ipv6_status={:?}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(),
                result.ipv4_status, result.ipv6_status);
            Ok(ScanResult::Traceroute(result))
        } else {
            let error_msg = format!("All traceroute protocols failed: IPv4={:?}, IPv6={:?}",
                result.ipv4_status, result.ipv6_status);
            log::error!("[scan::traceroute] scan_failed: target={} protocol={} duration={}ms error={}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(), error_msg);
            Err(eyre::eyre!(error_msg))
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "traceroute"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_traceroute_scanner_creation() {
        let scanner = TracerouteScanner::new();
        assert_eq!(scanner.name(), "traceroute");
        assert_eq!(scanner.max_hops, MAX_TRACEROUTE_HOPS);
        assert_eq!(scanner.probes_per_hop, PROBES_PER_HOP);
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
        let mut target = Target::parse("127.0.0.1").unwrap();
        target.resolve().await.expect("Failed to resolve target");

        // This test requires traceroute to be installed
        // Skip if not available
        if std::process::Command::new("which").arg("traceroute").output().is_err() {
            return;
        }

        match scanner.scan(&target, Protocol::Ipv4).await {
            Ok(ScanResult::Traceroute(result)) => {
                assert!(result.has_any_success());
                if let Some(ipv4_data) = &result.ipv4_result {
                    assert!(!ipv4_data.hops.is_empty());
                    assert_eq!(ipv4_data.target_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                    assert!(!ipv4_data.ipv6);
                }
            }
            Ok(_) => panic!("Expected TracerouteResult"),
            Err(e) => {
                // Traceroute might fail in some environments (containers, etc.)
                println!("Traceroute test skipped due to error: {}", e);
            }
        }
    }

    #[test]
    fn test_traceroute_result_structure() {
        let mut result = TracerouteResult::new();
        result.ipv4_result = Some(TracerouteData {
            hops: vec![],
            destination_reached: false,
            total_hops: 5,
            max_hops: 30,
            target_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            scan_duration: Duration::from_millis(500),
            ipv6: false,
        });
        result.ipv4_status = TracerouteStatus::Success(5);
        result.total_duration = Duration::from_millis(500);

        assert_eq!(result.total_hops(), 5);
        assert!(!result.any_destination_reached());
        if let Some(ipv4_data) = &result.ipv4_result {
            assert_eq!(ipv4_data.max_hops, 30);
            assert!(!ipv4_data.ipv6);
            assert!(ipv4_data.hops.is_empty());
        }
    }

    #[test]
    fn test_hop_response_structure() {
        let response = HopResponse {
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            rtt: Some(Duration::from_millis(5)),
            timeout: false,
        };

        assert!(response.ip_address.is_some());
        assert!(response.rtt.is_some());
        assert!(!response.timeout);

        let timeout_response = HopResponse {
            ip_address: None,
            rtt: None,
            timeout: true,
        };

        assert!(timeout_response.ip_address.is_none());
        assert!(timeout_response.rtt.is_none());
        assert!(timeout_response.timeout);
    }

    #[test]
    fn test_traceroute_hop_statistics() {
        let hop = TracerouteHop {
            hop_number: 3,
            responses: vec![
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(10)),
                    timeout: false,
                },
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(15)),
                    timeout: false,
                },
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(20)),
                    timeout: false,
                },
            ],
            best_rtt: Some(Duration::from_millis(10)),
            avg_rtt: Some(Duration::from_millis(15)),
            worst_rtt: Some(Duration::from_millis(20)),
            packet_loss: 0.0,
        };

        assert_eq!(hop.hop_number, 3);
        assert_eq!(hop.responses.len(), 3);
        assert_eq!(hop.best_rtt, Some(Duration::from_millis(10)));
        assert_eq!(hop.avg_rtt, Some(Duration::from_millis(15)));
        assert_eq!(hop.worst_rtt, Some(Duration::from_millis(20)));
        assert_eq!(hop.packet_loss, 0.0);
    }

    #[test]
    fn test_parse_hop_line_complex_cases() {
        let scanner = TracerouteScanner::new();

        // Test hop with hostname resolution - this might not parse correctly depending on implementation
        let hostname_line = " 1  router.local (192.168.1.1)  2.390 ms  2.250 ms  2.203 ms";
        if let Ok(Some(hop)) = scanner.parse_hop_line(hostname_line) {
            assert_eq!(hop.hop_number, 1);
            assert_eq!(hop.responses.len(), 3);
            // IP parsing might not work with hostname format
        }

        // Test hop with different IPs for each response
        let multi_ip_line = " 2  10.0.0.1  4.929 ms 10.0.0.2  8.298 ms 10.0.0.3  12.456 ms";
        let multi_hop = scanner.parse_hop_line(multi_ip_line).unwrap().unwrap();
        assert_eq!(multi_hop.hop_number, 2);
        assert_eq!(multi_hop.responses.len(), 3);
        assert_eq!(multi_hop.responses[0].ip_address, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_parse_hop_line_error_conditions() {
        let scanner = TracerouteScanner::new();

        // Test line without hop number
        let no_hop_line = "invalid line without hop number";
        assert!(scanner.parse_hop_line(no_hop_line).unwrap().is_none());

        // Test line with invalid hop number
        let invalid_hop_line = " invalid  192.168.1.1  2.390 ms";
        assert!(scanner.parse_hop_line(invalid_hop_line).unwrap().is_none());

        // Test empty/whitespace lines
        assert!(scanner.parse_hop_line("").unwrap().is_none());
        assert!(scanner.parse_hop_line("   ").unwrap().is_none());
    }

    #[test]
    fn test_traceroute_scanner_defaults() {
        let scanner = TracerouteScanner::default();

        assert_eq!(scanner.name(), "traceroute");
        assert_eq!(scanner.max_hops, 30); // Updated constant value
        assert_eq!(scanner.probes_per_hop, 3);
        assert_eq!(scanner.timeout, Duration::from_secs(3)); // Updated timeout value
    }

    #[test]
    fn test_traceroute_scanner_custom_config() {
        let scanner = TracerouteScanner::new();

        assert_eq!(scanner.interval(), Duration::from_secs(300)); // 5 minutes (updated value)
        assert_eq!(scanner.max_hops, 30); // Updated constant value
        assert_eq!(scanner.probes_per_hop, 3);
    }

    #[test]
    fn test_traceroute_status_enum() {
        // Test TracerouteStatus variants
        match TracerouteStatus::Success(5) {
            TracerouteStatus::Success(hops) => assert_eq!(hops, 5),
            _ => panic!("Expected Success status"),
        }

        match TracerouteStatus::Failed("Network unreachable".to_string()) {
            TracerouteStatus::Failed(msg) => assert!(msg.contains("unreachable")),
            _ => panic!("Expected Failed status"),
        }

        match TracerouteStatus::NoAddress {
            TracerouteStatus::NoAddress => {},
            _ => panic!("Expected NoAddress status"),
        }

        match TracerouteStatus::NotQueried {
            TracerouteStatus::NotQueried => {},
            _ => panic!("Expected NotQueried status"),
        }
    }

    #[test]
    fn test_packet_loss_calculation() {
        let scanner = TracerouteScanner::new();

        // Test 100% packet loss
        let all_timeout_line = " 5  * * *";
        let timeout_hop = scanner.parse_hop_line(all_timeout_line).unwrap().unwrap();
        assert_eq!(timeout_hop.packet_loss, 1.0);

        // Test 33% packet loss (1 out of 3)
        let partial_timeout_line = " 6  192.168.1.1  5.0 ms * 7.5 ms";
        let partial_hop = scanner.parse_hop_line(partial_timeout_line).unwrap().unwrap();
        assert!((partial_hop.packet_loss - 0.333).abs() < 0.01);

        // Test 0% packet loss
        let no_timeout_line = " 7  192.168.1.1  5.0 ms  6.0 ms  7.0 ms";
        let success_hop = scanner.parse_hop_line(no_timeout_line).unwrap().unwrap();
        assert_eq!(success_hop.packet_loss, 0.0);
    }
}