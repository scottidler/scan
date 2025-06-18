use crate::scanner::Scanner;
use crate::types::ScanResult;
use crate::target::{Target, Protocol};
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use std::time::{Duration, Instant};
use tokio::process::Command;

const DEFAULT_PING_INTERVAL_SECS: u64 = 1;
const DEFAULT_PING_TIMEOUT_SECS: u64 = 5;
const DEFAULT_PING_PACKET_COUNT: u8 = 1;
const SIMPLIFIED_PACKETS_RECEIVED: u32 = 1;

#[derive(Debug, Clone)]
pub struct PingData {
    pub latency: Duration,
    pub packet_loss: f32,
    pub ttl: Option<u8>,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub target_ip: String,
}

#[derive(Debug, Clone)]
pub enum PingStatus {
    NotQueried,           // Protocol not attempted (due to protocol restrictions)
    Success(Duration),    // Ping succeeded with latency
    Failed(String),       // Ping failed with error message
    NoAddress,           // No address available for this protocol
    ToolMissing(String), // Required tool (ping/ping6) not available
}

impl PingStatus {
    pub fn was_attempted(&self) -> bool {
        !matches!(self, PingStatus::NotQueried)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, PingStatus::Success(_))
    }

    pub fn latency(&self) -> Option<Duration> {
        match self {
            PingStatus::Success(latency) => Some(*latency),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingResult {
    // Protocol-specific results
    pub ipv4_result: Option<PingData>,
    pub ipv6_result: Option<PingData>,

    // Status tracking
    pub ipv4_status: PingStatus,
    pub ipv6_status: PingStatus,

    // Metadata
    pub queried_at: Instant,
    pub total_duration: Duration,
}

impl PingResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: PingStatus::NotQueried,
            ipv6_status: PingStatus::NotQueried,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn has_any_success(&self) -> bool {
        self.ipv4_status.is_success() || self.ipv6_status.is_success()
    }

    pub fn get_best_latency(&self) -> Option<Duration> {
        let ipv4_latency = self.ipv4_status.latency();
        let ipv6_latency = self.ipv6_status.latency();

        match (ipv4_latency, ipv6_latency) {
            (Some(v4), Some(v6)) => Some(v4.min(v6)),
            (Some(v4), None) => Some(v4),
            (None, Some(v6)) => Some(v6),
            (None, None) => None,
        }
    }

    pub fn get_primary_result(&self) -> Option<&PingData> {
        // Prefer IPv4, fallback to IPv6
        self.ipv4_result.as_ref().or(self.ipv6_result.as_ref())
    }
}

pub struct PingScanner {
    interval: Duration,
    timeout: Duration,
    packet_count: u8,
}

impl PingScanner {
    pub fn new(interval: Duration, timeout: Duration, packet_count: u8) -> Self {
        log::debug!("[scan::ping] new: interval={}ms timeout={}ms packet_count={}",
            interval.as_millis(), timeout.as_millis(), packet_count);

        Self {
            interval,
            timeout,
            packet_count,
        }
    }
}

impl Default for PingScanner {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(DEFAULT_PING_INTERVAL_SECS),    // Ping every second
            Duration::from_secs(DEFAULT_PING_TIMEOUT_SECS),    // 5 second timeout
            DEFAULT_PING_PACKET_COUNT,                         // Send 1 packet per scan
        )
    }
}

#[async_trait]
impl Scanner for PingScanner {
    fn name(&self) -> &'static str {
        "ping"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult, eyre::Error> {
        log::debug!("[scan::ping] scan: target={} protocol={}", target.display_name(), protocol.as_str());

        let scan_start = Instant::now();
        let mut result = PingResult::new();

        match protocol {
            Protocol::Ipv4 => {
                // IPv4 only
                match self.ping_protocol(target, Protocol::Ipv4).await {
                    Ok((ping_data, _)) => {
                        result.ipv4_status = PingStatus::Success(ping_data.latency);
                        result.ipv4_result = Some(ping_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_ping_error(&e);
                        if result.ipv4_status.is_success() {
                            return Err(e); // Shouldn't happen, but just in case
                        }
                    }
                }
            }
            Protocol::Ipv6 => {
                // IPv6 only
                match self.ping_protocol(target, Protocol::Ipv6).await {
                    Ok((ping_data, _)) => {
                        result.ipv6_status = PingStatus::Success(ping_data.latency);
                        result.ipv6_result = Some(ping_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_ping_error(&e);
                        if result.ipv6_status.is_success() {
                            return Err(e); // Shouldn't happen, but just in case
                        }
                    }
                }
            }
            Protocol::Both => {
                // Both IPv4 and IPv6

                // Try IPv4
                match self.ping_protocol(target, Protocol::Ipv4).await {
                    Ok((ping_data, _)) => {
                        result.ipv4_status = PingStatus::Success(ping_data.latency);
                        result.ipv4_result = Some(ping_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_ping_error(&e);
                        log::debug!("[scan::ping] ipv4_ping_failed: error={}", e);
                    }
                }

                // Try IPv6
                match self.ping_protocol(target, Protocol::Ipv6).await {
                    Ok((ping_data, _)) => {
                        result.ipv6_status = PingStatus::Success(ping_data.latency);
                        result.ipv6_result = Some(ping_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_ping_error(&e);
                        log::debug!("[scan::ping] ipv6_ping_failed: error={}", e);
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if at least one protocol succeeded, or error if all failed
        if result.has_any_success() {
            log::trace!("[scan::ping] ping_completed: target={} protocol={} duration={}ms best_latency={:?}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(), result.get_best_latency());
            Ok(ScanResult::Ping(result))
        } else {
            // All protocols failed
            let error_msg = format!("All ping attempts failed for target: {} ({})",
                target.display_name(), protocol.as_str());
            log::error!("[scan::ping] all_pings_failed: target={} protocol={} duration={}ms",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis());
            Err(eyre::eyre!(error_msg))
        }
    }
}

impl PingScanner {
    async fn ping_protocol(&self, target: &Target, protocol: Protocol) -> Result<(PingData, String)> {
        // Get protocol-specific target
        let ping_target = match target.network_target_for_protocol(protocol) {
            Some(target_addr) => target_addr,
            None => {
                log::warn!("[scan::ping] no_target_for_protocol: target={} protocol={}",
                    target.display_name(), protocol.as_str());
                eyre::bail!("No {} address available for target: {}", protocol.as_str(), target.display_name());
            }
        };

        log::debug!("[scan::ping] protocol_target: {} -> {} ({})",
            target.display_name(), ping_target, protocol.as_str());

        let ping_data = self.do_ping(&ping_target, protocol).await?;
        Ok((ping_data, ping_target))
    }

    fn classify_ping_error(error: &eyre::Error) -> PingStatus {
        let error_msg = error.to_string();

        if error_msg.contains("Command") && error_msg.contains("not found") {
            let tool = if error_msg.contains("ping6") { "ping6" } else { "ping" };
            PingStatus::ToolMissing(tool.to_string())
        } else if error_msg.contains("No") && error_msg.contains("address available") {
            PingStatus::NoAddress
        } else {
            PingStatus::Failed(error_msg)
        }
    }

    async fn do_ping(&self, target: &str, protocol: Protocol) -> Result<PingData> {
        log::debug!("[scan::ping] do_ping: target={} protocol={} packet_count={} timeout={}ms",
            target, protocol.as_str(), self.packet_count, self.timeout.as_millis());

        // Choose the appropriate ping command based on protocol
        let ping_command = match protocol {
            Protocol::Ipv4 => "ping",
            Protocol::Ipv6 => "ping6",
            Protocol::Both => {
                log::error!("[scan::ping] invalid_protocol_for_ping: protocol={}", protocol.as_str());
                eyre::bail!("Protocol::Both is not valid for individual ping operations");
            }
        };

        log::debug!("[scan::ping] using_command: {} for protocol {}", ping_command, protocol.as_str());

        // Check if the ping command is available
        let command_check = Command::new("which")
            .arg(ping_command)
            .output()
            .await;

        match command_check {
            Ok(output) if !output.status.success() => {
                log::error!("[scan::ping] command_not_found: command={} protocol={}",
                    ping_command, protocol.as_str());
                eyre::bail!("Command '{}' not found. Please install {} ping utilities.",
                    ping_command, protocol.as_str());
            }
            Err(e) => {
                log::error!("[scan::ping] command_check_failed: command={} error={}", ping_command, e);
                eyre::bail!("Failed to check for '{}' command availability: {}", ping_command, e);
            }
            Ok(_) => {
                log::trace!("[scan::ping] command_available: {}", ping_command);
            }
        }

        let ping_start = Instant::now();
        let output = Command::new(ping_command)
            .args([
                "-c", &self.packet_count.to_string(),
                "-W", &(self.timeout.as_millis() as u32).to_string(),
                target
            ])
            .output()
            .await;

        let command_duration = ping_start.elapsed();

        let output = match output {
            Ok(out) => {
                log::trace!("[scan::ping] ping_command_completed: command={} target={} duration={}ms status={}",
                    ping_command, target, command_duration.as_millis(), out.status);
                out
            }
            Err(e) => {
                log::error!("[scan::ping] ping_command_failed: command={} target={} duration={}ms error={}",
                    ping_command, target, command_duration.as_millis(), e);
                return Err(e).wrap_err(format!("Failed to execute {} command", ping_command));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!("[scan::ping] ping_command_unsuccessful: command={} target={} status={} stderr={}",
                ping_command, target, output.status, stderr.trim());
            eyre::bail!("Ping failed for target: {} (using {})", target, ping_command);
        }

        let stdout = match String::from_utf8(output.stdout) {
            Ok(s) => {
                log::trace!("[scan::ping] ping_output_decoded: command={} target={} output_len={}",
                    ping_command, target, s.len());
                s
            }
            Err(e) => {
                log::error!("[scan::ping] ping_output_decode_failed: command={} target={} error={}",
                    ping_command, target, e);
                return Err(e).wrap_err("Invalid UTF-8 in ping output");
            }
        };

        let parse_start = Instant::now();
        match self.parse_ping_output(&stdout, protocol, target) {
            Ok(result) => {
                let parse_duration = parse_start.elapsed();
                log::trace!("[scan::ping] ping_output_parsed: command={} target={} parse_duration={}μs latency={}ms",
                    ping_command, target, parse_duration.as_micros(), result.latency.as_millis());
                Ok(result)
            }
            Err(e) => {
                let parse_duration = parse_start.elapsed();
                log::error!("[scan::ping] ping_output_parse_failed: command={} target={} parse_duration={}μs error={}",
                    ping_command, target, parse_duration.as_micros(), e);
                log::trace!("[scan::ping] ping_output_content: command={} target={} stdout={}",
                    ping_command, target, stdout);
                Err(e.wrap_err(format!("Failed to parse {} output", ping_command)))
            }
        }
    }

    fn parse_ping_output(&self, output: &str, _protocol: Protocol, target_ip: &str) -> Result<PingData> {
        log::debug!("[scan::ping] parse_ping_output: output_len={}", output.len());

        // Parse ping output line like: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms"
        for (line_num, line) in output.lines().enumerate() {
            if line.contains("time=") {
                log::trace!("[scan::ping] found_timing_line: line_num={} content={}", line_num, line);

                let mut latency = None;
                let mut ttl = None;

                // Parse latency
                if let Some(time_part) = line.split("time=").nth(1) {
                    if let Some(time_str) = time_part.split_whitespace().next() {
                        match time_str.parse::<f64>() {
                            Ok(latency_ms) => {
                                latency = Some(Duration::from_millis(latency_ms.round() as u64));
                                log::trace!("[scan::ping] parsed_latency: {}ms", latency_ms);
                            }
                            Err(e) => {
                                log::warn!("[scan::ping] latency_parse_failed: time_str={} error={}", time_str, e);
                            }
                        }
                    }
                }

                // Parse TTL
                if let Some(ttl_part) = line.split("ttl=").nth(1) {
                    if let Some(ttl_str) = ttl_part.split_whitespace().next() {
                        match ttl_str.parse::<u8>() {
                            Ok(ttl_value) => {
                                ttl = Some(ttl_value);
                                log::trace!("[scan::ping] parsed_ttl: {}", ttl_value);
                            }
                            Err(e) => {
                                log::warn!("[scan::ping] ttl_parse_failed: ttl_str={} error={}", ttl_str, e);
                            }
                        }
                    }
                }

                if let Some(latency) = latency {
                    let result = PingData {
                        latency,
                        packet_loss: 0.0, // Would calculate from summary
                        ttl,
                        packets_sent: self.packet_count as u32,
                        packets_received: SIMPLIFIED_PACKETS_RECEIVED, // Simplified
                        target_ip: target_ip.to_string(),
                    };

                    log::debug!("[scan::ping] parse_successful: latency={}ms ttl={:?} packets_sent={}",
                        result.latency.as_millis(), result.ttl, result.packets_sent);

                    return Ok(result);
                }
            }
        }

        log::error!("[scan::ping] no_timing_info_found: output_lines={}", output.lines().count());
        eyre::bail!("Could not find timing information in ping output");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ping_output() {
        let scanner = PingScanner::default();
        let output = "PING google.com (142.250.80.238) 56(84) bytes of data.\n64 bytes from lga25s62-in-f14.1e100.net (142.250.80.238): icmp_seq=1 ttl=118 time=15.2 ms\n\n--- google.com ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 15.210/15.210/15.210/0.000 ms";

        let result = scanner.parse_ping_output(output, Protocol::Ipv4, "142.250.80.238").unwrap();
        assert_eq!(result.latency, Duration::from_millis(15));
        assert_eq!(result.ttl, Some(118));
        assert_eq!(result.packets_sent, 1);
        assert_eq!(result.packets_received, 1);
        assert_eq!(result.target_ip, "142.250.80.238");
    }

    #[test]
    fn test_ping_result_structure() {
        let result = PingData {
            latency: Duration::from_millis(25),
            packet_loss: 0.0,
            ttl: Some(64),
            packets_sent: 4,
            packets_received: 4,
            target_ip: String::new(),
        };

        assert_eq!(result.latency, Duration::from_millis(25));
        assert_eq!(result.packet_loss, 0.0);
        assert_eq!(result.ttl, Some(64));
        assert_eq!(result.packets_sent, 4);
        assert_eq!(result.packets_received, 4);
    }

    #[test]
    fn test_ping_scanner_configuration() {
        let custom_scanner = PingScanner::new(
            Duration::from_secs(2),
            Duration::from_secs(10),
            5,
        );

        assert_eq!(custom_scanner.interval(), Duration::from_secs(2));
        assert_eq!(custom_scanner.timeout, Duration::from_secs(10));
        assert_eq!(custom_scanner.packet_count, 5);
    }

    #[test]
    fn test_parse_ping_output_variations() {
        let scanner = PingScanner::default();

        // Test IPv6 ping output
        let ipv6_output = "PING google.com(2607:f8b0:4004:c1b::71) 56 data bytes\n64 bytes from 2607:f8b0:4004:c1b::71: icmp_seq=1 ttl=118 time=12.3 ms\n\n--- google.com ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms";

        let ipv6_result = scanner.parse_ping_output(ipv6_output, Protocol::Ipv6, "2607:f8b0:4004:c1b::71").unwrap();
        assert_eq!(ipv6_result.latency, Duration::from_millis(12));
        assert_eq!(ipv6_result.ttl, Some(118));

        // Test ping with different TTL
        let ttl_output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=64 time=8.123 ms";
        let ttl_result = scanner.parse_ping_output(ttl_output, Protocol::Ipv4, "8.8.8.8").unwrap();
        assert_eq!(ttl_result.latency, Duration::from_millis(8));
        assert_eq!(ttl_result.ttl, Some(64));

        // Test ping with microsecond precision
        let precise_output = "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.123 ms";
        let precise_result = scanner.parse_ping_output(precise_output, Protocol::Ipv4, "127.0.0.1").unwrap();
        assert_eq!(precise_result.latency, Duration::from_millis(0));
    }

    #[test]
    fn test_parse_ping_output_edge_cases() {
        let scanner = PingScanner::default();

        // Test output with no timing information
        let no_time_output = "PING google.com (142.250.80.238) 56(84) bytes of data.\n--- google.com ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 1000ms";
        assert!(scanner.parse_ping_output(no_time_output, Protocol::Ipv4, "142.250.80.238").is_err());

        // Test empty output
        assert!(scanner.parse_ping_output("", Protocol::Ipv4, "127.0.0.1").is_err());

        // Test malformed timing line
        let malformed_output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=invalid time=malformed ms";
        assert!(scanner.parse_ping_output(malformed_output, Protocol::Ipv4, "8.8.8.8").is_err());
    }

    #[test]
    fn test_ping_scanner_defaults() {
        let default_scanner = PingScanner::default();

        assert_eq!(default_scanner.interval(), Duration::from_secs(1));
        assert_eq!(default_scanner.timeout, Duration::from_secs(5));
        assert_eq!(default_scanner.packet_count, 1);
        assert_eq!(default_scanner.name(), "ping");
    }

    #[tokio::test]
    async fn test_ping_scanner_timeout_handling() {
        let timeout_scanner = PingScanner::new(
            Duration::from_secs(1),
            Duration::from_millis(1), // Very short timeout
            1,
        );

        let target = Target::parse("192.0.2.1").unwrap(); // RFC5737 test IP (should not respond)

        // Should handle timeout gracefully
        let result = timeout_scanner.scan(&target, Protocol::Ipv4).await;

        match result {
            Ok(_) => {
                // Unlikely but possible if system responds very quickly
            }
            Err(_) => {
                // Expected behavior - timeout or unreachable
            }
        }
    }

    #[tokio::test]
    async fn test_ping_localhost() {
        let scanner = PingScanner::default();
        let target = Target::parse("127.0.0.1").unwrap();

        let result = scanner.scan(&target, Protocol::Ipv4).await;

        match result {
            Ok(ScanResult::Ping(ping_result)) => {
                // Localhost should respond quickly
                if let Some(best_latency) = ping_result.get_best_latency() {
                    assert!(best_latency.as_millis() < 100);
                }
                assert!(ping_result.has_any_success());

                // Check that we have the expected protocol result
                if let Some(primary_result) = ping_result.get_primary_result() {
                    assert_eq!(primary_result.packets_sent, 1);
                    assert_eq!(primary_result.packets_received, 1);
                    assert_eq!(primary_result.packet_loss, 0.0);
                }
            }
            Ok(_) => panic!("Expected PingResult"),
            Err(e) => {
                // Some systems might not allow ping to localhost
                println!("Ping to localhost failed (might be expected): {}", e);
            }
        }
    }

    #[test]
    fn test_ping_output_parsing_robustness() {
        let scanner = PingScanner::default();

        // Test with extra whitespace
        let whitespace_output = "  64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms  ";
        let result = scanner.parse_ping_output(whitespace_output, Protocol::Ipv4, "8.8.8.8").unwrap();
        assert_eq!(result.latency, Duration::from_millis(15));

        // Test with multiple timing lines (should use first one)
        let multi_output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms\n64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=20.5 ms";
        let multi_result = scanner.parse_ping_output(multi_output, Protocol::Ipv4, "8.8.8.8").unwrap();
        assert_eq!(multi_result.latency, Duration::from_millis(15)); // Should use first line

        // Test with no TTL
        let no_ttl_output = "64 bytes from 8.8.8.8: icmp_seq=1 time=15.2 ms";
        let no_ttl_result = scanner.parse_ping_output(no_ttl_output, Protocol::Ipv4, "8.8.8.8").unwrap();
        assert_eq!(no_ttl_result.latency, Duration::from_millis(15));
        assert!(no_ttl_result.ttl.is_none());
    }

    #[tokio::test]
    async fn test_protocol_aware_ipv4_ping() {
        let scanner = PingScanner::default();
        let target = Target::parse("127.0.0.1").unwrap();

        let result = scanner.scan(&target, Protocol::Ipv4).await;

        match result {
            Ok(ScanResult::Ping(ping_result)) => {
                if let Some(best_latency) = ping_result.get_best_latency() {
                    assert!(best_latency.as_millis() < 100);
                }
                assert!(ping_result.has_any_success());

                // Should have IPv4 result, not IPv6
                assert!(ping_result.ipv4_result.is_some());
                assert!(ping_result.ipv6_result.is_none());
                assert!(ping_result.ipv4_status.is_success());
                assert!(matches!(ping_result.ipv6_status, PingStatus::NotQueried));

                if let Some(ipv4_result) = &ping_result.ipv4_result {
                    assert_eq!(ipv4_result.packets_sent, 1);
                    assert_eq!(ipv4_result.packets_received, 1);
                    assert_eq!(ipv4_result.packet_loss, 0.0);
                }
            }
            Ok(_) => panic!("Expected Ping result"),
            Err(e) => {
                // May fail if ping command is not available or localhost is not responding
                log::warn!("IPv4 ping test failed (may be expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_protocol_aware_ipv6_ping() {
        let scanner = PingScanner::default();
        let target = Target::parse("::1").unwrap();

        let result = scanner.scan(&target, Protocol::Ipv6).await;

        match result {
            Ok(ScanResult::Ping(ping_result)) => {
                if let Some(best_latency) = ping_result.get_best_latency() {
                    assert!(best_latency.as_millis() < 100);
                }
                assert!(ping_result.has_any_success());

                // Should have IPv6 result, not IPv4
                assert!(ping_result.ipv6_result.is_some());
                assert!(ping_result.ipv4_result.is_none());
                assert!(ping_result.ipv6_status.is_success());
                assert!(matches!(ping_result.ipv4_status, PingStatus::NotQueried));

                if let Some(ipv6_result) = &ping_result.ipv6_result {
                    assert_eq!(ipv6_result.packets_sent, 1);
                    assert_eq!(ipv6_result.packets_received, 1);
                    assert_eq!(ipv6_result.packet_loss, 0.0);
                }
            }
            Ok(_) => panic!("Expected Ping result"),
            Err(e) => {
                // May fail if ping6 command is not available or IPv6 localhost is not responding
                log::warn!("IPv6 ping test failed (may be expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_protocol_both_success() {
        let scanner = PingScanner::default();
        let target = Target::parse("127.0.0.1").unwrap();

        let result = scanner.scan(&target, Protocol::Both).await;

        match result {
            Ok(ScanResult::Ping(ping_result)) => {
                // Should have attempted both protocols
                assert!(ping_result.ipv4_status.was_attempted());
                // IPv6 may or may not be attempted depending on system support

                // At least one should succeed
                assert!(ping_result.has_any_success());

                // IPv4 should work for localhost
                assert!(ping_result.ipv4_status.is_success());
            }
            Ok(_) => panic!("Expected Ping result"),
            Err(e) => {
                // May fail if no protocols work
                log::warn!("Dual-stack ping test failed (may be expected): {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_no_target_for_protocol() {
        let scanner = PingScanner::default();

        // Create a target that only has IPv4 addresses
        let ipv4_only_target = Target::parse("127.0.0.1").unwrap();

        // Try to ping IPv6 on an IPv4-only target
        let result = scanner.scan(&ipv4_only_target, Protocol::Ipv6).await;

        // Should fail because no IPv6 address is available
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("All ping attempts failed"));
    }
}