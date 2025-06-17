use crate::scanner::Scanner;
use crate::types::ScanResult;
use crate::target::Target;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use std::time::{Duration, Instant};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct PingResult {
    pub latency: Duration,
    pub packet_loss: f32,
    pub ttl: Option<u8>,
    pub packets_sent: u32,
    pub packets_received: u32,
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
            Duration::from_secs(1),    // Ping every second
            Duration::from_secs(5),    // 5 second timeout
            1,                         // Send 1 packet per scan
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
    
    async fn scan(&self, target: &Target) -> Result<ScanResult, eyre::Error> {
        log::debug!("[scan::ping] scan: target={}", target.display_name());
        
        let ping_target = target.network_target();
        log::debug!("[scan::ping] network_target: {}", ping_target);
        
        let scan_start = Instant::now();
        match self.do_ping(&ping_target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::ping] ping_completed: target={} duration={}ms latency={}ms ttl={:?}", 
                    ping_target, scan_duration.as_millis(), result.latency.as_millis(), result.ttl);
                Ok(ScanResult::Ping(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::ping] ping_failed: target={} duration={}ms error={}", 
                    ping_target, scan_duration.as_millis(), e);
                Err(e.wrap_err(format!("Failed to ping target: {}", target.display_name())))
            }
        }
    }
}

impl PingScanner {
    async fn do_ping(&self, target: &str) -> Result<PingResult> {
        log::debug!("[scan::ping] do_ping: target={} packet_count={} timeout={}ms", 
            target, self.packet_count, self.timeout.as_millis());
        
        let ping_start = Instant::now();
        let output = Command::new("ping")
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
                log::trace!("[scan::ping] ping_command_completed: target={} duration={}ms status={}", 
                    target, command_duration.as_millis(), out.status);
                out
            }
            Err(e) => {
                log::error!("[scan::ping] ping_command_failed: target={} duration={}ms error={}", 
                    target, command_duration.as_millis(), e);
                return Err(e).wrap_err("Failed to execute ping command");
            }
        };
            
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!("[scan::ping] ping_command_unsuccessful: target={} status={} stderr={}", 
                target, output.status, stderr.trim());
            eyre::bail!("Ping failed for target: {}", target);
        }
        
        let stdout = match String::from_utf8(output.stdout) {
            Ok(s) => {
                log::trace!("[scan::ping] ping_output_decoded: target={} output_len={}", 
                    target, s.len());
                s
            }
            Err(e) => {
                log::error!("[scan::ping] ping_output_decode_failed: target={} error={}", 
                    target, e);
                return Err(e).wrap_err("Invalid UTF-8 in ping output");
            }
        };
        
        let parse_start = Instant::now();
        match self.parse_ping_output(&stdout) {
            Ok(result) => {
                let parse_duration = parse_start.elapsed();
                log::trace!("[scan::ping] ping_output_parsed: target={} parse_duration={}μs latency={}ms", 
                    target, parse_duration.as_micros(), result.latency.as_millis());
                Ok(result)
            }
            Err(e) => {
                let parse_duration = parse_start.elapsed();
                log::error!("[scan::ping] ping_output_parse_failed: target={} parse_duration={}μs error={}", 
                    target, parse_duration.as_micros(), e);
                log::trace!("[scan::ping] ping_output_content: target={} stdout={}", target, stdout);
                Err(e.wrap_err("Failed to parse ping output"))
            }
        }
    }
    
    fn parse_ping_output(&self, output: &str) -> Result<PingResult> {
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
                    let result = PingResult {
                        latency,
                        packet_loss: 0.0, // Would calculate from summary
                        ttl,
                        packets_sent: self.packet_count as u32,
                        packets_received: 1, // Simplified
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
        
        let result = scanner.parse_ping_output(output).unwrap();
        assert_eq!(result.latency, Duration::from_millis(15));
        assert_eq!(result.ttl, Some(118));
        assert_eq!(result.packets_sent, 1);
        assert_eq!(result.packets_received, 1);
    }
} 