use crate::scanner::Scanner;
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use std::time::Duration;
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
    
    async fn scan(&self, target: &str) -> Result<ScanResult, eyre::Error> {
        let result = self.do_ping(target).await
            .wrap_err_with(|| format!("Failed to ping target: {}", target))?;
        Ok(ScanResult::Ping(result))
    }
}

impl PingScanner {
    async fn do_ping(&self, target: &str) -> Result<PingResult> {
        let output = Command::new("ping")
            .args([
                "-c", &self.packet_count.to_string(),
                "-W", &(self.timeout.as_millis() as u32).to_string(),
                target
            ])
            .output()
            .await
            .wrap_err("Failed to execute ping command")?;
            
        if !output.status.success() {
            eyre::bail!("Ping failed for target: {}", target);
        }
        
        let stdout = String::from_utf8(output.stdout)
            .wrap_err("Invalid UTF-8 in ping output")?;
            
        self.parse_ping_output(&stdout)
            .wrap_err("Failed to parse ping output")
    }
    
    fn parse_ping_output(&self, output: &str) -> Result<PingResult> {
        // Parse ping output line like: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms"
        for line in output.lines() {
            if line.contains("time=") {
                let mut latency = None;
                let mut ttl = None;
                
                // Parse latency
                if let Some(time_part) = line.split("time=").nth(1) {
                    if let Some(time_str) = time_part.split_whitespace().next() {
                        if let Ok(latency_ms) = time_str.parse::<f64>() {
                            latency = Some(Duration::from_millis(latency_ms.round() as u64));
                        }
                    }
                }
                
                // Parse TTL
                if let Some(ttl_part) = line.split("ttl=").nth(1) {
                    if let Some(ttl_str) = ttl_part.split_whitespace().next() {
                        if let Ok(ttl_value) = ttl_str.parse::<u8>() {
                            ttl = Some(ttl_value);
                        }
                    }
                }
                
                if let Some(latency) = latency {
                    return Ok(PingResult {
                        latency,
                        packet_loss: 0.0, // Would calculate from summary
                        ttl,
                        packets_sent: self.packet_count as u32,
                        packets_received: 1, // Simplified
                    });
                }
            }
        }
        
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