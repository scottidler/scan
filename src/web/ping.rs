use std::collections::{VecDeque, HashMap};
use std::net::{IpAddr, TcpStream};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use tokio::time::timeout;

const PING_TIMEOUT: Duration = Duration::from_secs(1);
const WINDOW_SIZE: usize = 60;

#[derive(Debug, Clone)]
pub struct PingData {
    pub ipv4_stats: Option<PingStats>,
    pub ipv6_stats: Option<PingStats>,
    pub target_ips: Vec<IpAddr>,
    pub ping_methods: Vec<PingMethod>,
    pub active_methods: HashMap<IpAddr, PingMethod>,
}

impl PingData {
    pub fn new(target_ips: Vec<IpAddr>) -> Self {
        Self {
            ipv4_stats: None,
            ipv6_stats: None,
            target_ips,
            ping_methods: vec![PingMethod::Icmp, PingMethod::TcpPort80, PingMethod::TcpPort443],
            active_methods: HashMap::new(),
        }
    }

    pub async fn update_stats(&mut self) {
        for ip in &self.target_ips {
            let method = self.active_methods.get(ip).copied().unwrap_or_else(|| {
                // Default to ICMP if no method is set
                PingMethod::Icmp
            });

            let result = ping_target(*ip, method).await;
            
            let stats = if ip.is_ipv4() {
                &mut self.ipv4_stats
            } else {
                &mut self.ipv6_stats
            };

            if let Some(stats) = stats {
                stats.update_stats(result);
            } else {
                let mut new_stats = PingStats::new();
                new_stats.update_stats(result);
                if ip.is_ipv4() {
                    self.ipv4_stats = Some(new_stats);
                } else {
                    self.ipv6_stats = Some(new_stats);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingStats {
    pub current_ping: Option<Duration>,
    pub rolling_window: VecDeque<PingResult>,
    pub average: Option<Duration>,
    pub min_max: Option<(Duration, Duration)>,
    pub packet_loss: f32,
    pub jitter: Option<Duration>,
    pub success_rate: f32,
    pub last_updated: DateTime<Utc>,
}

impl PingStats {
    pub fn new() -> Self {
        Self {
            current_ping: None,
            rolling_window: VecDeque::with_capacity(WINDOW_SIZE),
            average: None,
            min_max: None,
            packet_loss: 0.0,
            jitter: None,
            success_rate: 0.0,
            last_updated: Utc::now(),
        }
    }

    pub fn update_stats(&mut self, result: PingResult) {
        self.current_ping = result.latency;
        self.last_updated = Utc::now();

        // Update rolling window
        if self.rolling_window.len() >= WINDOW_SIZE {
            self.rolling_window.pop_front();
        }
        self.rolling_window.push_back(result);

        // Calculate statistics
        self.calculate_average();
        self.calculate_packet_loss();
        self.calculate_jitter();
        self.calculate_min_max();
        self.calculate_success_rate();
    }

    fn calculate_average(&mut self) {
        let successful: Vec<_> = self.rolling_window
            .iter()
            .filter_map(|r| r.latency)
            .collect();
            
        if !successful.is_empty() {
            let sum: Duration = successful.iter().sum();
            self.average = Some(sum / successful.len() as u32);
        }
    }

    fn calculate_packet_loss(&mut self) {
        if self.rolling_window.is_empty() {
            self.packet_loss = 0.0;
            return;
        }

        let failed = self.rolling_window.iter()
            .filter(|r| !r.success)
            .count();
        
        self.packet_loss = (failed as f32 / self.rolling_window.len() as f32) * 100.0;
    }

    fn calculate_jitter(&mut self) {
        let latencies: Vec<_> = self.rolling_window
            .iter()
            .filter_map(|r| r.latency)
            .collect();

        if latencies.len() < 2 {
            self.jitter = None;
            return;
        }

        let mut diffs = Vec::new();
        for window in latencies.windows(2) {
            if let [a, b] = window {
                diffs.push((a.as_millis() as i64 - b.as_millis() as i64).abs());
            }
        }

        if !diffs.is_empty() {
            let sum: i64 = diffs.iter().sum();
            let avg = sum / diffs.len() as i64;
            self.jitter = Some(Duration::from_millis(avg as u64));
        }
    }

    fn calculate_min_max(&mut self) {
        let successful: Vec<_> = self.rolling_window
            .iter()
            .filter_map(|r| r.latency)
            .collect();

        if successful.is_empty() {
            self.min_max = None;
            return;
        }

        let min = successful.iter().min().copied();
        let max = successful.iter().max().copied();

        if let (Some(min), Some(max)) = (min, max) {
            self.min_max = Some((min, max));
        }
    }

    fn calculate_success_rate(&mut self) {
        if self.rolling_window.is_empty() {
            self.success_rate = 0.0;
            return;
        }

        let successful = self.rolling_window.iter()
            .filter(|r| r.success)
            .count();
        
        self.success_rate = (successful as f32 / self.rolling_window.len() as f32) * 100.0;
    }
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub timestamp: DateTime<Utc>,
    pub latency: Option<Duration>,
    pub success: bool,
    pub method: PingMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PingMethod {
    Icmp,
    TcpPort80,
    TcpPort443,
}

pub async fn ping_target(ip: IpAddr, method: PingMethod) -> PingResult {
    let start = Instant::now();
    let success = match method {
        PingMethod::Icmp => icmp_ping(ip).await,
        PingMethod::TcpPort80 => tcp_ping(ip, 80).await,
        PingMethod::TcpPort443 => tcp_ping(ip, 443).await,
    };
    let latency = if success {
        Some(start.elapsed())
    } else {
        None
    };

    PingResult {
        timestamp: Utc::now(),
        latency,
        success,
        method,
    }
}

async fn icmp_ping(ip: IpAddr) -> bool {
    // TODO: Implement actual ICMP ping using tokio-icmp or similar
    // For now, fallback to TCP ping
    tcp_ping(ip, 80).await
}

async fn tcp_ping(ip: IpAddr, port: u16) -> bool {
    let addr = format!("{}:{}", ip, port);
    match timeout(PING_TIMEOUT, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

pub async fn determine_ping_method(ip: IpAddr) -> PingMethod {
    // Try ICMP first
    if icmp_ping(ip).await {
        return PingMethod::Icmp;
    }
    
    // Try TCP port 80
    if tcp_ping(ip, 80).await {
        return PingMethod::TcpPort80;
    }
    
    // Fallback to TCP port 443
    PingMethod::TcpPort443
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_ping_data_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ping_data = PingData::new(vec![ip]);
        assert_eq!(ping_data.target_ips.len(), 1);
        assert_eq!(ping_data.ping_methods.len(), 3);
    }

    #[tokio::test]
    async fn test_ping_stats_update() {
        let mut stats = PingStats::new();
        let result = PingResult {
            timestamp: Utc::now(),
            latency: Some(Duration::from_millis(100)),
            success: true,
            method: PingMethod::Icmp,
        };
        
        stats.update_stats(result);
        assert!(stats.current_ping.is_some());
        assert!(stats.average.is_some());
        assert!(stats.min_max.is_some());
        assert_eq!(stats.packet_loss, 0.0);
        assert_eq!(stats.success_rate, 100.0);
    }
}
