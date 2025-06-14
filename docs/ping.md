# Ping Pane

## Overview
The ping pane provides real-time connectivity monitoring with continuous ping tests, showing latency statistics, packet loss, and connection reliability. Supports both IPv4 and IPv6 with automatic fallback from ICMP to TCP ping when needed.

## Display Elements

### Live Updates (Continuous Refresh - Every Second)
- **Current Ping Time**: Latest ping result in milliseconds
- **Average Latency**: Rolling average over last 60 pings
- **Packet Loss**: Percentage of failed pings in rolling window
- **Min/Max Latency**: Session minimums and maximums
- **Jitter**: Latency variation (standard deviation)
- **Connection Status**: Online/Offline indicator

### Static Elements (Set once, updated on target change)
- **Target IP(s)**: IPv4 and/or IPv6 addresses being pinged
- **Ping Method**: ICMP, TCP:80, TCP:443, or combination
- **Protocol**: IPv4/IPv6 indication

## Ping Strategy

### Frequency
- **Ping interval**: Every 1 second
- **Rolling window**: Last 60 samples (60 seconds of data)
- **Concurrent pings**: IPv4 and IPv6 simultaneously if both available

### Method Selection & Fallback
1. **Primary**: ICMP ping (traditional ping)
2. **Fallback**: TCP ping to port 80 (HTTP)
3. **Secondary Fallback**: TCP ping to port 443 (HTTPS)
4. **Method display**: Show active method in UI

### Dual Stack Support
- **IPv4 and IPv6**: Ping both protocols if available
- **Separate statistics**: Track each protocol independently
- **Combined view**: Show both in single pane with clear labels

## Statistics Calculation

### Rolling Window (60 samples)
- **Average**: Mean of successful pings in window
- **Min/Max**: Lowest/highest successful ping in window
- **Packet Loss**: (Failed pings / Total pings) * 100
- **Jitter**: Standard deviation of successful pings
- **Success Rate**: Percentage of successful pings

### Real-time Updates
- **Live ping**: Most recent ping result
- **Status**: Current connection state
- **Trend indicator**: Better/worse/stable compared to previous window

## Implementation Notes

### Data Structures
```rust
struct PingData {
    ipv4_stats: Option<PingStats>,
    ipv6_stats: Option<PingStats>,
    target_ips: Vec<IpAddr>,
    ping_methods: Vec<PingMethod>,
    active_methods: HashMap<IpAddr, PingMethod>,
}

struct PingStats {
    current_ping: Option<Duration>,
    rolling_window: VecDeque<PingResult>,
    average: Option<Duration>,
    min_max: Option<(Duration, Duration)>,
    packet_loss: f32,
    jitter: Option<Duration>,
    success_rate: f32,
    last_updated: DateTime<Utc>,
}

struct PingResult {
    timestamp: DateTime<Utc>,
    latency: Option<Duration>,
    success: bool,
    method: PingMethod,
}

enum PingMethod {
    Icmp,
    TcpPort80,
    TcpPort443,
}
```

### Ping Implementation
```rust
async fn ping_target(ip: IpAddr, method: PingMethod) -> PingResult {
    match method {
        PingMethod::Icmp => icmp_ping(ip).await,
        PingMethod::TcpPort80 => tcp_ping(ip, 80).await,
        PingMethod::TcpPort443 => tcp_ping(ip, 443).await,
    }
}

async fn determine_ping_method(ip: IpAddr) -> PingMethod {
    // Try ICMP first, fallback to TCP if failed/blocked
    if icmp_ping(ip).await.success {
        PingMethod::Icmp
    } else if tcp_ping(ip, 80).await.success {
        PingMethod::TcpPort80
    } else {
        PingMethod::TcpPort443
    }
}
```

### Statistics Calculation
```rust
impl PingStats {
    fn update_stats(&mut self, result: PingResult) {
        // Add to rolling window
        self.rolling_window.push_back(result);
        if self.rolling_window.len() > 60 {
            self.rolling_window.pop_front();
        }
        
        // Recalculate statistics
        self.calculate_average();
        self.calculate_packet_loss();
        self.calculate_jitter();
        self.calculate_min_max();
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
}
```

### Update Frequencies
- **Ping execution**: Every 1 second
- **Statistics update**: After each ping result
- **UI refresh**: Every second (display latest stats)
- **Method detection**: On target change or after sustained failures

## Error Handling
- **Network unreachable**: Show in status, continue trying
- **DNS resolution failure**: Use cached IPs if available
- **Permission denied**: ICMP may need privileges, fallback to TCP
- **Timeout**: Count as packet loss, continue monitoring
- **Method fallback**: Automatically switch and indicate in UI

## UI Layout Suggestions

### Single Protocol View
```
┌─ Ping ───────────────────────────────────────┐
│ 📍 192.168.1.1 (ICMP)                       │
│                                             │
│ 🟢 Live: 9.0ms     📊 Avg: 10.5ms          │
│ 📈 Range: 8.2-15.1ms  📉 Loss: 0.0%        │
│ 🎯 Jitter: 1.2ms   ✅ 60/60 success       │
│                                             │
│ Status: Online                              │
└─────────────────────────────────────────────┘
```

### Dual Stack View
```
┌─ Ping ───────────────────────────────────────┐
│ IPv4: 192.168.1.1 (ICMP)                    │
│ 🟢 Live: 9.0ms  📊 Avg: 10.5ms  📉 Loss: 0%│
│                                             │
│ IPv6: 2001:db8::1 (TCP:80)                 │
│ 🟡 Live: 45ms   📊 Avg: 42.1ms  📉 Loss: 5%│
│                                             │
│ Overall: Online (IPv4 preferred)            │
└─────────────────────────────────────────────┘
```

### Method Fallback Indicator
```
┌─ Ping ───────────────────────────────────────┐
│ 📍 192.168.1.1 (TCP:80 - ICMP blocked)      │
│                                             │
│ 🟡 Live: 25ms      📊 Avg: 28.3ms          │
│ 📈 Range: 22-35ms  📉 Loss: 2.1%           │
│ ⚠️  Using TCP ping (port 80)               │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with IPv4-only, IPv6-only, and dual-stack targets
- Test ICMP blocking scenarios (corporate firewalls)
- Test high-latency connections (satellite, international)
- Test unstable connections with packet loss
- Test rapid network changes (WiFi handoff, mobile roaming)
- Test privilege requirements for ICMP on different systems
- Test rolling window accuracy over time
- Test statistics calculation with various loss patterns

## Future Enhancements
- **Sparkline visualization**: Small ASCII graph of recent pings
- **Latency histogram**: Distribution of ping times
- **Network path changes**: Detect routing changes
- **Quality scoring**: Overall connection quality metric
- **Alerts**: Configurable thresholds for loss/latency 