# Ports Pane

## Overview
The ports pane provides asynchronous port scanning and basic service detection for all resolved IP addresses (IPv4 and IPv6) associated with the target domain. Both TCP and UDP scans are supported, with results displayed as they become available. The user can specify which ports to scan via the TUI or command line.

## Display Elements

### Static (User-triggered, not live by default)
- **Scanned IP(s)**: All resolved from DNS/Geo pane
- **Port scan results**: For each IP, show status for each port (open/closed/filtered)
- **Service detection**: Basic banner grab (e.g., SSH, HTTP, HTTPS, etc.)
- **Protocol**: TCP and UDP (as specified)
- **Scan duration**: Time taken for each scan
- **Scan method**: SYN scan, connect scan, UDP probe, etc.

### Summary View
- **Open ports/services**: e.g., "22/SSH, 80/HTTP, 443/HTTPS"
- **In-progress indicator**: Show which IPs/ports are still being scanned (spinner, progress bar, etc.)
- **Scan status**: "In progress", "Complete", "Error"

### Zoomed/Expanded View
- **Full port list**: All scanned ports, including closed/filtered
- **Service banners**: For open ports, show detected service/banner
- **Scan details**: Per-IP, per-port protocol, scan method, duration
- **User controls**: Option to rescan, add/remove ports, or change scan type

## Port Selection
- **Default ports**: 22, 80, 443, 8080, 8843
- **User-configurable**: Allow user to specify additional ports via TUI or CLI
- **All resolved IPs**: Scan all, with summary if many

## Data Collection Methods

### TCP Scan
- Async connect or SYN scan (depending on privileges)
- Banner grab for common services (e.g., SSH, HTTP)

### UDP Scan
- Async UDP probe (slower, less reliable)
- Only for specified ports

### Example Tools/Commands
```bash
# TCP scan
nc -zv <ip> 22 80 443 8080 8843
# UDP scan (example)
nmap -sU -p 8843 <ip>
```

## Implementation Notes

### Data Structures
```rust
struct PortsData {
    ip_scans: Vec<IpPortScan>,
    scan_status: ScanStatus,
    scan_duration: Option<Duration>,
}

struct IpPortScan {
    ip: IpAddr,
    port_results: Vec<PortResult>,
    in_progress: bool,
}

struct PortResult {
    port: u16,
    protocol: Protocol,
    status: PortStatus,
    service: Option<String>,
    banner: Option<String>,
    scan_method: ScanMethod,
    duration: Option<Duration>,
}

enum Protocol {
    Tcp,
    Udp,
}

enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
    InProgress,
}

enum ScanMethod {
    Syn,
    Connect,
    UdpProbe,
}

enum ScanStatus {
    NotStarted,
    InProgress,
    Complete,
    Error(String),
}
```

### Async Scanning
- Launch scans for all IPs/ports in parallel
- Update UI as results arrive (per-port, per-IP)
- Show in-progress indicator for pending scans
- Allow user to rescan or add/remove ports during session

### Update Frequencies
- **Results**: As soon as available (async)
- **UI refresh**: On each result or user action

## Error Handling
- **Timeouts**: Mark as filtered/unknown
- **Permission denied**: Indicate in UI
- **Network unreachable**: Show error for affected IPs

## UI Layout Suggestions

### Summary View
```
┌─ Ports ──────────────────────────────────────┐
│ 204.246.191.123: 22/SSH ✓ 80/HTTP ✓ 443 ✓   │
│ 204.246.191.46:  22 ✗ 80 ✓ 443 ✓ 8080 ✓     │
│ 204.246.191.109: 22 ✓ 443 ✓ 8843 ✓          │
│ [In progress: 204.246.191.46: 8843 ...]     │
│                                             │
│ Status: In progress (3/4 IPs complete)      │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Ports (Expanded) ───────────────────────────┐
│ IP: 204.246.191.123                         │
│   22/tcp: Open (SSH)   Banner: OpenSSH_8.2  │
│   80/tcp: Open (HTTP)  Banner: nginx/1.18.0 │
│   443/tcp: Open (HTTPS) Banner:              │
│   8080/tcp: Closed                          │
│   8843/udp: Open (service: unknown)         │
│   ...                                       │
│ [User controls: add/remove ports, rescan]   │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with single and multiple IPs
- Test with open, closed, and filtered ports
- Test with TCP and UDP
- Test async/in-progress UI
- Test user port configuration (TUI/CLI)
- Test error handling (timeouts, permission denied)

## Future Enhancements
- **Full port range scan**: Option for advanced users
- **Service fingerprinting**: Deeper banner analysis
- **Vulnerability checks**: Known exploits for open services
- **Rate limiting**: Avoid overwhelming remote hosts 