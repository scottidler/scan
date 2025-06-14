# Target Pane

## Overview
The target pane displays the input domain/URL being analyzed, basic status information, current time, and an overall health score based on data from other panes.

## Display Elements

### Live Updates (Continuous Refresh)
- **Current Time**: Real-time clock display (HH:MM:SS format)
- **Elapsed Time**: Duration since scan started (e.g., "2m 34s", "1h 15m 22s")

### Static Elements (Fire-once, F5 to refresh)
- **Target Domain**: User input after normalization
- **Resolved IP(s)**: Primary IPv4/IPv6 addresses from DNS resolution
- **Scan Start Time**: Timestamp when analysis began
- **Overall Status**: Running/Complete/Error indicator
- **Health Score**: Calculated percentage with color coding

## Input Validation & Normalization

### Rules
- Strip protocols (`http://`, `https://`)
- Remove trailing slashes
- Handle subdomains (keep as-is, don't strip www)
- Validate domain format (basic regex check)
- Convert to lowercase for consistency

### Examples
- Input: `https://example.com/` → Normalized: `example.com`
- Input: `HTTP://WWW.EXAMPLE.COM` → Normalized: `www.example.com`

## Health Score Calculation

### Score Components (0-100%)
- **Connectivity (25%)**: Ping success, HTTP reachability
- **Security (35%)**: HSTS, valid TLS cert, CSP headers, cert expiry
- **Performance (20%)**: HTTP response times, DNS resolution speed
- **DNS (20%)**: Resolution success, proper A/AAAA records

### Color Coding
- 🟢 **90-100%**: All systems healthy (green)
- 🟡 **70-89%**: Minor issues (yellow) 
- 🟠 **40-69%**: Significant issues (orange)
- 🔴 **0-39%**: Critical issues (red)

### Specific Scoring Rules
- **Connectivity**: Ping success (+12.5%), HTTP 200 response (+12.5%)
- **Security**: Valid cert (+10%), HSTS present (+8%), CSP present (+7%), cert expires >30 days (+10%)
- **Performance**: Response time <500ms (+10%), <1000ms (+5%), DNS resolution <100ms (+10%)
- **DNS**: A record present (+10%), AAAA record present (+5%), MX record present (+5%)

## Data Dependencies

### Required from other panes:
- **DNS pane**: IP resolution, A/AAAA records, resolution time
- **Ping pane**: Connectivity status, latency
- **HTTP pane**: Response codes, response times
- **TLS pane**: Certificate validity, expiration date
- **Security pane**: HSTS, CSP header status

## Implementation Notes

### Data Structures
```rust
struct TargetData {
    original_input: String,
    normalized_domain: String,
    resolved_ips: Vec<IpAddr>,
    scan_start: DateTime<Utc>,
    current_status: ScanStatus,
    health_score: Option<f32>,
}

enum ScanStatus {
    Starting,
    Running,
    Complete,
    Error(String),
}
```

### Update Frequencies
- **Current time**: Every second
- **Elapsed time**: Every second
- **Health score**: When any dependent pane updates
- **Static elements**: On F5 refresh or new target input

### Error Handling
- Invalid domain format: Show error in status
- DNS resolution failure: Show "Unknown" for IPs, mark in health score
- Network unreachable: Reflect in health score, show warning

## UI Layout Suggestions
```
┌─ Target ─────────────────────────────────────┐
│ 🎯 example.com                              │
│ 📍 192.168.1.1, 2001:db8::1                │
│                                             │
│ 🕐 10:04:04        ⚡ Started: 09:58:12     │
│ ⏱️  5m 52s         📊 Health: 85% 🟡        │
│                                             │
│ Status: Complete                            │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with various domain formats (with/without protocols, trailing slashes)
- Test with IPv6-only domains
- Test with unresolvable domains
- Test health score calculation with different combinations of pane data
- Test long domain names (truncation handling) 