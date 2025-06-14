# DNS Pane

## Overview
The DNS pane displays all DNS record types for the target domain, including resolution times, DNSSEC status, and modern DNS protocol support. Features live TTL countdown and expandable views for domains with many records.

## Display Elements

### Live Updates (Continuous Refresh)
- **TTL Countdown**: Real-time countdown for each record type, ticking down by second
  - Approximates cache expiry time (doesn't need to match server exactly)
  - Resets on F5 refresh

### Static Elements (Fire-once, F5 to refresh)
- **A Records**: IPv4 addresses with summary view if many
- **AAAA Records**: IPv6 addresses with summary view if many  
- **MX Records**: Mail exchange servers with priority
- **NS Records**: Authoritative nameservers
- **CNAME Records**: Canonical name aliases (if applicable)
- **TXT Records**: All text records including SPF, DKIM, DMARC
- **DNS Resolution Time**: Query response time in milliseconds
- **DNSSEC Status**: Validation success/failure
- **DNS over HTTPS/TLS Support**: DoH/DoT capability detection

## Record Display Strategy

### Summary View (Default)
- **Few records (≤3)**: Show all records fully
- **Many records (>3)**: Show summary with expandable option
  - Format: "A Records: 4 (192.168.1.1, 192.168.1.2, ...)"
  - Click/key to expand to full view

### Expandable/Zoom View
- **Pane zoom functionality**: Make selected pane full-screen
- **Show all records**: Complete list when zoomed
- **Return to summary**: ESC or similar to return to normal view

## TXT Record Handling

### Special TXT Records (Highlighted)
- **SPF**: Email sender policy (v=spf1...)
- **DKIM**: DomainKeys signature records (_domainkey)
- **DMARC**: Domain-based Message Authentication (_dmarc)
- **Others**: General TXT records (verification, configuration)

### Display Format
- Show record type prefix for important ones
- Truncate long records with expandable view
- Color-code by function (security vs general)

## Data Collection Methods

### Primary DNS Queries
```bash
dig <domain> A
dig <domain> AAAA  
dig <domain> MX
dig <domain> NS
dig <domain> TXT
dig <domain> CNAME
```

### DNSSEC Validation
```bash
dig <domain> +dnssec +short
```

### DNS over HTTPS/TLS Detection
- Check for DoH endpoint availability
- Test DoT support on port 853

## Implementation Notes

### Data Structures
```rust
struct DnsData {
    a_records: Vec<DnsRecord<Ipv4Addr>>,
    aaaa_records: Vec<DnsRecord<Ipv6Addr>>,
    mx_records: Vec<MxRecord>,
    ns_records: Vec<String>,
    cname_records: Vec<String>,
    txt_records: Vec<TxtRecord>,
    resolution_time: Duration,
    dnssec_valid: Option<bool>,
    doh_support: Option<bool>,
    dot_support: Option<bool>,
}

struct DnsRecord<T> {
    value: T,
    ttl: u32,
    last_updated: DateTime<Utc>,
}

struct MxRecord {
    priority: u16,
    exchange: String,
    ttl: u32,
    last_updated: DateTime<Utc>,
}

struct TxtRecord {
    value: String,
    record_type: TxtRecordType,
    ttl: u32,
    last_updated: DateTime<Utc>,
}

enum TxtRecordType {
    Spf,
    Dkim,
    Dmarc,
    General,
}
```

### TTL Countdown Logic
```rust
fn calculate_remaining_ttl(record: &DnsRecord) -> u32 {
    let elapsed = Utc::now().timestamp() - record.last_updated.timestamp();
    record.ttl.saturating_sub(elapsed as u32)
}
```

### Update Frequencies
- **TTL countdown**: Every second
- **All DNS records**: On F5 refresh or new target
- **DoH/DoT detection**: On F5 refresh (cached for session)

## Error Handling
- **NXDOMAIN**: Domain doesn't exist
- **SERVFAIL**: DNS server error
- **Timeout**: Network/DNS server unreachable
- **No records**: Record type doesn't exist for domain

## UI Layout Suggestions

### Normal View
```
┌─ DNS ────────────────────────────────────────┐
│ A Records: 4 (285s) 192.168.1.1, ...       │
│ AAAA Records: 2 (285s) 2001:db8::1, ...    │
│ MX Records: 3 (3585s)                       │
│   10 mail.example.com                       │
│   20 mail2.example.com                      │
│                                             │
│ TXT Records: 5 (1785s)                      │
│ 📧 SPF: v=spf1 include:_spf.google.com ~all│
│ 🔑 DMARC: v=DMARC1; p=quarantine;          │
│ 📝 Other: verification tokens...            │
│                                             │
│ 🕐 Resolution: 45ms  🛡️  DNSSEC: ✓         │
│ 🔒 DoH: ✓  DoT: ✓                          │
└─────────────────────────────────────────────┘
```

### Zoomed View (Full Screen)
```
┌─ DNS (Expanded) ─────────────────────────────┐
│ A Records (284s TTL):                        │
│   192.168.1.1                               │
│   192.168.1.2                               │
│   192.168.1.3                               │
│   192.168.1.4                               │
│                                             │
│ AAAA Records (284s TTL):                     │
│   2001:db8::1                               │
│   2001:db8::2                               │
│                                             │
│ [... full record listings ...]             │
│                                             │
│ Press ESC to return to summary view         │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with domains having many A records (CDNs)
- Test with IPv6-only domains
- Test with domains lacking specific record types
- Test TTL countdown accuracy over time
- Test DNSSEC validation with signed/unsigned domains
- Test DoH/DoT detection with various providers
- Test TXT record parsing for SPF/DKIM/DMARC detection
- Test expand/zoom functionality with large record sets 