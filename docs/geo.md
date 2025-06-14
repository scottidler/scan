# Geo Pane

## Overview
The geo pane provides geolocation and infrastructure information for all resolved IP addresses (IPv4 and IPv6) associated with the target domain. It summarizes country, city, ISP, ASN, hosting/CDN provider, and reverse DNS for each IP, with support for multiple IPs and summary statistics.

## Display Elements

### Static (F5 to refresh)
- **IP Address**: All resolved IPv4 and IPv6 addresses
- **Country**: Geolocated country for each IP
- **Region/City**: If available from geo lookup
- **ISP/Organization**: Who owns the IP (from WHOIS/GeoIP)
- **ASN**: Autonomous System Number
- **Hosting Provider**: If detected (e.g., AWS, GCP, DigitalOcean)
- **CDN Detection**: Cloudflare, Akamai, Fastly, etc. (badge/icon)
- **Reverse DNS**: PTR record for each IP
- **BGP Prefix**: If available
- **RIR**: Regional Internet Registry (ARIN, RIPE, APNIC, etc.)
- **Map Link**: Optional, e.g., "View on map" (external browser)

### Summary View
- **IP count**: e.g., "4 IPs in 2 countries, 3 ISPs"
- **CDN/Hosting badges**: e.g., "Cloudflare", "AWS"

### Zoomed/Expanded View
- **Full details for each IP**: All fields above, one per line
- **All IPs listed**: With ability to scroll if many

## Data Collection Methods

### GeoIP Lookup
- Use public GeoIP APIs (ipinfo.io, ip-api.com, etc.) or local GeoIP database
- Example API: `curl https://ipinfo.io/8.8.8.8/json`

### ASN/ISP/Org
- Parse from GeoIP or WHOIS data
- Example: `whois 8.8.8.8`

### Reverse DNS
- PTR lookup: `dig -x 8.8.8.8 +short`

### CDN/Hosting Detection
- Match known IP ranges or use GeoIP/WHOIS org fields
- Heuristics for common CDNs/providers

### BGP Prefix/RIR
- Use Team Cymru IP to ASN service or similar
- Example: `whois -h whois.cymru.com "-v 8.8.8.8"`

## Implementation Notes

### Data Structures
```rust
struct GeoData {
    ip_infos: Vec<IpGeoInfo>,
    summary: GeoSummary,
}

struct IpGeoInfo {
    ip: IpAddr,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    asn: Option<String>,
    hosting: Option<String>,
    cdn: Option<String>,
    reverse_dns: Option<String>,
    bgp_prefix: Option<String>,
    rir: Option<String>,
    map_url: Option<String>,
}

struct GeoSummary {
    ip_count: usize,
    country_count: usize,
    isp_count: usize,
    cdn_providers: Vec<String>,
    hosting_providers: Vec<String>,
}
```

### Update Frequencies
- **All data**: On F5 refresh or new target
- **No live updates**: Geo/IP info is static during session

## Error Handling
- **GeoIP lookup failure**: Show "Unknown" for missing fields
- **WHOIS failure**: Show partial info if available
- **PTR failure**: Show "No PTR" or blank

## UI Layout Suggestions

### Summary View
```
┌─ Geo ────────────────────────────────────────┐
│ 4 IPs in 2 countries, 3 ISPs                │
│                                             │
│ 🌎 204.246.191.123  🇺🇸 US  AWS  AS16509    │
│ 🌎 204.246.191.46   🇺🇸 US  Cloudflare AS13335│
│ 🌎 204.246.191.109  🇩🇪 DE  Hetzner  AS24940 │
│ 🌎 2606:4700:4700::1111  🇺🇸 US  Cloudflare  │
│                                             │
│ CDNs: Cloudflare   Hosting: AWS, Hetzner    │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Geo (Expanded) ─────────────────────────────┐
│ IP: 204.246.191.123                         │
│   Country: US  Region: California  City: SF │
│   ISP: Amazon.com  ASN: AS16509             │
│   Hosting: AWS  CDN: None                   │
│   Reverse DNS: ec2-204-246-191-123.compute. │
│   BGP Prefix: 204.246.128.0/17              │
│   RIR: ARIN                                 │
│   Map: https://ipinfo.io/204.246.191.123    │
│                                             │
│ [Repeat for each IP]                        │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with single and multiple IPs (CDN, geo-distributed)
- Test with IPv4 and IPv6
- Test with missing/unknown geo fields
- Test with known CDN/hosting IPs
- Test PTR/BGP/RIR lookups
- Test summary and zoomed views

## Future Enhancements
- **ASN reputation**: Known bad ASNs
- **IP blocklists**: Check against threat feeds
- **Map visualization**: Inline ASCII/world map
- **Traceroute integration**: Show path to each IP 