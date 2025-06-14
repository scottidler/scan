# HTTP Pane

## Overview
The HTTP pane provides real-time HTTP/HTTPS monitoring and protocol analysis, including response time tracking, status code monitoring, server detection, and redirect chain analysis. Supports both HTTP and HTTPS with automatic redirect following.

## Display Elements

### Live Updates (Continuous Refresh - Every 5 Seconds)
- **Current Response Time**: Latest HTTP request time in milliseconds
- **Average Response Time**: Rolling average over last 60 requests (5 minutes)
- **Status Code**: Current HTTP status (200, 404, 500, etc.)
- **Availability**: Online/Offline status based on successful responses
- **Min/Max Response Times**: Session minimums and maximums

### Static Elements (Fire-once, F5 to refresh)
- **Final URL**: After following redirects (if different from input)
- **Redirect Chain**: Full chain if redirects occurred
- **Server Software**: Web server identification (nginx, Apache, etc.)
- **HTTP Versions Supported**: 1.1, 2, 3 detection
- **Response Headers**: Non-security headers (Content-Type, Cache-Control, etc.)
- **Response Size**: Content-Length and transfer size
- **Protocol**: HTTP vs HTTPS final destination

## Request Strategy

### Protocol Testing
- **Both HTTP and HTTPS**: Test both protocols if domain supports both
- **Redirect following**: Follow up to 10 redirects maximum
- **Protocol preference**: Show final protocol after redirects
- **Port detection**: Standard ports (80, 443) and custom ports

### Request Configuration
- **Method**: HEAD requests for monitoring (less bandwidth)
- **User Agent**: Identify as this domain analysis tool
- **Timeout**: 30 second timeout for requests
- **Follow redirects**: Up to 10 hops maximum
- **Connection reuse**: HTTP/2 and HTTP/3 connection reuse

### Response Time Monitoring
- **Frequency**: Every 5 seconds
- **Rolling window**: Last 60 samples (5 minutes of data)
- **Statistics**: Same as ping (current, average, min/max)
- **Availability calculation**: Success rate over rolling window

## Data Collection

### Initial Analysis (F5 refresh)
```bash
# Equivalent curl commands for reference
curl -I -L --max-redirs 10 http://example.com
curl -I -L --max-redirs 10 https://example.com
curl -I --http2 https://example.com
curl -I --http3 https://example.com
```

### Live Monitoring
- **HEAD requests**: Minimal bandwidth usage
- **Status tracking**: Track status code changes
- **Response time**: Full request/response cycle timing
- **Error tracking**: Network errors, timeouts, invalid responses

## Implementation Notes

### Data Structures
```rust
struct HttpData {
    http_stats: Option<HttpStats>,
    https_stats: Option<HttpStats>,
    redirect_chain: Vec<RedirectHop>,
    final_url: Url,
    server_info: ServerInfo,
    supported_versions: Vec<HttpVersion>,
    headers: HashMap<String, String>,
}

struct HttpStats {
    current_response_time: Option<Duration>,
    rolling_window: VecDeque<HttpResult>,
    average_response_time: Option<Duration>,
    min_max_response_time: Option<(Duration, Duration)>,
    current_status: Option<u16>,
    availability: f32,
    last_updated: DateTime<Utc>,
}

struct HttpResult {
    timestamp: DateTime<Utc>,
    response_time: Option<Duration>,
    status_code: Option<u16>,
    success: bool,
    error: Option<String>,
}

struct RedirectHop {
    from_url: Url,
    to_url: Url,
    status_code: u16,
    response_time: Duration,
}

struct ServerInfo {
    server_header: Option<String>,
    detected_server: Option<ServerType>,
    powered_by: Option<String>,
}

enum ServerType {
    Nginx,
    Apache,
    IIS,
    Cloudflare,
    Other(String),
}

enum HttpVersion {
    Http11,
    Http2,
    Http3,
}
```

### HTTP Version Detection
```rust
async fn detect_http_versions(url: &Url) -> Vec<HttpVersion> {
    let mut versions = Vec::new();
    
    // Test HTTP/1.1 (always supported)
    if test_http11(url).await {
        versions.push(HttpVersion::Http11);
    }
    
    // Test HTTP/2
    if test_http2(url).await {
        versions.push(HttpVersion::Http2);
    }
    
    // Test HTTP/3
    if test_http3(url).await {
        versions.push(HttpVersion::Http3);
    }
    
    versions
}
```

### Redirect Chain Analysis
```rust
async fn follow_redirects(initial_url: Url, max_redirects: usize) -> Vec<RedirectHop> {
    let mut chain = Vec::new();
    let mut current_url = initial_url;
    
    for _ in 0..max_redirects {
        let response = make_head_request(&current_url).await;
        
        if let Some(location) = response.headers.get("location") {
            let next_url = current_url.join(location)?;
            chain.push(RedirectHop {
                from_url: current_url.clone(),
                to_url: next_url.clone(),
                status_code: response.status,
                response_time: response.response_time,
            });
            current_url = next_url;
        } else {
            break;
        }
    }
    
    chain
}
```

### User Agent Configuration
```rust
const USER_AGENT: &str = "domain-scanner/1.0 (Rust TUI Domain Analysis Tool)";
```

### Update Frequencies
- **HEAD requests**: Every 5 seconds
- **Statistics update**: After each response
- **UI refresh**: Every 5 seconds (display latest stats)
- **Full analysis**: On F5 refresh or new target

## Error Handling
- **Connection refused**: Port closed or service down
- **DNS resolution failure**: Domain not resolving
- **Timeout**: Request took longer than 30 seconds
- **Too many redirects**: Exceeded 10 redirect limit
- **Invalid response**: Malformed HTTP response
- **TLS/SSL errors**: Certificate issues (logged, but handled in TLS pane)

## UI Layout Suggestions

### Single Protocol View
```
┌─ HTTP ───────────────────────────────────────┐
│ 🌐 https://example.com (HTTP/2)             │
│ 🔗 → https://www.example.com (1 redirect)   │
│                                             │
│ 🟢 Status: 200 OK    ⚡ Live: 245ms         │
│ 📊 Avg: 267ms       📈 Range: 201-423ms    │
│ 📡 Uptime: 98.3%    🖥️  nginx/1.18.0       │
│                                             │
│ 📄 Content-Type: text/html; charset=utf-8   │
│ 🗜️  Content-Encoding: gzip                 │
└─────────────────────────────────────────────┘
```

### Dual Protocol View
```
┌─ HTTP ───────────────────────────────────────┐
│ HTTP: 🔴 301 → HTTPS (12ms)                 │
│ HTTPS: 🟢 200 OK (HTTP/2, 245ms)           │
│                                             │
│ 📊 Response: Avg 267ms, Range 201-423ms    │
│ 📡 Uptime: 98.3%    🖥️  nginx/1.18.0       │
│                                             │
│ Versions: HTTP/1.1 ✓ HTTP/2 ✓ HTTP/3 ✗    │
└─────────────────────────────────────────────┘
```

### Redirect Chain View
```
┌─ HTTP ───────────────────────────────────────┐
│ Redirect Chain (3 hops):                    │
│ 1. http://example.com                       │
│    → 301 https://example.com (15ms)         │
│ 2. https://example.com                      │
│    → 301 https://www.example.com (12ms)     │
│ 3. https://www.example.com                  │
│    → 200 OK (245ms) ✓ Final                │
│                                             │
│ Total: 272ms, 🖥️ nginx/1.18.0              │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with HTTP-only sites (legacy systems)
- Test with HTTPS-only sites (modern security)
- Test with complex redirect chains (multiple hops)
- Test with redirect loops (should hit 10-hop limit)
- Test with slow-responding servers (timeout handling)
- Test with various HTTP status codes (4xx, 5xx errors)
- Test with different server types (nginx, Apache, IIS, CDNs)
- Test HTTP version detection accuracy
- Test response time accuracy under load
- Test with custom ports (non-standard 80/443)

## Future Enhancements
- **Response body analysis**: Basic content detection
- **Performance waterfall**: Breakdown of request phases
- **HTTP/3 QUIC support**: Advanced protocol testing
- **Custom headers**: User-configurable request headers
- **Response caching**: Cache-Control header analysis 