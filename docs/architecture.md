# Scan TUI - Architecture Document

## Overview

Scan is a Rust CLI/TUI application that provides a `btop`-like display for comprehensive network scanning and monitoring of URLs, domains, and IP addresses. The application performs continuous monitoring of various network aspects including ping, DNS, HTTP, TLS, security headers, and more.

## Design Philosophy

### Core Principles

1. **Decoupled Scanner and UI Logic**: Scanners focus on data collection, TUI focuses on user-meaningful information presentation
2. **User-Centric Information Grouping**: TUI panels are organized around user needs (security, performance, connectivity) rather than technical scanner boundaries  
3. **Concurrent by Design**: All network operations run concurrently with a smooth UI render loop
4. **Extensible Scanner Architecture**: Adding new scanners should be straightforward and require minimal changes to existing code

### Architecture Pattern

```
┌─────────────┐    ┌─────────────────┐    ┌──────────────┐
│   CLI Args  │───▶│  Scanner Tasks  │───▶│ Shared State │
└─────────────┘    └─────────────────┘    └──────┬───────┘
                           │                     │
                           ▼                     ▼
                   ┌──────────────┐    ┌─────────────────┐
                   │ Network APIs │    │  TUI Render     │
                   └──────────────┘    │     Loop        │
                                       └─────────────────┘
```

## Core Architectural Decisions

### 1. State Management

**Decision**: Single shared state with `DashMap` for lock-free concurrent access

**Structure**:
```rust
// src/types.rs
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

pub struct AppState {
    pub target: String,
    pub scanners: DashMap<String, ScanState>,
}

pub struct ScanState {
    pub result: Option<ScanResult>,
    pub error: Option<eyre::Error>,
    pub status: ScanStatus,
    pub last_updated: Instant,
    pub history: VecDeque<TimestampedResult>,
}

#[derive(Debug, Clone)]
pub enum ScanStatus {
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TimestampedResult {
    pub timestamp: Instant,
    pub result: ScanResult,
}
```

**Rationale**: 
- `DashMap` provides lock-free concurrent HashMap access
- Each scanner gets its own `ScanState` with current result, error, and history
- History is stored directly with scanner state for locality
- `Arc<AppState>` allows sharing between scanner tasks and UI thread

### 2. Scanner Architecture

**Decision**: Trait-based scanners with self-scheduling and uniform error handling

**Scanner Trait**:
```rust
// src/scanner.rs
use async_trait::async_trait;
use eyre::Result;
use std::sync::Arc;
use std::time::Duration;

#[async_trait]
pub trait Scanner {
    /// Scanner identifier for state storage
    fn name(&self) -> &'static str;
    
    /// How frequently this scanner should run
    fn interval(&self) -> Duration;
    
    /// Perform the actual scan operation
    async fn scan(&self, target: &str) -> Result<ScanResult, eyre::Error>;
    
    /// Default implementation of the scanner loop
    async fn run(&self, target: String, state: Arc<AppState>) {
        let mut ticker = tokio::time::interval(self.interval());
        
        loop {
            ticker.tick().await;
            
            // Update status to running
            {
                let mut scan_state = ScanState {
                    result: None,
                    error: None,
                    status: ScanStatus::Running,
                    last_updated: Instant::now(),
                    history: VecDeque::new(),
                };
                state.scanners.insert(self.name().to_string(), scan_state);
            }
            
            // Perform scan
            match self.scan(&target).await {
                Ok(result) => {
                    let timestamp = Instant::now();
                    let timestamped = TimestampedResult {
                        timestamp,
                        result: result.clone(),
                    };
                    
                    if let Some(mut scan_state) = state.scanners.get_mut(self.name()) {
                        scan_state.result = Some(result);
                        scan_state.error = None;
                        scan_state.status = ScanStatus::Complete;
                        scan_state.last_updated = timestamp;
                        scan_state.history.push_back(timestamped);
                        
                        // Keep last 100 results
                        if scan_state.history.len() > 100 {
                            scan_state.history.pop_front();
                        }
                    }
                }
                Err(error) => {
                    if let Some(mut scan_state) = state.scanners.get_mut(self.name()) {
                        scan_state.error = Some(error);
                        scan_state.status = ScanStatus::Failed;
                        scan_state.last_updated = Instant::now();
                    }
                }
            }
        }
    }
}
```

**Rationale**:
- Each scanner is responsible for its own timing and lifecycle
- `eyre::Error` provides rich error context without custom error types
- Default `run()` implementation ensures consistent behavior
- History management is handled uniformly across all scanners

### 3. Scanner Result Types

**Decision**: Typed enum for results with scanner-specific data structures

**ScanResult Definition**:
```rust
// src/types.rs
#[derive(Debug, Clone)]
pub enum ScanResult {
    Ping(crate::scan::ping::PingResult),
    Dns(crate::scan::dns::DnsResult),
    Http(crate::scan::http::HttpResult),
    Tls(crate::scan::tls::TlsResult),
    Port(crate::scan::port::PortResult),
    Whois(crate::scan::whois::WhoisResult),
}
```

**Scanner-Specific Result Types**:
```rust
// src/scan/ping.rs
#[derive(Debug, Clone)]
pub struct PingResult {
    pub latency: Duration,
    pub packet_loss: f32,
    pub ttl: Option<u8>,
    pub packets_sent: u32,
    pub packets_received: u32,
}

// src/scan/http.rs
#[derive(Debug, Clone)]
pub struct HttpResult {
    pub status: u16,
    pub response_time: Duration,
    pub headers: std::collections::HashMap<String, String>,
    pub redirect_chain: Vec<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
}
```

**Rationale**:
- Type safety for scanner results
- Each scanner defines its own result structure
- Results are self-contained and cloneable for history storage

### 4. Error Handling Strategy

**Decision**: Use `eyre` for all error handling

**Benefits**:
- Already included as dependency
- Excellent error context chaining
- No need for custom error types
- Works seamlessly with `?` operator
- Built-in `Send + Sync` support

**Example Usage**:
```rust
// src/scan/ping.rs
impl Scanner for PingScanner {
    async fn scan(&self, target: &str) -> Result<ScanResult, eyre::Error> {
        let result = self.do_ping(target).await
            .wrap_err_with(|| format!("Failed to ping {}", target))?;
        Ok(ScanResult::Ping(result))
    }
}

impl PingScanner {
    async fn do_ping(&self, target: &str) -> eyre::Result<PingResult> {
        let output = tokio::process::Command::new("ping")
            .args(["-c", "1", target])
            .output()
            .await
            .wrap_err("Failed to execute ping command")?;
            
        if !output.status.success() {
            eyre::bail!("Ping command failed with status: {}", output.status);
        }
        
        // Parse output and return result
        self.parse_ping_output(&output.stdout)
    }
}
```

### 5. Project Structure

**Decision**: Separation of concerns with dedicated modules

```
src/
├── main.rs              # Application entry point and setup
├── cli.rs               # Command-line argument parsing
├── types.rs             # Shared data structures (AppState, ScanState, etc.)
├── scanner.rs           # Scanner trait definition
├── scan/                # Scanner implementations
│   ├── mod.rs           # Re-exports and scanner registry
│   ├── ping.rs          # Ping scanner implementation
│   ├── dns.rs           # DNS scanner implementation
│   ├── http.rs          # HTTP scanner implementation
│   ├── tls.rs           # TLS scanner implementation
│   ├── port.rs          # Port scanner implementation
│   └── whois.rs         # WHOIS scanner implementation
└── tui/                 # TUI rendering and user interface
    ├── mod.rs           # TUI application structure
    ├── security.rs      # Security-focused information panel
    ├── performance.rs   # Performance metrics panel
    ├── connectivity.rs  # Network connectivity panel
    └── infrastructure.rs # Infrastructure details panel
```

**Rationale**:
- Clear separation between data collection (`scan/`) and presentation (`tui/`)
- Each scanner is self-contained in its own file
- TUI modules are organized by user information needs, not technical boundaries

### 6. TUI Architecture Philosophy

**Decision**: Information-centric panels that consume multiple scanner results

**Example: Security Panel**:
```rust
// src/tui/security.rs
impl SecurityPanel {
    pub fn render(&self, state: &AppState) -> Result<Widget> {
        let http_data = state.scanners.get("http");
        let tls_data = state.scanners.get("tls");
        let dns_data = state.scanners.get("dns");
        
        match (http_data, tls_data, dns_data) {
            (Some(http), Some(tls), Some(dns)) => {
                self.render_full_security_assessment(http, tls, dns)
            }
            (Some(http), None, _) => {
                self.render_partial_security("TLS scan pending...", http)
            }
            (None, _, _) => {
                self.render_prerequisite_missing("HTTP scan required for security assessment")
            }
        }
    }
    
    fn render_full_security_assessment(
        &self, 
        http: &ScanState, 
        tls: &ScanState, 
        dns: &ScanState
    ) -> Widget {
        // Extract security-relevant data from multiple scanners:
        // - HTTP: CSP headers, X-Frame-Options, HSTS
        // - TLS: Certificate validity, cipher strength
        // - DNS: DNSSEC status
        todo!("Render comprehensive security view")
    }
}
```

**Rationale**:
- TUI panels present information as users think about it
- Panels can gracefully handle missing dependencies
- Same scanner data can be used by multiple panels
- Clean separation between data collection and presentation logic

## Example Scanner Implementation

**Complete Ping Scanner**:
```rust
// src/scan/ping.rs
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
        // Simplified parsing - real implementation would be more robust
        for line in output.lines() {
            if line.contains("time=") {
                // Parse latency from line like: "64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms"
                if let Some(time_part) = line.split("time=").nth(1) {
                    if let Some(time_str) = time_part.split_whitespace().next() {
                        let latency_ms: f64 = time_str.parse()
                            .wrap_err("Failed to parse latency")?;
                        
                        return Ok(PingResult {
                            latency: Duration::from_millis(latency_ms as u64),
                            packet_loss: 0.0, // Would calculate from summary
                            ttl: None,         // Would parse from output
                            packets_sent: self.packet_count as u32,
                            packets_received: 1, // Simplified
                        });
                    }
                }
            }
        }
        
        eyre::bail!("Could not find timing information in ping output");
    }
}
```

## Scanner Registry

**Scanner Collection and Initialization**:
```rust
// src/scan/mod.rs
pub mod ping;
pub mod dns;
pub mod http;

pub use ping::{PingScanner, PingResult};
pub use dns::{DnsScanner, DnsResult};
pub use http::{HttpScanner, HttpResult};

use crate::scanner::Scanner;
use std::sync::Arc;

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    vec![
        Box::new(PingScanner::default()),
        Box::new(DnsScanner::default()),
        Box::new(HttpScanner::default()),
    ]
}

pub async fn spawn_scanner_tasks(
    scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    target: String,
    state: Arc<crate::types::AppState>,
) {
    for scanner in scanners {
        let target_clone = target.clone();
        let state_clone = state.clone();
        
        tokio::spawn(async move {
            scanner.run(target_clone, state_clone).await;
        });
    }
}
```

## Application Entry Point

**Main Application Structure**:
```rust
// src/main.rs
use std::sync::Arc;
use eyre::Result;

mod cli;
mod types;
mod scanner;
mod scan;
mod tui;

use cli::Cli;
use types::AppState;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = cli::parse();
    
    if cli.verbose {
        env_logger::init();
    }

    // Initialize shared application state
    let state = Arc::new(AppState::new(cli.target.clone()));
    
    // Create and spawn scanner tasks
    let scanners = scan::create_default_scanners();
    scan::spawn_scanner_tasks(scanners, cli.target.clone(), state.clone()).await;
    
    // Run the TUI application
    let mut app = tui::App::new(state, Duration::from_millis(cli.refresh_rate));
    app.run().await?;
    
    Ok(())
}
```

## Implementation Priority

### Phase 1: Core Infrastructure
1. Implement basic types and scanner trait
2. Create ping scanner as proof of concept
3. Basic TUI with single scanner display

### Phase 2: Essential Scanners
1. DNS scanner (A, AAAA, MX records)
2. HTTP scanner (status, headers, timing)
3. Multi-scanner TUI dashboard

### Phase 3: Advanced Features
1. TLS scanner (certificates, cipher info)
2. Port scanner (service detection)
3. Information-focused TUI panels

### Phase 4: Polish
1. WHOIS scanner
2. Advanced TUI features (zoom, history graphs)
3. Configuration file support

## Future Architectural Considerations

- **Configuration Management**: TOML-based configuration for scanner intervals and behavior
- **Plugin System**: Runtime loading of scanners for extensibility
- **Data Persistence**: Optional storage of scan history across application runs
- **Distributed Scanning**: Architecture considerations for scanning from multiple viewpoints 