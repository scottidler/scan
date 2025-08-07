# Logging Schema for Scan Codebase

## Log Levels

### INFO
- **Purpose**: Startup/shutdown events, first TUI render timing
- **Usage**: Minimal logging - only major application lifecycle events
- **Examples**:
  - Application startup
  - First TUI render completion with timing
  - Application shutdown

### WARN
- **Purpose**: Issues that don't stop execution but should be noted
- **Usage**:
  - Timeouts with retries
  - Partial failures
  - Configuration issues
  - Resource constraints
- **Examples**:
  - DNS query timeout, retrying with different server
  - Some TLS vulnerabilities couldn't be checked
  - No DNS servers configured, falling back to default
  - Too many concurrent connections, throttling

### ERROR
- **Purpose**: Connection failures and caught exceptions we handle
- **Usage**: When we catch errors and either handle them or ignore them
- **Context**: Always include detailed context with target, operation, timing
- **Examples**:
  - TLS handshake failures
  - HTTP request failures
  - DNS resolution failures

### DEBUG
- **Purpose**: Function entry and user interactions
- **Usage**:
  - Function entry with parameters
  - User keypress interactions
  - Pane switching and scrolling
  - Function return values (logged at callsite)
- **Format**: `DEBUG [module::submodule] function_name: param1=value param2=value`

### TRACE
- **Purpose**: Detailed operational logging
- **Usage**:
  - Network operations (HTTP requests, DNS queries, TLS handshakes)
  - Data parsing (certificates, HTTP headers, DNS records)
  - Pane rendering
  - Data updates when scan results arrive
  - Performance timing for all operations
  - Scan results with pretty-printed structs

## Log Format Standards

### Function Entry
```
DEBUG [module::submodule] function_name: param1=value param2=value
```

### Function Results (at callsite)
```
DEBUG [module::submodule] variable_name: value
```

### Errors
```
ERROR [module::submodule] Detailed error with context - operation, target, timing, attempt numbers
```

### Module Prefix Format
- Always use `[scan::module]` or `[tui::module]` format
- Examples:
  - `[scan::tls]`
  - `[scan::http]`
  - `[tui::security]`
  - `[tui::layout]`

## Content Guidelines

### Sensitive Data Handling
- **Redact**: Certificate private keys, authentication tokens, personal information
- **Include**: Public certificate details, HTTP headers (filtered), DNS records

### Context Requirements
- **Errors**: Include target, operation type, timing, attempt numbers, scanner IDs
- **Network Operations**: Include timing information (e.g., "TLS handshake completed in 245ms")
- **User Actions**: Include pane context, scroll positions, key pressed

### Data Formatting
- **Structs**: Use pretty-printing for TRACE level scan results
- **Timing**: Always include duration for network operations
- **Values**: Log actual values, not just "success/failure"

## Module-Specific Applications

### Scanner Modules (scan/*)
- **Function Entry**: DEBUG level with all parameters
- **Network Operations**: TRACE level with timing
- **Data Parsing**: TRACE level with parsed results
- **Connection Failures**: WARN/ERROR level with full context
- **Scan Results**: TRACE level with pretty-printed structs

### TUI Modules (tui/*)
- **User Input**: DEBUG level (keypress, pane switching, scrolling)
- **Pane Rendering**: TRACE level
- **Data Updates**: TRACE level when scan results arrive and trigger updates
- **Function Entry**: DEBUG level with parameters

### Main/Startup (main.rs, lib.rs)
- **Application Lifecycle**: INFO level
- **First Render Timing**: INFO level with duration
- **Initialization**: DEBUG level for major components

### Target Resolution (target.rs)
- **DNS Resolution**: TRACE level with timing
- **IP Address Discovery**: DEBUG level with results
- **Resolution Failures**: WARN/ERROR level with context

## Implementation Notes

### Thread Safety
- No thread/task identifiers required at this time
- Standard logging without concurrent context

### Performance Considerations
- TRACE level may be verbose - ensure it can be disabled in production
- Include timing information for performance analysis
- Log at appropriate granularity to avoid log spam

### Error Handling
- Always log errors we catch and handle
- Include enough context for debugging
- Don't log errors that bubble up (avoid duplicate logging)

## Examples

### Function Entry
```rust
log::debug!("[scan::tls] connect_and_analyze: target={} port={}", target, port);
```

### Function Result
```rust
let result = some_function();
log::debug!("[scan::tls] handshake_result: {:?}", result);
```

### Network Operation
```rust
log::trace!("[scan::tls] TLS handshake to {}:{} completed in {}ms", host, port, duration.as_millis());
```

### Error with Context
```rust
log::error!("[scan::tls] Failed TLS handshake to {}:{} - timeout after {}s, attempt {}/{}",
    host, port, timeout_secs, attempt, max_attempts);
```

### User Interaction
```rust
log::debug!("[tui::security] scroll_down: offset={} max_scroll={}", offset, max_scroll);
```

### Scan Result
```rust
log::trace!("[scan::tls] TLS scan completed: {:#?}", tls_result);
```