# Status Pane

## Overview
The status pane acts as the dashboard's message center, showing overall scan status, recent errors/warnings, and progress. The summary view displays the most recent status and errors, while the zoomed view provides the full log and advanced controls.

## Display Elements

### Live Updates (Continuous)
- **Current Scan Status**: Running, Complete, Error, etc.
- **Pane-by-Pane Status**: e.g., DNS: OK, HTTP: Error, TLS: OK
- **Recent Errors/Warnings**: Most recent N (e.g., last 3)
- **Progress Indicators**: e.g., "5/8 panes complete"
- **Last Refresh Time**: Timestamp of last F5 or auto-refresh

### Static (F5 to refresh)
- **Full Log/History**: Scrollable in expanded view
- **Command Output**: If user triggers a manual scan/action
- **Error Details**: Stack traces, debug info (expanded view)

### User Controls
- **Clear Log**: Option to clear all logs/errors
- **Filter Log**: By pane (DNS, HTTP, etc.) or type (error, warning, info)

## Display Strategy

#### Summary View (Dashboard)
- **Current status**: e.g., "Running", "Complete", "Error: TLS handshake failed"
- **Most recent errors/warnings**: Last N (e.g., 3)
- **Progress**: e.g., "5/8 panes complete"
- **Last refresh**: e.g., "Refreshed: 10:04:04"

#### Zoomed/Expanded View
- **Full log/history**: All messages, scrollable
- **All errors/warnings**: With timestamps and details
- **Command output**: For manual actions
- **Error details**: Stack traces, debug info
- **Controls**: Clear log, filter by pane/type

## Implementation Notes

### Data Structures
```rust
struct StatusData {
    scan_status: ScanStatus,
    pane_statuses: Vec<PaneStatus>,
    recent_logs: Vec<LogEntry>,
    full_log: Vec<LogEntry>,
    progress: ProgressInfo,
    last_refresh: DateTime<Utc>,
}

struct PaneStatus {
    pane: String,
    status: PaneScanStatus, // OK, Error, InProgress
    message: Option<String>,
}

enum ScanStatus {
    NotStarted,
    Running,
    Complete,
    Error(String),
}

enum PaneScanStatus {
    Ok,
    Error,
    InProgress,
}

struct LogEntry {
    timestamp: DateTime<Utc>,
    pane: String,
    level: LogLevel,
    message: String,
    details: Option<String>,
}

enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

struct ProgressInfo {
    total_panes: usize,
    completed_panes: usize,
}
```

### Log Management
- **Summary**: Show only most recent N logs/errors
- **Expanded**: Show all, with scroll/filter/clear controls
- **Filter**: By pane or log level
- **Clear**: User can clear log/history

### Update Frequencies
- **Status/logs**: On every scan event, error, or user action
- **UI refresh**: Every time new data is available

## Error Handling
- **Log all errors/warnings**: With timestamps and details
- **Show error details**: In expanded view

## UI Layout Suggestions

### Summary View
```
┌─ Status ─────────────────────────────────────┐
│ Status: Running                             │
│ Progress: 5/8 panes complete                │
│ Last refresh: 10:04:04                      │
│                                             │
│ Recent:                                     │
│ [10:04:01] HTTP: Timeout                    │
│ [10:03:59] TLS: Handshake failed            │
│ [10:03:55] DNS: SERVFAIL                    │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Status (Expanded) ──────────────────────────┐
│ [10:04:01] HTTP: Timeout                     │
│ [10:03:59] TLS: Handshake failed             │
│ [10:03:55] DNS: SERVFAIL                    │
│ ...                                         │
│ [User controls: clear log, filter by pane]   │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with multiple errors/warnings
- Test log filtering and clearing
- Test progress and status updates
- Test summary and expanded views
- Test with long-running scans

## Future Enhancements
- **Export logs**: Save to file
- **Notification system**: Alerts for critical errors
- **Resource usage**: CPU/mem stats for the tool itself 