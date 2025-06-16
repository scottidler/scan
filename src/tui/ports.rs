use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// Ports pane displays port scanning results
pub struct PortsPane {
    title: &'static str,
    id: &'static str,
}

impl PortsPane {
    pub fn new() -> Self {
        Self {
            title: "ports",
            id: "ports",
        }
    }

    fn build_port_result_lines(
        open_count: usize,
        open_ports: Vec<crate::scan::port::OpenPort>,
        filtered_ports: u16,
        scan_duration_ms: u128,
    ) -> Vec<Line<'static>> {
        let mut port_lines = Vec::new();
        
        // Open ports count with color coding
        let port_color = if open_count == 0 {
            Color::Green
        } else if open_count <= 5 {
            Color::Yellow
        } else {
            Color::Red
        };
        
        port_lines.push(Line::from(vec![
            Span::styled("📊 Scanned: ", Style::default().fg(Color::White)),
            Span::styled("completed", Style::default().fg(Color::Green)),
        ]));
        
        port_lines.push(Line::from(vec![
            Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
            Span::styled(
                open_count.to_string(),
                Style::default().fg(port_color)
            ),
            Span::styled(" ports", Style::default().fg(Color::White)),
        ]));
        
        // Show first few open ports
        for open_port in open_ports.iter() {
            let service_name = open_port.service.as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            
            let protocol_str = match open_port.protocol {
                crate::scan::port::Protocol::Tcp => "tcp",
                crate::scan::port::Protocol::Udp => "udp",
            };
            
            port_lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("{}/{}", open_port.port, protocol_str),
                    Style::default().fg(Color::Cyan)
                ),
                Span::styled(" (", Style::default().fg(Color::Gray)),
                Span::styled(
                    service_name,
                    Style::default().fg(Color::Yellow)
                ),
                Span::styled(")", Style::default().fg(Color::Gray)),
            ]));
        }
        
        // Show "more" indicator
        if open_count > 3 {
            port_lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    format!("... and {} more", open_count - 3),
                    Style::default().fg(Color::Gray)
                ),
            ]));
        }
        
        // Filtered and closed ports summary
        if filtered_ports > 0 {
            port_lines.push(Line::from(vec![
                Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                Span::styled(
                    filtered_ports.to_string(),
                    Style::default().fg(Color::Yellow)
                ),
            ]));
        }
        
        // Scan duration
        port_lines.push(Line::from(vec![
            Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{}ms", scan_duration_ms),
                Style::default().fg(Color::Gray)
            ),
        ]));
        
        port_lines
    }
}

impl Default for PortsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for PortsPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // Ports status header
        lines.push(Line::from(vec![
            Span::styled("🔌 PORTS: ", Style::default().fg(Color::Cyan)),
            Span::styled("scanning...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get port scan results and render them
        let port_lines = match state.scanners.get("port") {
            Some(port_state) => {
                // Clone the data we need to avoid lifetime issues
                let result = port_state.result.clone();
                let status = port_state.status.clone();
                let last_updated = port_state.last_updated;
                
                match result {
                    Some(ScanResult::Port(port_result)) => {
                        // Update header with current status
                        lines[0] = Line::from(vec![
                            Span::styled("🔌 PORTS: ", Style::default().fg(Color::Cyan)),
                            Span::styled(
                                match status {
                                    crate::types::ScanStatus::Running => "scanning...",
                                    crate::types::ScanStatus::Complete => "completed",
                                    crate::types::ScanStatus::Failed => "failed",
                                },
                                Style::default().fg(match status {
                                    crate::types::ScanStatus::Running => Color::Yellow,
                                    crate::types::ScanStatus::Complete => Color::Green,
                                    crate::types::ScanStatus::Failed => Color::Red,
                                })
                            ),
                        ]);
                        
                        // Extract the data we need to avoid lifetime issues
                        let open_count = port_result.open_ports.len();
                        let open_ports: Vec<_> = port_result.open_ports.iter().take(5).cloned().collect();
                        let filtered_ports = port_result.filtered_ports;
                        let closed_ports = port_result.closed_ports;
                        let scan_duration_ms = port_result.scan_duration.as_millis();
                        
                        // Calculate estimated progress (rough estimate based on duration and typical scan times)
                        let progress_info = if matches!(status, crate::types::ScanStatus::Running) {
                            // Estimate progress based on scan duration and typical port scan timing
                            let total_expected = match port_result.scan_mode {
                                crate::scan::port::ScanMode::Quick => 100,
                                crate::scan::port::ScanMode::Standard => 1000,
                                crate::scan::port::ScanMode::Custom(ref ports) => ports.len(),
                            };
                            let scanned_so_far = open_count + filtered_ports as usize + closed_ports as usize;
                            let progress_percent = ((scanned_so_far as f32 / total_expected as f32) * 100.0).min(99.0) as u32;
                            Some((scanned_so_far, total_expected, progress_percent))
                        } else {
                            None
                        };
                        
                        let mut result_lines = Vec::new();
                        
                        // Progress information if actively scanning
                        if let Some((scanned, total, percent)) = progress_info {
                            result_lines.push(Line::from(vec![
                                Span::styled("📊 Progress: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    format!("{}% ({}/{})", percent, scanned, total),
                                    Style::default().fg(Color::Yellow)
                                ),
                            ]));
                        } else {
                            result_lines.push(Line::from(vec![
                                Span::styled("📊 Scanned: ", Style::default().fg(Color::White)),
                                Span::styled("completed", Style::default().fg(Color::Green)),
                            ]));
                        }
                        
                        // Open ports count with color coding
                        let port_color = if open_count == 0 {
                            Color::Green
                        } else if open_count <= 5 {
                            Color::Yellow
                        } else {
                            Color::Red
                        };
                        
                        result_lines.push(Line::from(vec![
                            Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                            Span::styled(
                                open_count.to_string(),
                                Style::default().fg(port_color)
                            ),
                            Span::styled(" ports", Style::default().fg(Color::White)),
                        ]));
                        
                        // Show discovered open ports (up to 5)
                        for (idx, open_port) in open_ports.iter().enumerate() {
                            if idx >= 5 { break; } // Limit display
                            
                            let service_name = open_port.service.as_ref()
                                .map(|s| s.name.clone())
                                .unwrap_or_else(|| "unknown".to_string());
                            
                            let protocol_str = match open_port.protocol {
                                crate::scan::port::Protocol::Tcp => "tcp",
                                crate::scan::port::Protocol::Udp => "udp",
                            };
                            
                            result_lines.push(Line::from(vec![
                                Span::styled("  ", Style::default()),
                                Span::styled(
                                    format!("{}/{}", open_port.port, protocol_str),
                                    Style::default().fg(Color::Cyan)
                                ),
                                Span::styled(" (", Style::default().fg(Color::Gray)),
                                Span::styled(
                                    service_name,
                                    Style::default().fg(Color::Yellow)
                                ),
                                Span::styled(")", Style::default().fg(Color::Gray)),
                            ]));
                        }
                        
                        // Show "more" indicator if there are more open ports
                        if open_count > 5 {
                            result_lines.push(Line::from(vec![
                                Span::styled("  ", Style::default()),
                                Span::styled(
                                    format!("... and {} more", open_count - 5),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        }
                        
                        // Filtered and closed ports summary
                        if filtered_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    filtered_ports.to_string(),
                                    Style::default().fg(Color::Yellow)
                                ),
                            ]));
                        }
                        
                        if closed_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🔴 Closed: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    closed_ports.to_string(),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        }
                        
                        // Scan duration
                        result_lines.push(Line::from(vec![
                            Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                            Span::styled(
                                if scan_duration_ms > 1000 {
                                    format!("{:.1}s", scan_duration_ms as f32 / 1000.0)
                                } else {
                                    format!("{}ms", scan_duration_ms)
                                },
                                Style::default().fg(Color::Gray)
                            ),
                        ]));
                        
                        result_lines
                    }
                    Some(_) => {
                        // Wrong result type (shouldn't happen)
                        vec![Line::from(vec![
                            Span::styled("❌ Error: ", Style::default().fg(Color::White)),
                            Span::styled("wrong result type", Style::default().fg(Color::Red)),
                        ])]
                    }
                    None => {
                        // Still scanning or no results yet
                        match status {
                            crate::types::ScanStatus::Running => {
                                // Show last updated time
                                let seconds_ago = last_updated.elapsed().as_secs();
                                let time_info = if seconds_ago < 60 {
                                    format!("{}s ago", seconds_ago)
                                } else {
                                    format!("{}m ago", seconds_ago / 60)
                                };
                                
                                vec![
                                    Line::from(vec![
                                        Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                                        Span::styled("initializing scan...", Style::default().fg(Color::Yellow)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("⏱️  Started: ", Style::default().fg(Color::White)),
                                        Span::styled(time_info, Style::default().fg(Color::Gray)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                                        Span::styled("detecting...", Style::default().fg(Color::Gray)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                                        Span::styled("checking...", Style::default().fg(Color::Gray)),
                                    ]),
                                ]
                            }
                            crate::types::ScanStatus::Failed => {
                                vec![Line::from(vec![
                                    Span::styled("❌ Status: ", Style::default().fg(Color::White)),
                                    Span::styled("scan failed", Style::default().fg(Color::Red)),
                                ])]
                            }
                            _ => {
                                vec![Line::from(vec![
                                    Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                                    Span::styled("waiting to start...", Style::default().fg(Color::Gray)),
                                ])]
                            }
                        }
                    }
                }
            }
            None => {
                // No port scanner registered
                vec![Line::from(vec![
                    Span::styled("❌ Error: ", Style::default().fg(Color::White)),
                    Span::styled("port scanner not available", Style::default().fg(Color::Red)),
                ])]
            }
        };
        
        // Add port lines to main lines
        lines.extend(port_lines);
        
        // Create and render the paragraph
        let paragraph = Paragraph::new(lines)
            .alignment(Alignment::Left);
        paragraph.render(inner_area, frame.buffer_mut());
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (25, 10) // Minimum width and height for port information
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ports_pane_creation() {
        let pane = PortsPane::new();
        assert_eq!(pane.title(), "ports");
        assert_eq!(pane.id(), "ports");
        assert_eq!(pane.min_size(), (25, 10));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 