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
        if let Some(port_state) = state.scanners.get("port") {
            if let Some(ScanResult::Port(port_result)) = &port_state.result {
                // Open ports count
                let open_count = port_result.open_ports.len();
                let open_color = if open_count == 0 {
                    Color::Green
                } else if open_count <= 5 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                    Span::styled(
                        open_count.to_string(),
                        Style::default().fg(open_color)
                    ),
                    Span::styled(" ports", Style::default().fg(Color::White)),
                ]));
                
                // Show first few open ports
                if !port_result.open_ports.is_empty() {
                    let ports_to_show = std::cmp::min(port_result.open_ports.len(), 4);
                    for i in 0..ports_to_show {
                        let port = &port_result.open_ports[i];
                        let service_info = if let Some(service) = &port.service {
                            format!(" ({})", service.name)
                        } else {
                            String::new()
                        };
                        
                        let protocol_str = match port.protocol {
                            crate::scan::port::Protocol::Tcp => "tcp",
                            crate::scan::port::Protocol::Udp => "udp",
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                format!("{}/{}", port.port, protocol_str),
                                Style::default().fg(Color::Green)
                            ),
                            Span::styled(
                                service_info,
                                Style::default().fg(Color::Gray)
                            ),
                        ]));
                    }
                    
                    // Show "more" indicator if there are additional ports
                    if port_result.open_ports.len() > 4 {
                        let remaining = port_result.open_ports.len() - 4;
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                format!("... +{} more", remaining),
                                Style::default().fg(Color::Gray)
                            ),
                        ]));
                    }
                }
                
                // Filtered ports
                if port_result.filtered_ports > 0 {
                    lines.push(Line::from(vec![
                        Span::styled("🔒 Filtered: ", Style::default().fg(Color::White)),
                        Span::styled(
                            port_result.filtered_ports.to_string(),
                            Style::default().fg(Color::Yellow)
                        ),
                        Span::styled(" ports", Style::default().fg(Color::White)),
                    ]));
                }
                
                // Closed ports
                if port_result.closed_ports > 0 {
                    lines.push(Line::from(vec![
                        Span::styled("🔴 Closed: ", Style::default().fg(Color::White)),
                        Span::styled(
                            port_result.closed_ports.to_string(),
                            Style::default().fg(Color::Red)
                        ),
                        Span::styled(" ports", Style::default().fg(Color::White)),
                    ]));
                }
                
                // Scan duration
                let scan_time_ms = port_result.scan_duration.as_millis();
                let time_color = if scan_time_ms < 1000 {
                    Color::Green
                } else if scan_time_ms < 5000 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}ms", scan_time_ms),
                        Style::default().fg(time_color)
                    ),
                ]));
                
            } else {
                // No port data available yet
                lines.push(Line::from(vec![
                    Span::styled("📊 Scanned: ", Style::default().fg(Color::White)),
                    Span::styled("scanning...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                    Span::styled("detecting...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🔒 Filtered: ", Style::default().fg(Color::White)),
                    Span::styled("checking...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No port scanner available
            lines.push(Line::from(vec![
                Span::styled("PORTS: ", Style::default().fg(Color::White)),
                Span::styled("scanner not available", Style::default().fg(Color::Red)),
            ]));
        }
        
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