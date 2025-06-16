use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};
use std::any::Any;

/// Traceroute pane displays network path tracing information
pub struct TraceroutePane {
    title: &'static str,
    id: &'static str,
}

impl TraceroutePane {
    pub fn new() -> Self {
        Self {
            title: "traceroute",
            id: "traceroute",
        }
    }
}

impl Default for TraceroutePane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TraceroutePane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // Traceroute status header
        lines.push(Line::from(vec![
            Span::styled("🗺️  ROUTE: ", Style::default().fg(Color::Cyan)),
            Span::styled("tracing...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get traceroute results and render them
        if let Some(traceroute_state) = state.scanners.get("traceroute") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🗺️  ROUTE: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match traceroute_state.status {
                        crate::types::ScanStatus::Running => "tracing...",
                        crate::types::ScanStatus::Complete => "traced",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match traceroute_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);
            
            if let Some(ScanResult::Traceroute(traceroute_result)) = &traceroute_state.result {
                // Basic traceroute info
                let hop_count = traceroute_result.hops.len();
                let status_color = if traceroute_result.destination_reached {
                    Color::Green
                } else {
                    Color::Yellow
                };
                
                let protocol = if traceroute_result.ipv6 { "IPv6" } else { "IPv4" };
                
                lines.push(Line::from(vec![
                    Span::styled(format!("📍 {}: ", protocol), Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{} hops", hop_count),
                        Style::default().fg(status_color)
                    ),
                    if traceroute_result.destination_reached {
                        Span::styled(" ✓", Style::default().fg(Color::Green))
                    } else {
                        Span::styled(" ✗", Style::default().fg(Color::Red))
                    },
                ]));
                
                // Show all hops
                for hop in &traceroute_result.hops {
                    // Get first responding IP and best RTT
                    let (ip_display, rtt_display, hop_color) = if let Some(response) = hop.responses.iter().find(|r| !r.timeout) {
                        let ip_str = response.ip_address.as_ref()
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "*".to_string());
                        let rtt_str = response.rtt.as_ref()
                            .map(|rtt| format!("{}ms", rtt.as_millis()))
                            .unwrap_or_else(|| "*".to_string());
                        (ip_str, rtt_str, Color::Cyan)
                    } else {
                        ("*".to_string(), "timeout".to_string(), Color::Gray)
                    };
                    
                    // Color code hop number based on position
                    let hop_num_color = if hop.hop_number <= 3 {
                        Color::Green // Local/ISP hops
                    } else if hop.hop_number <= 10 {
                        Color::Yellow // Mid-network
                    } else {
                        Color::Red // Far hops
                    };
                    
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {:2}: ", hop.hop_number), Style::default().fg(hop_num_color)),
                        Span::styled(ip_display, Style::default().fg(hop_color)),
                        Span::styled(format!(" ({})", rtt_display), Style::default().fg(Color::Gray)),
                    ]));
                }
                
                // Total scan time
                let scan_time_ms = traceroute_result.scan_duration.as_millis();
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}ms", scan_time_ms),
                        Style::default().fg(Color::Yellow)
                    ),
                ]));
                
            } else {
                // No traceroute data available yet - check scanner status
                match traceroute_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 IPv4: ", Style::default().fg(Color::White)),
                            Span::styled("tracing...", Style::default().fg(Color::Yellow)),
                        ]));
                        
                        lines.push(Line::from(vec![
                            Span::styled("📍 IPv6: ", Style::default().fg(Color::White)),
                            Span::styled("tracing...", Style::default().fg(Color::Yellow)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("trace failed", Style::default().fg(Color::Red)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("waiting to trace...", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
            }
        } else {
            // No traceroute scanner available
            lines[0] = Line::from(vec![
                Span::styled("🗺️  ROUTE: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);
            
            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                Span::styled("Traceroute scanner not available", Style::default().fg(Color::Red)),
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
        (35, 20) // Much larger to show all hops (up to ~30 hops)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn is_focusable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traceroute_pane_creation() {
        let pane = TraceroutePane::new();
        assert_eq!(pane.title(), "traceroute");
        assert_eq!(pane.id(), "traceroute");
        assert_eq!(pane.min_size(), (30, 10));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
} 