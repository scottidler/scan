use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

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
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
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
                
                // Show first few hops
                let hops_to_show = std::cmp::min(traceroute_result.hops.len(), 3);
                for i in 0..hops_to_show {
                    let hop = &traceroute_result.hops[i];
                    
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
                    
                    lines.push(Line::from(vec![
                        Span::styled(format!("   {}: ", hop.hop_number), Style::default().fg(Color::White)),
                        Span::styled(ip_display, Style::default().fg(hop_color)),
                        Span::styled(format!(" ({})", rtt_display), Style::default().fg(Color::Gray)),
                    ]));
                }
                
                // Show "more" indicator if there are additional hops
                if traceroute_result.hops.len() > 3 {
                    let remaining = traceroute_result.hops.len() - 3;
                    lines.push(Line::from(vec![
                        Span::styled("   ", Style::default()),
                        Span::styled(
                            format!("... +{} more hops", remaining),
                            Style::default().fg(Color::Gray)
                        ),
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
                // No traceroute data available yet
                lines.push(Line::from(vec![
                    Span::styled("📍 IPv4: ", Style::default().fg(Color::White)),
                    Span::styled("tracing...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("📍 IPv6: ", Style::default().fg(Color::White)),
                    Span::styled("tracing...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Total: ", Style::default().fg(Color::White)),
                    Span::styled("measuring...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No traceroute scanner available
            lines.push(Line::from(vec![
                Span::styled("TRACEROUTE: ", Style::default().fg(Color::White)),
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
        (30, 10) // Minimum width and height for traceroute information
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
        assert!(!pane.is_focusable());
    }
} 