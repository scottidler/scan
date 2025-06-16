use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// CONNECTIVITY pane displays real-time ping latency and network connectivity metrics
pub struct ConnectivityPane {
    title: &'static str,
    id: &'static str,
}

impl ConnectivityPane {
    pub fn new() -> Self {
        Self {
            title: "connectivity",
            id: "connectivity",
        }
    }
    

}

impl Default for ConnectivityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for ConnectivityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // Connectivity status header
        lines.push(Line::from(vec![
            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled("checking...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get ping results and render them
        if let Some(ping_state) = state.scanners.get("ping") {
            if let Some(ScanResult::Ping(ping)) = &ping_state.result {
            let latency_ms = ping.latency.as_millis();
            let loss_percent = ping.packet_loss * 100.0;
            
            // Latency information
            lines.push(Line::from(vec![
                Span::styled("⚡ Latency: ", Style::default().fg(Color::White)),
                Span::styled(format!("{}ms", latency_ms), Style::default().fg(Color::Green)),
            ]));
            
            // Packet loss
            lines.push(Line::from(vec![
                Span::styled("📦 Loss: ", Style::default().fg(Color::White)),
                Span::styled(format!("{:.1}%", loss_percent), Style::default().fg(Color::Green)),
            ]));
            
                // TTL information if available
                if let Some(ttl) = ping.ttl {
                    lines.push(Line::from(vec![
                        Span::styled("🔢 TTL: ", Style::default().fg(Color::White)),
                        Span::styled(format!("{} hops", ttl), Style::default().fg(Color::Gray)),
                    ]));
                }
            } else {
                // No ping data available yet
                lines.push(Line::from(vec![
                    Span::styled("⚡ Latency: ", Style::default().fg(Color::White)),
                    Span::styled("measuring...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("📦 Loss: ", Style::default().fg(Color::White)),
                    Span::styled("measuring...", Style::default().fg(Color::Gray)),
                ]));
            }
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
        (25, 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_connectivity_pane_creation() {
        let pane = ConnectivityPane::new();
        assert_eq!(pane.title(), "connectivity");
        assert_eq!(pane.id(), "connectivity");
        assert_eq!(pane.min_size(), (25, 8));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 