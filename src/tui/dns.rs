use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// DNS pane displays domain name system resolution information
pub struct DnsPane {
    title: &'static str,
    id: &'static str,
}

impl DnsPane {
    pub fn new() -> Self {
        Self {
            title: "dns",
            id: "dns",
        }
    }
}

impl Default for DnsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for DnsPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // DNS status header
        lines.push(Line::from(vec![
            Span::styled("🌐 DNS: ", Style::default().fg(Color::Cyan)),
            Span::styled("resolving...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get DNS results and render them
        if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(ScanResult::Dns(dns_result)) = &dns_state.result {
                // A records
                if !dns_result.A.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("A: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.A.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                    
                    // Show first A record with TTL
                    if let Some(first_a) = dns_result.A.first() {
                        let ttl_color = if first_a.ttl_remaining() > 300 {
                            Color::Green
                        } else if first_a.ttl_remaining() > 60 {
                            Color::Yellow
                        } else {
                            Color::Red
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                first_a.value.to_string(),
                                Style::default().fg(Color::Cyan)
                            ),
                            Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                            Span::styled(
                                first_a.ttl_remaining().to_string(),
                                Style::default().fg(ttl_color)
                            ),
                            Span::styled("s)", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
                
                // AAAA records
                if !dns_result.AAAA.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("AAAA: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.AAAA.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                    
                    // Show first AAAA record with TTL
                    if let Some(first_aaaa) = dns_result.AAAA.first() {
                        let ttl_color = if first_aaaa.ttl_remaining() > 300 {
                            Color::Green
                        } else if first_aaaa.ttl_remaining() > 60 {
                            Color::Yellow
                        } else {
                            Color::Red
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                first_aaaa.value.to_string(),
                                Style::default().fg(Color::Cyan)
                            ),
                            Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                            Span::styled(
                                first_aaaa.ttl_remaining().to_string(),
                                Style::default().fg(ttl_color)
                            ),
                            Span::styled("s)", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
                
                // MX records
                if !dns_result.MX.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("MX: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.MX.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                    
                    // Show first MX record
                    if let Some(first_mx) = dns_result.MX.first() {
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                format!("{} ({})", first_mx.value.exchange, first_mx.value.priority),
                                Style::default().fg(Color::Magenta)
                            ),
                        ]));
                    }
                }
                
                // CNAME records
                if !dns_result.CNAME.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("CNAME: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.CNAME.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                    
                    // Show first CNAME
                    if let Some(first_cname) = dns_result.CNAME.first() {
                        lines.push(Line::from(vec![
                            Span::styled("   ", Style::default()),
                            Span::styled(
                                first_cname.value.to_string(),
                                Style::default().fg(Color::Yellow)
                            ),
                        ]));
                    }
                }
                
                // TXT records
                if !dns_result.TXT.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("TXT: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.TXT.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                }
                
                // NS records
                if !dns_result.NS.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("NS: ", Style::default().fg(Color::White)),
                        Span::styled(
                            dns_result.NS.len().to_string(),
                            Style::default().fg(Color::Green)
                        ),
                        Span::styled(" records", Style::default().fg(Color::White)),
                    ]));
                }
                
            } else {
                // No DNS data available yet
                lines.push(Line::from(vec![
                    Span::styled("A: ", Style::default().fg(Color::White)),
                    Span::styled("resolving...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("AAAA: ", Style::default().fg(Color::White)),
                    Span::styled("resolving...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("MX: ", Style::default().fg(Color::White)),
                    Span::styled("resolving...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No DNS scanner available
            lines.push(Line::from(vec![
                Span::styled("DNS: ", Style::default().fg(Color::White)),
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
        (25, 10) // Minimum width and height for DNS information
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_pane_creation() {
        let pane = DnsPane::new();
        assert_eq!(pane.title(), "dns");
        assert_eq!(pane.id(), "dns");
        assert_eq!(pane.min_size(), (25, 10));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 