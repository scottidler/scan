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

    fn truncate_txt(text: &str, max_len: usize) -> String {
        if text.len() <= max_len {
            text.to_string()
        } else {
            format!("{}...", &text[..max_len.saturating_sub(3)])
        }
    }

    fn build_dns_result_lines(dns_result: crate::scan::dns::DnsResult) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        
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
            
            // Show A records with TTL (up to 6)
            for record in dns_result.A.iter().take(6) {
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.to_string(),
                        Style::default().fg(Color::Cyan)
                    ),
                    Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
            
            if dns_result.A.len() > 6 {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("... and {} more", dns_result.A.len() - 6),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
        }
        
        // AAAA records (IPv6)
        if !dns_result.AAAA.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("AAAA: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.AAAA.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" IPv6", Style::default().fg(Color::White)),
            ]));
            
            for record in dns_result.AAAA.iter().take(3) {
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                let ipv6_str = record.value.to_string();
                let display_str = if ipv6_str.len() > 25 {
                    format!("{}...", &ipv6_str[..22])
                } else {
                    ipv6_str
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        display_str,
                        Style::default().fg(Color::Cyan)
                    ),
                    Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
            
            if dns_result.AAAA.len() > 3 {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("... and {} more", dns_result.AAAA.len() - 3),
                        Style::default().fg(Color::Gray)
                    ),
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
            
            for record in dns_result.MX.iter().take(4) {
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                let priority_color = if record.value.priority <= 10 {
                    Color::Green
                } else if record.value.priority <= 20 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.exchange.clone(),
                        Style::default().fg(Color::Magenta)
                    ),
                    Span::styled(" (pri: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", record.value.priority),
                        Style::default().fg(priority_color)
                    ),
                    Span::styled(", TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
            
            if dns_result.MX.len() > 4 {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("... and {} more", dns_result.MX.len() - 4),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
        }
        
        // TXT records (basic display, security analysis goes to security pane)
        if !dns_result.TXT.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("TXT: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.TXT.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" records", Style::default().fg(Color::White)),
            ]));
            
            for record in dns_result.TXT.iter().take(4) {
                let value = record.value.clone();
                let display_value = if value.starts_with("google-site-verification") {
                    "google-site-verification=...".to_string()
                } else if value.starts_with("MS=") {
                    format!("MS={}...", &value[3..].chars().take(10).collect::<String>())
                } else {
                    Self::truncate_txt(&value, 45)
                };
                
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        display_value,
                        Style::default().fg(Color::Yellow)
                    ),
                    Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
            
            if dns_result.TXT.len() > 4 {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("... and {} more TXT records", dns_result.TXT.len() - 4),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
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
            
            for record in dns_result.NS.iter().take(4) {
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.clone(),
                        Style::default().fg(Color::Blue)
                    ),
                    Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
            
            if dns_result.NS.len() > 4 {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("... and {} more", dns_result.NS.len() - 4),
                        Style::default().fg(Color::Gray)
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
            
            for record in dns_result.CNAME.iter().take(3) {
                let ttl_color = if record.ttl_remaining() > 300 {
                    Color::Green
                } else if record.ttl_remaining() > 60 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.clone(),
                        Style::default().fg(Color::Magenta)
                    ),
                    Span::styled(" (TTL: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}s", record.ttl_remaining()),
                        Style::default().fg(ttl_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
        }
        
        // CAA records
        if !dns_result.CAA.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("CAA: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.CAA.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" cert auth", Style::default().fg(Color::White)),
            ]));
            
            for record in dns_result.CAA.iter().take(3) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("{} {}", record.value.tag, record.value.value),
                        Style::default().fg(Color::Green)
                    ),
                ]));
            }
        }
        
        // SOA records
        if !dns_result.SOA.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("SOA: ", Style::default().fg(Color::White)),
                Span::styled("authority", Style::default().fg(Color::Green)),
            ]));
            
            if let Some(soa) = dns_result.SOA.first() {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("NS: {}", soa.value.primary_ns),
                        Style::default().fg(Color::Cyan)
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("Serial: {}", soa.value.serial),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
        }
        
        // SRV records
        if !dns_result.SRV.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("SRV: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.SRV.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" services", Style::default().fg(Color::White)),
            ]));
            
            for record in dns_result.SRV.iter().take(3) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("{}:{} (p:{}, w:{})", 
                            record.value.target, 
                            record.value.port,
                            record.value.priority,
                            record.value.weight
                        ),
                        Style::default().fg(Color::Blue)
                    ),
                ]));
            }
        }
        
        lines
    }

    fn build_dns_loading_lines() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled("A: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("AAAA: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("MX: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
        ]
    }

    fn build_dns_unavailable_lines() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled("DNS: ", Style::default().fg(Color::White)),
                Span::styled("scanner not available", Style::default().fg(Color::Red)),
            ])
        ]
    }
}

impl Default for DnsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for DnsPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
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
        let dns_lines = if let Some(dns_state) = state.scanners.get("dns") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🌐 DNS: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match dns_state.status {
                        crate::types::ScanStatus::Running => "resolving...",
                        crate::types::ScanStatus::Complete => "resolved",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match dns_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);
            
            // Clone the result to avoid lifetime issues
            let result = dns_state.result.clone();
            if let Some(ScanResult::Dns(dns_result)) = result {
                Self::build_dns_result_lines(dns_result)
            } else {
                Self::build_dns_loading_lines()
            }
        } else {
            Self::build_dns_unavailable_lines()
        };
        
        // Add DNS lines to main lines
        lines.extend(dns_lines);
        
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
    fn test_dns_pane_creation() {
        let pane = DnsPane::new();
        assert_eq!(pane.title(), "dns");
        assert_eq!(pane.id(), "dns");
        assert_eq!(pane.min_size(), (25, 10));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
} 