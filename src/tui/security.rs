use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// SECURITY pane displays TLS/SSL certificate information and security analysis
pub struct SecurityPane {
    title: &'static str,
    id: &'static str,
}

impl SecurityPane {
    pub fn new() -> Self {
        Self {
            title: "security",
            id: "security",
        }
    }
}

impl Default for SecurityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for SecurityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // Security status header
        lines.push(Line::from(vec![
            Span::styled("🔒 TLS: ", Style::default().fg(Color::Cyan)),
            Span::styled("scanning...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get TLS results and render them
        if let Some(tls_state) = state.scanners.get("tls") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🔒 TLS: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match tls_state.status {
                        crate::types::ScanStatus::Running => "scanning...",
                        crate::types::ScanStatus::Complete => "analyzed",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match tls_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);
            
            if let Some(ScanResult::Tls(tls_result)) = &tls_state.result {
                // Connection status
                let (status_text, status_color) = if tls_result.connection_successful {
                    ("connected", Color::Green)
                } else {
                    ("failed", Color::Red)
                };
                
                lines.push(Line::from(vec![
                    Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                    Span::styled(status_text, Style::default().fg(status_color)),
                ]));
                
                // TLS version
                if let Some(version) = &tls_result.negotiated_version {
                    let version_color = match version.as_str() {
                        "TLS 1.3" => Color::Green,
                        "TLS 1.2" => Color::Yellow,
                        _ => Color::Red,
                    };
                    
                    lines.push(Line::from(vec![
                        Span::styled("🔐 Version: ", Style::default().fg(Color::White)),
                        Span::styled(version.as_str(), Style::default().fg(version_color)),
                    ]));
                }
                
                // Certificate validity
                if !tls_result.certificate_chain.is_empty() {
                    let cert_color = if tls_result.certificate_valid {
                        Color::Green
                    } else {
                        Color::Red
                    };
                    
                    let cert_status = if tls_result.certificate_valid {
                        "valid"
                    } else {
                        "invalid"
                    };
                    
                    lines.push(Line::from(vec![
                        Span::styled("📜 Cert: ", Style::default().fg(Color::White)),
                        Span::styled(cert_status, Style::default().fg(cert_color)),
                    ]));
                    
                    // Certificate expiry
                    if let Some(days_until_expiry) = tls_result.days_until_expiry {
                        let expiry_color = if days_until_expiry > 30 {
                            Color::Green
                        } else if days_until_expiry > 7 {
                            Color::Yellow
                        } else {
                            Color::Red
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("⏰ Expires: ", Style::default().fg(Color::White)),
                            Span::styled(
                                format!("{}d", days_until_expiry),
                                Style::default().fg(expiry_color)
                            ),
                        ]));
                    }
                }
                
                // Security grade
                let grade_color = match tls_result.security_grade.as_str() {
                    "A+" | "A" => Color::Green,
                    "B" => Color::Yellow,
                    "C" => Color::Magenta,
                    _ => Color::Red,
                };
                
                lines.push(Line::from(vec![
                    Span::styled("🏆 Grade: ", Style::default().fg(Color::White)),
                    Span::styled(
                        tls_result.security_grade.as_str(),
                        Style::default().fg(grade_color)
                    ),
                ]));
                
                // Vulnerabilities count
                if !tls_result.vulnerabilities.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("⚠️  Issues: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{}", tls_result.vulnerabilities.len()),
                            Style::default().fg(Color::Red)
                        ),
                    ]));
                }
                
            } else {
                // No TLS data available yet
                lines.push(Line::from(vec![
                    Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                    Span::styled("checking...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🔐 Version: ", Style::default().fg(Color::White)),
                    Span::styled("detecting...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("📜 Cert: ", Style::default().fg(Color::White)),
                    Span::styled("validating...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No TLS scanner available
            lines[0] = Line::from(vec![
                Span::styled("🔒 TLS: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);
            
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                Span::styled("TLS scanner not available", Style::default().fg(Color::Red)),
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
        (25, 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_pane_creation() {
        let pane = SecurityPane::new();
        assert_eq!(pane.title(), "security");
        assert_eq!(pane.id(), "security");
        assert_eq!(pane.min_size(), (25, 8));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 