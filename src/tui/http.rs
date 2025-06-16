use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// HTTP pane displays web server response information
pub struct HttpPane {
    title: &'static str,
    id: &'static str,
}

impl HttpPane {
    pub fn new() -> Self {
        Self {
            title: "http",
            id: "http",
        }
    }
    
    /// Truncate URL to fit in the display
    fn truncate_url(url: &str) -> String {
        if url.len() <= 35 {
            url.to_string()
        } else {
            // Remove protocol and show domain + path
            let url_without_protocol = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url);
            
            if url_without_protocol.len() <= 35 {
                url_without_protocol.to_string()
            } else {
                format!("{}...", &url_without_protocol[..32])
            }
        }
    }
}

impl Default for HttpPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for HttpPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // HTTP status header
        lines.push(Line::from(vec![
            Span::styled("🌐 HTTP: ", Style::default().fg(Color::Cyan)),
            Span::styled("scanning...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get HTTP results and render them
        if let Some(http_state) = state.scanners.get("http") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🌐 HTTP: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match http_state.status {
                        crate::types::ScanStatus::Running => "scanning...",
                        crate::types::ScanStatus::Complete => "completed",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match http_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);
            
            if let Some(ScanResult::Http(http_result)) = &http_state.result {
                // Status code
                let status_color = match http_result.status_code {
                    200..=299 => Color::Green,
                    300..=399 => Color::Yellow,
                    400..=499 => Color::Red,
                    500..=599 => Color::Magenta,
                    _ => Color::Gray,
                };
                
                lines.push(Line::from(vec![
                    Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}", http_result.status_code),
                        Style::default().fg(status_color)
                    ),
                ]));
                
                // Response time
                let response_time_ms = http_result.response_time.as_millis();
                let time_color = if response_time_ms < 100 {
                    Color::Green
                } else if response_time_ms < 500 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Time: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}ms", response_time_ms),
                        Style::default().fg(time_color)
                    ),
                ]));
                
                // Content type
                if let Some(content_type) = &http_result.content_type {
                    lines.push(Line::from(vec![
                        Span::styled("📄 Type: ", Style::default().fg(Color::White)),
                        Span::styled(
                            content_type.clone(),
                            Style::default().fg(Color::Yellow)
                        ),
                    ]));
                }
                
                // Content length
                lines.push(Line::from(vec![
                    Span::styled("📏 Size: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{} bytes", http_result.content_length),
                        Style::default().fg(Color::Green)
                    ),
                ]));
                
                // Security grade
                let grade_color = match http_result.security_grade {
                    crate::scan::http::SecurityGrade::APlus | crate::scan::http::SecurityGrade::A => Color::Green,
                    crate::scan::http::SecurityGrade::B | crate::scan::http::SecurityGrade::C => Color::Yellow,
                    crate::scan::http::SecurityGrade::D | crate::scan::http::SecurityGrade::F => Color::Red,
                };
                
                lines.push(Line::from(vec![
                    Span::styled("🔒 Grade: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", http_result.security_grade),
                        Style::default().fg(grade_color)
                    ),
                ]));
                
                // Redirect chain - show details
                if !http_result.redirect_chain.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("🔗 Redirects: ", Style::default().fg(Color::White)),
                        Span::styled(
                            http_result.redirect_chain.len().to_string(),
                            Style::default().fg(Color::Magenta)
                        ),
                    ]));
                    
                    // Show each redirect in the chain
                    for redirect in &http_result.redirect_chain {
                        let from_url = Self::truncate_url(&redirect.from);
                        let to_url = Self::truncate_url(&redirect.to);
                        
                        lines.push(Line::from(vec![
                            Span::styled("  ", Style::default()),
                            Span::styled(from_url, Style::default().fg(Color::Gray)),
                            Span::styled(" → ", Style::default().fg(Color::Magenta)),
                            Span::styled(to_url, Style::default().fg(Color::Cyan)),
                            Span::styled(format!(" ({})", redirect.status_code), Style::default().fg(Color::Yellow)),
                        ]));
                    }
                }
                
                // Vulnerabilities - show details
                if !http_result.vulnerabilities.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("⚠️  Issues: ", Style::default().fg(Color::White)),
                        Span::styled(
                            http_result.vulnerabilities.len().to_string(),
                            Style::default().fg(Color::Red)
                        ),
                    ]));
                    
                    // Show each vulnerability
                    for vulnerability in &http_result.vulnerabilities {
                        let vuln_text = match vulnerability {
                            crate::scan::http::HttpVulnerability::MissingHsts => "Missing HSTS",
                            crate::scan::http::HttpVulnerability::MissingXFrameOptions => "Missing X-Frame-Options",
                            crate::scan::http::HttpVulnerability::MissingXContentTypeOptions => "Missing X-Content-Type-Options",
                            crate::scan::http::HttpVulnerability::MissingCsp => "Missing CSP",
                            crate::scan::http::HttpVulnerability::WeakCsp => "Weak CSP",
                            crate::scan::http::HttpVulnerability::InsecureCors => "Insecure CORS",
                            crate::scan::http::HttpVulnerability::InformationDisclosure => "Information Disclosure",
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("  • ", Style::default().fg(Color::Red)),
                            Span::styled(vuln_text, Style::default().fg(Color::Red)),
                        ]));
                    }
                }
            } else {
                // No HTTP data available yet
                lines.push(Line::from(vec![
                    Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                    Span::styled("checking...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Time: ", Style::default().fg(Color::White)),
                    Span::styled("measuring...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🖥️  Server: ", Style::default().fg(Color::White)),
                    Span::styled("detecting...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No HTTP scanner available
            lines[0] = Line::from(vec![
                Span::styled("🌐 HTTP: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);
            
            lines.push(Line::from(vec![
                Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                Span::styled("HTTP scanner not available", Style::default().fg(Color::Red)),
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
        (25, 10) // Minimum width and height for HTTP information
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_pane_creation() {
        let pane = HttpPane::new();
        assert_eq!(pane.title(), "http");
        assert_eq!(pane.id(), "http");
        assert_eq!(pane.min_size(), (25, 10));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 