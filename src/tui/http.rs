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
                
                // Redirect chain
                if !http_result.redirect_chain.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("🔗 Redirects: ", Style::default().fg(Color::White)),
                        Span::styled(
                            http_result.redirect_chain.len().to_string(),
                            Style::default().fg(Color::Magenta)
                        ),
                    ]));
                }
                
                // Vulnerabilities count
                if !http_result.vulnerabilities.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("⚠️  Issues: ", Style::default().fg(Color::White)),
                        Span::styled(
                            http_result.vulnerabilities.len().to_string(),
                            Style::default().fg(Color::Red)
                        ),
                    ]));
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
            lines.push(Line::from(vec![
                Span::styled("HTTP: ", Style::default().fg(Color::White)),
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