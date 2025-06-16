use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// WHOIS pane displays domain registration and ownership information
pub struct WhoisPane {
    title: &'static str,
    id: &'static str,
}

impl WhoisPane {
    pub fn new() -> Self {
        Self {
            title: "whois",
            id: "whois",
        }
    }
}

impl Default for WhoisPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for WhoisPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // WHOIS status header
        lines.push(Line::from(vec![
            Span::styled("📋 WHOIS: ", Style::default().fg(Color::Cyan)),
            Span::styled("querying...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get WHOIS results and render them
        if let Some(whois_state) = state.scanners.get("whois") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("📋 WHOIS: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match whois_state.status {
                        crate::types::ScanStatus::Running => "querying...",
                        crate::types::ScanStatus::Complete => "retrieved",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match whois_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);
            
            if let Some(ScanResult::Whois(whois_result)) = &whois_state.result {
                // Domain name
                lines.push(Line::from(vec![
                    Span::styled("🌐 Domain: ", Style::default().fg(Color::White)),
                    Span::styled(
                        whois_result.domain.clone(),
                        Style::default().fg(Color::Cyan)
                    ),
                ]));
                
                // Registrar
                if let Some(registrar) = &whois_result.registrar {
                    lines.push(Line::from(vec![
                        Span::styled("🏢 Registrar: ", Style::default().fg(Color::White)),
                        Span::styled(
                            registrar.name.clone(),
                            Style::default().fg(Color::Green)
                        ),
                    ]));
                }
                
                // Registration date
                if let Some(created) = &whois_result.registration_date {
                    lines.push(Line::from(vec![
                        Span::styled("📅 Created: ", Style::default().fg(Color::White)),
                        Span::styled(
                            created.format("%Y-%m-%d").to_string(),
                            Style::default().fg(Color::Yellow)
                        ),
                    ]));
                }
                
                // Expiration date with color coding
                if let Some(expires) = &whois_result.expiry_date {
                    let now = chrono::Utc::now().date_naive();
                    let expires_date = expires.date_naive();
                    let days_until_expiry = (expires_date - now).num_days();
                    
                    let expiry_color = if days_until_expiry < 30 {
                        Color::Red
                    } else if days_until_expiry < 90 {
                        Color::Yellow
                    } else {
                        Color::Green
                    };
                    
                    lines.push(Line::from(vec![
                        Span::styled("⏰ Expires: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{} ({}d)", expires.format("%Y-%m-%d"), days_until_expiry),
                            Style::default().fg(expiry_color)
                        ),
                    ]));
                }
                
                // Name servers (show all)
                if !whois_result.nameservers.is_empty() {
                    for (i, nameserver) in whois_result.nameservers.iter().enumerate() {
                        let prefix = if i == 0 {
                            "🔗 NS: "
                        } else {
                            "     "
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(Color::White)),
                            Span::styled(
                                nameserver.clone(),
                                Style::default().fg(Color::Magenta)
                            ),
                        ]));
                    }
                }
                
                // Status - show all status items
                if !whois_result.status.is_empty() {
                    for (i, status) in whois_result.status.iter().enumerate() {
                        let status_color = if status.to_lowercase().contains("ok") {
                            Color::Green
                        } else if status.to_lowercase().contains("pending") {
                            Color::Yellow
                        } else {
                            Color::Red
                        };
                        
                        let prefix = if i == 0 {
                            "📊 Status: "
                        } else {
                            "         "
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(Color::White)),
                            Span::styled(
                                status.clone(),
                                Style::default().fg(status_color)
                            ),
                        ]));
                    }
                }
                
                // Privacy level
                let privacy_color = match whois_result.privacy_score {
                    crate::scan::whois::PrivacyLevel::Open => Color::Red,
                    crate::scan::whois::PrivacyLevel::Corporate => Color::Yellow,
                    crate::scan::whois::PrivacyLevel::Protected => Color::Green,
                    crate::scan::whois::PrivacyLevel::Unknown => Color::Gray,
                };
                
                lines.push(Line::from(vec![
                    Span::styled("🔐 Privacy: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", whois_result.privacy_score),
                        Style::default().fg(privacy_color)
                    ),
                ]));
                
                // Risk indicators - show all risks
                if !whois_result.risk_indicators.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("⚠️  Risks: ", Style::default().fg(Color::White)),
                        Span::styled(
                            whois_result.risk_indicators.len().to_string(),
                            Style::default().fg(Color::Red)
                        ),
                        Span::styled(" indicators", Style::default().fg(Color::Red)),
                    ]));
                    
                    // Show each risk indicator
                    for risk in &whois_result.risk_indicators {
                        let risk_text = match risk {
                            crate::scan::whois::RiskIndicator::RecentRegistration => "Recent Registration (<30 days)",
                            crate::scan::whois::RiskIndicator::NearExpiry => "Near Expiry (<30 days)",
                            crate::scan::whois::RiskIndicator::FrequentUpdates => "Frequent Updates",
                            crate::scan::whois::RiskIndicator::SuspiciousRegistrar => "Suspicious Registrar",
                            crate::scan::whois::RiskIndicator::NoAbuseContact => "No Abuse Contact",
                            crate::scan::whois::RiskIndicator::WeakDnssec => "Weak DNSSEC",
                            crate::scan::whois::RiskIndicator::QueryFailed => "Query Failed",
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("     • ", Style::default().fg(Color::Red)),
                            Span::styled(
                                risk_text,
                                Style::default().fg(Color::Red)
                            ),
                        ]));
                    }
                }
                
                // Data source
                let source_color = match whois_result.data_source {
                    crate::scan::whois::DataSource::Rdap => Color::Green,
                    crate::scan::whois::DataSource::Whois => Color::Yellow,
                    crate::scan::whois::DataSource::Failed => Color::Red,
                };
                
                lines.push(Line::from(vec![
                    Span::styled("📡 Source: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", whois_result.data_source),
                        Style::default().fg(source_color)
                    ),
                ]));

            } else {
                // No WHOIS data available yet - check scanner status
                match whois_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(Color::White)),
                            Span::styled("querying...", Style::default().fg(Color::Yellow)),
                        ]));
                        
                        lines.push(Line::from(vec![
                            Span::styled("🏢 Registrar: ", Style::default().fg(Color::White)),
                            Span::styled("looking up...", Style::default().fg(Color::Yellow)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(Color::White)),
                            Span::styled("query failed", Style::default().fg(Color::Red)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(Color::White)),
                            Span::styled("waiting to query...", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
            }
        } else {
            // No WHOIS scanner available
            lines[0] = Line::from(vec![
                Span::styled("📋 WHOIS: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);
            
            lines.push(Line::from(vec![
                Span::styled("🌐 Domain: ", Style::default().fg(Color::White)),
                Span::styled("WHOIS scanner not available", Style::default().fg(Color::Red)),
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
        (35, 16) // Larger to show all nameservers and details
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_whois_pane_creation() {
        let pane = WhoisPane::new();
        assert_eq!(pane.title(), "whois");
        assert_eq!(pane.id(), "whois");
        assert_eq!(pane.min_size(), (30, 12));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 