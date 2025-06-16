use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// GeoIP pane displays geographical and network location information
pub struct GeoIpPane {
    title: &'static str,
    id: &'static str,
}

impl GeoIpPane {
    pub fn new() -> Self {
        Self {
            title: "geoip",
            id: "geoip",
        }
    }
}

impl Default for GeoIpPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for GeoIpPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // GeoIP status header
        lines.push(Line::from(vec![
            Span::styled("🌍 GEOIP: ", Style::default().fg(Color::Cyan)),
            Span::styled("locating...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Get GeoIP results and render them
        if let Some(geoip_state) = state.scanners.get("geoip") {
            if let Some(ScanResult::GeoIp(geoip_result)) = &geoip_state.result {
                // Location
                if let Some(location) = &geoip_result.location {
                    let location_text = format!("{}, {}, {}", location.city, location.region, location.country);
                    
                    lines.push(Line::from(vec![
                        Span::styled("📍 Location: ", Style::default().fg(Color::White)),
                        Span::styled(
                            location_text,
                            Style::default().fg(Color::Green)
                        ),
                    ]));
                    
                    // Coordinates
                    lines.push(Line::from(vec![
                        Span::styled("📐 Coords: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{:.4}, {:.4}", location.latitude, location.longitude),
                            Style::default().fg(Color::Yellow)
                        ),
                    ]));
                    
                    // Timezone
                    lines.push(Line::from(vec![
                        Span::styled("🕐 TZ: ", Style::default().fg(Color::White)),
                        Span::styled(
                            location.timezone.clone(),
                            Style::default().fg(Color::Yellow)
                        ),
                    ]));
                }
                
                // Network information
                if let Some(network_info) = &geoip_result.network_info {
                    // ISP/Organization
                    lines.push(Line::from(vec![
                        Span::styled("🏢 ISP: ", Style::default().fg(Color::White)),
                        Span::styled(
                            network_info.isp.clone(),
                            Style::default().fg(Color::Cyan)
                        ),
                    ]));
                    
                    // AS Number
                    if let Some(as_number) = network_info.asn {
                        let as_text = if let Some(as_name) = &network_info.asn_name {
                            format!("AS{} ({})", as_number, as_name)
                        } else {
                            format!("AS{}", as_number)
                        };
                        
                        lines.push(Line::from(vec![
                            Span::styled("🔗 ASN: ", Style::default().fg(Color::White)),
                            Span::styled(
                                as_text,
                                Style::default().fg(Color::Magenta)
                            ),
                        ]));
                    }
                    
                    // Organization (if different from ISP)
                    if network_info.organization != network_info.isp {
                        lines.push(Line::from(vec![
                            Span::styled("🏛️  Org: ", Style::default().fg(Color::White)),
                            Span::styled(
                                network_info.organization.clone(),
                                Style::default().fg(Color::Blue)
                            ),
                        ]));
                    }
                }
                
                // Data source
                lines.push(Line::from(vec![
                    Span::styled("📡 Source: ", Style::default().fg(Color::White)),
                    Span::styled(
                        geoip_result.data_source.clone(),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
                
            } else {
                // No GeoIP data available yet
                lines.push(Line::from(vec![
                    Span::styled("📍 Location: ", Style::default().fg(Color::White)),
                    Span::styled("locating...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🏢 ISP: ", Style::default().fg(Color::White)),
                    Span::styled("identifying...", Style::default().fg(Color::Gray)),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("🔗 ASN: ", Style::default().fg(Color::White)),
                    Span::styled("looking up...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No GeoIP scanner available
            lines.push(Line::from(vec![
                Span::styled("GEOIP: ", Style::default().fg(Color::White)),
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
        (30, 10) // Minimum width and height for GeoIP information
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_pane_creation() {
        let pane = GeoIpPane::new();
        assert_eq!(pane.title(), "geoip");
        assert_eq!(pane.id(), "geoip");
        assert_eq!(pane.min_size(), (30, 10));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
} 