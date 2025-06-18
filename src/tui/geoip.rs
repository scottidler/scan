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
use log;

const MIN_GEOIP_PANE_WIDTH: u16 = 30;
const MIN_GEOIP_PANE_HEIGHT: u16 = 10;

/// GeoIP pane displays geographical and network location information
pub struct GeoIpPane {
    title: &'static str,
    id: &'static str,
}

impl GeoIpPane {
    pub fn new() -> Self {
        log::debug!("[tui::geoip] new:");
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
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::geoip] render: area={}x{} focused={}",
            area.width, area.height, focused);

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
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🌍 GEOIP: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match geoip_state.status {
                        crate::types::ScanStatus::Running => "locating...",
                        crate::types::ScanStatus::Complete => "located",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match geoip_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);

            if let Some(ScanResult::GeoIp(geoip_result)) = &geoip_state.result {
                // Protocol status section
                lines.push(Line::from(vec![
                    Span::styled("🌐 Protocols:", Style::default().fg(Color::Cyan)),
                ]));

                // IPv4 status
                let (ipv4_icon, ipv4_text, ipv4_color) = match &geoip_result.ipv4_status {
                    crate::scan::geoip::GeoIpStatus::Success => ("✅", "located".to_string(), Color::Green),
                    crate::scan::geoip::GeoIpStatus::Failed(_) => ("❌", "failed".to_string(), Color::Red),
                    crate::scan::geoip::GeoIpStatus::NoAddress => ("❌", "no address".to_string(), Color::Red),
                    crate::scan::geoip::GeoIpStatus::NotQueried => ("⚫", "not queried".to_string(), Color::Gray),
                };

                lines.push(Line::from(vec![
                    Span::styled("  IPv4: ", Style::default().fg(Color::White)),
                    Span::styled(ipv4_icon, Style::default().fg(ipv4_color)),
                    Span::styled(" ", Style::default()),
                    Span::styled(ipv4_text, Style::default().fg(ipv4_color)),
                ]));

                // IPv6 status
                let (ipv6_icon, ipv6_text, ipv6_color) = match &geoip_result.ipv6_status {
                    crate::scan::geoip::GeoIpStatus::Success => ("✅", "located".to_string(), Color::Green),
                    crate::scan::geoip::GeoIpStatus::Failed(_) => ("❌", "failed".to_string(), Color::Red),
                    crate::scan::geoip::GeoIpStatus::NoAddress => ("❌", "no address".to_string(), Color::Red),
                    crate::scan::geoip::GeoIpStatus::NotQueried => ("⚫", "not queried".to_string(), Color::Gray),
                };

                lines.push(Line::from(vec![
                    Span::styled("  IPv6: ", Style::default().fg(Color::White)),
                    Span::styled(ipv6_icon, Style::default().fg(ipv6_color)),
                    Span::styled(" ", Style::default()),
                    Span::styled(ipv6_text, Style::default().fg(ipv6_color)),
                ]));

                lines.push(Line::from(""));

                // Show location data for the primary result
                if let Some(primary_data) = geoip_result.get_primary_result() {
                    let protocol = if primary_data.target_ip.is_ipv6() { "IPv6" } else { "IPv4" };

                    // Location
                    if let Some(location) = &primary_data.location {
                        let location_text = format!("{}, {}, {}", location.city, location.region, location.country);

                        lines.push(Line::from(vec![
                            Span::styled(format!("📍 {} Location: ", protocol), Style::default().fg(Color::White)),
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
                    if let Some(network_info) = &primary_data.network_info {
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
                            primary_data.data_source.clone(),
                            Style::default().fg(Color::Gray)
                        ),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                        Span::styled("All protocols failed", Style::default().fg(Color::Red)),
                    ]));
                }

            } else {
                // No GeoIP data available yet - check scanner status
                match geoip_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Location: ", Style::default().fg(Color::White)),
                            Span::styled("locating...", Style::default().fg(Color::Yellow)),
                        ]));

                        lines.push(Line::from(vec![
                            Span::styled("🏢 ISP: ", Style::default().fg(Color::White)),
                            Span::styled("identifying...", Style::default().fg(Color::Yellow)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("location lookup failed", Style::default().fg(Color::Red)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("waiting to locate...", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
            }
        } else {
            // No GeoIP scanner available
            lines[0] = Line::from(vec![
                Span::styled("🌍 GEOIP: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                Span::styled("GeoIP scanner not available", Style::default().fg(Color::Red)),
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
        (MIN_GEOIP_PANE_WIDTH, MIN_GEOIP_PANE_HEIGHT) // Minimum width and height for GeoIP information
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
    fn test_geoip_pane_creation() {
        let pane = GeoIpPane::new();
        assert_eq!(pane.title(), "geoip");
        assert_eq!(pane.id(), "geoip");
        assert_eq!(pane.min_size(), (MIN_GEOIP_PANE_WIDTH, MIN_GEOIP_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
}