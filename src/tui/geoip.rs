use crate::tui::pane::{Pane, create_block};
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget, Wrap},
};
use std::any::Any;

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
        log::trace!(
            "[tui::geoip] render: area={}x{} focused={}",
            area.width,
            area.height,
            focused
        );

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let wrapped = [0];

        // GeoIP status header
        lines.push(Line::from(vec![
            Span::styled("🌍 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled("locating...", Style::default().fg(Color::Gray)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get GeoIP results and render them
        if let Some(geoip_state) = state.scanners.get("geoip") {
            // Update header with current status
            let (label, label_color) = crate::tui::status_label(&geoip_state, "locating...", "located");
            lines[0] = Line::from(vec![
                Span::styled("🌍 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::GeoIp(geoip_result)) = &geoip_state.result {
                // Show location data for the primary result
                if let Some(primary_data) = geoip_result.get_primary_result() {
                    // Location
                    if let Some(location) = &primary_data.location {
                        let location_text = format!("{}, {}, {}", location.city, location.region, location.country);

                        lines.push(Line::from(vec![
                            Span::styled("📍 Location: ", Style::default().fg(Color::White)),
                            Span::styled(location_text, Style::default().fg(Color::Green)),
                        ]));

                        // Coordinates
                        lines.push(Line::from(vec![
                            Span::styled("📐 Coords: ", Style::default().fg(Color::White)),
                            Span::styled(
                                format!("{:.4}, {:.4}", location.latitude, location.longitude),
                                Style::default().fg(Color::Yellow),
                            ),
                        ]));

                        // Timezone
                        lines.push(Line::from(vec![
                            Span::styled("🕐 TZ: ", Style::default().fg(Color::White)),
                            Span::styled(location.timezone.clone(), Style::default().fg(Color::Yellow)),
                        ]));
                    }

                    // Network information
                    if let Some(network_info) = &primary_data.network_info {
                        // ISP/Organization
                        lines.push(Line::from(vec![
                            Span::styled("🏢 ISP: ", Style::default().fg(Color::White)),
                            Span::styled(network_info.isp.clone(), Style::default().fg(Color::Cyan)),
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
                                Span::styled(as_text, Style::default().fg(Color::Magenta)),
                            ]));
                        }

                        // Organization (if different from ISP)
                        if network_info.organization != network_info.isp {
                            lines.push(Line::from(vec![
                                Span::styled("🏛️  Org: ", Style::default().fg(Color::White)),
                                Span::styled(network_info.organization.clone(), Style::default().fg(Color::Blue)),
                            ]));
                        }
                    }

                    // Data source
                    lines.push(Line::from(vec![
                        Span::styled("📡 Source: ", Style::default().fg(Color::White)),
                        Span::styled(primary_data.data_source.clone(), Style::default().fg(Color::Gray)),
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
                Span::styled("🌍 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                Span::styled("GeoIP scanner not available", Style::default().fg(Color::Red)),
            ]));
        }

        // Identifiers are fit to the width; the status header and reason rows wrap so their cause
        // stays readable.
        let lines = crate::tui::text::fit_lines_except(lines, inner_area.width, &wrapped);
        let paragraph = Paragraph::new(lines)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false });
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

    fn complete_state(scanner: &str, result: crate::types::ScanResult) -> AppState {
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            scanner.to_string(),
            crate::types::ScanState {
                result: Some(result),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        state
    }

    #[test]
    fn long_location_is_fit_with_ellipsis_in_narrow_terminals() {
        use crate::scan::geoip::{GeoIpData, GeoIpResult, GeoIpStatus, GeoLocation};
        let mut result = GeoIpResult::new();
        result.ipv4_status = GeoIpStatus::Success;
        result.ipv4_result = Some(GeoIpData {
            target_ip: "192.0.2.1".parse().expect("ip"),
            location: Some(GeoLocation {
                country: "United Kingdom of Great Britain and Northern Ireland".to_string(),
                country_code: "GB".to_string(),
                region: "Llanfairpwllgwyngyll".to_string(),
                region_code: "AGY".to_string(),
                city: "Newcastle upon Tyne".to_string(),
                latitude: 54.9783,
                longitude: -1.6178,
                timezone: "Europe/London".to_string(),
            }),
            network_info: None,
            scan_duration: std::time::Duration::from_millis(20),
            data_source: "ip-api.com".to_string(),
        });
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &GeoIpPane::new(),
            &complete_state("geoip", ScanResult::GeoIp(result)),
            1,
            3,
            "📍 Location: Newcastle upon Tyne, Llanfairpwllgwyngyll, United Kingdom of Great Britain and Northern Ireland",
        );
    }
}
