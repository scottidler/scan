use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
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

/// `<label>: <value>`, indented under a zoomed family.
fn field_line(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label}: "), Style::default().fg(theme::LABEL)),
        Span::styled(value, Style::default().fg(theme::MUTED)),
    ])
}

/// Why a family has no lookup data, and its color: a failure is a fault, the rest are not.
fn status_text(status: &crate::scan::geoip::GeoIpStatus) -> (String, Color) {
    use crate::scan::geoip::{GeoIpStatus, NotGeolocatable};
    match status {
        GeoIpStatus::Success => ("located".to_string(), theme::GOOD),
        GeoIpStatus::Failed(reason) => (format!("failed: {reason}"), theme::BAD),
        GeoIpStatus::NoAddress => ("no address".to_string(), theme::MUTED),
        GeoIpStatus::NotQueried => ("not queried".to_string(), theme::MUTED),
        GeoIpStatus::NotGeolocatable(kind) => (NotGeolocatable(*kind).to_string(), theme::MUTED),
    }
}

/// Zoomed only: every field of each family's lookup, or why the family has none.
fn zoomed_lines(result: &crate::scan::geoip::GeoIpResult) -> Vec<Line<'static>> {
    let families = [
        ("IPv4", &result.ipv4_result, &result.ipv4_status),
        ("IPv6", &result.ipv6_result, &result.ipv6_status),
    ];
    let mut lines = Vec::new();
    for (name, data, status) in families {
        lines.push(Line::from(""));
        let Some(data) = data else {
            let (text, color) = status_text(status);
            lines.push(Line::from(vec![
                Span::styled(format!("{name}: "), Style::default().fg(theme::VALUE)),
                Span::styled(text, Style::default().fg(color)),
            ]));
            continue;
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{name}: "), Style::default().fg(theme::VALUE)),
            Span::styled(data.target_ip.to_string(), Style::default().fg(theme::VALUE)),
        ]));
        if let Some(location) = &data.location {
            lines.push(field_line("City", location.city.clone()));
            lines.push(field_line(
                "Region",
                format!("{} ({})", location.region, location.region_code),
            ));
            lines.push(field_line(
                "Country",
                format!("{} ({})", location.country, location.country_code),
            ));
            lines.push(field_line(
                "Coords",
                format!("{:.4}, {:.4}", location.latitude, location.longitude),
            ));
            lines.push(field_line("Timezone", location.timezone.clone()));
        }
        if let Some(network) = &data.network_info {
            lines.push(field_line("ISP", network.isp.clone()));
            lines.push(field_line("Organization", network.organization.clone()));
            if let Some(asn) = network.asn {
                lines.push(field_line("ASN", format!("AS{asn}")));
            }
            if let Some(asn_name) = &network.asn_name {
                lines.push(field_line("AS name", asn_name.clone()));
            }
            if let Some(range) = &network.network_range {
                lines.push(field_line("Network", range.clone()));
            }
        }
        lines.push(field_line("Source", data.data_source.clone()));
        lines.push(field_line("Lookup", format!("{}ms", data.scan_duration.as_millis())));
    }
    lines
}

impl Pane for GeoIpPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::geoip] content: width={} detail={:?}", width, detail);

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let wrapped = [0];

        // GeoIP status header
        lines.push(Line::from(vec![
            Span::styled("🌍 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled("locating...", Style::default().fg(theme::MUTED)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get GeoIP results and render them
        if let Some(geoip_state) = state.scanners.get("geoip") {
            // An address with no public location was never looked up, so it is not `located`.
            let not_geolocatable = match &geoip_state.result {
                Some(ScanResult::GeoIp(geoip_result)) if !geoip_result.has_any_success() => {
                    geoip_result.not_geolocatable()
                }
                _ => None,
            };
            let complete = if not_geolocatable.is_some() { "not geolocatable" } else { "located" };
            let (label, mut label_color) = crate::tui::status_label(&geoip_state, "locating...", complete);
            if not_geolocatable.is_some() && matches!(geoip_state.status, crate::types::ScanStatus::Complete) {
                label_color = theme::MUTED;
            }
            lines[0] = Line::from(vec![
                Span::styled("🌍 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::GeoIp(geoip_result)) = &geoip_state.result {
                // Show location data for the primary result
                if let Some(primary_data) = geoip_result.get_primary_result() {
                    // Location
                    if let Some(location) = &primary_data.location {
                        let location_text = format!("{}, {}, {}", location.city, location.region, location.country);

                        lines.push(Line::from(vec![
                            Span::styled("📍 Location: ", Style::default().fg(theme::LABEL)),
                            Span::styled(location_text, Style::default().fg(theme::GOOD)),
                        ]));

                        // Coordinates
                        lines.push(Line::from(vec![
                            Span::styled("📐 Coords: ", Style::default().fg(theme::LABEL)),
                            Span::styled(
                                format!("{:.4}, {:.4}", location.latitude, location.longitude),
                                Style::default().fg(theme::WARN),
                            ),
                        ]));

                        // Timezone
                        lines.push(Line::from(vec![
                            Span::styled("🕐 TZ: ", Style::default().fg(theme::LABEL)),
                            Span::styled(location.timezone.clone(), Style::default().fg(theme::WARN)),
                        ]));
                    }

                    // Network information
                    if let Some(network_info) = &primary_data.network_info {
                        // ISP/Organization
                        lines.push(Line::from(vec![
                            Span::styled("🏢 ISP: ", Style::default().fg(theme::LABEL)),
                            Span::styled(network_info.isp.clone(), Style::default().fg(theme::VALUE)),
                        ]));

                        // AS Number
                        if let Some(as_number) = network_info.asn {
                            let as_text = if let Some(as_name) = &network_info.asn_name {
                                format!("AS{} ({})", as_number, as_name)
                            } else {
                                format!("AS{}", as_number)
                            };

                            lines.push(Line::from(vec![
                                Span::styled("🔗 ASN: ", Style::default().fg(theme::LABEL)),
                                Span::styled(as_text, Style::default().fg(theme::ACCENT)),
                            ]));
                        }

                        // Organization (if different from ISP)
                        if network_info.organization != network_info.isp {
                            lines.push(Line::from(vec![
                                Span::styled("🏦  Org: ", Style::default().fg(theme::LABEL)),
                                Span::styled(network_info.organization.clone(), Style::default().fg(theme::ACCENT)),
                            ]));
                        }
                    }

                    // Data source
                    lines.push(Line::from(vec![
                        Span::styled("📡 Source: ", Style::default().fg(theme::LABEL)),
                        Span::styled(primary_data.data_source.clone(), Style::default().fg(theme::MUTED)),
                    ]));

                    if detail == Detail::Zoomed {
                        lines.extend(zoomed_lines(geoip_result));
                    }
                } else if let Some(not_geolocatable) = not_geolocatable {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Location: ", Style::default().fg(theme::LABEL)),
                        Span::styled(not_geolocatable.to_string(), Style::default().fg(theme::MUTED)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                        Span::styled("All protocols failed", Style::default().fg(theme::BAD)),
                    ]));
                }
            } else {
                // No GeoIP data available yet - check scanner status
                match geoip_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Location: ", Style::default().fg(theme::LABEL)),
                            Span::styled("locating...", Style::default().fg(theme::WARN)),
                        ]));

                        lines.push(Line::from(vec![
                            Span::styled("🏢 ISP: ", Style::default().fg(theme::LABEL)),
                            Span::styled("identifying...", Style::default().fg(theme::WARN)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled("location lookup failed", Style::default().fg(theme::BAD)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled("waiting to locate...", Style::default().fg(theme::MUTED)),
                        ]));
                    }
                }
            }
        } else {
            // No GeoIP scanner available
            lines[0] = Line::from(vec![
                Span::styled("🌍 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled("unavailable", Style::default().fg(theme::BAD)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("GeoIP scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        // Identifiers are fit to the width; the status header and reason rows wrap so their cause
        // stays readable.
        crate::tui::text::to_rows(lines, width, detail, &wrapped)
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

    #[test]
    fn loopback_renders_not_geolocatable_in_gray_never_located() {
        use crate::scan::geoip::{AddressKind, GeoIpResult, GeoIpStatus};
        let mut result = GeoIpResult::new();
        result.ipv4_status = GeoIpStatus::NotGeolocatable(AddressKind::Loopback);
        result.ipv6_status = GeoIpStatus::NotGeolocatable(AddressKind::Loopback);
        let state = complete_state("geoip", ScanResult::GeoIp(result));
        let out = crate::tui::testing::render_pane(&GeoIpPane::new(), &state, 80, 12, false);
        assert!(out.contains("not geolocatable (loopback address)"), "{out}");
        assert!(!out.contains("located"), "{out}");
        assert!(!out.contains("failed"), "{out}");

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 12)).expect("TestBackend terminal");
        terminal
            .draw(|frame| GeoIpPane::new().render(frame, frame.area(), &state, false))
            .expect("draw pane");
        let buffer = terminal.backend().buffer();
        let row = (0..12)
            .find(|&y| {
                (0..80)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .contains("not geolocatable (")
            })
            .expect("label row");
        let x = (0..80)
            .find(|&x| buffer[(x, row)].symbol() == "(")
            .expect("label start");
        assert_eq!(buffer[(x, row)].fg, Color::Gray);
    }

    #[test]
    fn zoomed_content_shows_every_field_of_each_family() {
        use crate::scan::geoip::{AddressKind, GeoIpData, GeoIpResult, GeoIpStatus, GeoLocation, NetworkInfo};
        use crate::tui::pane::Detail;
        let mut result = GeoIpResult::new();
        result.ipv4_status = GeoIpStatus::Success;
        result.ipv4_result = Some(GeoIpData {
            target_ip: "192.0.2.1".parse().expect("ip"),
            location: Some(GeoLocation {
                country: "United States".to_string(),
                country_code: "US".to_string(),
                region: "Oregon".to_string(),
                region_code: "OR".to_string(),
                city: "Portland".to_string(),
                latitude: 45.5,
                longitude: -122.6,
                timezone: "America/Los_Angeles".to_string(),
            }),
            network_info: Some(NetworkInfo {
                isp: "Example ISP".to_string(),
                organization: "Example ISP".to_string(),
                asn: Some(64500),
                asn_name: Some("EXAMPLE-AS".to_string()),
                network_range: Some("192.0.2.0/24".to_string()),
            }),
            scan_duration: std::time::Duration::from_millis(20),
            data_source: "ip-api.com".to_string(),
        });
        result.ipv6_status = GeoIpStatus::NotGeolocatable(AddressKind::Documentation);
        let state = complete_state("geoip", ScanResult::GeoIp(result));
        let pane = GeoIpPane::new();
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Zoomed).join("\n");
        for expected in [
            "IPv4: 192.0.2.1",
            "Region: Oregon (OR)",
            "Country: United States (US)",
            "Network: 192.0.2.0/24",
            "AS name: EXAMPLE-AS",
            "IPv6: not geolocatable (documentation address)",
        ] {
            assert!(zoomed.contains(expected), "{expected}:\n{zoomed}");
        }
        let normal = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Normal).join("\n");
        assert!(!normal.contains("192.0.2.0/24"), "{normal}");
    }
}
