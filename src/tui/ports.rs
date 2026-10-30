use crate::tui::pane::{Detail, Pane};
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use std::any::Any;

const MAX_DISPLAYED_PORTS: usize = 5;
const SECONDS_THRESHOLD_FOR_MINUTES: u64 = 60;
const MILLISECONDS_THRESHOLD_FOR_SECONDS: u128 = 1000;
const MIN_PORTS_PANE_WIDTH: u16 = 25;
const MIN_PORTS_PANE_HEIGHT: u16 = 10;
const PORT_COUNT_WARNING_THRESHOLD: usize = 5;

/// Ports pane displays port scanning results
pub struct PortsPane {
    title: &'static str,
    id: &'static str,
}

impl PortsPane {
    pub fn new() -> Self {
        log::debug!("[tui::ports] new:");
        Self {
            title: "ports",
            id: "ports",
        }
    }
}

impl Default for PortsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for PortsPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::ports] content: width={} detail={:?}", width, detail);

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let wrapped = [0];

        // Ports status header
        lines.push(Line::from(vec![
            Span::styled("🔌 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled("scanning...", Style::default().fg(Color::Gray)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get port scan results and render them
        let port_lines = match state.scanners.get("port") {
            Some(port_state) => {
                // Clone the data we need to avoid lifetime issues
                let result = port_state.result.clone();
                let status = port_state.status.clone();
                let last_updated = port_state.last_updated;

                let (label, label_color) = crate::tui::status_label(&port_state, "scanning...", "completed");
                lines[0] = Line::from(vec![
                    Span::styled("🔌 Status: ", Style::default().fg(Color::Cyan)),
                    Span::styled(label, Style::default().fg(label_color)),
                ]);

                match result {
                    Some(ScanResult::Port(port_result)) => {
                        // Extract the data we need to avoid lifetime issues
                        let open_count = port_result.total_open_ports();
                        let (filtered_ports, closed_ports) = if let Some(primary) = port_result.get_primary_result() {
                            (primary.filtered_ports, primary.closed_ports)
                        } else {
                            (0, 0)
                        };
                        let scan_duration_ms = port_result.total_duration.as_millis();

                        let mut result_lines = Vec::new();

                        // A refresh keeps the previous result on screen; the header says `↻ refreshing`,
                        // so there is no progress to report and no `completed` to claim.
                        if !matches!(status, crate::types::ScanStatus::Running) {
                            result_lines.push(Line::from(vec![
                                Span::styled("📊 Scanned: ", Style::default().fg(Color::White)),
                                Span::styled("completed", Style::default().fg(Color::Green)),
                            ]));
                        }

                        // Open ports count with color coding
                        let port_color = if open_count == 0 {
                            Color::Green
                        } else if open_count <= PORT_COUNT_WARNING_THRESHOLD {
                            Color::Yellow
                        } else {
                            Color::Red
                        };

                        result_lines.push(Line::from(vec![
                            Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                            Span::styled(open_count.to_string(), Style::default().fg(port_color)),
                            Span::styled(" ports", Style::default().fg(Color::White)),
                        ]));

                        // Show open ports from all protocols (clean display)
                        let all_open_ports = port_result.get_all_open_ports();
                        let mut ports_shown = 0;
                        // `ports_shown` gates an early break (display cap), not just an
                        // index, so `.enumerate()` would not preserve the loop semantics.
                        #[allow(clippy::explicit_counter_loop)]
                        for open_port in all_open_ports.iter() {
                            if ports_shown >= MAX_DISPLAYED_PORTS {
                                break;
                            }

                            let service_name = open_port
                                .service
                                .as_ref()
                                .map(|s| s.name.clone())
                                .unwrap_or_else(|| "unknown".to_string());

                            let protocol_str = match open_port.transport {
                                crate::scan::port::Transport::Tcp => "tcp",
                                crate::scan::port::Transport::Udp => "udp",
                            };

                            result_lines.push(Line::from(vec![
                                Span::styled("   ", Style::default()),
                                Span::styled(
                                    format!("{}/{}", open_port.port, protocol_str),
                                    Style::default().fg(Color::Cyan),
                                ),
                                Span::styled(" (", Style::default().fg(Color::Gray)),
                                Span::styled(service_name, Style::default().fg(Color::Yellow)),
                                Span::styled(")", Style::default().fg(Color::Gray)),
                            ]));
                            ports_shown += 1;
                        }

                        if all_open_ports.len() > MAX_DISPLAYED_PORTS {
                            result_lines.push(Line::from(vec![
                                Span::styled("   ", Style::default()),
                                Span::styled(
                                    format!("... and {} more", all_open_ports.len() - MAX_DISPLAYED_PORTS),
                                    Style::default().fg(Color::Gray),
                                ),
                            ]));
                        }

                        // Filtered and closed ports summary
                        if filtered_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                                Span::styled(filtered_ports.to_string(), Style::default().fg(Color::Yellow)),
                            ]));
                        }

                        if closed_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🔴 Closed: ", Style::default().fg(Color::White)),
                                Span::styled(closed_ports.to_string(), Style::default().fg(Color::Gray)),
                            ]));
                        }

                        // Scan duration
                        result_lines.push(Line::from(vec![
                            Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                            Span::styled(
                                if scan_duration_ms > MILLISECONDS_THRESHOLD_FOR_SECONDS {
                                    format!(
                                        "{:.1}s",
                                        scan_duration_ms as f32 / MILLISECONDS_THRESHOLD_FOR_SECONDS as f32
                                    )
                                } else {
                                    format!("{}ms", scan_duration_ms)
                                },
                                Style::default().fg(Color::Gray),
                            ),
                        ]));

                        result_lines
                    }
                    Some(_) => {
                        // Wrong result type (shouldn't happen)
                        vec![Line::from(vec![
                            Span::styled("❌ Error: ", Style::default().fg(Color::White)),
                            Span::styled("wrong result type", Style::default().fg(Color::Red)),
                        ])]
                    }
                    None => {
                        // Still scanning or no results yet
                        match status {
                            crate::types::ScanStatus::Running => {
                                // Show last updated time
                                let seconds_ago = last_updated.elapsed().as_secs();
                                let time_info = if seconds_ago < SECONDS_THRESHOLD_FOR_MINUTES {
                                    format!("{}s ago", seconds_ago)
                                } else {
                                    format!("{}m ago", seconds_ago / SECONDS_THRESHOLD_FOR_MINUTES)
                                };

                                vec![
                                    Line::from(vec![
                                        Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                                        Span::styled("initializing scan...", Style::default().fg(Color::Yellow)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("⏱️  Started: ", Style::default().fg(Color::White)),
                                        Span::styled(time_info, Style::default().fg(Color::Gray)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("🟢 Open: ", Style::default().fg(Color::White)),
                                        Span::styled("detecting...", Style::default().fg(Color::Yellow)),
                                    ]),
                                    Line::from(vec![
                                        Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                                        Span::styled("checking...", Style::default().fg(Color::Yellow)),
                                    ]),
                                ]
                            }
                            // The header carries the failure reason.
                            crate::types::ScanStatus::Failed => vec![],
                            _ => {
                                vec![Line::from(vec![
                                    Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                                    Span::styled("waiting to start...", Style::default().fg(Color::Gray)),
                                ])]
                            }
                        }
                    }
                }
            }
            None => {
                // No port scanner registered
                vec![Line::from(vec![
                    Span::styled("❌ Error: ", Style::default().fg(Color::White)),
                    Span::styled("port scanner not available", Style::default().fg(Color::Red)),
                ])]
            }
        };

        // Add port lines to main lines
        lines.extend(port_lines);

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
        (MIN_PORTS_PANE_WIDTH, MIN_PORTS_PANE_HEIGHT) // Minimum width and height for port information
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
    fn test_ports_pane_creation() {
        let pane = PortsPane::new();
        assert_eq!(pane.title(), "ports");
        assert_eq!(pane.id(), "ports");
        assert_eq!(pane.min_size(), (MIN_PORTS_PANE_WIDTH, MIN_PORTS_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn long_service_name_is_fit_with_ellipsis_in_narrow_terminals() {
        use crate::scan::port::{
            OpenPort, PortData, PortResult, PortState, PortStatus, ScanMode, ServiceInfo, Transport,
        };
        let service = "a-very-long-service-name-from-a-banner-grab-for-clipping";
        let mut result = PortResult::new();
        result.ipv4_status = PortStatus::Success(1);
        result.ipv4_result = Some(PortData {
            target_ip: "192.0.2.1".parse().expect("ip"),
            open_ports: vec![OpenPort {
                port: 8080,
                transport: Transport::Tcp,
                state: PortState::Open,
                service: Some(ServiceInfo {
                    name: service.to_string(),
                    version: None,
                    banner: None,
                    confidence: 1.0,
                }),
                response_time: std::time::Duration::from_millis(5),
            }],
            closed_ports: 0,
            filtered_ports: 0,
            scan_duration: std::time::Duration::from_millis(50),
            scan_mode: ScanMode::Quick,
        });
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            "port".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Port(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &PortsPane::new(),
            &state,
            1,
            2,
            &format!("   8080/tcp ({service})"),
        );
    }

    #[test]
    fn refreshing_ports_pane_shows_no_progress() {
        use crate::scan::port::{PortData, PortResult, PortStatus, ScanMode};
        let mut result = PortResult::new();
        result.ipv4_status = PortStatus::Success(0);
        result.ipv4_result = Some(PortData {
            target_ip: "192.0.2.1".parse().expect("ip"),
            open_ports: vec![],
            closed_ports: 6,
            filtered_ports: 0,
            scan_duration: std::time::Duration::from_millis(50),
            scan_mode: ScanMode::Minimal,
        });
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            "port".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Port(result)),
                error: None,
                status: crate::types::ScanStatus::Running,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        let out = crate::tui::testing::render_pane(&PortsPane::new(), &state, 60, 16, false);
        assert!(out.contains("refreshing"), "{out}");
        assert!(!out.contains("Progress:"), "{out}");
        assert!(!out.contains("Scanned: completed"), "{out}");
    }
}
