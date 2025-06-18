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

const MAX_DISPLAYED_PORTS: usize = 5;
const QUICK_SCAN_EXPECTED_PORTS: usize = 100;
const STANDARD_SCAN_EXPECTED_PORTS: usize = 1000;
const MAX_PROGRESS_PERCENT: f32 = 99.0;
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
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::ports] render: area={}x{} focused={}",
            area.width, area.height, focused);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

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

                match result {
                    Some(ScanResult::Port(port_result)) => {
                        // Update header with current status
                        lines[0] = Line::from(vec![
                            Span::styled("🔌 Status: ", Style::default().fg(Color::Cyan)),
                            Span::styled(
                                match status {
                                    crate::types::ScanStatus::Running => "scanning...",
                                    crate::types::ScanStatus::Complete => "completed",
                                    crate::types::ScanStatus::Failed => "failed",
                                },
                                Style::default().fg(match status {
                                    crate::types::ScanStatus::Running => Color::Yellow,
                                    crate::types::ScanStatus::Complete => Color::Green,
                                    crate::types::ScanStatus::Failed => Color::Red,
                                })
                            ),
                        ]);

                        // Extract the data we need to avoid lifetime issues
                        let open_count = port_result.total_open_ports();
                        let (filtered_ports, closed_ports) = if let Some(primary) = port_result.get_primary_result() {
                            (primary.filtered_ports, primary.closed_ports)
                        } else {
                            (0, 0)
                        };
                        let scan_duration_ms = port_result.total_duration.as_millis();

                        // Calculate estimated progress (rough estimate based on duration and typical scan times)
                        let progress_info = if matches!(status, crate::types::ScanStatus::Running) {
                            // Estimate progress based on scan duration and typical port scan timing
                            let total_expected = if let Some(primary) = port_result.get_primary_result() {
                            match primary.scan_mode {
                                    crate::scan::port::ScanMode::Minimal => crate::scan::port::get_minimal_ports().len(),
                                    crate::scan::port::ScanMode::Quick => QUICK_SCAN_EXPECTED_PORTS,
                                    crate::scan::port::ScanMode::Standard => STANDARD_SCAN_EXPECTED_PORTS,
                                    crate::scan::port::ScanMode::Custom(ref ports) => ports.len(),
                                }
                            } else {
                                QUICK_SCAN_EXPECTED_PORTS
                            };
                            let scanned_so_far = open_count + filtered_ports as usize + closed_ports as usize;
                            let progress_percent = ((scanned_so_far as f32 / total_expected as f32) * 100.0).min(MAX_PROGRESS_PERCENT) as u32;
                            Some((scanned_so_far, total_expected, progress_percent))
                        } else {
                            None
                        };

                        let mut result_lines = Vec::new();

                        // Progress information if actively scanning
                        if let Some((scanned, total, percent)) = progress_info {
                            result_lines.push(Line::from(vec![
                                Span::styled("📊 Progress: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    format!("{}% ({}/{})", percent, scanned, total),
                                    Style::default().fg(Color::Yellow)
                                ),
                            ]));
                        } else {
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
                            Span::styled(
                                open_count.to_string(),
                                Style::default().fg(port_color)
                            ),
                            Span::styled(" ports", Style::default().fg(Color::White)),
                        ]));

                        // Show open ports from all protocols (clean display)
                        let all_open_ports = port_result.get_all_open_ports();
                        let mut ports_shown = 0;
                        for open_port in all_open_ports.iter() {
                            if ports_shown >= MAX_DISPLAYED_PORTS { break; }

                            let service_name = open_port.service.as_ref()
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
                                    Style::default().fg(Color::Cyan)
                                ),
                                Span::styled(" (", Style::default().fg(Color::Gray)),
                                Span::styled(
                                    service_name,
                                    Style::default().fg(Color::Yellow)
                                ),
                                Span::styled(")", Style::default().fg(Color::Gray)),
                            ]));
                            ports_shown += 1;
                        }

                        if all_open_ports.len() > MAX_DISPLAYED_PORTS {
                            result_lines.push(Line::from(vec![
                                Span::styled("   ", Style::default()),
                                Span::styled(
                                    format!("... and {} more", all_open_ports.len() - MAX_DISPLAYED_PORTS),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        }



                        // Filtered and closed ports summary
                        if filtered_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🟡 Filtered: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    filtered_ports.to_string(),
                                    Style::default().fg(Color::Yellow)
                                ),
                            ]));
                        }

                        if closed_ports > 0 {
                            result_lines.push(Line::from(vec![
                                Span::styled("🔴 Closed: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    closed_ports.to_string(),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        }

                        // Scan duration
                        result_lines.push(Line::from(vec![
                            Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                            Span::styled(
                                if scan_duration_ms > MILLISECONDS_THRESHOLD_FOR_SECONDS {
                                    format!("{:.1}s", scan_duration_ms as f32 / MILLISECONDS_THRESHOLD_FOR_SECONDS as f32)
                                } else {
                                    format!("{}ms", scan_duration_ms)
                                },
                                Style::default().fg(Color::Gray)
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
                            crate::types::ScanStatus::Failed => {
                                vec![Line::from(vec![
                                    Span::styled("❌ Status: ", Style::default().fg(Color::White)),
                                    Span::styled("scan failed", Style::default().fg(Color::Red)),
                                ])]
                            }
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
}