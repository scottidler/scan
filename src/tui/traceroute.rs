use crate::tui::pane::{create_block, Pane};
use crate::tui::scrollable::ScrollablePane;
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

const LOCAL_ISP_HOP_THRESHOLD: u8 = 3;
const MID_NETWORK_HOP_THRESHOLD: u8 = 10;
const MIN_TRACEROUTE_PANE_WIDTH: u16 = 35;
const MIN_TRACEROUTE_PANE_HEIGHT: u16 = 20;

/// Traceroute pane displays network path tracing information
pub struct TraceroutePane {
    title: &'static str,
    id: &'static str,
    scroll_offset: u16,
}

impl TraceroutePane {
    pub fn new() -> Self {
        log::debug!("[tui::traceroute] new:");
        Self {
            title: "traceroute",
            id: "traceroute",
            scroll_offset: 0,
        }
    }
}

impl Default for TraceroutePane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TraceroutePane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::traceroute] render: area={}x{} focused={}",
            area.width, area.height, focused);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Traceroute status header
        lines.push(Line::from(vec![
            Span::styled("🗺️  TRACEROUTE: ", Style::default().fg(Color::Cyan)),
            Span::styled("tracing...", Style::default().fg(Color::Gray)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get traceroute results and render them
        if let Some(traceroute_state) = state.scanners.get("traceroute") {
            // Update header with current status
            lines[0] = Line::from(vec![
                Span::styled("🗺️  TRACEROUTE: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match traceroute_state.status {
                        crate::types::ScanStatus::Running => "tracing...",
                        crate::types::ScanStatus::Complete => "traced",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match traceroute_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]);

            if let Some(ScanResult::Traceroute(traceroute_result)) = &traceroute_state.result {
                // Protocol status section
                lines.push(Line::from(vec![
                    Span::styled("🌐 Protocols:", Style::default().fg(Color::Cyan)),
                ]));

                // IPv4 status
                let (ipv4_icon, ipv4_text, ipv4_color) = match &traceroute_result.ipv4_status {
                    crate::scan::traceroute::TracerouteStatus::Success(hops) => ("✅", format!("{} hops", hops), Color::Green),
                    crate::scan::traceroute::TracerouteStatus::Failed(_) => ("❌", "failed".to_string(), Color::Red),
                    crate::scan::traceroute::TracerouteStatus::NoAddress => ("❌", "no address".to_string(), Color::Red),
                    crate::scan::traceroute::TracerouteStatus::NotQueried => ("⚫", "not queried".to_string(), Color::Gray),
                };

                lines.push(Line::from(vec![
                    Span::styled("  IPv4: ", Style::default().fg(Color::White)),
                    Span::styled(ipv4_icon, Style::default().fg(ipv4_color)),
                    Span::styled(" ", Style::default()),
                    Span::styled(ipv4_text, Style::default().fg(ipv4_color)),
                ]));

                // IPv6 status
                let (ipv6_icon, ipv6_text, ipv6_color) = match &traceroute_result.ipv6_status {
                    crate::scan::traceroute::TracerouteStatus::Success(hops) => ("✅", format!("{} hops", hops), Color::Green),
                    crate::scan::traceroute::TracerouteStatus::Failed(_) => ("❌", "failed".to_string(), Color::Red),
                    crate::scan::traceroute::TracerouteStatus::NoAddress => ("❌", "no address".to_string(), Color::Red),
                    crate::scan::traceroute::TracerouteStatus::NotQueried => ("⚫", "not queried".to_string(), Color::Gray),
                };

                lines.push(Line::from(vec![
                    Span::styled("  IPv6: ", Style::default().fg(Color::White)),
                    Span::styled(ipv6_icon, Style::default().fg(ipv6_color)),
                    Span::styled(" ", Style::default()),
                    Span::styled(ipv6_text, Style::default().fg(ipv6_color)),
                ]));

                lines.push(Line::from(""));

                // Show traceroute data for the primary result
                if let Some(primary_data) = traceroute_result.get_primary_result() {
                    let protocol = if primary_data.ipv6 { "IPv6" } else { "IPv4" };

                    lines.push(Line::from(vec![
                        Span::styled(format!("📍 {} Route:", protocol), Style::default().fg(Color::White)),
                        if primary_data.destination_reached {
                            Span::styled(" ✓ reached", Style::default().fg(Color::Green))
                        } else {
                            Span::styled(" ✗ unreached", Style::default().fg(Color::Red))
                        },
                    ]));

                    // Show all hops
                    for hop in &primary_data.hops {
                        // Get first responding IP and best RTT
                        let (ip_display, rtt_display, hop_color) = if let Some(response) = hop.responses.iter().find(|r| !r.timeout) {
                            let ip_str = response.ip_address.as_ref()
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| "*".to_string());
                            let rtt_str = response.rtt.as_ref()
                                .map(|rtt| format!("{}ms", rtt.as_millis()))
                                .unwrap_or_else(|| "*".to_string());
                            (ip_str, rtt_str, Color::Cyan)
                        } else {
                            ("*".to_string(), "timeout".to_string(), Color::Gray)
                        };

                        // Color code hop number based on position
                        let hop_num_color = if hop.hop_number <= LOCAL_ISP_HOP_THRESHOLD {
                            Color::Green // Local/ISP hops
                        } else if hop.hop_number <= MID_NETWORK_HOP_THRESHOLD {
                            Color::Yellow // Mid-network
                        } else {
                            Color::Red // Far hops
                        };

                        lines.push(Line::from(vec![
                            Span::styled(format!("  {:2}: ", hop.hop_number), Style::default().fg(hop_num_color)),
                            Span::styled(ip_display, Style::default().fg(hop_color)),
                            Span::styled(format!(" ({})", rtt_display), Style::default().fg(Color::Gray)),
                        ]));
                    }
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                        Span::styled("All protocols failed", Style::default().fg(Color::Red)),
                    ]));
                }

                // Total scan time
                let scan_time_ms = traceroute_result.total_duration.as_millis();
                lines.push(Line::from(vec![
                    Span::styled("⏱️  Duration: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}ms", scan_time_ms),
                        Style::default().fg(Color::Yellow)
                    ),
                ]));

            } else {
                // No traceroute data available yet - check scanner status
                match traceroute_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 IPv4: ", Style::default().fg(Color::White)),
                            Span::styled("tracing...", Style::default().fg(Color::Yellow)),
                        ]));

                        lines.push(Line::from(vec![
                            Span::styled("📍 IPv6: ", Style::default().fg(Color::White)),
                            Span::styled("tracing...", Style::default().fg(Color::Yellow)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("trace failed", Style::default().fg(Color::Red)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                            Span::styled("waiting to trace...", Style::default().fg(Color::Gray)),
                        ]));
                    }
                }
            }
        } else {
            // No traceroute scanner available
            lines[0] = Line::from(vec![
                Span::styled("🗺️  TRACEROUTE: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(Color::White)),
                Span::styled("Traceroute scanner not available", Style::default().fg(Color::Red)),
            ]));
        }

        // Apply scrolling to lines
        let visible_height = inner_area.height;
        let visible_lines = self.apply_scroll_to_lines(lines, visible_height);

        // Create and render the paragraph
        let paragraph = Paragraph::new(visible_lines)
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
        (MIN_TRACEROUTE_PANE_WIDTH, MIN_TRACEROUTE_PANE_HEIGHT) // Much larger to show all hops (up to ~30 hops)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn is_focusable(&self) -> bool {
        true
    }
}

impl ScrollablePane for TraceroutePane {
    fn scroll_offset(&self) -> u16 {
        self.scroll_offset
    }

    fn set_scroll_offset(&mut self, offset: u16) {
        self.scroll_offset = offset;
    }

    fn calculate_content_lines(&self, state: &AppState) -> u16 {
        // Calculate total lines that would be rendered for traceroute content
        let mut line_count = 0u16;

        // Header line
        line_count += 1;
        // Empty line
        line_count += 1;

        if let Some(traceroute_state) = state.scanners.get("traceroute") {
            if let Some(ScanResult::Traceroute(traceroute_result)) = &traceroute_state.result {
                // Protocol status section (3 lines: header + IPv4 + IPv6)
                line_count += 3;
                // Empty line
                line_count += 1;

                if let Some(primary_data) = traceroute_result.get_primary_result() {
                    // Route header line
                    line_count += 1;
                    // Each hop line
                    line_count += primary_data.hops.len() as u16;
                } else {
                    // Failed status line
                    line_count += 1;
                }
                // Duration line
                line_count += 1;
            } else {
                // Status lines when no data
                line_count += 2;
            }
        } else {
            // No scanner available lines
            line_count += 1;
        }

        line_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traceroute_pane_creation() {
        let pane = TraceroutePane::new();
        assert_eq!(pane.title(), "traceroute");
        assert_eq!(pane.id(), "traceroute");
        assert_eq!(pane.min_size(), (MIN_TRACEROUTE_PANE_WIDTH, MIN_TRACEROUTE_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
}