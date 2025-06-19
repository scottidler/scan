use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanStatus};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};
use std::any::Any;
use log;

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * 60; // 3600
const MIN_TARGET_PANE_WIDTH: u16 = 25;
const MIN_TARGET_PANE_HEIGHT: u16 = 12;

/// TARGET pane displays basic target information and scanner status overview
pub struct TargetPane {
    title: &'static str,
    id: &'static str,
}

impl TargetPane {
    pub fn new() -> Self {
        log::debug!("[tui::target] new:");
        Self {
            title: "target",
            id: "target",
        }
    }

    /// Format elapsed time in a human-readable way
    fn format_elapsed(elapsed: std::time::Duration) -> String {
        let secs = elapsed.as_secs();
        if secs < SECONDS_PER_MINUTE {
            format!("{}s", secs)
        } else if secs < SECONDS_PER_HOUR {
            format!("{}m {}s", secs / SECONDS_PER_MINUTE, secs % SECONDS_PER_MINUTE)
        } else {
            format!("{}h {}m", secs / SECONDS_PER_HOUR, (secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE)
        }
    }

    /// Get status icon and color for a scanner status
    fn status_icon_and_color(status: &ScanStatus) -> (&'static str, Color) {
        match status {
            ScanStatus::Running => ("🔄", Color::Yellow),
            ScanStatus::Complete => ("✅", Color::Green),
            ScanStatus::Failed => ("❌", Color::Red),
        }
    }

    /// Calculate scanner statistics
    fn calculate_stats(state: &AppState) -> (usize, usize, usize, usize) {
        let total = state.scanners.len();
        let mut running = 0;
        let mut complete = 0;
        let mut failed = 0;

        for scanner in state.scanners.iter() {
            match scanner.status {
                ScanStatus::Running => running += 1,
                ScanStatus::Complete => complete += 1,
                ScanStatus::Failed => failed += 1,
            }
        }

        log::trace!("[tui::target] calculate_stats: total={} running={} complete={} failed={}",
            total, running, complete, failed);

        (total, running, complete, failed)
    }
}

impl Default for TargetPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TargetPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::target] render: area={}x{} focused={} target={}",
            area.width, area.height, focused, state.target);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Target information
        lines.push(Line::from(vec![
            Span::styled("🎯 ", Style::default().fg(Color::Cyan)),
            Span::styled(&state.target, Style::default().fg(Color::White)),
        ]));

        // Protocol information
        lines.push(Line::from(vec![
            Span::styled("🔗 ", Style::default().fg(Color::Magenta)),
            Span::styled("Protocol: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{} (Press 'p' to cycle)", state.protocol_display()),
                Style::default().fg(Color::Cyan)
            ),
        ]));

        // IPv4/IPv6 Protocol Status - Single source of truth
        match state.scanners.get("dns") {
            Some(dns_state) => {
                match &dns_state.result {
                    Some(crate::types::ScanResult::Dns(dns_result)) => {
                        // IPv4 status
                        let ipv4_selected = state.protocol.includes_ipv4();
                        let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " }; // Chevron or 2 spaces for alignment

                        if ipv4_selected {
                            if !dns_result.A.is_empty() {
                                let ip = &dns_result.A[0].value;
                                log::trace!("[tui::target] ipv4_resolved: ip={}", ip);
                                lines.push(Line::from(vec![
                                    Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                    Span::styled("✅ IPv4: ", Style::default().fg(Color::Green)),
                                    Span::styled(ip.to_string(), Style::default().fg(Color::Green)),
                                ]));
                            } else {
                                log::trace!("[tui::target] ipv4_no_records:");
                                lines.push(Line::from(vec![
                                    Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                    Span::styled("❌ IPv4: ", Style::default().fg(Color::Red)),
                                    Span::styled("no data", Style::default().fg(Color::Red)),
                                ]));
                            }
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                                Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                Span::styled("disabled", Style::default().fg(Color::Gray)),
                            ]));
                        }

                        // IPv6 status
                        let ipv6_selected = state.protocol.includes_ipv6();
                        let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " }; // Chevron or 2 spaces for alignment

                        if ipv6_selected {
                            if !dns_result.AAAA.is_empty() {
                                let ip = &dns_result.AAAA[0].value;
                                log::trace!("[tui::target] ipv6_resolved: ip={}", ip);
                                lines.push(Line::from(vec![
                                    Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                    Span::styled("✅ IPv6: ", Style::default().fg(Color::Green)),
                                    Span::styled(ip.to_string(), Style::default().fg(Color::Green)),
                                ]));
                            } else {
                                log::trace!("[tui::target] ipv6_no_records:");
                                lines.push(Line::from(vec![
                                    Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                    Span::styled("❌ IPv6: ", Style::default().fg(Color::Red)),
                                    Span::styled("no data", Style::default().fg(Color::Red)),
                                ]));
                            }
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                                Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                Span::styled("disabled", Style::default().fg(Color::Gray)),
                            ]));
                        }
                    }
                    None => {
                        match dns_state.status {
                            ScanStatus::Running => {
                                log::trace!("[tui::target] dns_resolving:");

                                // IPv4 status during resolution
                                let ipv4_selected = state.protocol.includes_ipv4();
                                let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " };

                                if ipv4_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("🔄 IPv4: ", Style::default().fg(Color::Yellow)),
                                        Span::styled("resolving...", Style::default().fg(Color::Yellow)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }

                                // IPv6 status during resolution
                                let ipv6_selected = state.protocol.includes_ipv6();
                                let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " };

                                if ipv6_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("🔄 IPv6: ", Style::default().fg(Color::Yellow)),
                                        Span::styled("resolving...", Style::default().fg(Color::Yellow)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }
                            }
                            ScanStatus::Failed => {
                                log::trace!("[tui::target] dns_failed:");

                                // IPv4 status during failure
                                let ipv4_selected = state.protocol.includes_ipv4();
                                let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " };

                                if ipv4_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("❌ IPv4: ", Style::default().fg(Color::Red)),
                                        Span::styled("resolution failed", Style::default().fg(Color::Red)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }

                                // IPv6 status during failure
                                let ipv6_selected = state.protocol.includes_ipv6();
                                let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " };

                                if ipv6_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("❌ IPv6: ", Style::default().fg(Color::Red)),
                                        Span::styled("resolution failed", Style::default().fg(Color::Red)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }
                            }
                            _ => {
                                log::trace!("[tui::target] dns_waiting:");

                                // IPv4 status while waiting
                                let ipv4_selected = state.protocol.includes_ipv4();
                                let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " };

                                if ipv4_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                        Span::styled("waiting to resolve...", Style::default().fg(Color::Gray)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }

                                // IPv6 status while waiting
                                let ipv6_selected = state.protocol.includes_ipv6();
                                let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " };

                                if ipv6_selected {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                        Span::styled("waiting to resolve...", Style::default().fg(Color::Gray)),
                                    ]));
                                } else {
                                    lines.push(Line::from(vec![
                                        Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                                    ]));
                                }
                            }
                        }
                    }
                    Some(_) => {
                        // Non-DNS result (shouldn't happen)
                        log::warn!("[tui::target] dns_unexpected_result_type:");

                        // IPv4 status during error
                        let ipv4_selected = state.protocol.includes_ipv4();
                        let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " };

                        if ipv4_selected {
                            lines.push(Line::from(vec![
                                Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                                Span::styled("❌ IPv4: ", Style::default().fg(Color::Red)),
                                Span::styled("error", Style::default().fg(Color::Red)),
                            ]));
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                                Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                                Span::styled("disabled", Style::default().fg(Color::Gray)),
                            ]));
                        }

                        // IPv6 status during error
                        let ipv6_selected = state.protocol.includes_ipv6();
                        let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " };

                        if ipv6_selected {
                            lines.push(Line::from(vec![
                                Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                                Span::styled("❌ IPv6: ", Style::default().fg(Color::Red)),
                                Span::styled("error", Style::default().fg(Color::Red)),
                            ]));
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                                Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                                Span::styled("disabled", Style::default().fg(Color::Gray)),
                            ]));
                        }
                    }
                }
            }
            None => {
                // No DNS scanner state yet
                log::trace!("[tui::target] dns_no_state:");

                // IPv4 status when no DNS state
                let ipv4_selected = state.protocol.includes_ipv4();
                let ipv4_arrow = if ipv4_selected { "▶ " } else { "  " };

                if ipv4_selected {
                    lines.push(Line::from(vec![
                        Span::styled(ipv4_arrow, Style::default().fg(Color::Green)),
                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                        Span::styled("initializing...", Style::default().fg(Color::Gray)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(ipv4_arrow, Style::default().fg(Color::Gray)),
                        Span::styled("⚫ IPv4: ", Style::default().fg(Color::Gray)),
                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                    ]));
                }

                // IPv6 status when no DNS state
                let ipv6_selected = state.protocol.includes_ipv6();
                let ipv6_arrow = if ipv6_selected { "▶ " } else { "  " };

                if ipv6_selected {
                    lines.push(Line::from(vec![
                        Span::styled(ipv6_arrow, Style::default().fg(Color::Green)),
                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                        Span::styled("initializing...", Style::default().fg(Color::Gray)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(ipv6_arrow, Style::default().fg(Color::Gray)),
                        Span::styled("⚫ IPv6: ", Style::default().fg(Color::Gray)),
                        Span::styled("disabled", Style::default().fg(Color::Gray)),
                    ]));
                }
            }
        }

        // Empty line for spacing
        lines.push(Line::from(""));

        // Scanner statistics
        let (total, running, complete, failed) = Self::calculate_stats(state);

        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{}/{} scanners", complete, total),
                if failed > 0 {
                    Style::default().fg(Color::Red)
                } else if running > 0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));

        // Show all scanner statuses
        for scanner in state.scanners.iter() {
            let (icon, color) = Self::status_icon_and_color(&scanner.status);
            let elapsed = scanner.last_updated.elapsed();

            lines.push(Line::from(vec![
                Span::styled(format!("{} ", icon), Style::default().fg(color)),
                Span::styled(
                    format!("{}: ", scanner.key().to_uppercase()),
                    Style::default().fg(Color::White)
                ),
                Span::styled(
                    Self::format_elapsed(elapsed),
                    Style::default().fg(Color::Gray)
                ),
            ]));
        }

        log::trace!("[tui::target] content_prepared: lines={} scanners={}",
            lines.len(), state.scanners.len());

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
        (MIN_TARGET_PANE_WIDTH, MIN_TARGET_PANE_HEIGHT) // Larger to show all scanners
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
    use crate::types::{ScanState, ScanStatus};
    use crate::target::Protocol;
    use dashmap::DashMap;
    use std::time::Instant;

    #[test]
    fn test_target_pane_creation() {
        let pane = TargetPane::new();
        assert_eq!(pane.title(), "target");
        assert_eq!(pane.id(), "target");
        assert_eq!(pane.min_size(), (MIN_TARGET_PANE_WIDTH, MIN_TARGET_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn test_format_elapsed() {
        use std::time::Duration;

        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(30)), "30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(90)), "1m 30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(3661)), "1h 1m");
    }

    #[test]
    fn test_status_icon_and_color() {
        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Running);
        assert_eq!(icon, "🔄");
        assert_eq!(color, Color::Yellow);

        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Complete);
        assert_eq!(icon, "✅");
        assert_eq!(color, Color::Green);

        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Failed);
        assert_eq!(icon, "❌");
        assert_eq!(color, Color::Red);
    }

    #[test]
    fn test_calculate_stats() {
        let state = AppState {
            target: "example.com".to_string(),
            scanners: DashMap::new(),
            protocol: Protocol::Both,
        };

        // Add some test scanner states
        state.scanners.insert("ping".to_string(), ScanState {
            result: None,
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: Default::default(),
        });

        state.scanners.insert("dns".to_string(), ScanState {
            result: None,
            error: None,
            status: ScanStatus::Running,
            last_updated: Instant::now(),
            history: Default::default(),
        });

        state.scanners.insert("http".to_string(), ScanState {
            result: None,
            error: Some(eyre::eyre!("Connection failed")),
            status: ScanStatus::Failed,
            last_updated: Instant::now(),
            history: Default::default(),
        });

        let (total, running, complete, failed) = TargetPane::calculate_stats(&state);
        assert_eq!(total, 3);
        assert_eq!(running, 1);
        assert_eq!(complete, 1);
        assert_eq!(failed, 1);
    }
}
