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

const EXCELLENT_LATENCY_THRESHOLD_MS: u128 = 50;
const GOOD_LATENCY_THRESHOLD_MS: u128 = 100;
const FAIR_LATENCY_THRESHOLD_MS: u128 = 150;
const POOR_LATENCY_THRESHOLD_MS: u128 = 200;
const FAST_CONNECTION_THRESHOLD_MS: u128 = 100;
const SLOW_CONNECTION_THRESHOLD_MS: u128 = 300;

const MAJOR_PACKET_LOSS_THRESHOLD: f32 = 5.0;
const SEVERE_PACKET_LOSS_THRESHOLD: f32 = 50.0;
const HTTP_SUCCESS_STATUS: u16 = 200;
const HTTP_CLIENT_ERROR_THRESHOLD: u16 = 400;

const MIN_CONNECTIVITY_PANE_WIDTH: u16 = 25;
const MIN_CONNECTIVITY_PANE_HEIGHT: u16 = 8;

/// CONNECTIVITY pane displays real-time ping latency and network connectivity metrics
pub struct ConnectivityPane {
    title: &'static str,
    id: &'static str,
}

impl ConnectivityPane {
    pub fn new() -> Self {
        log::debug!("[tui::connectivity] new:");
        Self {
            title: "connectivity",
            id: "connectivity",
        }
    }


}

impl Default for ConnectivityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for ConnectivityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::connectivity] render: area={}x{} focused={}",
            area.width, area.height, focused);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Get ping results and render them
        if let Some(ping_state) = state.scanners.get("ping") {
            match &ping_state.result {
                Some(ScanResult::Ping(ping)) => {
                    // Use the best available result for display
                    if let Some(best_latency) = ping.get_best_latency() {
                        let latency_ms = best_latency.as_millis();
                        let primary_result = ping.get_primary_result();
                        let loss_percent = primary_result.map(|r| r.packet_loss * 100.0).unwrap_or(0.0);

                        // Connection status header with color coding
                        let status_color = if loss_percent == 0.0 && latency_ms < FAST_CONNECTION_THRESHOLD_MS {
                            Color::Green
                        } else if loss_percent < MAJOR_PACKET_LOSS_THRESHOLD && latency_ms < SLOW_CONNECTION_THRESHOLD_MS {
                            Color::Yellow
                        } else {
                            Color::Red
                        };

                        let status_text = if loss_percent == 0.0 {
                            "connected"
                        } else if loss_percent < SEVERE_PACKET_LOSS_THRESHOLD {
                            "unstable"
                        } else {
                            "poor"
                        };

                        lines.push(Line::from(vec![
                            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                            Span::styled(status_text, Style::default().fg(status_color)),
                        ]));

                        // Show protocol results
                        lines.push(Line::from(""));

                        // IPv4 status
                        match &ping.ipv4_status {
                            crate::scan::ping::PingStatus::Success(latency) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("✅", Style::default().fg(Color::Green)),
                                    Span::styled(format!(" {}ms", latency.as_millis()), Style::default().fg(Color::Green)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::NotQueried => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("⏭️ ", Style::default().fg(Color::Gray)),
                                    Span::styled("not queried", Style::default().fg(Color::Gray)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::NoAddress => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("❌", Style::default().fg(Color::Red)),
                                    Span::styled(" no address", Style::default().fg(Color::Red)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::ToolMissing(tool) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("🛠️ ", Style::default().fg(Color::Yellow)),
                                    Span::styled(format!("{} missing", tool), Style::default().fg(Color::Yellow)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::Failed(_) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("❌", Style::default().fg(Color::Red)),
                                    Span::styled(" failed", Style::default().fg(Color::Red)),
                                ]));
                            }
                        }

                        // IPv6 status
                        match &ping.ipv6_status {
                            crate::scan::ping::PingStatus::Success(latency) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("✅", Style::default().fg(Color::Green)),
                                    Span::styled(format!(" {}ms", latency.as_millis()), Style::default().fg(Color::Green)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::NotQueried => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("⏭️ ", Style::default().fg(Color::Gray)),
                                    Span::styled("not queried", Style::default().fg(Color::Gray)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::NoAddress => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("❌", Style::default().fg(Color::Red)),
                                    Span::styled(" no address", Style::default().fg(Color::Red)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::ToolMissing(tool) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("🛠️ ", Style::default().fg(Color::Yellow)),
                                    Span::styled(format!("{} missing", tool), Style::default().fg(Color::Yellow)),
                                ]));
                            }
                            crate::scan::ping::PingStatus::Failed(_) => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("❌", Style::default().fg(Color::Red)),
                                    Span::styled(" failed", Style::default().fg(Color::Red)),
                                ]));
                            }
                        }

                        lines.push(Line::from(""));

                        // Overall latency with performance grading
                        let latency_color = if latency_ms < EXCELLENT_LATENCY_THRESHOLD_MS {
                            Color::Green
                        } else if latency_ms < FAIR_LATENCY_THRESHOLD_MS {
                            Color::Yellow
                        } else {
                            Color::Red
                        };

                        let latency_grade = if latency_ms < EXCELLENT_LATENCY_THRESHOLD_MS {
                            "excellent"
                        } else if latency_ms < GOOD_LATENCY_THRESHOLD_MS {
                            "good"
                        } else if latency_ms < POOR_LATENCY_THRESHOLD_MS {
                            "fair"
                        } else {
                            "poor"
                        };

                        lines.push(Line::from(vec![
                            Span::styled("⚡ Best: ", Style::default().fg(Color::White)),
                            Span::styled(format!("{}ms", latency_ms), Style::default().fg(latency_color)),
                            Span::styled(" (", Style::default().fg(Color::Gray)),
                            Span::styled(latency_grade, Style::default().fg(latency_color)),
                            Span::styled(")", Style::default().fg(Color::Gray)),
                        ]));

                        // TTL information if available
                        if let Some(result) = primary_result {
                            if let Some(ttl) = result.ttl {
                                lines.push(Line::from(vec![
                                    Span::styled("🔢 TTL: ", Style::default().fg(Color::White)),
                                    Span::styled(format!("{} hops", ttl), Style::default().fg(Color::Gray)),
                                ]));
                            }

                            // Reliability metrics
                            lines.push(Line::from(vec![
                                Span::styled("📊 Reliability: ", Style::default().fg(Color::White)),
                                Span::styled(
                                    format!("{}/{} pkts", result.packets_received, result.packets_sent),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        }
                    } else {
                        // No successful pings
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                            Span::styled("failed", Style::default().fg(Color::Red)),
                        ]));

                        lines.push(Line::from(""));

                        // Show why each protocol failed
                        match &ping.ipv4_status {
                            crate::scan::ping::PingStatus::NotQueried => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("⏭️ not queried", Style::default().fg(Color::Gray)),
                                ]));
                            }
                            _ => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
                                    Span::styled("❌ failed", Style::default().fg(Color::Red)),
                                ]));
                            }
                        }

                        match &ping.ipv6_status {
                            crate::scan::ping::PingStatus::NotQueried => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("⏭️ not queried", Style::default().fg(Color::Gray)),
                                ]));
                            }
                            _ => {
                                lines.push(Line::from(vec![
                                    Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
                                    Span::styled("❌ failed", Style::default().fg(Color::Red)),
                                ]));
                            }
                        }
                    }

                    // Show additional connectivity info from other scanners
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![
                        Span::styled("🔗 Services:", Style::default().fg(Color::Cyan)),
                    ]));

                    // Check HTTP connectivity
                    if let Some(http_state) = state.scanners.get("http") {
                        if let Some(ScanResult::Http(http_result)) = &http_state.result {
                            if let Some(primary_data) = http_result.get_primary_result() {
                                let http_status = if primary_data.status_code == HTTP_SUCCESS_STATUS {
                                    ("✅", Color::Green)
                                } else if primary_data.status_code < HTTP_CLIENT_ERROR_THRESHOLD {
                                    ("⚠️", Color::Yellow)
                                } else {
                                    ("❌", Color::Red)
                                };

                                lines.push(Line::from(vec![
                                    Span::styled("  HTTP: ", Style::default().fg(Color::White)),
                                    Span::styled(http_status.0, Style::default().fg(http_status.1)),
                                    Span::styled(format!(" {}", primary_data.status_code), Style::default().fg(Color::Gray)),
                                ]));
                            } else {
                                lines.push(Line::from(vec![
                                    Span::styled("  HTTP: ", Style::default().fg(Color::White)),
                                    Span::styled("❌", Style::default().fg(Color::Red)),
                                    Span::styled(" failed", Style::default().fg(Color::Gray)),
                                ]));
                            }
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled("  HTTP: ", Style::default().fg(Color::White)),
                                Span::styled("checking...", Style::default().fg(Color::Yellow)),
                            ]));
                        }
                    }

                    // Check TLS connectivity
                    if let Some(tls_state) = state.scanners.get("tls") {
                        if let Some(ScanResult::Tls(tls_result)) = &tls_state.result {
                            let tls_status = if let Some(primary_data) = tls_result.get_primary_result() {
                                if primary_data.connection_successful && primary_data.certificate_valid {
                                    ("✅", Color::Green)
                                } else if primary_data.connection_successful {
                                    ("⚠️", Color::Yellow)
                                } else {
                                    ("❌", Color::Red)
                                }
                            } else {
                                ("❌", Color::Red)
                            };

                            let version_text = tls_result.get_primary_result()
                                .and_then(|data| data.negotiated_version.as_ref())
                                .map(|v| v.as_str())
                                .unwrap_or("unknown");

                            lines.push(Line::from(vec![
                                Span::styled("  TLS: ", Style::default().fg(Color::White)),
                                Span::styled(tls_status.0, Style::default().fg(tls_status.1)),
                                Span::styled(
                                    format!(" {}", version_text),
                                    Style::default().fg(Color::Gray)
                                ),
                            ]));
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled("  TLS: ", Style::default().fg(Color::White)),
                                Span::styled("checking...", Style::default().fg(Color::Yellow)),
                            ]));
                        }
                    }
                }
                Some(_) => {
                    // Non-ping result (shouldn't happen for ping scanner)
                    lines.push(Line::from(vec![
                        Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                        Span::styled("error", Style::default().fg(Color::Red)),
                    ]));
                }
                None => {
                    // Show scanning status based on ping scanner state
                    match ping_state.status {
                        crate::types::ScanStatus::Running => {
                            lines.push(Line::from(vec![
                                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                                Span::styled("checking...", Style::default().fg(Color::Yellow)),
                            ]));

                            lines.push(Line::from(""));
                            lines.push(Line::from(vec![
                                Span::styled("⚡ Latency: ", Style::default().fg(Color::White)),
                                Span::styled("measuring...", Style::default().fg(Color::Yellow)),
                            ]));

                            lines.push(Line::from(vec![
                                Span::styled("📦 Loss: ", Style::default().fg(Color::White)),
                                Span::styled("measuring...", Style::default().fg(Color::Yellow)),
                            ]));
                        }
                        crate::types::ScanStatus::Failed => {
                            lines.push(Line::from(vec![
                                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                                Span::styled("failed", Style::default().fg(Color::Red)),
                            ]));

                            lines.push(Line::from(""));

                            // Show protocol information
                            lines.push(Line::from(vec![
                                Span::styled("🔧 Protocol: ", Style::default().fg(Color::White)),
                                Span::styled(state.protocol_display(), Style::default().fg(Color::Yellow)),
                            ]));

                            if let Some(error) = &ping_state.error {
                                let error_msg = error.to_string();

                                // Parse error for better display
                                if error_msg.contains("Command") && error_msg.contains("not found") {
                                    // Tool not available
                                    let tool = if error_msg.contains("ping6") { "ping6" } else { "ping" };
                                    let protocol = if tool == "ping6" { "IPv6" } else { "IPv4" };

                                    lines.push(Line::from(vec![
                                        Span::styled("❌ Issue: ", Style::default().fg(Color::White)),
                                        Span::styled("Tool missing", Style::default().fg(Color::Red)),
                                    ]));

                                    lines.push(Line::from(vec![
                                        Span::styled("🛠️  Missing: ", Style::default().fg(Color::White)),
                                        Span::styled(tool, Style::default().fg(Color::Yellow)),
                                        Span::styled(" command", Style::default().fg(Color::Gray)),
                                    ]));

                                    lines.push(Line::from(vec![
                                        Span::styled("💡 Fix: ", Style::default().fg(Color::White)),
                                        Span::styled(format!("Install {} utilities", protocol), Style::default().fg(Color::Cyan)),
                                    ]));

                                } else if error_msg.contains("No") && error_msg.contains("address available") {
                                    // No address for protocol
                                    let protocol = if error_msg.contains("IPv6") { "IPv6" } else if error_msg.contains("IPv4") { "IPv4" } else { "IP" };

                                    lines.push(Line::from(vec![
                                        Span::styled("❌ Issue: ", Style::default().fg(Color::White)),
                                        Span::styled("No address", Style::default().fg(Color::Red)),
                                    ]));

                                    lines.push(Line::from(vec![
                                        Span::styled("🏠 Missing: ", Style::default().fg(Color::White)),
                                        Span::styled(format!("{} address", protocol), Style::default().fg(Color::Yellow)),
                                    ]));

                                    if protocol == "IPv6" {
                                        lines.push(Line::from(vec![
                                            Span::styled("💡 Note: ", Style::default().fg(Color::White)),
                                            Span::styled("Target has no IPv6", Style::default().fg(Color::Cyan)),
                                        ]));
                                    }

                                } else if error_msg.contains("Ping failed") {
                                    // Ping command failed
                                    lines.push(Line::from(vec![
                                        Span::styled("❌ Issue: ", Style::default().fg(Color::White)),
                                        Span::styled("Ping failed", Style::default().fg(Color::Red)),
                                    ]));

                                    if error_msg.contains("ping6") {
                                        lines.push(Line::from(vec![
                                            Span::styled("🔧 Command: ", Style::default().fg(Color::White)),
                                            Span::styled("ping6", Style::default().fg(Color::Yellow)),
                                            Span::styled(" (IPv6)", Style::default().fg(Color::Gray)),
                                        ]));
                                    } else {
                                        lines.push(Line::from(vec![
                                            Span::styled("🔧 Command: ", Style::default().fg(Color::White)),
                                            Span::styled("ping", Style::default().fg(Color::Yellow)),
                                            Span::styled(" (IPv4)", Style::default().fg(Color::Gray)),
                                        ]));
                                    }

                                    lines.push(Line::from(vec![
                                        Span::styled("💡 Reason: ", Style::default().fg(Color::White)),
                                        Span::styled("No response/timeout", Style::default().fg(Color::Cyan)),
                                    ]));

                                } else {
                                    // Generic error
                                    lines.push(Line::from(vec![
                                        Span::styled("❌ Error: ", Style::default().fg(Color::White)),
                                    ]));

                                    // Split long error messages into multiple lines
                                    let error_lines: Vec<&str> = error_msg.lines().collect();
                                    for (i, line) in error_lines.iter().take(3).enumerate() {
                                        let truncated = if line.len() > 40 {
                                            format!("{}...", &line[..37])
                                        } else {
                                            line.to_string()
                                        };

                                        lines.push(Line::from(vec![
                                            if i == 0 {
                                                Span::styled("   ", Style::default())
                                            } else {
                                                Span::styled("   ", Style::default())
                                            },
                                            Span::styled(truncated, Style::default().fg(Color::Red)),
                                        ]));
                                    }
                                }
                            }
                        }
                        _ => {
                            lines.push(Line::from(vec![
                                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                                Span::styled("initializing...", Style::default().fg(Color::Gray)),
                            ]));
                        }
                    }
                }
            }
        } else {
            // No ping scanner data
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled("waiting...", Style::default().fg(Color::Gray)),
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
        (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT)
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
    fn test_connectivity_pane_creation() {
        let pane = ConnectivityPane::new();
        assert_eq!(pane.title(), "connectivity");
        assert_eq!(pane.id(), "connectivity");
        assert_eq!(pane.min_size(), (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
}
