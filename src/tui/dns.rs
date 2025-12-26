use crate::tui::pane::{create_block, Pane};
use crate::types::AppState;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};
use std::any::Any;
use log;

const TXT_TRUNCATE_SUFFIX_LENGTH: usize = 3;
const MAX_A_RECORDS_DISPLAYED: usize = 1000;
const TTL_GOOD_THRESHOLD: u32 = 300;
const TTL_WARNING_THRESHOLD: u32 = 60;
const MAX_AAAA_RECORDS_DISPLAYED: usize = 1000;
const IPV6_DISPLAY_MAX_LENGTH: usize = 25;
const IPV6_TRUNCATE_LENGTH: usize = 22;
const MAX_MX_RECORDS_DISPLAYED: usize = 1000;
const MX_PRIORITY_GOOD_THRESHOLD: u16 = 10;
const MX_PRIORITY_WARNING_THRESHOLD: u16 = 20;
const MAX_TXT_RECORDS_DISPLAYED: usize = 1000;
const TXT_DISPLAY_MAX_LENGTH: usize = 45;
const MS_RECORD_PREVIEW_LENGTH: usize = 10;
const MS_RECORD_PREFIX_LENGTH: usize = 3;
const MAX_NS_RECORDS_DISPLAYED: usize = 1000;
const MAX_CNAME_RECORDS_DISPLAYED: usize = 1000;
const MAX_CAA_RECORDS_DISPLAYED: usize = 1000;
const MAX_SRV_RECORDS_DISPLAYED: usize = 1000;
const MIN_DNS_PANE_WIDTH: u16 = 25;
const MIN_DNS_PANE_HEIGHT: u16 = 10;
const SCROLL_STEP: u16 = 1;

/// DNS pane displays domain name system resolution information
pub struct DnsPane {
    title: &'static str,
    id: &'static str,
    scroll_offset: u16,
}

impl DnsPane {
    pub fn new() -> Self {
        log::debug!("[tui::dns] new:");
        Self {
            title: "dns",
            id: "dns",
            scroll_offset: 0,
        }
    }

    pub fn scroll_up(&mut self) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = self.scroll_offset.saturating_sub(SCROLL_STEP);
        log::debug!("[tui::dns] scroll_up: old_offset={} new_offset={}",
            old_offset, self.scroll_offset);
    }

    pub fn scroll_down_smart(&mut self, state: &AppState, visible_height: u16) {
        // Use the SINGLE SOURCE OF TRUTH for content calculation
        let lines = self.build_content_lines(state);
        let actual_lines = lines.len() as u16;

        let old_offset = self.scroll_offset;
        if actual_lines > visible_height {
            let max_scroll = actual_lines.saturating_sub(visible_height);
            if self.scroll_offset < max_scroll {
                self.scroll_offset += SCROLL_STEP;
            }
        }

        log::debug!("[tui::dns] scroll_down_smart: old_offset={} new_offset={} actual_lines={} visible_height={} max_scroll={}",
            old_offset, self.scroll_offset, actual_lines, visible_height,
            actual_lines.saturating_sub(visible_height));
    }

    pub fn reset_scroll(&mut self) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = 0;
        log::debug!("[tui::dns] reset_scroll: old_offset={}", old_offset);
    }

    fn truncate_txt(text: &str, max_len: usize) -> String {
        if text.len() <= max_len {
            text.to_string()
        } else {
            format!("{}...", &text[..max_len.saturating_sub(TXT_TRUNCATE_SUFFIX_LENGTH)])
        }
    }

    /// Build the actual content lines - SINGLE SOURCE OF TRUTH
    /// This method is used by both scroll calculation and rendering
    fn build_content_lines(&self, state: &AppState) -> Vec<Line<'_>> {
        log::trace!("[tui::dns] build_content_lines: building DNS resolution content");

        let mut lines = Vec::new();

        // DNS status header
        if let Some(dns_state) = state.scanners.get("dns") {
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    match dns_state.status {
                        crate::types::ScanStatus::Running => "resolving...",
                        crate::types::ScanStatus::Complete => "resolved",
                        crate::types::ScanStatus::Failed => "failed",
                    },
                    Style::default().fg(match dns_state.status {
                        crate::types::ScanStatus::Running => Color::Yellow,
                        crate::types::ScanStatus::Complete => Color::Green,
                        crate::types::ScanStatus::Failed => Color::Red,
                    })
                ),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled("scanner not available", Style::default().fg(Color::Red)),
            ]));
        }

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get DNS results and add them
        let dns_lines = if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(crate::types::ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                Self::build_dns_result_lines(dns_result.clone())
            } else {
                Self::build_dns_loading_lines()
            }
        } else {
            Self::build_dns_unavailable_lines()
        };

        lines.extend(dns_lines);
        lines
    }

    fn build_dns_result_lines(dns_result: crate::scan::dns::DnsResult) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        // Helper function to get status color and text
        let get_status_display = |status: &crate::scan::dns::QueryStatus| -> (Color, String) {
            match status {
                crate::scan::dns::QueryStatus::NotQueried => (Color::Gray, "not queried".to_string()),
                crate::scan::dns::QueryStatus::Success(count) => (Color::Green, format!("{} records", count)),
                crate::scan::dns::QueryStatus::NoRecords => (Color::Yellow, "No Records".to_string()),
                crate::scan::dns::QueryStatus::Failed(_error) => (Color::Red, "Failed".to_string()),
                crate::scan::dns::QueryStatus::Timeout => (Color::Red, "Timeout".to_string()),
            }
        };

        // A records
        let (a_color, a_status_text) = get_status_display(&dns_result.A_status);
        lines.push(Line::from(vec![
            Span::styled("A: ", Style::default().fg(Color::White)),
            Span::styled(a_status_text, Style::default().fg(a_color)),
        ]));

        if !dns_result.A.is_empty() {
            let ttl = dns_result.A[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
            ]));

            // Show A records
            for record in dns_result.A.iter().take(MAX_A_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.to_string(),
                        Style::default().fg(Color::Cyan)
                    ),
                ]));
            }
        }

        // AAAA records (IPv6)
        let (aaaa_color, aaaa_status_text) = get_status_display(&dns_result.AAAA_status);
        lines.push(Line::from(vec![
            Span::styled("AAAA: ", Style::default().fg(Color::White)),
            Span::styled(aaaa_status_text, Style::default().fg(aaaa_color)),
        ]));

        if !dns_result.AAAA.is_empty() {
            let ttl = dns_result.AAAA[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
            ]));

            for record in dns_result.AAAA.iter().take(MAX_AAAA_RECORDS_DISPLAYED) {
                let ipv6_str = record.value.to_string();
                let display_str = if ipv6_str.len() > IPV6_DISPLAY_MAX_LENGTH {
                    format!("{}...", &ipv6_str[..IPV6_TRUNCATE_LENGTH])
                } else {
                    ipv6_str
                };

                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        display_str,
                        Style::default().fg(Color::Cyan)
                    ),
                ]));
            }
        }

        // CNAME records
        if !dns_result.CNAME.is_empty() {
            let ttl = dns_result.CNAME[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("CNAME: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.CNAME.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" records (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.CNAME.iter().take(MAX_CNAME_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.clone(),
                        Style::default().fg(Color::Magenta)
                    ),
                ]));
            }
        }

        // NS records
        if !dns_result.NS.is_empty() {
            let ttl = dns_result.NS[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("NS: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.NS.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" records (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.NS.iter().take(MAX_NS_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.clone(),
                        Style::default().fg(Color::Blue)
                    ),
                ]));
            }
        }

        // TXT records (basic display, security analysis goes to security pane)
        if !dns_result.TXT.is_empty() {
            let ttl = dns_result.TXT[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("TXT: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.TXT.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" records (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.TXT.iter().take(MAX_TXT_RECORDS_DISPLAYED) {
                let value = record.value.clone();
                let display_value = if value.starts_with("google-site-verification") {
                    "google-site-verification=...".to_string()
                } else if value.starts_with("MS=") {
                    format!("MS={}...", &value[MS_RECORD_PREFIX_LENGTH..].chars().take(MS_RECORD_PREVIEW_LENGTH).collect::<String>())
                } else {
                    Self::truncate_txt(&value, TXT_DISPLAY_MAX_LENGTH)
                };

                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        display_value,
                        Style::default().fg(Color::Yellow)
                    ),
                ]));
            }
        }

        // CAA records
        if !dns_result.CAA.is_empty() {
            let ttl = dns_result.CAA[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("CAA: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.CAA.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" cert auth (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.CAA.iter().take(MAX_CAA_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("{} {}", record.value.tag, record.value.value),
                        Style::default().fg(Color::Green)
                    ),
                ]));
            }
        }

        // MX records
        if !dns_result.MX.is_empty() {
            let ttl = dns_result.MX[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("MX: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.MX.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" records (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.MX.iter().take(MAX_MX_RECORDS_DISPLAYED) {
                let priority_color = if record.value.priority <= MX_PRIORITY_GOOD_THRESHOLD {
                    Color::Green
                } else if record.value.priority <= MX_PRIORITY_WARNING_THRESHOLD {
                    Color::Yellow
                } else {
                    Color::Red
                };

                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        record.value.exchange.clone(),
                        Style::default().fg(Color::Magenta)
                    ),
                    Span::styled(" (pri: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", record.value.priority),
                        Style::default().fg(priority_color)
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
        }

        // SOA records
        if !dns_result.SOA.is_empty() {
            let ttl = dns_result.SOA[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("SOA: ", Style::default().fg(Color::White)),
                Span::styled("authority (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            if let Some(soa) = dns_result.SOA.first() {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("NS: {}", soa.value.primary_ns),
                        Style::default().fg(Color::Cyan)
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("Serial: {}", soa.value.serial),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
        }

        // SRV records
        if !dns_result.SRV.is_empty() {
            let ttl = dns_result.SRV[0].ttl_remaining();
            let ttl_color = if ttl > TTL_GOOD_THRESHOLD {
                Color::Green
            } else if ttl > TTL_WARNING_THRESHOLD {
                Color::Yellow
            } else {
                Color::Red
            };

            lines.push(Line::from(vec![
                Span::styled("SRV: ", Style::default().fg(Color::White)),
                Span::styled(
                    dns_result.SRV.len().to_string(),
                    Style::default().fg(Color::Green)
                ),
                Span::styled(" services (TTL: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}s", ttl),
                    Style::default().fg(ttl_color)
                ),
                Span::styled(")", Style::default().fg(Color::White)),
            ]));

            for record in dns_result.SRV.iter().take(MAX_SRV_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("{}:{} (p:{}, w:{})",
                            record.value.target,
                            record.value.port,
                            record.value.priority,
                            record.value.weight
                        ),
                        Style::default().fg(Color::Blue)
                    ),
                ]));
            }
        }

        lines
    }

    fn build_dns_loading_lines() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled("A: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("AAAA: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("MX: ", Style::default().fg(Color::White)),
                Span::styled("resolving...", Style::default().fg(Color::Gray)),
            ]),
        ]
    }

    fn build_dns_unavailable_lines() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled("DNS: ", Style::default().fg(Color::White)),
                Span::styled("scanner not available", Style::default().fg(Color::Red)),
            ])
        ]
    }
}

impl Default for DnsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for DnsPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::dns] render: area={}x{} focused={} scroll_offset={}",
            area.width, area.height, focused, self.scroll_offset);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Use the SINGLE SOURCE OF TRUTH for content
        let lines = self.build_content_lines(state);

        // Apply scrolling
        let total_lines = lines.len() as u16;
        let visible_area_height = inner_area.height;
        let max_scroll_offset = if total_lines > visible_area_height {
            total_lines.saturating_sub(visible_area_height)
        } else {
            0
        };
        let safe_scroll_offset = self.scroll_offset.min(max_scroll_offset);

        log::trace!("[tui::dns] scroll_calculation: total_lines={} visible_height={} max_scroll={} safe_scroll={}",
            total_lines, visible_area_height, max_scroll_offset, safe_scroll_offset);

        // Apply scroll offset - skip lines from the beginning
        let visible_lines = if safe_scroll_offset < total_lines {
            lines.into_iter().skip(safe_scroll_offset as usize).collect()
        } else {
            lines
        };

        log::trace!("[tui::dns] render_content: visible_lines={}", visible_lines.len());

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
        (MIN_DNS_PANE_WIDTH, MIN_DNS_PANE_HEIGHT) // Minimum width and height for DNS information
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
    fn test_dns_pane_creation() {
        let pane = DnsPane::new();
        assert_eq!(pane.title(), "dns");
        assert_eq!(pane.id(), "dns");
        assert_eq!(pane.min_size(), (MIN_DNS_PANE_WIDTH, MIN_DNS_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }
}