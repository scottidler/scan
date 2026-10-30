use crate::tui::pane::{Pane, create_block};
use crate::types::AppState;
use log;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};
use std::any::Any;

const MAX_A_RECORDS_DISPLAYED: usize = 1000;
const TTL_GOOD_THRESHOLD: u32 = 300;
const TTL_WARNING_THRESHOLD: u32 = 60;
const MAX_AAAA_RECORDS_DISPLAYED: usize = 1000;
const MAX_MX_RECORDS_DISPLAYED: usize = 1000;
const MX_PRIORITY_GOOD_THRESHOLD: u16 = 10;
const MX_PRIORITY_WARNING_THRESHOLD: u16 = 20;
const MAX_TXT_RECORDS_DISPLAYED: usize = 1000;
const MS_RECORD_PREVIEW_LENGTH: usize = 10;
const MS_RECORD_PREFIX_LENGTH: usize = 3;
const MAX_NS_RECORDS_DISPLAYED: usize = 1000;
const MAX_CNAME_RECORDS_DISPLAYED: usize = 1000;
const MAX_CAA_RECORDS_DISPLAYED: usize = 1000;
const MAX_SRV_RECORDS_DISPLAYED: usize = 1000;
const MAX_PTR_RECORDS_DISPLAYED: usize = 1000;
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
        log::debug!(
            "[tui::dns] scroll_up: old_offset={} new_offset={}",
            old_offset,
            self.scroll_offset
        );
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

        log::debug!(
            "[tui::dns] scroll_down_smart: old_offset={} new_offset={} actual_lines={} visible_height={} max_scroll={}",
            old_offset,
            self.scroll_offset,
            actual_lines,
            visible_height,
            actual_lines.saturating_sub(visible_height)
        );
    }

    pub fn reset_scroll(&mut self) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = 0;
        log::debug!("[tui::dns] reset_scroll: old_offset={}", old_offset);
    }

    /// Build the actual content lines - SINGLE SOURCE OF TRUTH
    /// This method is used by both scroll calculation and rendering
    fn build_content_lines(&self, state: &AppState) -> Vec<Line<'_>> {
        log::trace!("[tui::dns] build_content_lines: building DNS resolution content");

        let mut lines = Vec::new();

        // DNS status header
        if let Some(dns_state) = state.scanners.get("dns") {
            let (label, label_color) = crate::tui::status_label(&dns_state, "resolving...", "resolved");
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled(label, Style::default().fg(label_color)),
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
            } else if matches!(dns_state.status, crate::types::ScanStatus::Failed) {
                // The header carries the reason; nothing is still resolving.
                Vec::new()
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

        // An IP target has only reverse DNS, so PTR leads.
        let reverse_only = dns_result.is_reverse_only();
        if reverse_only {
            lines.extend(ptr_lines(&dns_result));
        }

        // A records
        let (a_color, a_status_text) = status_display(&dns_result.A_status);
        lines.push(Line::from(vec![
            Span::styled("A: ", Style::default().fg(Color::White)),
            Span::styled(a_status_text, Style::default().fg(a_color)),
        ]));

        if !dns_result.A.is_empty() {
            let ttl = ttl_span(dns_result.A[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            // Show A records
            for record in dns_result.A.iter().take(MAX_A_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(record.value.to_string(), Style::default().fg(Color::Cyan)),
                ]));
            }
        }

        // AAAA records (IPv6)
        let (aaaa_color, aaaa_status_text) = status_display(&dns_result.AAAA_status);
        lines.push(Line::from(vec![
            Span::styled("AAAA: ", Style::default().fg(Color::White)),
            Span::styled(aaaa_status_text, Style::default().fg(aaaa_color)),
        ]));

        if !dns_result.AAAA.is_empty() {
            let ttl = ttl_span(dns_result.AAAA[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.AAAA.iter().take(MAX_AAAA_RECORDS_DISPLAYED) {
                let ipv6_str = record.value.to_string();

                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(ipv6_str, Style::default().fg(Color::Cyan)),
                ]));
            }
        }

        // CNAME records
        lines.extend(failed_query_line("CNAME", &dns_result.CNAME_status));
        if !dns_result.CNAME.is_empty() {
            let ttl = ttl_span(dns_result.CNAME[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("CNAME: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.CNAME.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" records, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.CNAME.iter().take(MAX_CNAME_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(record.value.clone(), Style::default().fg(Color::Magenta)),
                ]));
            }
        }

        // NS records
        if !dns_result.NS.is_empty() {
            let ttl = ttl_span(dns_result.NS[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("NS: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.NS.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" records, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.NS.iter().take(MAX_NS_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(record.value.clone(), Style::default().fg(Color::Blue)),
                ]));
            }
        }

        // TXT records (basic display, security analysis goes to security pane)
        if !dns_result.TXT.is_empty() {
            let ttl = ttl_span(dns_result.TXT[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("TXT: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.TXT.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" records, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.TXT.iter().take(MAX_TXT_RECORDS_DISPLAYED) {
                let value = record.value.clone();
                let display_value = if value.starts_with("google-site-verification") {
                    "google-site-verification=...".to_string()
                } else if value.starts_with("MS=") {
                    format!(
                        "MS={}...",
                        value[MS_RECORD_PREFIX_LENGTH..]
                            .chars()
                            .take(MS_RECORD_PREVIEW_LENGTH)
                            .collect::<String>()
                    )
                } else {
                    value
                };

                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(display_value, Style::default().fg(Color::Yellow)),
                ]));
            }
        }

        // CAA records
        lines.extend(failed_query_line("CAA", &dns_result.CAA_status));
        if !dns_result.CAA.is_empty() {
            let ttl = ttl_span(dns_result.CAA[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("CAA: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.CAA.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" cert auth, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.CAA.iter().take(MAX_CAA_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("{} {}", record.value.tag, record.value.value),
                        Style::default().fg(Color::Green),
                    ),
                ]));
            }
        }

        // MX records
        if is_null_mx(&dns_result.MX) {
            // RFC 7505: a lone `0 .` says the domain accepts no mail; it is not a mail server.
            lines.push(Line::from(vec![
                Span::styled("MX: ", Style::default().fg(Color::White)),
                Span::styled("none (null MX)", Style::default().fg(Color::Gray)),
            ]));
        } else if !dns_result.MX.is_empty() {
            let ttl = ttl_span(dns_result.MX[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("MX: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.MX.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" records, TTL: ", Style::default().fg(Color::White)),
                ttl,
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
                    Span::styled(record.value.exchange.clone(), Style::default().fg(Color::Magenta)),
                    Span::styled(" (pri: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("{}", record.value.priority),
                        Style::default().fg(priority_color),
                    ),
                    Span::styled(")", Style::default().fg(Color::Gray)),
                ]));
            }
        }

        // SOA records
        if !dns_result.SOA.is_empty() {
            let ttl = ttl_span(dns_result.SOA[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("SOA: ", Style::default().fg(Color::White)),
                Span::styled("authority, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            if let Some(soa) = dns_result.SOA.first() {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("NS: {}", soa.value.primary_ns),
                        Style::default().fg(Color::Cyan),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("Serial: {}", soa.value.serial),
                        Style::default().fg(Color::Gray),
                    ),
                ]));
            }
        }

        // SRV records
        if !dns_result.SRV.is_empty() {
            let ttl = ttl_span(dns_result.SRV[0].ttl_remaining());

            lines.push(Line::from(vec![
                Span::styled("SRV: ", Style::default().fg(Color::White)),
                Span::styled(dns_result.SRV.len().to_string(), Style::default().fg(Color::Green)),
                Span::styled(" services, TTL: ", Style::default().fg(Color::White)),
                ttl,
            ]));

            for record in dns_result.SRV.iter().take(MAX_SRV_RECORDS_DISPLAYED) {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!(
                            "{}:{} (p:{}, w:{})",
                            record.value.target, record.value.port, record.value.priority, record.value.weight
                        ),
                        Style::default().fg(Color::Blue),
                    ),
                ]));
            }
        }

        if !reverse_only {
            lines.extend(ptr_lines(&dns_result));
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
        vec![Line::from(vec![
            Span::styled("DNS: ", Style::default().fg(Color::White)),
            Span::styled("scanner not available", Style::default().fg(Color::Red)),
        ])]
    }
}

/// A record set's query outcome: color and text.
fn status_display(status: &crate::scan::dns::QueryStatus) -> (Color, String) {
    match status {
        crate::scan::dns::QueryStatus::NotQueried => (Color::Gray, "not queried".to_string()),
        crate::scan::dns::QueryStatus::Success(count) => (Color::Green, format!("{} records", count)),
        crate::scan::dns::QueryStatus::NoRecords => (Color::Yellow, "No Records".to_string()),
        crate::scan::dns::QueryStatus::Failed(_error) => (Color::Red, "Failed".to_string()),
        crate::scan::dns::QueryStatus::Timeout => (Color::Red, "Timeout".to_string()),
    }
}

/// A record's remaining TTL as the stub resolver reported it: `<n>s (cached)`, since that is the
/// resolver cache's countdown, not the zone's TTL. At 0 the scanner is already re-querying, so it
/// reads `expired, refreshing` (MUTED: Gray until the theme lands).
fn ttl_span(ttl: u32) -> Span<'static> {
    if ttl == 0 {
        return Span::styled("expired, refreshing", Style::default().fg(Color::Gray));
    }
    let color = if ttl > TTL_GOOD_THRESHOLD {
        Color::Green
    } else if ttl > TTL_WARNING_THRESHOLD {
        Color::Yellow
    } else {
        Color::Red
    };
    Span::styled(format!("{}s (cached)", ttl), Style::default().fg(color))
}

/// `<label>: Failed` or `Timeout` for a lookup that did not answer; nothing otherwise, since most
/// names have no CNAME or CAA and an empty answer is not news.
fn failed_query_line(label: &'static str, status: &crate::scan::dns::QueryStatus) -> Option<Line<'static>> {
    if !matches!(
        status,
        crate::scan::dns::QueryStatus::Failed(_) | crate::scan::dns::QueryStatus::Timeout
    ) {
        return None;
    }
    let (color, text) = status_display(status);
    Some(Line::from(vec![
        Span::styled(format!("{}: ", label), Style::default().fg(Color::White)),
        Span::styled(text, Style::default().fg(color)),
    ]))
}

/// The `PTR:` section: reverse DNS for the target's addresses.
fn ptr_lines(dns_result: &crate::scan::dns::DnsResult) -> Vec<Line<'static>> {
    let (color, text) = status_display(&dns_result.PTR_status);
    let mut header = vec![
        Span::styled("PTR: ", Style::default().fg(Color::White)),
        Span::styled(text, Style::default().fg(color)),
    ];
    if let Some(first) = dns_result.PTR.first() {
        header.push(Span::styled(", TTL: ", Style::default().fg(Color::White)));
        header.push(ttl_span(first.ttl_remaining()));
    }
    let mut lines = vec![Line::from(header)];
    for record in dns_result.PTR.iter().take(MAX_PTR_RECORDS_DISPLAYED) {
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(record.value.clone(), Style::default().fg(Color::Cyan)),
        ]));
    }
    lines
}

/// True for the RFC 7505 null MX: exactly one record, priority 0, exchange `.`.
fn is_null_mx(records: &[crate::scan::dns::DnsRecord<crate::scan::dns::MxRecord>]) -> bool {
    matches!(records, [record] if record.value.priority == 0 && record.value.exchange == ".")
}

impl Default for DnsPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for DnsPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!(
            "[tui::dns] render: area={}x{} focused={} scroll_offset={}",
            area.width,
            area.height,
            focused,
            self.scroll_offset
        );

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

        log::trace!(
            "[tui::dns] scroll_calculation: total_lines={} visible_height={} max_scroll={} safe_scroll={}",
            total_lines,
            visible_area_height,
            max_scroll_offset,
            safe_scroll_offset
        );

        // Apply scroll offset - skip lines from the beginning
        // Scrolling is by logical line, so every line is fit to one row rather than wrapped.
        let visible_lines: Vec<Line<'_>> = if safe_scroll_offset < total_lines {
            lines.into_iter().skip(safe_scroll_offset as usize).collect()
        } else {
            lines
        }
        .into_iter()
        .map(|line| crate::tui::text::fit_line(line, inner_area.width))
        .collect();

        log::trace!("[tui::dns] render_content: visible_lines={}", visible_lines.len());

        let paragraph = Paragraph::new(visible_lines).alignment(Alignment::Left);
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
    fn long_txt_record_is_fit_with_ellipsis_in_narrow_terminals() {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
        let txt = "v=spf1 include:_spf.a-very-long-mail-provider.example.com include:_spf.another.example.net -all";
        let mut result = DnsResult::new();
        result.TXT = vec![DnsRecord {
            value: txt.to_string(),
            ttl_original: 3600,
            queried_at: std::time::Instant::now(),
        }];
        result.TXT_status = QueryStatus::Success(1);
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &DnsPane::new(),
            &complete_state("dns", crate::types::ScanResult::Dns(result)),
            2,
            0,
            &format!("  {txt}"),
        );
    }

    #[test]
    fn long_multibyte_txt_record_is_fit_by_display_width() {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
        let txt = format!("v{}", "é".repeat(60));
        let mut result = DnsResult::new();
        result.TXT = vec![DnsRecord {
            value: txt.clone(),
            ttl_original: 3600,
            queried_at: std::time::Instant::now(),
        }];
        result.TXT_status = QueryStatus::Success(1);
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &DnsPane::new(),
            &complete_state("dns", crate::types::ScanResult::Dns(result)),
            2,
            0,
            &format!("  {txt}"),
        );
    }

    fn mx(priority: u16, exchange: &str) -> crate::scan::dns::DnsRecord<crate::scan::dns::MxRecord> {
        crate::scan::dns::DnsRecord::new(
            crate::scan::dns::MxRecord {
                priority,
                exchange: exchange.to_string(),
            },
            300,
        )
    }

    fn render_mx(records: Vec<crate::scan::dns::DnsRecord<crate::scan::dns::MxRecord>>) -> String {
        use crate::scan::dns::{DnsResult, QueryStatus};
        let mut result = DnsResult::new();
        result.MX_status = QueryStatus::Success(records.len());
        result.MX = records;
        crate::tui::testing::render_pane(
            &DnsPane::new(),
            &complete_state("dns", crate::types::ScanResult::Dns(result)),
            80,
            30,
            false,
        )
    }

    use crate::scan::dns::{CaaRecord, DnsRecord, DnsResult, QueryStatus};

    fn render_dns(result: DnsResult, target: &str) -> String {
        let mut state = complete_state("dns", crate::types::ScanResult::Dns(result));
        state.target = target.to_string();
        crate::tui::testing::render_pane(&DnsPane::new(), &state, 80, 40, false)
    }

    /// The pane's text rows with the border stripped and trailing space trimmed.
    fn rows(pane: &str) -> Vec<String> {
        pane.lines()
            .map(|l| l.trim_matches(['│', ' ']).to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    /// Item 6: CNAME and CAA answers render their own sections.
    #[test]
    fn cname_and_caa_render_their_sections() {
        let mut result = DnsResult::new();
        result.MX_status = QueryStatus::NoRecords;
        result.CNAME = vec![DnsRecord::new("cname.vercel-dns.com.".to_string(), 300)];
        result.CNAME_status = QueryStatus::Success(1);
        result.CAA = vec![DnsRecord::new(
            CaaRecord {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            },
            300,
        )];
        result.CAA_status = QueryStatus::Success(1);
        let out = render_dns(result, "www.tatari.tv");
        assert!(out.contains("CNAME: 1 records, TTL: "), "{out}");
        assert!(out.contains("cname.vercel-dns.com."), "{out}");
        assert!(out.contains("CAA: 1 cert auth, TTL: "), "{out}");
        assert!(out.contains("issue letsencrypt.org"), "{out}");
    }

    #[test]
    fn failed_cname_lookup_says_so_and_an_empty_one_is_silent() {
        let mut result = DnsResult::new();
        result.MX_status = QueryStatus::NoRecords;
        result.CNAME_status = QueryStatus::Timeout;
        result.CAA_status = QueryStatus::NoRecords;
        let out = render_dns(result, "example.com");
        assert!(out.contains("CNAME: Timeout"), "{out}");
        assert!(!out.contains("CAA:"), "{out}");
    }

    /// Item 7: an IP target's DNS pane leads with PTR.
    #[test]
    fn ip_target_renders_ptr_first() {
        let mut result = DnsResult::new();
        result.PTR = vec![DnsRecord::new("one.one.one.one.".to_string(), 300)];
        result.PTR_status = QueryStatus::Success(1);
        let out = render_dns(result, "1.1.1.1");
        let rows = rows(&out);
        let first_record_row = rows
            .iter()
            .position(|r| r.contains(':') && !r.contains("Status"))
            .unwrap();
        assert!(rows[first_record_row].starts_with("PTR: 1 records"), "{out}");
        assert_eq!(rows[first_record_row + 1], "one.one.one.one.", "{out}");
    }

    /// A name target keeps A first and shows PTR after the forward records.
    #[test]
    fn name_target_renders_ptr_after_the_forward_records() {
        let mut result = DnsResult::new();
        result.MX_status = QueryStatus::NoRecords;
        result.A = vec![DnsRecord::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 300)];
        result.A_status = QueryStatus::Success(1);
        result.PTR = vec![DnsRecord::new("host.example.".to_string(), 300)];
        result.PTR_status = QueryStatus::Success(1);
        let out = render_dns(result, "example.com");
        let a = out.find("A: 1 records").unwrap();
        let ptr = out.find("PTR: 1 records").unwrap();
        assert!(a < ptr, "{out}");
    }

    /// Item B: a TTL is the stub resolver's countdown, so it says `cached`; at 0 the scanner is
    /// re-querying, and the pane says that instead of a bare `0s`.
    #[test]
    fn ttl_reads_cached_and_expired_reads_refreshing() {
        let mut result = DnsResult::new();
        result.MX_status = QueryStatus::NoRecords;
        result.A = vec![DnsRecord::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 300)];
        result.A_status = QueryStatus::Success(1);
        let fresh = render_dns(result.clone(), "example.com");
        assert!(
            fresh.contains("TTL: 300s (cached)") || fresh.contains("TTL: 299s (cached)"),
            "{fresh}"
        );

        result.A[0].queried_at = std::time::Instant::now() - std::time::Duration::from_secs(301);
        let mut state = complete_state("dns", crate::types::ScanResult::Dns(result));
        state.target = "example.com".to_string();
        let buffer = crate::tui::testing::render_buffer(&DnsPane::new(), &state, 80, 40, false);
        let out = crate::tui::testing::render_pane(&DnsPane::new(), &state, 80, 40, false);
        assert!(out.contains("TTL: expired, refreshing"), "{out}");
        assert!(!out.contains("TTL: 0s"), "{out}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "expired, refreshing"), Color::Gray);
    }

    #[test]
    fn null_mx_renders_as_none_not_a_mail_server() {
        let out = render_mx(vec![mx(0, ".")]);
        assert!(out.contains("MX: none (null MX)"), "{out}");
        assert!(!out.contains("pri:"), "null MX shown as a server:\n{out}");
    }

    #[test]
    fn real_mx_records_still_render_as_servers() {
        let out = render_mx(vec![mx(0, "mail.example.com"), mx(10, "backup.example.com")]);
        assert!(out.contains("MX: 2 records"), "{out}");
        assert!(out.contains("mail.example.com (pri: 0)"), "{out}");
        let lone_dot_with_peer = render_mx(vec![mx(0, "."), mx(10, "mail.example.com")]);
        assert!(!lone_dot_with_peer.contains("null MX"), "{lone_dot_with_peer}");
    }
}
