use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::AppState;
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use std::any::Any;

const MAX_A_RECORDS_DISPLAYED: usize = 1000;
const TTL_WARNING_THRESHOLD: u32 = 60;
const MAX_AAAA_RECORDS_DISPLAYED: usize = 1000;
const MAX_MX_RECORDS_DISPLAYED: usize = 1000;
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

/// DNS pane displays domain name system resolution information
pub struct DnsPane {
    title: &'static str,
    id: &'static str,
}

impl DnsPane {
    pub fn new() -> Self {
        log::debug!("[tui::dns] new:");
        Self {
            title: "dns",
            id: "dns",
        }
    }

    /// The pane's logical lines, before they are laid out as rows by `content`.
    fn build_content_lines(&self, state: &AppState, detail: Detail) -> Vec<Line<'_>> {
        log::trace!("[tui::dns] build_content_lines: building DNS resolution content");

        let mut lines = Vec::new();

        // DNS status header
        if let Some(dns_state) = state.scanners.get("dns") {
            let (label, label_color) = crate::tui::status_label(&dns_state, "resolving...", "resolved");
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(label_color)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled("scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get DNS results and add them
        let dns_lines = if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(crate::types::ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                let refreshing = matches!(dns_state.status, crate::types::ScanStatus::Running);
                Self::build_dns_result_lines(dns_result.clone(), detail, refreshing)
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

    /// `refreshing` is true while the DNS scanner is re-querying; only then does an expired TTL
    /// claim a refresh.
    fn build_dns_result_lines(
        dns_result: crate::scan::dns::DnsResult,
        detail: Detail,
        refreshing: bool,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        // An IP target has only reverse DNS, so PTR leads.
        let reverse_only = dns_result.is_reverse_only();
        if reverse_only {
            lines.extend(ptr_lines(&dns_result, detail, refreshing));
        }

        // A records
        let (a_color, a_status_text) = status_display(&dns_result.A_status);
        lines.push(Line::from(vec![
            Span::styled("A: ", Style::default().fg(theme::LABEL)),
            Span::styled(a_status_text, Style::default().fg(a_color)),
        ]));

        if !dns_result.A.is_empty() {
            let ttl = ttl_span(dns_result.A[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            // Show A records
            for record in dns_result.A.iter().take(MAX_A_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(
                        record.value.to_string(),
                        Style::default().fg(theme::VALUE),
                    )],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // AAAA records (IPv6)
        let (aaaa_color, aaaa_status_text) = status_display(&dns_result.AAAA_status);
        lines.push(Line::from(vec![
            Span::styled("AAAA: ", Style::default().fg(theme::LABEL)),
            Span::styled(aaaa_status_text, Style::default().fg(aaaa_color)),
        ]));

        if !dns_result.AAAA.is_empty() {
            let ttl = ttl_span(dns_result.AAAA[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("  TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.AAAA.iter().take(MAX_AAAA_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(
                        record.value.to_string(),
                        Style::default().fg(theme::VALUE),
                    )],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // CNAME records
        lines.extend(failed_query_line("CNAME", &dns_result.CNAME_status));
        if !dns_result.CNAME.is_empty() {
            let ttl = ttl_span(dns_result.CNAME[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("CNAME: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.CNAME.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" records, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.CNAME.iter().take(MAX_CNAME_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(record.value.clone(), Style::default().fg(theme::ACCENT))],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // NS records
        if !dns_result.NS.is_empty() {
            let ttl = ttl_span(dns_result.NS[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("NS: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.NS.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" records, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.NS.iter().take(MAX_NS_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(record.value.clone(), Style::default().fg(theme::ACCENT))],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // TXT records (basic display, security analysis goes to security pane)
        if !dns_result.TXT.is_empty() {
            let ttl = ttl_span(dns_result.TXT[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("TXT: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.TXT.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" records, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.TXT.iter().take(MAX_TXT_RECORDS_DISPLAYED) {
                let value = record.value.clone();
                // The grid abbreviates verification tokens; zoom shows every record whole.
                let display_value = if detail == Detail::Zoomed {
                    value
                } else if value.starts_with("google-site-verification") {
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

                lines.push(record_line(
                    vec![Span::styled(display_value, Style::default().fg(theme::WARN))],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // CAA records
        lines.extend(failed_query_line("CAA", &dns_result.CAA_status));
        if !dns_result.CAA.is_empty() {
            let ttl = ttl_span(dns_result.CAA[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("CAA: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.CAA.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" cert auth, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.CAA.iter().take(MAX_CAA_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(
                        format!("{} {}", record.value.tag, record.value.value),
                        Style::default().fg(theme::GOOD),
                    )],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // MX records
        if is_null_mx(&dns_result.MX) {
            // RFC 7505: a lone `0 .` says the domain accepts no mail; it is not a mail server.
            lines.push(Line::from(vec![
                Span::styled("MX: ", Style::default().fg(theme::LABEL)),
                Span::styled("none (null MX)", Style::default().fg(theme::MUTED)),
            ]));
        } else if !dns_result.MX.is_empty() {
            let ttl = ttl_span(dns_result.MX[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("MX: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.MX.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" records, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.MX.iter().take(MAX_MX_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![
                        Span::styled(record.value.exchange.clone(), Style::default().fg(theme::ACCENT)),
                        Span::styled(" (pri: ", Style::default().fg(theme::MUTED)),
                        Span::styled(format!("{}", record.value.priority), Style::default().fg(theme::LABEL)),
                        Span::styled(")", Style::default().fg(theme::MUTED)),
                    ],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        // SOA records
        if !dns_result.SOA.is_empty() {
            let ttl = ttl_span(dns_result.SOA[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("SOA: ", Style::default().fg(theme::LABEL)),
                Span::styled("authority, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            if let Some(soa) = dns_result.SOA.first() {
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("NS: {}", soa.value.primary_ns),
                        Style::default().fg(theme::VALUE),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(
                        format!("Serial: {}", soa.value.serial),
                        Style::default().fg(theme::MUTED),
                    ),
                ]));
                if detail == Detail::Zoomed {
                    let fields = [
                        ("Email", soa.value.responsible_email.clone()),
                        ("Refresh", format!("{}s", soa.value.refresh)),
                        ("Retry", format!("{}s", soa.value.retry)),
                        ("Expire", format!("{}s", soa.value.expire)),
                        ("Minimum TTL", format!("{}s", soa.value.minimum_ttl)),
                    ];
                    for (label, value) in fields {
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {label}: "), Style::default().fg(theme::LABEL)),
                            Span::styled(value, Style::default().fg(theme::MUTED)),
                        ]));
                    }
                }
            }
        }

        // SRV records
        if !dns_result.SRV.is_empty() {
            let ttl = ttl_span(dns_result.SRV[0].ttl_remaining(), refreshing);

            lines.push(Line::from(vec![
                Span::styled("SRV: ", Style::default().fg(theme::LABEL)),
                Span::styled(dns_result.SRV.len().to_string(), Style::default().fg(theme::GOOD)),
                Span::styled(" services, TTL: ", Style::default().fg(theme::LABEL)),
                ttl,
            ]));

            for record in dns_result.SRV.iter().take(MAX_SRV_RECORDS_DISPLAYED) {
                lines.push(record_line(
                    vec![Span::styled(
                        format!(
                            "{}:{} (p:{}, w:{})",
                            record.value.target, record.value.port, record.value.priority, record.value.weight
                        ),
                        Style::default().fg(theme::ACCENT),
                    )],
                    record.ttl_remaining(),
                    detail,
                    refreshing,
                ));
            }
        }

        if !reverse_only {
            lines.extend(ptr_lines(&dns_result, detail, refreshing));
        }

        lines
    }

    fn build_dns_loading_lines() -> Vec<Line<'static>> {
        vec![
            Line::from(vec![
                Span::styled("A: ", Style::default().fg(theme::LABEL)),
                Span::styled("resolving...", Style::default().fg(theme::MUTED)),
            ]),
            Line::from(vec![
                Span::styled("AAAA: ", Style::default().fg(theme::LABEL)),
                Span::styled("resolving...", Style::default().fg(theme::MUTED)),
            ]),
            Line::from(vec![
                Span::styled("MX: ", Style::default().fg(theme::LABEL)),
                Span::styled("resolving...", Style::default().fg(theme::MUTED)),
            ]),
        ]
    }

    fn build_dns_unavailable_lines() -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled("DNS: ", Style::default().fg(theme::LABEL)),
            Span::styled("scanner not available", Style::default().fg(theme::BAD)),
        ])]
    }
}

/// A record set's query outcome: color and text.
fn status_display(status: &crate::scan::dns::QueryStatus) -> (Color, String) {
    match status {
        crate::scan::dns::QueryStatus::NotQueried => (theme::MUTED, "not queried".to_string()),
        crate::scan::dns::QueryStatus::Success(count) => (theme::GOOD, format!("{} records", count)),
        crate::scan::dns::QueryStatus::NoRecords => (theme::WARN, "No Records".to_string()),
        crate::scan::dns::QueryStatus::Failed(_error) => (theme::BAD, "Failed".to_string()),
        crate::scan::dns::QueryStatus::Timeout => (theme::BAD, "Timeout".to_string()),
    }
}

/// A record's remaining TTL as the stub resolver reported it: `<n>s (cached)`, since that is the
/// resolver cache's countdown, not the zone's TTL. At 0 it reads `expired, refreshing` only while
/// the DNS scanner is re-querying (`refreshing`), and plain `expired` otherwise; both MUTED.
fn ttl_span(ttl: u32, refreshing: bool) -> Span<'static> {
    if ttl == 0 {
        let text = if refreshing { "expired, refreshing" } else { "expired" };
        return Span::styled(text, Style::default().fg(theme::MUTED));
    }
    let color = if ttl > TTL_WARNING_THRESHOLD { theme::GOOD } else { theme::WARN };
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
        Span::styled(format!("{}: ", label), Style::default().fg(theme::LABEL)),
        Span::styled(text, Style::default().fg(color)),
    ]))
}

/// One record's row, indented under its section header. Zoomed, it ends with the record's own TTL,
/// since records of one set can expire apart.
fn record_line(value: Vec<Span<'static>>, ttl: u32, detail: Detail, refreshing: bool) -> Line<'static> {
    let mut spans = vec![Span::styled("  ", Style::default())];
    spans.extend(value);
    if detail == Detail::Zoomed {
        spans.push(Span::styled("  TTL: ", Style::default().fg(theme::LABEL)));
        spans.push(ttl_span(ttl, refreshing));
    }
    Line::from(spans)
}

/// The `PTR:` section: reverse DNS for the target's addresses. An address with no PTR record is
/// common and not a fault, so it reads `none` (MUTED).
fn ptr_lines(dns_result: &crate::scan::dns::DnsResult, detail: Detail, refreshing: bool) -> Vec<Line<'static>> {
    let (color, text) = match &dns_result.PTR_status {
        crate::scan::dns::QueryStatus::NoRecords => (theme::MUTED, "none".to_string()),
        status => status_display(status),
    };
    let mut header = vec![
        Span::styled("PTR: ", Style::default().fg(theme::LABEL)),
        Span::styled(text, Style::default().fg(color)),
    ];
    if let Some(first) = dns_result.PTR.first() {
        header.push(Span::styled(", TTL: ", Style::default().fg(theme::LABEL)));
        header.push(ttl_span(first.ttl_remaining(), refreshing));
    }
    let mut lines = vec![Line::from(header)];
    for record in dns_result.PTR.iter().take(MAX_PTR_RECORDS_DISPLAYED) {
        lines.push(record_line(
            vec![Span::styled(record.value.clone(), Style::default().fg(theme::VALUE))],
            record.ttl_remaining(),
            detail,
            refreshing,
        ));
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
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::dns] content: width={} detail={:?}", width, detail);
        crate::tui::text::to_rows(self.build_content_lines(state, detail), width, detail, &[])
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

    /// Item 2: an address with no PTR record reads `PTR: none` in MUTED; a resolver error still
    /// reads `PTR: Failed` in BAD.
    #[test]
    fn ptr_without_a_record_reads_none_and_an_error_reads_failed() {
        let render = |status: QueryStatus| {
            let mut result = DnsResult::new();
            result.MX_status = QueryStatus::NoRecords;
            result.PTR_status = status;
            let state = complete_state("dns", crate::types::ScanResult::Dns(result));
            (
                crate::tui::testing::render_pane(&DnsPane::new(), &state, 80, 40, false),
                crate::tui::testing::render_buffer(&DnsPane::new(), &state, 80, 40, false),
            )
        };
        let (out, buffer) = render(QueryStatus::NoRecords);
        assert!(out.contains("PTR: none"), "{out}");
        assert!(!out.contains("Failed"), "{out}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "none"), theme::MUTED);

        let (out, buffer) = render(QueryStatus::Failed("SERVFAIL".to_string()));
        assert!(out.contains("PTR: Failed"), "{out}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "Failed"), theme::BAD);
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

    /// Item B: a TTL is the stub resolver's countdown, so it says `cached`. Item 1 (v0.5.8): at 0
    /// it says `expired, refreshing` only while the DNS scanner is `Running`; an idle scanner's 0
    /// is plain `expired`, since nothing is refreshing. Both MUTED, never a bare `0s`.
    #[test]
    fn ttl_reads_cached_and_expired_reads_refreshing_only_while_running() {
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

        let idle_buffer = crate::tui::testing::render_buffer(&DnsPane::new(), &state, 80, 40, false);
        let idle = crate::tui::testing::render_pane(&DnsPane::new(), &state, 80, 40, false);
        assert!(idle.contains("TTL: expired"), "{idle}");
        assert!(
            !idle.contains("refreshing"),
            "an idle scanner claims a refresh:\n{idle}"
        );
        assert!(!idle.contains("TTL: 0s"), "{idle}");
        assert_eq!(crate::tui::testing::fg_of(&idle_buffer, "expired"), theme::MUTED);

        state.scanners.get_mut("dns").expect("dns state").status = crate::types::ScanStatus::Running;
        let running_buffer = crate::tui::testing::render_buffer(&DnsPane::new(), &state, 80, 40, false);
        let running = crate::tui::testing::render_pane(&DnsPane::new(), &state, 80, 40, false);
        assert!(running.contains("TTL: expired, refreshing"), "{running}");
        assert_eq!(
            crate::tui::testing::fg_of(&running_buffer, "expired, refreshing"),
            theme::MUTED
        );
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

    fn txt_state(records: &[&str]) -> AppState {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
        let mut result = DnsResult::new();
        result.TXT = records
            .iter()
            .map(|value| DnsRecord::new(value.to_string(), 3600))
            .collect();
        result.TXT_status = QueryStatus::Success(records.len());
        complete_state("dns", crate::types::ScanResult::Dns(result))
    }

    #[test]
    fn zoomed_content_shows_a_300_char_txt_record_in_full_wrapped() {
        let mut txt = "v=spf1".to_string();
        let mut n = 0;
        while txt.len() < 290 {
            txt.push_str(&format!(" include:_spf{n}.mail.example.com"));
            n += 1;
        }
        let txt: String = format!("{txt} -all").chars().take(300).collect();
        assert_eq!(txt.chars().count(), 300);
        let verification = "google-site-verification=0123456789abcdefABCDEF";
        let state = txt_state(&[&txt, verification]);
        let pane = DnsPane::new();

        let rows = crate::tui::testing::content_rows(&pane, &state, 80, Detail::Zoomed);
        assert!(rows.iter().all(|row| row.chars().count() <= 80), "{rows:#?}");
        let start = rows
            .iter()
            .position(|row| row.starts_with("  v=spf1"))
            .expect("TXT row");
        let joined: String = rows[start..].concat();
        assert!(joined.contains(&txt), "TXT not shown whole:\n{rows:#?}");
        let tail: String = txt.chars().skip(280).collect();
        assert!(!rows[start].contains(&tail), "TXT did not wrap: {rows:#?}");
        assert!(
            rows.concat().contains(verification),
            "verification token abbreviated in zoom"
        );

        let normal = crate::tui::testing::content_rows(&pane, &state, 80, Detail::Normal).concat();
        assert!(!normal.contains(&txt), "the grid fits the record to one row");
        assert!(!normal.contains(verification));
    }

    #[test]
    fn zoomed_content_gives_each_record_its_ttl_and_every_soa_field() {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus, SoaRecord};
        let mut result = DnsResult::new();
        result.A = vec![
            DnsRecord::new("192.0.2.1".parse().expect("ip"), 300),
            DnsRecord::new("192.0.2.2".parse().expect("ip"), 1200),
        ];
        result.A_status = QueryStatus::Success(2);
        result.SOA = vec![DnsRecord::new(
            SoaRecord {
                primary_ns: "ns1.example.com".to_string(),
                responsible_email: "hostmaster.example.com".to_string(),
                serial: 2026102901,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum_ttl: 300,
            },
            3600,
        )];
        let state = complete_state("dns", crate::types::ScanResult::Dns(result));
        let pane = DnsPane::new();
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Zoomed).join("\n");
        assert!(zoomed.contains("192.0.2.1  TTL: 300s (cached)"), "{zoomed}");
        assert!(zoomed.contains("192.0.2.2  TTL: 1200s (cached)"), "{zoomed}");
        for field in [
            "Email: hostmaster.example.com",
            "Refresh: 7200s",
            "Retry: 3600s",
            "Expire: 1209600s",
            "Minimum TTL: 300s",
        ] {
            assert!(zoomed.contains(field), "{field}: {zoomed}");
        }
        let normal = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Normal).join("\n");
        assert!(!normal.contains("1200s"), "{normal}");
        assert!(!normal.contains("Refresh:"), "{normal}");
    }
}
