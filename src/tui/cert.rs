//! The cert pane: the certificate chain the server presented, read from the `tls` scanner. The
//! issuing CA leads, and a CA under a known browser distrust action reads `(distrusted CA)`. The
//! chain is what the server sent, not a verified path: the root is usually not sent, so the pane
//! never claims to show it.

use crate::scan::tls::{CertificateInfo, TlsData, distrust_of};
use crate::tui::pane::{Detail, Pane};
use crate::tui::text::plural;
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use std::any::Any;

const CN_EXTRACT_PREFIX_LENGTH: usize = 3;
const CERT_EXPIRY_WARNING_DAYS: i64 = 30;
const CERT_EXPIRY_CRITICAL_DAYS: i64 = 7;
const DISTRUSTED_LABEL: &str = " (distrusted CA)";
/// The status row and the CA row wrap rather than clip: a failure's reason and the CA name stay
/// whole.
const WRAPPED_ROWS: [usize; 2] = [0, 1];

/// CERT pane: the issuing CA, validity, subject, key and the chain as sent.
pub struct CertPane {
    title: &'static str,
    id: &'static str,
}

impl CertPane {
    pub fn new() -> Self {
        log::debug!("[tui::cert] new:");
        Self {
            title: "cert",
            id: "cert",
        }
    }

    /// The pane's logical lines, before they are laid out as rows by `content`. The first is
    /// always the `Status:` row; the CA row follows it whenever a certificate was presented.
    fn build_content_lines(&self, state: &AppState, detail: Detail) -> Vec<Line<'static>> {
        let Some(tls_state) = state.scanners.get("tls") else {
            return vec![status_line(vec![Span::styled(
                "unavailable",
                Style::default().fg(theme::BAD),
            )])];
        };
        let (label, color) = crate::tui::status_label(&tls_state, "analyzing...", "analyzed");
        let mut status = vec![Span::styled(label, Style::default().fg(color))];
        let data = match tls_state.result.as_ref() {
            Some(ScanResult::Tls(result)) => result.get_primary_result(),
            _ => None,
        };
        let Some(data) = data else {
            log::trace!("[tui::cert] build_content_lines: no TLS result yet");
            return vec![status_line(status)];
        };
        let Some(leaf) = data.certificate_chain.first() else {
            status.push(Span::styled(
                format!(" · {}", no_certificate_reason(data)),
                Style::default().fg(theme::WARN),
            ));
            return vec![status_line(status)];
        };

        let mut lines = vec![status_line(status), ca_line(leaf), validity_line(data)];
        lines.push(row("Subject: ", common_name_display(&leaf.subject), theme::WARN));
        lines.push(Line::from(vec![
            Span::styled("Key: ", Style::default().fg(theme::LABEL)),
            Span::styled(leaf.public_key_algorithm.clone(), Style::default().fg(theme::WARN)),
            Span::styled(
                leaf.key_size.map_or(String::new(), |size| format!(" {size}bit")),
                Style::default().fg(theme::MUTED),
            ),
        ]));
        if !leaf.san_domains.is_empty() {
            lines.push(row("SAN: ", plural(leaf.san_domains.len(), "domain"), theme::GOOD));
        }
        lines.extend(chain_lines(&data.certificate_chain, leaf, detail));
        lines
    }
}

/// `📜 Status: <spans>`.
fn status_line(spans: Vec<Span<'static>>) -> Line<'static> {
    let mut line = vec![Span::styled("📜 Status: ", Style::default().fg(theme::VALUE))];
    line.extend(spans);
    Line::from(line)
}

fn row(label: &'static str, value: String, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(theme::LABEL)),
        Span::styled(value, Style::default().fg(color)),
    ])
}

/// Why a scan that finished has no certificate to show: its first recorded certificate error,
/// or the bare fact.
fn no_certificate_reason(data: &TlsData) -> String {
    match data.certificate_errors.first() {
        Some(error) => format!("no certificate: {error}"),
        None if !data.connection_successful => "no certificate: handshake failed".to_string(),
        None => "no certificate".to_string(),
    }
}

/// The issuer as `Organization (CN)`; either alone when the other is missing, and the joined
/// issuer name when both are.
fn ca_text(cert: &CertificateInfo) -> String {
    match (&cert.issuer_organization, &cert.issuer_common_name) {
        (Some(organization), Some(common_name)) => format!("{organization} ({common_name})"),
        (Some(organization), None) => organization.clone(),
        (None, Some(common_name)) => common_name.clone(),
        (None, None) => cert.issuer.clone(),
    }
}

/// `CA: Google Trust Services (WE2)`, in `BAD` with `(distrusted CA)` when the leaf's issuer is
/// under a distrust action.
fn ca_line(leaf: &CertificateInfo) -> Line<'static> {
    let distrusted = distrust_of(leaf.issuer_organization.as_deref(), leaf.not_before).is_some();
    let mut spans = vec![
        Span::styled("CA: ", Style::default().fg(theme::LABEL)),
        Span::styled(
            ca_text(leaf),
            Style::default().fg(if distrusted { theme::BAD } else { theme::GOOD }),
        ),
    ];
    if distrusted {
        spans.push(Span::styled(DISTRUSTED_LABEL, Style::default().fg(theme::BAD)));
    }
    Line::from(spans)
}

/// `Valid: yes · 53 days`, the days colored by how soon the leaf expires.
fn validity_line(data: &TlsData) -> Line<'static> {
    let mut spans = vec![
        Span::styled("Valid: ", Style::default().fg(theme::LABEL)),
        Span::styled(
            if data.certificate_valid { "yes" } else { "no" },
            Style::default().fg(if data.certificate_valid { theme::GOOD } else { theme::BAD }),
        ),
    ];
    if let Some(days) = data.days_until_expiry {
        let color = if days > CERT_EXPIRY_WARNING_DAYS {
            theme::GOOD
        } else if days > CERT_EXPIRY_CRITICAL_DAYS {
            theme::WARN
        } else {
            theme::BAD
        };
        spans.push(Span::styled(" · ", Style::default().fg(theme::MUTED)));
        spans.push(Span::styled(plural(days, "day"), Style::default().fg(color)));
    }
    Line::from(spans)
}

/// The chain as the server sent it. The grid shows one row per certificate, its subject's CN;
/// zoom shows each certificate's full detail. A certificate whose issuer is under a distrust
/// action, judged by the leaf's `notBefore`, reads `BAD` with `(distrusted CA)`.
fn chain_lines(chain: &[CertificateInfo], leaf: &CertificateInfo, detail: Detail) -> Vec<Line<'static>> {
    let distrusted =
        |cert: &CertificateInfo| distrust_of(cert.issuer_organization.as_deref(), leaf.not_before).is_some();
    let mut lines = Vec::new();
    if detail == Detail::Normal {
        lines.push(Line::from(Span::styled(
            "Chain (as sent):",
            Style::default().fg(theme::LABEL),
        )));
        for cert in chain {
            lines.push(chain_row("  ", cert, distrusted(cert)));
        }
        return lines;
    }
    let field = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("    {label}: "), Style::default().fg(theme::LABEL)),
            Span::styled(value, Style::default().fg(theme::MUTED)),
        ])
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Chain (as sent): ", Style::default().fg(theme::VALUE)),
        Span::styled(plural(chain.len(), "certificate"), Style::default().fg(theme::MUTED)),
    ]));
    for (index, cert) in chain.iter().enumerate() {
        lines.push(chain_row(&format!("  [{index}] "), cert, distrusted(cert)));
        lines.push(field("Subject", cert.subject.clone()));
        lines.push(field("Issuer", cert.issuer.clone()));
        lines.push(field("Serial", cert.serial_number.clone()));
        lines.push(field(
            "Valid",
            format!(
                "{} to {}",
                cert.not_before.format("%Y-%m-%d"),
                cert.not_after.format("%Y-%m-%d")
            ),
        ));
        lines.push(field("Signature", cert.signature_algorithm.clone()));
        lines.push(field(
            "Key",
            match cert.key_size {
                Some(size) => format!("{} {}bit", cert.public_key_algorithm, size),
                None => cert.public_key_algorithm.clone(),
            },
        ));
        if !cert.san_domains.is_empty() {
            lines.push(field("SAN", cert.san_domains.join(", ")));
        }
    }
    lines
}

fn chain_row(prefix: &str, cert: &CertificateInfo, distrusted: bool) -> Line<'static> {
    let mut spans = vec![
        Span::styled(prefix.to_string(), Style::default().fg(theme::LABEL)),
        Span::styled(
            common_name_display(&cert.subject),
            Style::default().fg(if distrusted { theme::BAD } else { theme::WARN }),
        ),
    ];
    if distrusted {
        spans.push(Span::styled(DISTRUSTED_LABEL, Style::default().fg(theme::BAD)));
    }
    Line::from(spans)
}

/// The `CN=` value of a distinguished name, cut at the next `,`. Never cut by length: the line is
/// fit to the pane width, which marks the cut with `…`.
fn common_name_display(distinguished_name: &str) -> String {
    let Some(cn_start) = distinguished_name.find("CN=") else {
        return "unknown".to_string();
    };
    let cn_part = &distinguished_name[cn_start + CN_EXTRACT_PREFIX_LENGTH..];
    let cn = cn_part.split(',').next().unwrap_or_default();
    cn.to_string()
}

impl Default for CertPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for CertPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::cert] content: width={} detail={:?}", width, detail);
        let lines = self.build_content_lines(state, detail);
        crate::tui::text::to_rows(lines, width, detail, &WRAPPED_ROWS)
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn is_focusable(&self) -> bool {
        true
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::tls::{SecurityGrade, TlsResult, TlsStatus, TlsVersion};
    use crate::tui::testing::{content_rows, fg_of, render_buffer, render_pane};
    use crate::types::{ScanState, ScanStatus};
    use chrono::{TimeZone, Utc};
    use std::time::{Duration, Instant};

    fn cert(subject: &str, organization: Option<&str>, common_name: Option<&str>) -> CertificateInfo {
        let issuer = [
            organization.map(|o| format!("O={o}")),
            common_name.map(|cn| format!("CN={cn}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        CertificateInfo {
            subject: subject.to_string(),
            issuer,
            issuer_organization: organization.map(str::to_string),
            issuer_common_name: common_name.map(str::to_string),
            serial_number: "1".to_string(),
            not_before: Utc::now() - chrono::Duration::days(10),
            not_after: Utc::now() + chrono::Duration::days(80),
            signature_algorithm: "ecdsa-with-SHA256".to_string(),
            public_key_algorithm: "EC".to_string(),
            key_size: Some(256),
            san_domains: vec!["*.google.com".to_string(), "google.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        }
    }

    fn tls_data(chain: Vec<CertificateInfo>) -> TlsData {
        TlsData {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: chain,
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: None,
            days_until_expiry: Some(53),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: false,
            vulnerabilities: vec![],
            security_grade: SecurityGrade::A,
            scan_time: Duration::from_millis(500),
            target_ip: "192.0.2.1".to_string(),
            queried_at: Instant::now(),
        }
    }

    fn state_with(data: TlsData, status: ScanStatus) -> AppState {
        let state = AppState::new("google.com".to_string());
        let mut result = TlsResult::new();
        result.ipv4_status = TlsStatus::Success(data.security_grade.clone());
        result.ipv4_result = Some(data);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(result)),
                error: None,
                status,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    fn google_state() -> AppState {
        let leaf = cert("CN=*.google.com", Some("Google Trust Services"), Some("WE2"));
        let intermediate = cert(
            "C=US, O=Google Trust Services, CN=WE2",
            Some("Google Trust Services LLC"),
            Some("GTS Root R1"),
        );
        state_with(tls_data(vec![leaf, intermediate]), ScanStatus::Complete)
    }

    /// Phase 4 criterion: the CA row is the first row after `Status:`.
    #[test]
    fn ca_is_the_first_row_after_status() {
        let rows = content_rows(&CertPane::new(), &google_state(), 58, Detail::Normal);
        assert!(rows[0].starts_with("📜 Status: analyzed"), "{rows:#?}");
        assert_eq!(rows[1].trim_end(), "CA: Google Trust Services (WE2)", "{rows:#?}");
        let order: Vec<usize> = [
            "Valid: yes · 53 days",
            "Subject: *.google.com",
            "Key: EC 256bit",
            "SAN: 2 domains",
            "Chain (as sent):",
            "  *.google.com",
            "  WE2",
        ]
        .iter()
        .map(|needle| {
            rows.iter()
                .position(|row| row.trim_end() == *needle)
                .unwrap_or_else(|| panic!("{needle}: {rows:#?}"))
        })
        .collect();
        assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{rows:#?}");
    }

    fn entrust_state(not_before: chrono::DateTime<Utc>) -> AppState {
        let mut leaf = cert(
            "CN=www.example.com",
            Some("Entrust, Inc."),
            Some("Entrust Certification Authority - L1K"),
        );
        leaf.not_before = not_before;
        let intermediate = cert(
            "C=US, O=Entrust, Inc., CN=Entrust Certification Authority - L1K",
            Some("Entrust, Inc."),
            Some("Entrust Root Certification Authority - G2"),
        );
        state_with(tls_data(vec![leaf, intermediate]), ScanStatus::Complete)
    }

    /// Phase 4 criterion: an Entrust leaf issued after the distrust date marks the CA row and the
    /// chain rows `BAD` with `(distrusted CA)`; Google Trust Services is never marked.
    #[test]
    fn an_entrust_leaf_after_the_distrust_date_reads_distrusted_and_google_does_not() {
        let pane = CertPane::new();
        let state = entrust_state(Utc.with_ymd_and_hms(2025, 1, 15, 0, 0, 0).unwrap());
        let out = render_pane(&pane, &state, 120, 20, false);
        assert!(
            out.contains("CA: Entrust, Inc. (Entrust Certification Authority - L1K) (distrusted CA)"),
            "{out}"
        );
        let buffer = render_buffer(&pane, &state, 120, 20, false);
        assert_eq!(fg_of(&buffer, "Entrust, Inc. (Entrust"), theme::BAD);
        assert_eq!(fg_of(&buffer, "www.example.com (distrusted CA)"), theme::BAD);

        let before = entrust_state(Utc.with_ymd_and_hms(2024, 11, 1, 0, 0, 0).unwrap());
        assert!(!render_pane(&pane, &before, 120, 20, false).contains("distrusted"));

        let google = google_state();
        let out = render_pane(&pane, &google, 120, 20, false);
        assert!(!out.contains("distrusted"), "{out}");
        let buffer = render_buffer(&pane, &google, 120, 20, false);
        assert_eq!(fg_of(&buffer, "Google Trust Services (WE2)"), theme::GOOD);
    }

    /// Phase 4 criterion: a failed scan with a kept older result says so on the status row.
    #[test]
    fn a_failed_scan_with_a_kept_result_reads_failed_on_the_status_row() {
        let state = google_state();
        if let Some(mut tls) = state.scanners.get_mut("tls") {
            tls.status = ScanStatus::Failed;
            tls.error = Some(eyre::eyre!("timed out after 30s"));
        }
        let rows = content_rows(&CertPane::new(), &state, 58, Detail::Normal);
        assert_eq!(
            rows[0].trim_end(),
            "📜 Status: failed: timed out after 30s",
            "{rows:#?}"
        );
        assert!(
            rows[1].starts_with("CA: Google Trust Services"),
            "kept result dropped: {rows:#?}"
        );
        let buffer = render_buffer(&CertPane::new(), &state, 60, 14, false);
        assert_eq!(fg_of(&buffer, "failed: timed out"), theme::BAD);
    }

    #[test]
    fn an_empty_chain_draws_only_the_status_row_with_its_reason() {
        let mut data = tls_data(vec![]);
        data.connection_successful = false;
        data.certificate_errors = vec!["Certificate analysis failed: reset".to_string()];
        let rows = content_rows(
            &CertPane::new(),
            &state_with(data, ScanStatus::Complete),
            100,
            Detail::Normal,
        );
        assert_eq!(
            rows,
            vec!["📜 Status: analyzed · no certificate: Certificate analysis failed: reset".to_string()]
        );
        let rows = content_rows(
            &CertPane::new(),
            &state_with(tls_data(vec![]), ScanStatus::Complete),
            100,
            Detail::Normal,
        );
        assert_eq!(rows, vec!["📜 Status: analyzed · no certificate".to_string()]);
    }

    #[test]
    fn an_issuer_with_no_organization_or_common_name_falls_back_to_the_joined_name() {
        let mut leaf = cert("CN=host.example", None, None);
        leaf.issuer = "OU=Fixture Unit, C=US".to_string();
        let rows = content_rows(
            &CertPane::new(),
            &state_with(tls_data(vec![leaf.clone()]), ScanStatus::Complete),
            80,
            Detail::Normal,
        );
        assert_eq!(rows[1].trim_end(), "CA: OU=Fixture Unit, C=US");
        leaf.issuer_common_name = Some("R3".to_string());
        assert_eq!(ca_text(&leaf), "R3");
        leaf.issuer_organization = Some("Let's Encrypt".to_string());
        leaf.issuer_common_name = None;
        assert_eq!(ca_text(&leaf), "Let's Encrypt");
    }

    /// A long CA name wraps whole in the 200x55 cell rather than being cut.
    #[test]
    fn a_long_ca_name_wraps_whole_at_200x55() {
        let cn = "Sectigo Public Server Authentication CA DV R36";
        let leaf = cert("CN=example.com", Some("Sectigo Limited"), Some(cn));
        let state = state_with(tls_data(vec![leaf]), ScanStatus::Complete);
        let (width, height) = crate::tui::testing::dashboard_pane_size(0, 2, 200, 55);
        let rows = content_rows(&CertPane::new(), &state, width - 2, Detail::Normal);
        assert!(rows.concat().contains(cn), "CN cut: {rows:#?}");
        let out = render_pane(&CertPane::new(), &state, width, height, false);
        assert!(!out.contains('…'), "{out}");
    }

    #[test]
    fn render_multibyte_cn_is_fit_by_width_without_panic() {
        let cn = "é".repeat(30);
        let leaf = cert(&format!("CN={cn}"), Some("Example"), Some(&cn));
        let state = state_with(tls_data(vec![leaf]), ScanStatus::Complete);
        let wide = render_pane(&CertPane::new(), &state, 100, 20, false);
        assert!(wide.contains(&format!("Subject: {cn}")), "subject CN cut:\n{wide}");
        let narrow = render_pane(&CertPane::new(), &state, 30, 20, false);
        assert!(narrow.contains('…'), "narrow CN not marked:\n{narrow}");
    }

    #[test]
    fn expiry_counts_read_singular_and_negative_for_an_expired_leaf() {
        let mut data = tls_data(vec![cert("CN=example.com", None, Some("R3"))]);
        data.days_until_expiry = Some(1);
        data.certificate_chain[0].san_domains = vec!["example.com".to_string()];
        let out = render_pane(
            &CertPane::new(),
            &state_with(data, ScanStatus::Complete),
            100,
            20,
            false,
        );
        assert!(out.contains("Valid: yes · 1 day "), "{out}");
        assert!(out.contains("SAN: 1 domain "), "{out}");

        let state = AppState::new("expired.example".to_string());
        let mut result = TlsResult::new();
        let data = crate::scan::tls::fixtures::expired_handshake_result();
        result.ipv4_status = TlsStatus::Success(data.security_grade.clone());
        result.ipv4_result = Some(data);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let out = render_pane(&CertPane::new(), &state, 100, 20, false);
        assert!(out.contains("Valid: no · -30 days"), "{out}");
        assert!(out.contains("CA: Fixture CA"), "{out}");
    }

    #[test]
    fn zoom_lists_the_chain_as_sent_in_full_and_the_grid_does_not() {
        let state = google_state();
        if let Some(mut tls) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(result)) = tls.result.as_mut()
            && let Some(data) = result.ipv4_result.as_mut()
        {
            data.certificate_chain[0].serial_number = "0a:1b:2c".to_string();
        }
        let text = content_rows(&CertPane::new(), &state, 60, Detail::Zoomed).join("\n");
        for expected in [
            "Chain (as sent): 2 certificates",
            "[0] *.google.com",
            "Serial: 0a:1b:2c",
            "Subject: C=US, O=Google Trust Services, CN=WE2",
            "Signature: ecdsa-with-SHA256",
            "SAN: *.google.com, google.com",
        ] {
            assert!(text.contains(expected), "{expected}:\n{text}");
        }
        let normal = content_rows(&CertPane::new(), &state, 60, Detail::Normal).join("\n");
        assert!(!normal.contains("0a:1b:2c"), "{normal}");
    }

    #[test]
    fn common_name_display_cases() {
        assert_eq!(common_name_display("O=Example,CN=host.example,C=US"), "host.example");
        assert_eq!(common_name_display("O=No Common Name"), "unknown");
        assert_eq!(
            common_name_display(&format!("CN={}", "ü".repeat(40))).chars().count(),
            40
        );
        assert_eq!(common_name_display("CN="), "");
    }

    #[test]
    fn no_tls_scanner_reads_unavailable() {
        let rows = content_rows(
            &CertPane::new(),
            &AppState::new("x.test".to_string()),
            60,
            Detail::Normal,
        );
        assert_eq!(rows, vec!["📜 Status: unavailable".to_string()]);
    }
}
