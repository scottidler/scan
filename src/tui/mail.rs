//! The mail pane: the target's email posture from the `dns` scanner. SPF, DMARC and MX as the
//! security pane showed them, plus DNSSEC (DS published at the zone) and DKIM at the common
//! selectors. DS and DKIM are asked at the registrable domain, named on a `Zone:` row whenever it
//! differs from the host, so neither is read as the host's own.

use crate::scan::dns::{DkimKey, EmailSecurityAnalysis};
use crate::scan::lens::LensOutcome;
use crate::tui::http::lens_value_or;
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

/// The status row wraps rather than clips, so a failure's reason stays whole.
const WRAPPED_ROWS: [usize; 1] = [0];

/// MAIL pane: SPF, DMARC, DNSSEC, DKIM and MX for a name target.
pub struct MailPane {
    title: &'static str,
    id: &'static str,
}

impl MailPane {
    pub fn new() -> Self {
        log::debug!("[tui::mail] new:");
        Self {
            title: "mail",
            id: "mail",
        }
    }

    /// The pane's logical lines, before they are laid out as rows by `content`. The first is
    /// always the `Status:` row.
    fn build_content_lines(&self, state: &AppState, detail: Detail) -> Vec<Line<'static>> {
        let Some(dns_state) = state.scanners.get("dns") else {
            return vec![status_line("scanner not available".to_string(), theme::BAD)];
        };
        let (label, color) = crate::tui::status_label(&dns_state, "resolving...", "resolved");
        let mut lines = vec![status_line(label, color)];
        let Some(ScanResult::Dns(dns)) = dns_state.result.as_ref() else {
            return lines;
        };
        let Some(email) = dns.email_security.as_ref() else {
            if dns.is_reverse_only() {
                lines.push(Line::from(Span::styled(
                    "not applicable (IP target)",
                    Style::default().fg(theme::MUTED),
                )));
            }
            return lines;
        };

        if zone_differs_from_host(&email.zone, &state.target) {
            lines.push(row("Zone: ", email.zone.clone(), theme::VALUE));
        }
        lines.push(configured_row("SPF: ", email.spf_record.is_some()));
        lines.push(configured_row("DMARC: ", email.dmarc_record.is_some()));
        // Zoomed only, under DMARC: the MTA-STS policy id and the TLS-RPT report address.
        if detail == Detail::Zoomed {
            for (label, outcome) in [("MTA-STS: ", &email.mta_sts), ("TLS-RPT: ", &email.tls_rpt)] {
                lines.push(Line::from(vec![
                    Span::styled(label, Style::default().fg(theme::LABEL)),
                    crate::tui::http::lens_value(outcome, |value| (value.clone(), theme::GOOD)),
                ]));
            }
        }
        lines.push(dnssec_line(email, rdap_dnssec(state)));
        lines.push(Line::from(vec![
            Span::styled("DKIM: ", Style::default().fg(theme::LABEL)),
            lens_value_or(
                &email.dkim,
                |keys| dkim_summary(keys),
                ("none at common selectors".to_string(), theme::MUTED),
            ),
        ]));
        if detail == Detail::Zoomed
            && let LensOutcome::Present(keys) = &email.dkim
        {
            for key in keys {
                lines.push(row(
                    "  selector: ",
                    dkim_key_text(key),
                    if key.revoked { theme::WARN } else { theme::GOOD },
                ));
            }
        }
        lines.push(row(
            "MX: ",
            plural(email.mx_count, "record"),
            if email.has_mx { theme::GOOD } else { theme::MUTED },
        ));
        if let Some(spf) = &email.spf_record {
            lines.push(row("  SPF: ", spf.clone(), theme::MUTED));
        }
        if let Some(dmarc) = &email.dmarc_record {
            lines.push(row("  DMARC: ", dmarc.clone(), theme::MUTED));
        }
        lines
    }
}

/// `📧 Status: <label>`.
fn status_line(label: String, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled("📧 Status: ", Style::default().fg(theme::VALUE)),
        Span::styled(label, Style::default().fg(color)),
    ])
}

fn row(label: &'static str, value: String, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(theme::LABEL)),
        Span::styled(value, Style::default().fg(color)),
    ])
}

fn configured_row(label: &'static str, configured: bool) -> Line<'static> {
    row(
        label,
        if configured { "configured" } else { "missing" }.to_string(),
        if configured { theme::GOOD } else { theme::BAD },
    )
}

/// Whether `zone` names something other than the host of `target` (the raw target: a name or a
/// URL).
fn zone_differs_from_host(zone: &str, target: &str) -> bool {
    let Some(host) = crate::target::Target::parse(target)
        .ok()
        .and_then(|target| target.domain)
    else {
        return false;
    };
    !zone.eq_ignore_ascii_case(host.trim_end_matches('.'))
}

/// The WHOIS RDAP DNSSEC flag for the same registrable domain, when WHOIS has one.
fn rdap_dnssec(state: &AppState) -> Option<bool> {
    let whois = state.scanners.get("whois")?;
    match whois.result.as_ref()? {
        ScanResult::Whois(result) => result.dnssec,
        _ => None,
    }
}

/// `DNSSEC: DS published`, `no DS`, or `failed: <reason>`, which names WHOIS RDAP's flag beside it
/// when there is one. A miss at a zone that is not the registrable domain says nothing, so it
/// reads `unknown (no suffix list)`, never `no DS`.
fn dnssec_line(email: &EmailSecurityAnalysis, rdap: Option<bool>) -> Line<'static> {
    let absent = if email.zone_is_registrable {
        ("no DS".to_string(), theme::WARN)
    } else {
        ("unknown (no suffix list)".to_string(), theme::MUTED)
    };
    let mut spans = vec![
        Span::styled("DNSSEC: ", Style::default().fg(theme::LABEL)),
        lens_value_or(&email.dnssec, |_| ("DS published".to_string(), theme::GOOD), absent),
    ];
    if matches!(email.dnssec, LensOutcome::Failed(_))
        && let Some(signed) = rdap
    {
        spans.push(Span::styled(
            format!(" · RDAP: {}", if signed { "signed" } else { "unsigned" }),
            Style::default().fg(theme::MUTED),
        ));
    }
    Line::from(spans)
}

fn dkim_key_text(key: &DkimKey) -> String {
    if key.revoked {
        format!("{} (revoked)", key.selector)
    } else {
        key.selector.clone()
    }
}

/// The first key found, `+N` for the rest: `google +1`.
fn dkim_summary(keys: &[DkimKey]) -> (String, Color) {
    let Some(first) = keys.first() else {
        return ("none at common selectors".to_string(), theme::MUTED);
    };
    let mut text = dkim_key_text(first);
    if keys.len() > 1 {
        text.push_str(&format!(" +{}", keys.len() - 1));
    }
    (text, if first.revoked { theme::WARN } else { theme::GOOD })
}

impl Default for MailPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for MailPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::mail] content: width={} detail={:?}", width, detail);
        crate::tui::text::to_rows(self.build_content_lines(state, detail), width, detail, &WRAPPED_ROWS)
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
    use crate::scan::dns::{DnsResult, QueryStatus};
    use crate::tui::testing::{content_rows, fg_of, render_buffer, render_pane};
    use crate::types::{ScanState, ScanStatus};
    use std::time::Instant;

    fn dns_state(target: &str, dns: DnsResult) -> AppState {
        let state = AppState::new(target.to_string());
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    fn email_state(target: &str, email: EmailSecurityAnalysis) -> AppState {
        let mut dns = DnsResult::new();
        dns.MX_status = QueryStatus::Success(1);
        dns.email_security = Some(email);
        dns_state(target, dns)
    }

    fn google() -> EmailSecurityAnalysis {
        EmailSecurityAnalysis {
            spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com".to_string()),
            has_mx: true,
            mx_count: 1,
            zone: "google.com".to_string(),
            dnssec: LensOutcome::Absent,
            dkim: LensOutcome::Present(vec![DkimKey {
                selector: "google".to_string(),
                revoked: false,
            }]),
            ..EmailSecurityAnalysis::fixture()
        }
    }

    fn rows(state: &AppState, detail: Detail) -> Vec<String> {
        content_rows(&MailPane::new(), state, 60, detail)
            .into_iter()
            .map(|row| row.trim_end().to_string())
            .collect()
    }

    #[test]
    fn a_name_target_shows_spf_dmarc_dnssec_and_dkim_under_its_status() {
        let rows = rows(&email_state("google.com", google()), Detail::Normal);
        assert_eq!(
            rows[..6],
            [
                "📧 Status: resolved",
                "SPF: configured",
                "DMARC: configured",
                "DNSSEC: no DS",
                "DKIM: google",
                "MX: 1 record",
            ],
            "{rows:#?}"
        );
    }

    /// Phase 4 criterion: an IP target reads `not applicable (IP target)` under the status row.
    #[test]
    fn an_ip_target_reads_not_applicable() {
        let mut dns = DnsResult::new();
        dns.PTR_status = QueryStatus::Success(1);
        let rows = rows(&dns_state("192.0.2.1", dns), Detail::Normal);
        assert_eq!(rows, ["📧 Status: resolved", "not applicable (IP target)"]);
    }

    /// Phase 4 criterion: each DNSSEC state, one fixture each.
    #[test]
    fn dnssec_renders_published_no_ds_failed_and_unknown_without_a_suffix_list() {
        for (dnssec, registrable, text, color) in [
            (LensOutcome::Present(2), true, "DS published", theme::GOOD),
            (LensOutcome::Absent, true, "no DS", theme::WARN),
            (
                LensOutcome::Failed("timed out".to_string()),
                true,
                "failed: timed out",
                theme::BAD,
            ),
            (LensOutcome::Absent, false, "unknown (no suffix list)", theme::MUTED),
        ] {
            let state = email_state(
                "google.com",
                EmailSecurityAnalysis {
                    dnssec,
                    zone_is_registrable: registrable,
                    ..google()
                },
            );
            let out = render_pane(&MailPane::new(), &state, 60, 16, false);
            assert!(out.contains(&format!("DNSSEC: {text} ")), "{text}:\n{out}");
            assert_eq!(
                fg_of(&render_buffer(&MailPane::new(), &state, 60, 16, false), text),
                color,
                "{text}"
            );
        }
    }

    /// A failed DS lookup names WHOIS RDAP's flag beside it; a lookup that answered does not.
    #[test]
    fn a_failed_ds_lookup_falls_back_to_rdap() {
        let state = email_state(
            "google.com",
            EmailSecurityAnalysis {
                dnssec: LensOutcome::Failed("timed out".to_string()),
                ..google()
            },
        );
        let mut whois = crate::scan::whois::WhoisResult::not_applicable(
            "google.com".to_string(),
            crate::scan::whois::NotApplicableReason::IpTarget,
        );
        whois.dnssec = Some(false);
        state.scanners.insert(
            "whois".to_string(),
            ScanState {
                result: Some(ScanResult::Whois(whois)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        assert!(rows(&state, Detail::Normal).contains(&"DNSSEC: failed: timed out · RDAP: unsigned".to_string()));
        if let Some(mut dns) = state.scanners.get_mut("dns")
            && let Some(ScanResult::Dns(result)) = dns.result.as_mut()
            && let Some(email) = result.email_security.as_mut()
        {
            email.dnssec = LensOutcome::Absent;
        }
        assert!(rows(&state, Detail::Normal).contains(&"DNSSEC: no DS".to_string()));
    }

    /// Phase 4 criterion: each DKIM state, one fixture each.
    #[test]
    fn dkim_renders_a_selector_none_failed_and_revoked() {
        let key = |selector: &str, revoked: bool| DkimKey {
            selector: selector.to_string(),
            revoked,
        };
        for (dkim, text, color) in [
            (LensOutcome::Present(vec![key("google", false)]), "google", theme::GOOD),
            (LensOutcome::Absent, "none at common selectors", theme::MUTED),
            (
                LensOutcome::Failed("timed out (9 of 9 selectors)".to_string()),
                "failed: timed out (9 of 9 selectors)",
                theme::BAD,
            ),
            (LensOutcome::Present(vec![key("s1", true)]), "s1 (revoked)", theme::WARN),
            (
                LensOutcome::Present(vec![key("google", false), key("k1", false)]),
                "google +1",
                theme::GOOD,
            ),
        ] {
            let state = email_state("google.com", EmailSecurityAnalysis { dkim, ..google() });
            assert!(
                rows(&state, Detail::Normal).contains(&format!("DKIM: {text}")),
                "{text}: {:#?}",
                rows(&state, Detail::Normal)
            );
            assert_eq!(
                fg_of(&render_buffer(&MailPane::new(), &state, 60, 16, false), text),
                color,
                "{text}"
            );
        }
    }

    #[test]
    fn zoom_lists_every_dkim_selector_and_the_transport_lenses_under_dmarc() {
        let key = |selector: &str, revoked: bool| DkimKey {
            selector: selector.to_string(),
            revoked,
        };
        let state = email_state(
            "google.com",
            EmailSecurityAnalysis {
                dkim: LensOutcome::Present(vec![key("google", false), key("s1", true)]),
                mta_sts: LensOutcome::Present("20210803T010101".to_string()),
                tls_rpt: LensOutcome::Failed("timed out".to_string()),
                ..google()
            },
        );
        let zoomed = rows(&state, Detail::Zoomed);
        let at = |needle: &str| {
            zoomed
                .iter()
                .position(|row| row == needle)
                .unwrap_or_else(|| panic!("{needle}: {zoomed:#?}"))
        };
        assert!(at("DMARC: configured") < at("MTA-STS: 20210803T010101"));
        assert!(at("MTA-STS: 20210803T010101") < at("TLS-RPT: failed: timed out"));
        assert!(at("TLS-RPT: failed: timed out") < at("DKIM: google +1"));
        assert!(at("DKIM: google +1") < at("  selector: google"));
        at("  selector: s1 (revoked)");
        let normal = rows(&state, Detail::Normal).join("\n");
        assert!(!normal.contains("MTA-STS") && !normal.contains("selector:"), "{normal}");
        let text = content_rows(&MailPane::new(), &state, 40, Detail::Zoomed).concat();
        assert!(
            text.contains("mailauth-reports@google.com"),
            "DMARC text not whole: {text}"
        );
    }

    #[test]
    fn a_zone_row_names_the_registrable_domain_only_when_it_differs_from_the_host() {
        let state = email_state("https://www.google.com/search", google());
        assert_eq!(rows(&state, Detail::Normal)[1], "Zone: google.com");
        let state = email_state("google.com", google());
        assert!(!rows(&state, Detail::Normal).iter().any(|row| row.starts_with("Zone:")));
    }

    #[test]
    fn a_failed_first_dns_scan_shows_only_its_status() {
        let state = AppState::new("google.com".to_string());
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: None,
                error: Some(eyre::eyre!("timed out after 30s")),
                status: ScanStatus::Failed,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        assert_eq!(rows(&state, Detail::Normal), ["📧 Status: failed: timed out after 30s"]);
    }
}
