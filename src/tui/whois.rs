use crate::scan::whois::DataSource;
use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::any::Any;

const EXPIRY_WARNING_DAYS: i64 = 30;
const EXPIRY_CAUTION_DAYS: i64 = 90;
const MIN_WHOIS_PANE_WIDTH: u16 = 35;
const MIN_WHOIS_PANE_HEIGHT: u16 = 16;

/// WHOIS pane displays domain registration and ownership information
pub struct WhoisPane {
    title: &'static str,
    id: &'static str,
}

impl WhoisPane {
    pub fn new() -> Self {
        log::debug!("[tui::whois] new:");
        Self {
            title: "whois",
            id: "whois",
        }
    }
}

impl Default for WhoisPane {
    fn default() -> Self {
        Self::new()
    }
}

/// `<label>: <value>`, indented under a zoomed section.
/// EPP `ok` and the `... prohibited` transfer/delete/update locks are the healthy statuses.
fn is_lock_or_ok(status: &str) -> bool {
    let status = status.to_lowercase();
    status.contains("ok") || status.contains("prohibited")
}

fn field_line(label: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label}: "), Style::default().fg(theme::LABEL)),
        Span::styled(value, Style::default().fg(theme::MUTED)),
    ])
}

/// A contact's fields, one row each. A fully withheld contact reads `<role> (redacted)` alone; a
/// partly withheld one prints `(redacted)` for each field the registry withholds.
fn contact_lines(role: &str, contact: &crate::scan::whois::ContactInfo) -> Vec<Line<'static>> {
    let fully_redacted = contact.is_fully_redacted();
    let mut lines = vec![Line::from(Span::styled(
        format!("👤 {role}{}", if fully_redacted { " (redacted)" } else { "" }),
        Style::default().fg(theme::VALUE),
    ))];
    if fully_redacted {
        return lines;
    }
    for field in crate::scan::whois::ContactField::ALL {
        if contact.is_redacted(field) {
            lines.push(field_line(field.label(), "(redacted)".to_string()));
        } else if let Some(value) = contact.visible(field) {
            lines.push(field_line(field.label(), value.to_string()));
        }
    }
    lines
}

/// Zoomed only, after everything the grid shows: last update, DNSSEC, age, the registrar's
/// details, and every contact.
fn zoomed_lines(result: &crate::scan::whois::WhoisResult) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    if let Some(updated) = &result.last_updated {
        lines.push(field_line("Last updated", updated.format("%Y-%m-%d").to_string()));
    }
    lines.push(field_line(
        "DNSSEC",
        match result.dnssec {
            Some(true) => "signed".to_string(),
            Some(false) => "unsigned".to_string(),
            None => "unknown".to_string(),
        },
    ));
    if let Some(age) = result.domain_age_days {
        lines.push(field_line("Age", format!("{age} days")));
    }
    if let Some(registrar) = &result.registrar {
        if let Some(iana_id) = registrar.iana_id {
            lines.push(field_line("Registrar IANA ID", iana_id.to_string()));
        }
        if let Some(url) = &registrar.url {
            lines.push(field_line("Registrar URL", url.clone()));
        }
        if let Some(abuse) = &registrar.abuse_contact {
            lines.extend(contact_lines("Registrar abuse", abuse));
        }
    }
    let contacts = [
        ("Registrant", &result.registrant),
        ("Admin", &result.admin_contact),
        ("Tech", &result.tech_contact),
        ("Abuse", &result.abuse_contact),
    ];
    for (role, contact) in contacts {
        if let Some(contact) = contact {
            lines.extend(contact_lines(role, contact));
        }
    }
    lines
}

impl Pane for WhoisPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::whois] content: width={} detail={:?}", width, detail);

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let mut wrapped = vec![0];

        // WHOIS status header
        lines.push(Line::from(vec![
            Span::styled("📋 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled("querying...", Style::default().fg(theme::MUTED)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get WHOIS results and render them
        if let Some(whois_state) = state.scanners.get("whois") {
            // Update header with current status
            let (label, label_color) = crate::tui::status_label(&whois_state, "querying...", "retrieved");
            lines[0] = Line::from(vec![
                Span::styled("📋 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::Whois(whois_result)) = &whois_state.result
                && let DataSource::NotApplicable(reason) = &whois_result.data_source
            {
                // Nothing was retrieved, so the header must not claim it was.
                lines[0] = Line::from(vec![
                    Span::styled("📋 Status: ", Style::default().fg(theme::VALUE)),
                    Span::styled("n/a", Style::default().fg(theme::MUTED)),
                ]);
                lines.push(Line::from(vec![
                    Span::styled("🎯 Target: ", Style::default().fg(theme::LABEL)),
                    Span::styled(whois_result.domain.clone(), Style::default().fg(theme::VALUE)),
                ]));
                wrapped.push(lines.len());
                lines.push(Line::from(vec![
                    Span::styled("📡 Source: ", Style::default().fg(theme::LABEL)),
                    Span::styled(reason.to_string(), Style::default().fg(theme::MUTED)),
                ]));
            } else if let Some(ScanResult::Whois(whois_result)) = &whois_state.result {
                // Domain name. A suffix-list failure rides on it, and then it wraps to keep the cause.
                if whois_result.suffix_list_error.is_some() {
                    wrapped.push(lines.len());
                }
                lines.push(Line::from(vec![
                    Span::styled("🌐 Domain: ", Style::default().fg(theme::LABEL)),
                    Span::styled(whois_result.domain_label(), Style::default().fg(theme::VALUE)),
                ]));

                // Data source, directly under the domain: a long NS or status list below cannot push
                // it out of the pane.
                let source_color = match &whois_result.data_source {
                    crate::scan::whois::DataSource::Rdap => theme::GOOD,
                    crate::scan::whois::DataSource::Whois => theme::WARN,
                    crate::scan::whois::DataSource::NotApplicable(_) => theme::MUTED,
                };
                lines.push(Line::from(vec![
                    Span::styled("📡 Source: ", Style::default().fg(theme::LABEL)),
                    Span::styled(whois_result.data_source.to_string(), Style::default().fg(source_color)),
                ]));

                // Registrar
                if let Some(registrar) = &whois_result.registrar {
                    lines.push(Line::from(vec![
                        Span::styled("🏢 Registrar: ", Style::default().fg(theme::LABEL)),
                        Span::styled(registrar.name.clone(), Style::default().fg(theme::GOOD)),
                    ]));
                }

                // Registration date
                if let Some(created) = &whois_result.registration_date {
                    lines.push(Line::from(vec![
                        Span::styled("📅 Created: ", Style::default().fg(theme::LABEL)),
                        Span::styled(created.format("%Y-%m-%d").to_string(), Style::default().fg(theme::WARN)),
                    ]));
                }

                // Expiration date with color coding
                if let Some(expires) = &whois_result.expiry_date {
                    let now = chrono::Utc::now().date_naive();
                    let expires_date = expires.date_naive();
                    let days_until_expiry = (expires_date - now).num_days();

                    let expiry_color = if days_until_expiry < EXPIRY_WARNING_DAYS {
                        theme::BAD
                    } else if days_until_expiry < EXPIRY_CAUTION_DAYS {
                        theme::WARN
                    } else {
                        theme::GOOD
                    };

                    lines.push(Line::from(vec![
                        Span::styled("⏰ Expires: ", Style::default().fg(theme::LABEL)),
                        Span::styled(
                            format!("{} ({}d)", expires.format("%Y-%m-%d"), days_until_expiry),
                            Style::default().fg(expiry_color),
                        ),
                    ]));
                }

                // Name servers (show all)
                if !whois_result.nameservers.is_empty() {
                    for (i, nameserver) in whois_result.nameservers.iter().enumerate() {
                        let prefix = if i == 0 { "🔗 NS: " } else { "     " };

                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(theme::LABEL)),
                            Span::styled(nameserver.clone(), Style::default().fg(theme::ACCENT)),
                        ]));
                    }
                }

                // Status - show all status items
                if !whois_result.status.is_empty() {
                    for (i, status) in whois_result.status.iter().enumerate() {
                        let status_color = if is_lock_or_ok(status) {
                            theme::GOOD
                        } else if status.to_lowercase().contains("pending") {
                            theme::WARN
                        } else {
                            theme::BAD
                        };

                        let prefix = if i == 0 { "📊 Status: " } else { "         " };

                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(theme::LABEL)),
                            Span::styled(status.clone(), Style::default().fg(status_color)),
                        ]));
                    }
                }

                // Privacy level
                let privacy_color = match whois_result.privacy_score {
                    crate::scan::whois::PrivacyLevel::Open => theme::VALUE,
                    crate::scan::whois::PrivacyLevel::Partial => theme::WARN,
                    crate::scan::whois::PrivacyLevel::Corporate => theme::WARN,
                    crate::scan::whois::PrivacyLevel::Protected => theme::GOOD,
                    crate::scan::whois::PrivacyLevel::Unknown => theme::MUTED,
                };

                lines.push(Line::from(vec![
                    Span::styled("🔐 Privacy: ", Style::default().fg(theme::LABEL)),
                    Span::styled(whois_result.privacy_score.label(), Style::default().fg(privacy_color)),
                ]));

                // Risk indicators - show all risks
                if !whois_result.risk_indicators.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("❗ Risks: ", Style::default().fg(theme::LABEL)),
                        Span::styled(
                            crate::tui::text::plural(whois_result.risk_indicators.len(), "indicator"),
                            Style::default().fg(theme::BAD),
                        ),
                    ]));

                    // Show each risk indicator
                    for risk in &whois_result.risk_indicators {
                        let risk_text = match risk {
                            crate::scan::whois::RiskIndicator::RecentRegistration => "Recent Registration (<30 days)",
                            crate::scan::whois::RiskIndicator::NearExpiry => "Near Expiry (<30 days)",
                            crate::scan::whois::RiskIndicator::FrequentUpdates => "Frequent Updates",
                            crate::scan::whois::RiskIndicator::SuspiciousRegistrar => "Suspicious Registrar",
                            crate::scan::whois::RiskIndicator::NoAbuseContact => "No Abuse Contact",
                            crate::scan::whois::RiskIndicator::WeakDnssec => "Weak DNSSEC",
                        };

                        lines.push(Line::from(vec![
                            Span::styled("     • ", Style::default().fg(theme::BAD)),
                            Span::styled(risk_text, Style::default().fg(theme::BAD)),
                        ]));
                    }
                }

                if detail == Detail::Zoomed {
                    lines.extend(zoomed_lines(whois_result));
                }
            } else {
                // No WHOIS data available yet - check scanner status
                match whois_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(theme::LABEL)),
                            Span::styled("querying...", Style::default().fg(theme::WARN)),
                        ]));

                        lines.push(Line::from(vec![
                            Span::styled("🏢 Registrar: ", Style::default().fg(theme::LABEL)),
                            Span::styled("looking up...", Style::default().fg(theme::WARN)),
                        ]));
                    }
                    crate::types::ScanStatus::Failed => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(theme::LABEL)),
                            Span::styled("query failed", Style::default().fg(theme::BAD)),
                        ]));
                    }
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("🌐 Domain: ", Style::default().fg(theme::LABEL)),
                            Span::styled("waiting to query...", Style::default().fg(theme::MUTED)),
                        ]));
                    }
                }
            }
        } else {
            // No WHOIS scanner available
            lines[0] = Line::from(vec![
                Span::styled("📋 WHOIS: ", Style::default().fg(theme::VALUE)),
                Span::styled("unavailable", Style::default().fg(theme::BAD)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("🌐 Domain: ", Style::default().fg(theme::LABEL)),
                Span::styled("WHOIS scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

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
        (MIN_WHOIS_PANE_WIDTH, MIN_WHOIS_PANE_HEIGHT) // Larger to show all nameservers and details
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
    use ratatui::style::Color;

    #[test]
    fn test_whois_pane_creation() {
        let pane = WhoisPane::new();
        assert_eq!(pane.title(), "whois");
        assert_eq!(pane.id(), "whois");
        assert_eq!(pane.min_size(), (MIN_WHOIS_PANE_WIDTH, MIN_WHOIS_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    fn state_with_whois(result: crate::scan::whois::WhoisResult) -> AppState {
        let state = AppState::new(result.domain.clone());
        state.scanners.insert(
            "whois".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Whois(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        state
    }

    #[test]
    fn ip_target_renders_not_applicable_not_failure() {
        use crate::scan::whois::{NotApplicableReason, WhoisResult};
        use crate::tui::testing::render_pane;
        let state = state_with_whois(WhoisResult::not_applicable(
            "1.1.1.1".to_string(),
            NotApplicableReason::IpTarget,
        ));
        let out = render_pane(&WhoisPane::new(), &state, 60, 16, false);
        assert!(out.contains("n/a for IP targets (see GEOIP)"), "{}", out);
        assert!(out.contains("1.1.1.1"), "{}", out);
        for wrong in ["failed", "Query Failed", "retrieved", "Privacy"] {
            assert!(!out.contains(wrong), "found {:?}:\n{}", wrong, out);
        }
    }

    const LONG_DOMAIN: &str = "a-very-long-registrable-domain-name-for-clipping.example";

    #[test]
    fn long_domain_is_fit_with_ellipsis_in_narrow_terminals() {
        use crate::scan::whois::{DataSource, NotApplicableReason, WhoisResult};
        let mut result = WhoisResult::not_applicable(LONG_DOMAIN.to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &WhoisPane::new(),
            &state_with_whois(result),
            1,
            0,
            &format!("🌐 Domain: {LONG_DOMAIN}"),
        );
    }

    #[test]
    fn suffix_list_failure_on_the_domain_row_wraps_instead_of_clipping() {
        use crate::scan::whois::{DataSource, NotApplicableReason, WhoisResult};
        let mut result = WhoisResult::not_applicable("www.tatari.tv".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.suffix_list_error = Some("connection refused".to_string());
        let (width, height) = crate::tui::testing::dashboard_pane_size(1, 0, 108, 40);
        let out = crate::tui::testing::render_pane(&WhoisPane::new(), &state_with_whois(result), width, height, false);
        let flat: String = out
            .lines()
            .map(|l| l.trim_matches(['│', ' ']))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(flat.contains("refused)"), "reason cut off:\n{out}");
        assert!(!out.contains('…'), "reason row was fit, not wrapped:\n{out}");
    }

    #[test]
    fn domain_from_host_is_intact_at_200x55() {
        use crate::scan::whois::{DataSource, NotApplicableReason, WhoisResult};
        let mut result = WhoisResult::not_applicable("www.tatari.tv".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.queried_domain = "tatari.tv".to_string();
        let (width, height) = crate::tui::testing::dashboard_pane_size(1, 0, 200, 55);
        let out = crate::tui::testing::render_pane(&WhoisPane::new(), &state_with_whois(result), width, height, false);
        assert!(out.contains("Domain: tatari.tv (from www.tatari.tv)"), "{out}");
        assert!(out.contains("Source: RDAP"), "{out}");
    }

    #[test]
    fn epp_locks_and_ok_render_good_and_other_statuses_bad() {
        use crate::scan::whois::{NotApplicableReason, WhoisResult};
        let mut result = WhoisResult::not_applicable("tatari.tv".to_string(), NotApplicableReason::IpTarget);
        result.data_source = crate::scan::whois::DataSource::Rdap;
        result.status = ["client transfer prohibited", "ok", "pendingDelete", "serverHold"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (width, height) = crate::tui::testing::dashboard_pane_size(1, 0, 200, 55);
        let buffer =
            crate::tui::testing::render_buffer(&WhoisPane::new(), &state_with_whois(result), width, height, false);
        assert_eq!(
            crate::tui::testing::fg_of(&buffer, "client transfer prohibited"),
            Color::Green
        );
        assert_eq!(crate::tui::testing::fg_of(&buffer, "ok"), Color::Green);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "pendingDelete"), Color::Yellow);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "serverHold"), Color::LightRed);
    }

    #[test]
    fn source_stays_visible_under_long_ns_and_status_lists_at_200x55() {
        use crate::scan::whois::{DataSource, NotApplicableReason, RegistrarInfo, RiskIndicator, WhoisResult};
        // Shaped like web.dev: 4 name servers, 6 status items, 1 risk, which overran 17 rows.
        let mut result = WhoisResult::not_applicable("web.dev".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.registrar = Some(RegistrarInfo {
            name: "MarkMonitor Inc.".to_string(),
            iana_id: None,
            abuse_contact: None,
            url: None,
        });
        result.registration_date = Some(chrono::Utc::now() - chrono::Duration::days(2000));
        result.expiry_date = Some(chrono::Utc::now() + chrono::Duration::days(365));
        result.nameservers = (1..=4).map(|n| format!("ns{n}.zdns.google")).collect();
        result.status = [
            "client delete prohibited",
            "client transfer prohibited",
            "client update prohibited",
            "server delete prohibited",
            "server transfer prohibited",
            "server update prohibited",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        result.risk_indicators = vec![RiskIndicator::WeakDnssec];
        let (width, height) = crate::tui::testing::dashboard_pane_size(1, 0, 200, 55);
        let out = crate::tui::testing::render_pane(&WhoisPane::new(), &state_with_whois(result), width, height, false);
        assert!(out.contains("Source: RDAP"), "Source pushed below the pane:\n{out}");
        let rows: Vec<&str> = out.lines().collect();
        let domain_row = rows
            .iter()
            .position(|r| r.contains("Domain: web.dev"))
            .expect("domain row");
        assert!(
            rows[domain_row + 1].contains("📡 Source: RDAP"),
            "Source not under Domain:\n{out}"
        );
    }

    /// Item 4: zoom prints `(redacted)` for each field the registry withholds, the visible fields
    /// as they are, and no empty `Name:`; the grid reads partial, never open.
    #[test]
    fn zoom_marks_each_withheld_field_redacted() {
        use crate::scan::whois::{
            ContactField, ContactInfo, DataSource, NotApplicableReason, PrivacyLevel, WhoisResult,
        };
        use crate::tui::pane::Detail;
        let mut result = WhoisResult::not_applicable("example.tv".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.privacy_score = PrivacyLevel::Partial;
        result.registrant = Some(ContactInfo {
            email: Some("owner@example.tv".to_string()),
            redacted: vec![ContactField::Name, ContactField::Phone],
            ..ContactInfo::default()
        });
        let state = state_with_whois(result);
        let pane = WhoisPane::new();
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Zoomed).join("\n");
        for expected in ["Name: (redacted)", "Phone: (redacted)", "Email: owner@example.tv"] {
            assert!(zoomed.contains(expected), "{expected}:\n{zoomed}");
        }
        assert!(
            !zoomed.contains("Registrant (redacted)"),
            "partly withheld is not fully:\n{zoomed}"
        );
        assert!(zoomed.contains("Privacy: partial"), "{zoomed}");
        assert!(!zoomed.contains("Privacy: open"), "{zoomed}");
    }

    #[test]
    fn privacy_renders_a_label_not_the_enum_name() {
        use crate::scan::whois::{DataSource, NotApplicableReason, PrivacyLevel, WhoisResult};
        let mut result = WhoisResult::not_applicable("example.com".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.privacy_score = PrivacyLevel::Corporate;
        let out = crate::tui::testing::render_pane(&WhoisPane::new(), &state_with_whois(result), 80, 30, false);
        assert!(out.contains("Privacy: organization only"), "{out}");
        assert!(!out.contains("Corporate"), "enum name leaked:\n{out}");
    }

    #[test]
    fn zoomed_content_shows_every_field_and_contact() {
        use crate::scan::whois::{ContactInfo, DataSource, NotApplicableReason, RegistrarInfo, WhoisResult};
        use crate::tui::pane::Detail;
        let mut result = WhoisResult::not_applicable("example.com".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.dnssec = Some(true);
        result.last_updated = Some(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
                .expect("date")
                .into(),
        );
        result.registrar = Some(RegistrarInfo {
            name: "Example Registrar".to_string(),
            iana_id: Some(292),
            abuse_contact: None,
            url: Some("https://registrar.example".to_string()),
        });
        result.tech_contact = Some(ContactInfo {
            name: None,
            organization: Some("Example Org".to_string()),
            email: Some("tech@example.com".to_string()),
            phone: None,
            address: None,
            redacted: Vec::new(),
        });
        result.registrant = Some(ContactInfo::fully_redacted());
        let state = state_with_whois(result);
        let pane = WhoisPane::new();
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Zoomed).join("\n");
        for expected in [
            "Last updated: 2026-01-02",
            "DNSSEC: signed",
            "Registrar IANA ID: 292",
            "Registrar URL: https://registrar.example",
            "Registrant (redacted)",
            "Tech",
            "Organization: Example Org",
            "Email: tech@example.com",
        ] {
            assert!(zoomed.contains(expected), "{expected}:\n{zoomed}");
        }
        let normal = crate::tui::testing::content_rows(&pane, &state, 100, Detail::Normal).join("\n");
        assert!(!normal.contains("DNSSEC"), "{normal}");
    }

    /// Item 9: one risk indicator reads `1 indicator`.
    #[test]
    fn one_risk_indicator_reads_in_the_singular() {
        use crate::scan::whois::{DataSource, NotApplicableReason, RiskIndicator, WhoisResult};
        let mut result = WhoisResult::not_applicable("example.com".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.risk_indicators = vec![RiskIndicator::WeakDnssec];
        let out = crate::tui::testing::render_pane(&WhoisPane::new(), &state_with_whois(result), 80, 30, false);
        assert!(out.contains("Risks: 1 indicator"), "{out}");
        assert!(!out.contains("1 indicators"), "{out}");
    }
}
