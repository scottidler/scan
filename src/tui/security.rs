use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::AppState;
use log;
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::any::Any;

const MAX_CSP_ISSUES_DISPLAYED: usize = 3;
const MAX_CORS_ISSUES_DISPLAYED: usize = 3;
const MAX_HTTP_VULNERABILITIES_DISPLAYED: usize = 5;
const MAX_TLS_VULNERABILITIES_DISPLAYED: usize = 5;
const CN_EXTRACT_PREFIX_LENGTH: usize = 3;
const CERT_EXPIRY_WARNING_DAYS: i64 = 30;
const CERT_EXPIRY_CRITICAL_DAYS: i64 = 7;
const MIN_SECURITY_PANE_WIDTH: u16 = 50;
const MIN_SECURITY_PANE_HEIGHT: u16 = 35;

/// SECURITY pane displays TLS/SSL certificate information and security analysis
pub struct SecurityPane {
    title: &'static str,
    id: &'static str,
}

impl SecurityPane {
    pub fn new() -> Self {
        log::debug!("[tui::security] new:");
        Self {
            title: "security",
            id: "security",
        }
    }

    /// The pane's logical lines, before they are laid out as rows by `content`.
    fn build_content_lines(&self, state: &AppState, detail: Detail) -> Vec<Line<'_>> {
        log::trace!("[tui::security] build_content_lines: building security analysis content");
        // The grid caps each list to keep the pane short; zoom shows every entry.
        let cap = |grid_cap: usize| if detail == Detail::Zoomed { usize::MAX } else { grid_cap };

        let mut lines = Vec::new();

        // Security status header
        lines.push(Line::from(vec![
            Span::styled("🔒 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled("analyzing...", Style::default().fg(theme::WARN)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        let tls_failed = state
            .scanners
            .get("tls")
            .is_some_and(|tls_state| matches!(tls_state.status, crate::types::ScanStatus::Failed));
        if let Some(tls_state) = state.scanners.get("tls") {
            let (label, color) = crate::tui::status_label(&tls_state, "analyzing...", "analyzed");
            lines[0] = Line::from(vec![
                Span::styled("🔒 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(color)),
            ]);
        }

        // Extract TLS data upfront
        let tls_data = if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(crate::types::ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                tls_result.get_primary_result().map(|primary_data| {
                    (
                        primary_data.connection_successful,
                        primary_data.negotiated_version.as_ref().map(|v| v.as_str().to_string()),
                        primary_data.negotiated_cipher.as_ref().map(|c| c.name.clone()),
                        primary_data.perfect_forward_secrecy,
                        primary_data.certificate_valid,
                        primary_data.days_until_expiry,
                        tls_result
                            .get_best_security_grade()
                            .map(|g| g.as_str().to_string())
                            .unwrap_or_else(|| "F".to_string()),
                        primary_data.issue_count(),
                        primary_data.certificate_chain.first().map(|cert| {
                            (
                                cert.subject.clone(),
                                cert.issuer.clone(),
                                cert.public_key_algorithm.clone(),
                                cert.key_size,
                                cert.san_domains.len(),
                            )
                        }),
                    )
                })
            } else {
                None
            }
        } else {
            None
        };

        // Extract HTTP data upfront
        let http_data = if let Some(http_state) = state.scanners.get("http") {
            if let Some(crate::types::ScanResult::Http(http_result)) = http_state.result.as_ref() {
                http_result.get_primary_result().map(|primary_data| {
                    (
                        primary_data.security_headers.strict_transport_security.is_some(),
                        primary_data
                            .security_headers
                            .x_frame_options
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data
                            .security_headers
                            .x_content_type_options
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data
                            .security_headers
                            .x_xss_protection
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data
                            .security_headers
                            .referrer_policy
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data
                            .security_headers
                            .permissions_policy
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data.csp.as_ref().map(|csp| {
                            (
                                csp.strength.clone(),
                                csp.header_value.clone(),
                                csp.issues
                                    .iter()
                                    .take(cap(MAX_CSP_ISSUES_DISPLAYED))
                                    .map(|issue| match issue {
                                        crate::scan::http::CspIssue::UnsafeInline(directive) => {
                                            format!("unsafe-inline in {}", directive)
                                        }
                                        crate::scan::http::CspIssue::UnsafeEval(directive) => {
                                            format!("unsafe-eval in {}", directive)
                                        }
                                        crate::scan::http::CspIssue::WildcardSource(directive) => {
                                            format!("wildcard in {}", directive)
                                        }
                                        crate::scan::http::CspIssue::MissingDirective(directive) => {
                                            format!("missing {}", directive)
                                        }
                                    })
                                    .collect::<Vec<_>>(),
                            )
                        }),
                        primary_data.cors.as_ref().map(|cors| {
                            (
                                cors.security_level.clone(),
                                cors.access_control_allow_origin.clone(),
                                cors.access_control_allow_methods.clone(),
                                cors.access_control_allow_credentials,
                                cors.issues
                                    .iter()
                                    .take(cap(MAX_CORS_ISSUES_DISPLAYED))
                                    .map(|issue| match issue {
                                        crate::scan::http::CorsIssue::WildcardOrigin => "wildcard origin".to_string(),
                                        crate::scan::http::CorsIssue::WildcardMethods => "wildcard methods".to_string(),
                                        crate::scan::http::CorsIssue::WildcardHeaders => "wildcard headers".to_string(),
                                        crate::scan::http::CorsIssue::WildcardWithCredentials => {
                                            "wildcard + credentials".to_string()
                                        }
                                    })
                                    .collect::<Vec<_>>(),
                            )
                        }),
                        http_result
                            .get_all_vulnerabilities()
                            .iter()
                            .take(cap(MAX_HTTP_VULNERABILITIES_DISPLAYED))
                            .map(|vuln| match vuln {
                                crate::scan::http::HttpVulnerability::MissingHsts => "Missing HSTS header".to_string(),
                                crate::scan::http::HttpVulnerability::MissingXFrameOptions => {
                                    "Missing X-Frame-Options".to_string()
                                }
                                crate::scan::http::HttpVulnerability::MissingXContentTypeOptions => {
                                    "Missing X-Content-Type-Options".to_string()
                                }
                                crate::scan::http::HttpVulnerability::MissingCsp => {
                                    "Missing Content Security Policy".to_string()
                                }
                                crate::scan::http::HttpVulnerability::WeakCsp => {
                                    "Weak Content Security Policy".to_string()
                                }
                                crate::scan::http::HttpVulnerability::InsecureCors => {
                                    "Insecure CORS configuration".to_string()
                                }
                                crate::scan::http::HttpVulnerability::InformationDisclosure => {
                                    "Information disclosure risk".to_string()
                                }
                            })
                            .collect::<Vec<_>>(),
                        http_result
                            .get_best_security_grade()
                            .map(|g| g.as_str().to_string())
                            .unwrap_or_else(|| "N/A".to_string()),
                    )
                })
            } else {
                None
            }
        } else {
            None
        };

        // Extract DNS data upfront
        let dns_data = if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(crate::types::ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                dns_result.email_security.as_ref().map(|email_security| {
                    (
                        email_security.spf_record.clone(),
                        email_security.dmarc_record.clone(),
                        email_security.mx_count,
                        email_security.has_mx,
                    )
                })
            } else {
                None
            }
        } else {
            None
        };

        // Extract TLS issue details: the same primary result and lists that `Issues:` counts
        let tls_issues = if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(crate::types::ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                tls_result.get_primary_result().map(|primary_data| {
                    primary_data
                        .vulnerabilities
                        .iter()
                        .map(|vuln| vuln.description())
                        .chain(primary_data.certificate_errors.iter().cloned())
                        .take(cap(MAX_TLS_VULNERABILITIES_DISPLAYED))
                        .collect::<Vec<_>>()
                })
            } else {
                None
            }
        } else {
            None
        };

        // Now build the UI with owned data
        if let Some((
            connection_successful,
            negotiated_version,
            negotiated_cipher,
            pfs,
            cert_valid,
            days_until_expiry,
            security_grade,
            vuln_count,
            cert_info,
        )) = tls_data
        {
            // TLS Connection
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    if connection_successful { "connected" } else { "failed" },
                    Style::default().fg(if connection_successful { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // TLS Version
            if let Some(version) = negotiated_version {
                lines.push(Line::from(vec![
                    Span::styled("🔐 Version: ", Style::default().fg(theme::LABEL)),
                    Span::styled(version, Style::default().fg(theme::GOOD)),
                ]));
            }

            // Cipher Suite
            if let Some(cipher) = negotiated_cipher {
                lines.push(Line::from(vec![
                    Span::styled("🔑 Cipher: ", Style::default().fg(theme::LABEL)),
                    Span::styled(cipher, Style::default().fg(theme::WARN)),
                ]));
            }

            // Security Features
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "🔰 Security Features",
                Style::default().fg(theme::VALUE),
            )]));

            lines.push(Line::from(vec![
                Span::styled("  PFS: ", Style::default().fg(theme::LABEL)),
                if !connection_successful {
                    Span::styled("n/a", Style::default().fg(theme::MUTED))
                } else {
                    Span::styled(
                        if pfs { "yes" } else { "no" },
                        Style::default().fg(if pfs { theme::GOOD } else { theme::BAD }),
                    )
                },
            ]));

            lines.push(Line::from(vec![
                Span::styled("  OCSP: ", Style::default().fg(theme::LABEL)),
                // Stapling is never collected, so `no` would claim a check that did not happen.
                Span::styled("not checked", Style::default().fg(theme::MUTED)),
            ]));

            // Certificate Details
            if let Some((subject, issuer, key_algo, key_size, san_count)) = cert_info {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "📜 Certificate Details",
                    Style::default().fg(theme::VALUE),
                )]));

                let cert_color = if cert_valid { theme::GOOD } else { theme::BAD };

                lines.push(Line::from(vec![
                    Span::styled("  Valid: ", Style::default().fg(theme::LABEL)),
                    Span::styled(if cert_valid { "yes" } else { "no" }, Style::default().fg(cert_color)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("  Subject: ", Style::default().fg(theme::LABEL)),
                    Span::styled(common_name_display(&subject), Style::default().fg(theme::WARN)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("  Issuer: ", Style::default().fg(theme::LABEL)),
                    Span::styled(common_name_display(&issuer), Style::default().fg(theme::GOOD)),
                ]));

                // Certificate expiry
                if let Some(days_until_expiry) = days_until_expiry {
                    let expiry_color = if days_until_expiry > CERT_EXPIRY_WARNING_DAYS {
                        theme::GOOD
                    } else if days_until_expiry > CERT_EXPIRY_CRITICAL_DAYS {
                        theme::WARN
                    } else {
                        theme::BAD
                    };

                    lines.push(Line::from(vec![
                        Span::styled("  Expires: ", Style::default().fg(theme::LABEL)),
                        Span::styled(format!("{} days", days_until_expiry), Style::default().fg(expiry_color)),
                    ]));
                }

                // Key algorithm and size
                lines.push(Line::from(vec![
                    Span::styled("  Key: ", Style::default().fg(theme::LABEL)),
                    Span::styled(key_algo, Style::default().fg(theme::WARN)),
                    Span::styled(
                        key_size.map_or(String::new(), |size| format!(" {}bit", size)),
                        Style::default().fg(theme::MUTED),
                    ),
                ]));

                // SAN domains count
                if san_count > 0 {
                    lines.push(Line::from(vec![
                        Span::styled("  SAN: ", Style::default().fg(theme::LABEL)),
                        Span::styled(format!("{} domains", san_count), Style::default().fg(theme::GOOD)),
                    ]));
                }
            }

            // Grade and vulnerabilities
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📊 Grade: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    security_grade.clone(),
                    Style::default().fg(match security_grade.as_str() {
                        "A+" | "A" => theme::GOOD,
                        "B" => theme::WARN,
                        _ => theme::BAD,
                    }),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("❗ Issues: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    format!("{}", vuln_count),
                    Style::default().fg(if vuln_count == 0 { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // The reasons `Issues:` counts sit right under it, so a failed handshake's cause is above the fold.
            for issue in tls_issues.into_iter().flatten() {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(theme::BAD)),
                    Span::styled(issue, Style::default().fg(theme::BAD)),
                ]));
            }
        } else if tls_failed {
            // The first scan failed: the header carries the reason, nothing is still pending.
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("failed", Style::default().fg(theme::BAD)),
            ]));
        } else if state.scanners.contains_key("tls") {
            // TLS scanner exists but no result yet
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("checking...", Style::default().fg(theme::MUTED)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("🔐 Version: ", Style::default().fg(theme::LABEL)),
                Span::styled("detecting...", Style::default().fg(theme::MUTED)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("📜 Cert: ", Style::default().fg(theme::LABEL)),
                Span::styled("validating...", Style::default().fg(theme::MUTED)),
            ]));
        } else {
            // No TLS scanner available
            lines[0] = Line::from(vec![
                Span::styled("🔒 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled("unavailable", Style::default().fg(theme::BAD)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("TLS scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        // HTTP Security Headers
        if let Some((
            hsts_present,
            x_frame,
            x_content,
            xss_protect,
            referrer_policy,
            permissions_policy,
            csp_data,
            cors_data,
            http_vulnerabilities,
            http_grade,
        )) = http_data
        {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "🌐 HTTP Security",
                Style::default().fg(theme::VALUE),
            )]));

            // HSTS
            lines.push(Line::from(vec![
                Span::styled("  HSTS: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    if hsts_present { "yes" } else { "no" },
                    Style::default().fg(if hsts_present { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // X-Frame-Options
            lines.push(Line::from(vec![
                Span::styled("  X-Frame: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    x_frame.clone(),
                    Style::default().fg(if x_frame != "missing" { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // X-Content-Type-Options
            lines.push(Line::from(vec![
                Span::styled("  X-Content: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    x_content.clone(),
                    Style::default().fg(if x_content != "missing" { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // X-XSS-Protection
            lines.push(Line::from(vec![
                Span::styled("  XSS-Protect: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    xss_protect.clone(),
                    Style::default().fg(if xss_protect != "missing" { theme::GOOD } else { theme::WARN }),
                ),
            ]));

            // Referrer Policy
            lines.push(Line::from(vec![
                Span::styled("  Referrer: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    referrer_policy.clone(),
                    Style::default().fg(if referrer_policy != "missing" { theme::GOOD } else { theme::WARN }),
                ),
            ]));

            // Permissions Policy
            lines.push(Line::from(vec![
                Span::styled("  Permissions: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    permissions_policy.clone(),
                    Style::default().fg(if permissions_policy != "missing" { theme::GOOD } else { theme::WARN }),
                ),
            ]));

            // CSP
            if let Some((strength, header_value, issues)) = csp_data {
                lines.push(Line::from(vec![
                    Span::styled("  CSP: ", Style::default().fg(theme::LABEL)),
                    Span::styled(
                        strength.label(),
                        Style::default().fg(match strength {
                            crate::scan::http::CspStrength::Strong => theme::GOOD,
                            crate::scan::http::CspStrength::Moderate => theme::WARN,
                            crate::scan::http::CspStrength::Weak => theme::BAD,
                            crate::scan::http::CspStrength::None => theme::BAD,
                        }),
                    ),
                ]));

                // CSP Header Value
                lines.push(Line::from(vec![
                    Span::styled("    Policy: ", Style::default().fg(theme::LABEL)),
                    Span::styled(header_value, Style::default().fg(theme::MUTED)),
                ]));

                // CSP Issues
                for issue in issues {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(theme::BAD)),
                        Span::styled(issue, Style::default().fg(theme::BAD)),
                    ]));
                }
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  CSP: ", Style::default().fg(theme::LABEL)),
                    Span::styled("missing", Style::default().fg(theme::BAD)),
                ]));
            }

            // CORS
            if let Some((
                security_level,
                access_control_allow_origin,
                access_control_allow_methods,
                access_control_allow_credentials,
                issues,
            )) = cors_data
            {
                lines.push(Line::from(vec![
                    Span::styled("  CORS: ", Style::default().fg(theme::LABEL)),
                    Span::styled(
                        security_level.label(),
                        Style::default().fg(match security_level {
                            crate::scan::http::CorsSecurityLevel::Secure => theme::GOOD,
                            crate::scan::http::CorsSecurityLevel::Moderate => theme::WARN,
                            crate::scan::http::CorsSecurityLevel::Weak => theme::BAD,
                            crate::scan::http::CorsSecurityLevel::Dangerous => theme::BAD,
                        }),
                    ),
                ]));

                // CORS Details (compact)
                if let Some(origin) = &access_control_allow_origin {
                    lines.push(Line::from(vec![
                        Span::styled("    Origin: ", Style::default().fg(theme::LABEL)),
                        Span::styled(origin.clone(), Style::default().fg(theme::MUTED)),
                    ]));
                }

                let methods = if detail == Detail::Zoomed && !access_control_allow_methods.is_empty() {
                    access_control_allow_methods.join(", ")
                } else {
                    format!("{}", access_control_allow_methods.len())
                };
                lines.push(Line::from(vec![
                    Span::styled("    Methods: ", Style::default().fg(theme::LABEL)),
                    Span::styled(methods, Style::default().fg(theme::MUTED)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("    Credentials: ", Style::default().fg(theme::LABEL)),
                    Span::styled(
                        if access_control_allow_credentials { "yes" } else { "no" },
                        Style::default().fg(if access_control_allow_credentials { theme::WARN } else { theme::GOOD }),
                    ),
                ]));

                // CORS Issues
                for issue in issues {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(theme::BAD)),
                        Span::styled(issue, Style::default().fg(theme::BAD)),
                    ]));
                }
            }

            // HTTP Vulnerabilities
            if !http_vulnerabilities.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![Span::styled(
                    "❗ HTTP Vulnerabilities",
                    Style::default().fg(theme::BAD),
                )]));

                for vuln in http_vulnerabilities {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(theme::BAD)),
                        Span::styled(vuln, Style::default().fg(theme::BAD)),
                    ]));
                }
            }

            // HTTP Security Grade
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📊 HTTP Grade: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    http_grade.clone(),
                    Style::default().fg(match http_grade.as_str() {
                        "A+" | "A" => theme::GOOD,
                        "B" => theme::WARN,
                        _ => theme::BAD,
                    }),
                ),
            ]));
        }

        // DNS Security Records
        if let Some((spf_record, dmarc_record, mx_count, has_mx)) = dns_data {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "📧 Email Security",
                Style::default().fg(theme::VALUE),
            )]));

            // SPF Record
            lines.push(Line::from(vec![
                Span::styled("  SPF: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    if spf_record.is_some() { "configured" } else { "missing" },
                    Style::default().fg(if spf_record.is_some() { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // DMARC Record
            lines.push(Line::from(vec![
                Span::styled("  DMARC: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    if dmarc_record.is_some() { "configured" } else { "missing" },
                    Style::default().fg(if dmarc_record.is_some() { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            // DKIM keys sit at `<selector>._domainkey`; without a selector there is nothing to query.
            lines.push(Line::from(vec![
                Span::styled("  DKIM: ", Style::default().fg(theme::LABEL)),
                Span::styled("not checked (needs selector)", Style::default().fg(theme::MUTED)),
            ]));

            // MX Records
            lines.push(Line::from(vec![
                Span::styled("  MX: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    format!("{} records", mx_count),
                    Style::default().fg(if has_mx { theme::GOOD } else { theme::MUTED }),
                ),
            ]));

            // Show actual record contents
            if let Some(spf) = &spf_record {
                lines.push(Line::from(vec![
                    Span::styled("    SPF: ", Style::default().fg(theme::LABEL)),
                    Span::styled(spf.clone(), Style::default().fg(theme::MUTED)),
                ]));
            }

            if let Some(dmarc) = &dmarc_record {
                lines.push(Line::from(vec![
                    Span::styled("    DMARC: ", Style::default().fg(theme::LABEL)),
                    Span::styled(dmarc.clone(), Style::default().fg(theme::MUTED)),
                ]));
            }
        }

        if detail == Detail::Zoomed {
            lines.extend(zoomed_tls_lines(state));
        }

        lines
    }
}

/// Zoomed only, after everything the grid shows: the negotiated family's supported TLS versions
/// and its full certificate chain.
fn zoomed_tls_lines(state: &AppState) -> Vec<Line<'static>> {
    let Some(tls_state) = state.scanners.get("tls") else {
        return Vec::new();
    };
    let Some(crate::types::ScanResult::Tls(tls_result)) = tls_state.result.as_ref() else {
        return Vec::new();
    };
    let Some(data) = tls_result.get_primary_result() else {
        return Vec::new();
    };
    let field = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("    {label}: "), Style::default().fg(theme::LABEL)),
            Span::styled(value, Style::default().fg(theme::MUTED)),
        ])
    };
    let mut lines = vec![Line::from("")];
    let versions: Vec<&str> = data.supported_versions.iter().map(|version| version.as_str()).collect();
    lines.push(Line::from(vec![
        Span::styled("🔐 Supported Versions: ", Style::default().fg(theme::VALUE)),
        Span::styled(
            if versions.is_empty() {
                "none recorded".to_string()
            } else {
                versions.join(", ")
            },
            Style::default().fg(theme::MUTED),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("📜 Certificate Chain: ", Style::default().fg(theme::VALUE)),
        Span::styled(
            format!("{} certificates", data.certificate_chain.len()),
            Style::default().fg(theme::MUTED),
        ),
    ]));
    for (index, cert) in data.certificate_chain.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!("  [{index}] "), Style::default().fg(theme::LABEL)),
            Span::styled(common_name_display(&cert.subject), Style::default().fg(theme::WARN)),
        ]));
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

impl Default for SecurityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for SecurityPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::security] content: width={} detail={:?}", width, detail);
        crate::tui::text::to_rows(self.build_content_lines(state, detail), width, detail, &[])
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_SECURITY_PANE_WIDTH, MIN_SECURITY_PANE_HEIGHT)
    }

    fn is_focusable(&self) -> bool {
        true
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dns::{DnsResult, EmailSecurityAnalysis};
    use crate::scan::http::{
        CorsIssue, CorsPolicy, CorsSecurityLevel, CspIssue, CspPolicy, CspStrength, HttpVulnerability,
        SecurityGrade as HttpSecurityGrade, SecurityHeaders,
    };
    use crate::scan::tls::{
        CertificateInfo, SecurityGrade, TlsData, TlsResult, TlsStatus, TlsVersion, TlsVulnerability,
    };
    use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
    use chrono::Utc;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn test_security_pane_creation() {
        let pane = SecurityPane::new();
        assert_eq!(pane.title(), "security");
        assert_eq!(pane.id(), "security");
        assert_eq!(pane.min_size(), (MIN_SECURITY_PANE_WIDTH, MIN_SECURITY_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn test_tls_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());

        // Create comprehensive TLS result with certificate details
        let cert = CertificateInfo {
            subject: "CN=example.com,O=Example Corp,C=US".to_string(),
            issuer: "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US".to_string(),
            serial_number: "123456789".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(90),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            san_domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        };

        let tls_data = TlsData {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![cert],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: Some(Utc::now() + chrono::Duration::days(90)),
            days_until_expiry: Some(90),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![
                TlsVulnerability::Heartbleed,
                TlsVulnerability::WeakCipher("RC4-MD5".to_string()),
            ],
            security_grade: SecurityGrade::A,
            scan_time: Duration::from_millis(500),
            target_ip: "192.168.1.1".to_string(),
            queried_at: Instant::now(),
        };

        let mut tls_result = TlsResult::new();
        tls_result.ipv4_result = Some(tls_data);
        tls_result.ipv4_status = TlsStatus::Success(SecurityGrade::A);

        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        // Test TLS data extraction
        if let Some(tls_state) = state.scanners.get("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_ref()
        {
            assert!(tls_result.has_any_success(), "TLS should have successful results");

            if let Some(primary_data) = tls_result.get_primary_result() {
                assert!(
                    primary_data.connection_successful,
                    "TLS connection should be successful"
                );
                assert_eq!(primary_data.negotiated_version.as_ref().unwrap().as_str(), "TLSv1.3");
                assert!(primary_data.perfect_forward_secrecy, "PFS should be enabled");
                assert!(primary_data.ocsp_stapling, "OCSP should be enabled");
                assert!(primary_data.certificate_valid, "Certificate should be valid");
                assert_eq!(primary_data.days_until_expiry, Some(90));
                assert_eq!(primary_data.security_grade.as_str(), "A");
                assert_eq!(primary_data.vulnerabilities.len(), 2);

                // Test certificate details
                let cert = &primary_data.certificate_chain[0];
                assert!(cert.subject.contains("example.com"));
                assert!(cert.issuer.contains("Let's Encrypt"));
                assert_eq!(cert.public_key_algorithm, "RSA");
                assert_eq!(cert.key_size, Some(2048));
                assert_eq!(cert.san_domains.len(), 2);
            }

            // Test vulnerability extraction
            let vuln_strings: Vec<String> = tls_result
                .get_all_vulnerabilities()
                .iter()
                .map(|vuln| match vuln {
                    TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
                    TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
                    _ => "Other vulnerability".to_string(),
                })
                .collect();

            assert!(vuln_strings.contains(&"Heartbleed (CVE-2014-0160)".to_string()));
            assert!(vuln_strings.contains(&"Weak cipher: RC4-MD5".to_string()));
        }
    }

    #[test]
    fn test_http_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());

        let security_headers = SecurityHeaders {
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=()".to_string()),
        };

        let mut csp_directives = HashMap::new();
        csp_directives.insert("default-src".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert(
            "script-src".to_string(),
            vec!["'self'".to_string(), "'unsafe-inline'".to_string()],
        );

        let csp_policy = CspPolicy {
            header_value: "default-src 'self'; script-src 'self' 'unsafe-inline'".to_string(),
            directives: csp_directives,
            issues: vec![CspIssue::UnsafeInline("script-src".to_string())],
            strength: CspStrength::Moderate,
        };

        let cors_policy = CorsPolicy {
            access_control_allow_origin: Some("*".to_string()),
            access_control_allow_methods: vec!["GET".to_string(), "POST".to_string()],
            access_control_allow_headers: vec!["Content-Type".to_string()],
            access_control_allow_credentials: true,
            issues: vec![CorsIssue::WildcardWithCredentials],
            security_level: CorsSecurityLevel::Dangerous,
        };

        let http_data = crate::scan::http::HttpData {
            url: "https://example.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(200),
            content_length: 1024,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers,
            csp: Some(csp_policy),
            cors: Some(cors_policy),
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![HttpVulnerability::WeakCsp, HttpVulnerability::InsecureCors],
            security_grade: HttpSecurityGrade::C,
            scan_duration: Duration::from_millis(300),
            target_ip: "1.2.3.4".to_string(),
            https_failure: None,
        };

        let http_result = crate::scan::http::HttpResult {
            ipv4_result: Some(http_data.clone()),
            ipv6_result: None,
            ipv4_status: crate::scan::http::HttpStatus::Success(http_data.security_grade.clone()),
            ipv6_status: crate::scan::http::HttpStatus::NotQueried,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(300),
        };

        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(http_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        // Test HTTP data extraction
        if let Some(http_state) = state.scanners.get("http")
            && let Some(ScanResult::Http(http_result)) = http_state.result.as_ref()
        {
            // Get primary data for testing
            let primary_data = http_result.get_primary_result().unwrap();

            // Test security headers
            assert!(primary_data.security_headers.strict_transport_security.is_some());
            assert_eq!(primary_data.security_headers.x_frame_options.as_ref().unwrap(), "DENY");
            assert_eq!(
                primary_data.security_headers.x_content_type_options.as_ref().unwrap(),
                "nosniff"
            );
            assert_eq!(
                primary_data.security_headers.x_xss_protection.as_ref().unwrap(),
                "1; mode=block"
            );
            assert!(primary_data.security_headers.referrer_policy.is_some());
            assert!(primary_data.security_headers.permissions_policy.is_some());

            // Test CSP
            let csp = primary_data.csp.as_ref().unwrap();
            assert_eq!(csp.strength, CspStrength::Moderate);
            assert!(csp.header_value.contains("default-src 'self'"));
            assert_eq!(csp.issues.len(), 1);

            // Test CORS
            let cors = primary_data.cors.as_ref().unwrap();
            assert_eq!(cors.security_level, CorsSecurityLevel::Dangerous);
            assert_eq!(cors.access_control_allow_origin.as_ref().unwrap(), "*");
            assert_eq!(cors.access_control_allow_methods.len(), 2);
            assert!(cors.access_control_allow_credentials);
            assert_eq!(cors.issues.len(), 1);

            // Test vulnerabilities using helper methods
            let all_vulnerabilities = http_result.get_all_vulnerabilities();
            assert_eq!(all_vulnerabilities.len(), 2);
            assert!(all_vulnerabilities.iter().any(|v| **v == HttpVulnerability::WeakCsp));
            assert!(
                all_vulnerabilities
                    .iter()
                    .any(|v| **v == HttpVulnerability::InsecureCors)
            );

            // Test grade using helper method
            assert_eq!(*http_result.get_best_security_grade().unwrap(), HttpSecurityGrade::C);
        }
    }

    /// Item 4: DKIM cannot be found without a selector, so the pane says it was not checked.
    #[test]
    fn dkim_reads_not_checked_and_dmarc_reads_configured() {
        let state = AppState::new("google.com".to_string());
        let mut dns_result = DnsResult::new();
        dns_result.email_security = Some(EmailSecurityAnalysis {
            spf_record: Some("v=spf1 -all".to_string()),
            dmarc_record: Some("v=DMARC1; p=reject".to_string()),
            has_mx: true,
            mx_count: 1,
        });
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let pane = SecurityPane::new();
        let out = crate::tui::testing::render_pane(&pane, &state, 120, 80, false);
        assert!(out.contains("DKIM: not checked (needs selector)"), "{out}");
        assert!(out.contains("DMARC: configured"), "{out}");
        let buffer = crate::tui::testing::render_buffer(&pane, &state, 120, 80, false);
        assert_eq!(
            crate::tui::testing::fg_of(&buffer, "not checked (needs selector)"),
            theme::MUTED
        );
    }

    #[test]
    fn test_dns_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());

        let email_security = EmailSecurityAnalysis {
            spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string()),
            has_mx: true,
            mx_count: 2,
        };

        let dns_result = DnsResult {
            A: vec![],
            AAAA: vec![],
            CNAME: vec![],
            MX: vec![],
            TXT: vec![],
            NS: vec![],
            CAA: vec![],
            PTR: vec![],
            SOA: vec![],
            SRV: vec![],
            email_security: Some(email_security),
            A_status: crate::scan::dns::QueryStatus::NoRecords,
            AAAA_status: crate::scan::dns::QueryStatus::NoRecords,
            MX_status: crate::scan::dns::QueryStatus::NoRecords,
            TXT_status: crate::scan::dns::QueryStatus::Success(0),
            NS_status: crate::scan::dns::QueryStatus::NoRecords,
            SOA_status: crate::scan::dns::QueryStatus::NoRecords,
            SRV_status: crate::scan::dns::QueryStatus::NoRecords,
            PTR_status: crate::scan::dns::QueryStatus::NoRecords,
            CNAME_status: crate::scan::dns::QueryStatus::NoRecords,
            CAA_status: crate::scan::dns::QueryStatus::NoRecords,
            response_time: Duration::from_millis(50),
            queried_at: Instant::now(),
        };

        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        // Test DNS data extraction
        if let Some(dns_state) = state.scanners.get("dns")
            && let Some(ScanResult::Dns(dns_result)) = dns_state.result.as_ref()
        {
            let email_security = dns_result.email_security.as_ref().unwrap();

            // Test SPF
            assert!(email_security.spf_record.is_some());
            assert!(email_security.spf_record.as_ref().unwrap().contains("v=spf1"));

            // Test DMARC
            assert!(email_security.dmarc_record.is_some());
            assert!(email_security.dmarc_record.as_ref().unwrap().contains("v=DMARC1"));

            // Test MX
            assert!(email_security.has_mx);
            assert_eq!(email_security.mx_count, 2);
        }
    }

    #[test]
    fn test_comprehensive_data_availability() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("comprehensive.com".to_string());

        // Add all scanner types with data
        let cert = CertificateInfo {
            subject: "CN=comprehensive.com".to_string(),
            issuer: "CN=DigiCert".to_string(),
            serial_number: "123".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            san_domains: vec!["comprehensive.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        };

        let tls_data = TlsData {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![cert],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: Some(Utc::now() + chrono::Duration::days(365)),
            days_until_expiry: Some(365),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![],
            security_grade: SecurityGrade::APlus,
            scan_time: Duration::from_millis(500),
            target_ip: "192.168.1.1".to_string(),
            queried_at: Instant::now(),
        };

        let mut tls_result = TlsResult::new();
        tls_result.ipv4_result = Some(tls_data);
        tls_result.ipv4_status = TlsStatus::Success(SecurityGrade::APlus);

        let http_data = crate::scan::http::HttpData {
            url: "https://comprehensive.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(100),
            content_length: 2048,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers: SecurityHeaders {
                strict_transport_security: Some("max-age=31536000".to_string()),
                x_frame_options: Some("SAMEORIGIN".to_string()),
                x_content_type_options: Some("nosniff".to_string()),
                x_xss_protection: Some("1; mode=block".to_string()),
                referrer_policy: Some("strict-origin".to_string()),
                permissions_policy: Some("geolocation=()".to_string()),
            },
            csp: None,
            cors: None,
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![HttpVulnerability::MissingCsp],
            security_grade: HttpSecurityGrade::B,
            scan_duration: Duration::from_millis(200),
            target_ip: "1.2.3.4".to_string(),
            https_failure: None,
        };

        let http_result = crate::scan::http::HttpResult {
            ipv4_result: Some(http_data.clone()),
            ipv6_result: None,
            ipv4_status: crate::scan::http::HttpStatus::Success(http_data.security_grade.clone()),
            ipv6_status: crate::scan::http::HttpStatus::NotQueried,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(200),
        };

        let dns_result = DnsResult {
            A: vec![],
            AAAA: vec![],
            CNAME: vec![],
            MX: vec![],
            TXT: vec![],
            NS: vec![],
            CAA: vec![],
            PTR: vec![],
            SOA: vec![],
            SRV: vec![],
            email_security: Some(EmailSecurityAnalysis {
                spf_record: Some("v=spf1 -all".to_string()),
                dmarc_record: Some("v=DMARC1; p=reject".to_string()),
                has_mx: true,
                mx_count: 1,
            }),
            A_status: crate::scan::dns::QueryStatus::NoRecords,
            AAAA_status: crate::scan::dns::QueryStatus::NoRecords,
            MX_status: crate::scan::dns::QueryStatus::Success(1),
            TXT_status: crate::scan::dns::QueryStatus::Success(2),
            NS_status: crate::scan::dns::QueryStatus::NoRecords,
            SOA_status: crate::scan::dns::QueryStatus::NoRecords,
            SRV_status: crate::scan::dns::QueryStatus::NoRecords,
            PTR_status: crate::scan::dns::QueryStatus::NoRecords,
            CNAME_status: crate::scan::dns::QueryStatus::NoRecords,
            CAA_status: crate::scan::dns::QueryStatus::NoRecords,
            response_time: Duration::from_millis(30),
            queried_at: Instant::now(),
        };

        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(http_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );

        // Verify all scanners have data
        assert!(state.scanners.contains_key("tls"));
        assert!(state.scanners.contains_key("http"));
        assert!(state.scanners.contains_key("dns"));

        // Verify TLS data is extractable
        if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                assert!(tls_result.has_any_success());
                if let Some(primary_data) = tls_result.get_primary_result() {
                    assert!(primary_data.connection_successful);
                    assert_eq!(primary_data.security_grade.as_str(), "A+");
                    assert!(!primary_data.certificate_chain.is_empty());
                }
            } else {
                panic!("TLS result should be extractable");
            }
        }

        // Verify HTTP data is extractable
        if let Some(http_state) = state.scanners.get("http") {
            if let Some(ScanResult::Http(http_result)) = http_state.result.as_ref() {
                let primary_data = http_result.get_primary_result().unwrap();
                assert!(primary_data.security_headers.strict_transport_security.is_some());
                assert_eq!(*http_result.get_best_security_grade().unwrap(), HttpSecurityGrade::B);
                assert!(!http_result.get_all_vulnerabilities().is_empty());
            } else {
                panic!("HTTP result should be extractable");
            }
        }

        // Verify DNS data is extractable
        if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                assert!(dns_result.email_security.is_some());
                let email_security = dns_result.email_security.as_ref().unwrap();
                assert!(email_security.spf_record.is_some());
                assert!(email_security.dmarc_record.is_some());
            } else {
                panic!("DNS result should be extractable");
            }
        }
    }

    #[test]
    fn test_vulnerability_extraction_logic() {
        // Test TLS vulnerability extraction
        let tls_vulnerabilities = [
            TlsVulnerability::Heartbleed,
            TlsVulnerability::Poodle,
            TlsVulnerability::WeakCipher("RC4-MD5".to_string()),
            TlsVulnerability::ExpiredCertificate,
        ];

        let vuln_strings: Vec<String> = tls_vulnerabilities
            .iter()
            .map(|vuln| match vuln {
                TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
                TlsVulnerability::Poodle => "POODLE (CVE-2014-3566)".to_string(),
                TlsVulnerability::Beast => "BEAST (CVE-2011-3389)".to_string(),
                TlsVulnerability::Crime => "CRIME (CVE-2012-4929)".to_string(),
                TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
                TlsVulnerability::ExpiredCertificate => "Certificate expired".to_string(),
                TlsVulnerability::SelfSignedCertificate => "Self-signed certificate".to_string(),
                TlsVulnerability::UntrustedIssuer => "Untrusted certificate issuer".to_string(),
                TlsVulnerability::HostnameMismatch => "Certificate hostname mismatch".to_string(),
                TlsVulnerability::WeakSignatureAlgorithm(alg) => format!("Weak signature: {}", alg),
                TlsVulnerability::InsecureRenegotiation => "Insecure renegotiation".to_string(),
                TlsVulnerability::WeakDhParams => "Weak DH parameters".to_string(),
                TlsVulnerability::SslV2Enabled => "SSLv2 enabled".to_string(),
                TlsVulnerability::SslV3Enabled => "SSLv3 enabled".to_string(),
            })
            .collect();

        assert_eq!(vuln_strings.len(), 4);
        assert!(vuln_strings.contains(&"Heartbleed (CVE-2014-0160)".to_string()));
        assert!(vuln_strings.contains(&"POODLE (CVE-2014-3566)".to_string()));
        assert!(vuln_strings.contains(&"Weak cipher: RC4-MD5".to_string()));
        assert!(vuln_strings.contains(&"Certificate expired".to_string()));

        // Test HTTP vulnerability extraction
        let http_vulnerabilities = [
            HttpVulnerability::MissingHsts,
            HttpVulnerability::WeakCsp,
            HttpVulnerability::InsecureCors,
        ];

        let http_vuln_strings: Vec<String> = http_vulnerabilities
            .iter()
            .map(|vuln| match vuln {
                HttpVulnerability::MissingHsts => "Missing HSTS header".to_string(),
                HttpVulnerability::MissingXFrameOptions => "Missing X-Frame-Options".to_string(),
                HttpVulnerability::MissingXContentTypeOptions => "Missing X-Content-Type-Options".to_string(),
                HttpVulnerability::MissingCsp => "Missing Content Security Policy".to_string(),
                HttpVulnerability::WeakCsp => "Weak Content Security Policy".to_string(),
                HttpVulnerability::InsecureCors => "Insecure CORS configuration".to_string(),
                HttpVulnerability::InformationDisclosure => "Information disclosure risk".to_string(),
            })
            .collect();

        assert_eq!(http_vuln_strings.len(), 3);
        assert!(http_vuln_strings.contains(&"Missing HSTS header".to_string()));
        assert!(http_vuln_strings.contains(&"Weak Content Security Policy".to_string()));
        assert!(http_vuln_strings.contains(&"Insecure CORS configuration".to_string()));
    }

    fn state_with_tls(status: ScanStatus) -> AppState {
        let state = AppState::new("example.com".to_string());
        let mut tls_result = TlsResult::new();
        tls_result.ipv4_result = Some(TlsData {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: None,
            days_until_expiry: Some(90),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![],
            security_grade: SecurityGrade::A,
            scan_time: Duration::from_millis(500),
            target_ip: "192.168.1.1".to_string(),
            queried_at: Instant::now(),
        });
        tls_result.ipv4_status = TlsStatus::Success(SecurityGrade::A);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    #[test]
    fn render_running_state_with_result_shows_refreshing_not_analyzed() {
        let state = state_with_tls(ScanStatus::Running);
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(out.contains("refreshing"), "missing refreshing marker:\n{}", out);
        assert!(!out.contains("analyzed"), "stale result claims analyzed:\n{}", out);
    }

    #[test]
    fn render_complete_state_shows_analyzed() {
        let state = state_with_tls(ScanStatus::Complete);
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(out.contains("analyzed"), "missing analyzed:\n{}", out);
        assert!(!out.contains("refreshing"), "unexpected refreshing marker:\n{}", out);
    }

    #[test]
    fn render_expired_handshake_counts_one_issue_and_names_it() {
        let state = AppState::new("expired.example".to_string());
        let mut tls_result = TlsResult::new();
        let data = crate::scan::tls::fixtures::expired_handshake_result();
        tls_result.ipv4_status = TlsStatus::Success(data.security_grade.clone());
        tls_result.ipv4_result = Some(data);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(out.contains("Issues: 1"), "expected one issue:\n{}", out);
        assert!(out.contains("Certificate expired"), "missing expiry issue:\n{}", out);
        assert!(
            out.contains("Expires: -30 days"),
            "missing certificate expiry:\n{}",
            out
        );
        assert!(out.contains("Valid: no"), "expired cert shown valid:\n{}", out);
    }

    #[test]
    fn render_issue_count_is_primary_vulnerabilities_plus_certificate_errors() {
        let state = AppState::new("expired.example".to_string());
        let mut tls_result = TlsResult::new();
        let mut ipv4 = crate::scan::tls::fixtures::expired_handshake_result();
        ipv4.certificate_errors
            .push("Version enumeration failed: reset".to_string());
        ipv4.certificate_errors
            .push("Certificate analysis failed: timeout".to_string());
        let ipv6 = crate::scan::tls::fixtures::expired_handshake_result();
        tls_result.ipv4_status = TlsStatus::Success(ipv4.security_grade.clone());
        tls_result.ipv6_status = TlsStatus::Success(ipv6.security_grade.clone());
        tls_result.ipv4_result = Some(ipv4);
        tls_result.ipv6_result = Some(ipv6);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(
            out.contains("Issues: 3"),
            "expected expiry + two unmapped errors:\n{}",
            out
        );
        assert!(
            out.contains("Version enumeration failed"),
            "unmapped error not listed:\n{}",
            out
        );
        assert_eq!(
            out.matches("Certificate expired").count(),
            1,
            "expiry listed twice:\n{}",
            out
        );
    }

    #[test]
    fn render_expired_handshake_reason_visible_without_scrolling() {
        let state = AppState::new("expired.example".to_string());
        let mut tls_result = TlsResult::new();
        let data = crate::scan::tls::fixtures::expired_handshake_result();
        tls_result.ipv4_status = TlsStatus::Success(data.security_grade.clone());
        tls_result.ipv4_result = Some(data);
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        // expired.badssl.com serves no security headers, which fills the pane past the fold.
        let http_data = crate::scan::http::HttpData {
            url: "https://expired.example".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(200),
            content_length: 1024,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers: SecurityHeaders {
                strict_transport_security: None,
                x_frame_options: None,
                x_content_type_options: None,
                x_xss_protection: None,
                referrer_policy: None,
                permissions_policy: None,
            },
            csp: None,
            cors: None,
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![
                HttpVulnerability::MissingHsts,
                HttpVulnerability::MissingXFrameOptions,
                HttpVulnerability::MissingXContentTypeOptions,
                HttpVulnerability::MissingCsp,
            ],
            security_grade: HttpSecurityGrade::F,
            scan_duration: Duration::from_millis(300),
            target_ip: "192.0.2.1".to_string(),
            https_failure: None,
        };
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(crate::scan::http::HttpResult {
                    ipv4_status: crate::scan::http::HttpStatus::Success(HttpSecurityGrade::F),
                    ipv4_result: Some(http_data),
                    ipv6_result: None,
                    ipv6_status: crate::scan::http::HttpStatus::NotQueried,
                    queried_at: Instant::now(),
                    total_duration: Duration::from_millis(300),
                })),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        // The Security pane at a 200x55 terminal: 68 wide, 20 inner lines plus borders.
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 68, 22, true);
        assert!(out.contains("Issues: 1"), "missing issue count:\n{}", out);
        assert!(out.contains("Certificate expired"), "reason below the fold:\n{}", out);
    }

    fn state_with_cert(subject: &str, issuer: &str) -> AppState {
        let state = state_with_tls(ScanStatus::Complete);
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.certificate_chain = vec![CertificateInfo {
                subject: subject.to_string(),
                issuer: issuer.to_string(),
                serial_number: "1".to_string(),
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(90),
                signature_algorithm: "SHA256withRSA".to_string(),
                public_key_algorithm: "RSA".to_string(),
                key_size: Some(2048),
                san_domains: vec![],
                is_self_signed: false,
                is_ca: false,
            }];
        }
        state
    }

    #[test]
    fn render_multibyte_cn_is_fit_by_width_without_panic() {
        let cn = "é".repeat(30);
        let state = state_with_cert(&format!("CN={cn}"), &format!("CN={cn},O=Example"));
        let wide = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(wide.contains(&format!("Subject: {cn}")), "subject CN cut:\n{wide}");
        assert!(wide.contains(&format!("Issuer: {cn}")), "issuer CN cut:\n{wide}");
        // Narrow panes still cut on a char boundary, with an ellipsis.
        let narrow = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 40, 40, false);
        assert!(narrow.contains('…'), "narrow CN not marked:\n{narrow}");
    }

    #[test]
    fn forty_char_cn_renders_in_full_at_200x55() {
        let cn = "Sectigo Public Server Authentication CA DV R36";
        assert!(cn.chars().count() > 40);
        let state = state_with_cert("CN=example.com", &format!("CN={cn},O=Sectigo Limited"));
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 2, 200, 55);
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, width, height, false);
        assert!(out.contains(&format!("Issuer: {cn}")), "CN cut:\n{out}");
    }

    #[test]
    fn security_features_say_what_was_not_checked() {
        let out = crate::tui::testing::render_pane(
            &SecurityPane::new(),
            &state_with_tls(ScanStatus::Complete),
            100,
            80,
            false,
        );
        assert!(out.contains("PFS: yes"), "{out}");
        assert!(out.contains("OCSP: not checked"), "{out}");
        assert!(!out.contains("OCSP: no\n") && !out.contains("OCSP: yes"), "{out}");
    }

    #[test]
    fn failed_handshake_has_no_pfs_verdict() {
        let state = state_with_tls(ScanStatus::Complete);
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.connection_successful = false;
            data.perfect_forward_secrecy = false;
        }
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 80, false);
        assert!(out.contains("PFS: n/a"), "{out}");
        assert!(!out.contains("PFS: no"), "{out}");
    }

    fn http_state_with_policies(grade: HttpSecurityGrade, strength: CspStrength, level: CorsSecurityLevel) -> AppState {
        let state = AppState::new("example.com".to_string());
        let http_data = crate::scan::http::HttpData {
            url: "https://example.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(200),
            content_length: 1024,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers: SecurityHeaders {
                strict_transport_security: None,
                x_frame_options: None,
                x_content_type_options: None,
                x_xss_protection: None,
                referrer_policy: None,
                permissions_policy: None,
            },
            csp: Some(CspPolicy {
                header_value: "default-src 'self'".to_string(),
                directives: HashMap::new(),
                issues: vec![],
                strength,
            }),
            cors: Some(CorsPolicy {
                access_control_allow_origin: Some("*".to_string()),
                access_control_allow_methods: vec![],
                access_control_allow_headers: vec![],
                access_control_allow_credentials: false,
                issues: vec![],
                security_level: level,
            }),
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![],
            security_grade: grade.clone(),
            scan_duration: Duration::from_millis(300),
            target_ip: "192.0.2.1".to_string(),
            https_failure: None,
        };
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(crate::scan::http::HttpResult {
                    ipv4_status: crate::scan::http::HttpStatus::Success(grade),
                    ipv4_result: Some(http_data),
                    ipv6_result: None,
                    ipv6_status: crate::scan::http::HttpStatus::NotQueried,
                    queried_at: Instant::now(),
                    total_duration: Duration::from_millis(300),
                })),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    #[test]
    fn http_grade_csp_and_cors_render_user_labels_not_enum_names() {
        let state = http_state_with_policies(
            HttpSecurityGrade::APlus,
            CspStrength::Moderate,
            CorsSecurityLevel::Dangerous,
        );
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 80, false);
        assert!(out.contains("HTTP Grade: A+"), "{out}");
        assert!(out.contains("CSP: moderate"), "{out}");
        assert!(out.contains("CORS: dangerous"), "{out}");
        for enum_name in ["APlus", "Moderate", "Dangerous"] {
            assert!(!out.contains(enum_name), "enum name {enum_name} leaked:\n{out}");
        }
    }

    #[test]
    fn render_ascii_cn_stops_at_comma() {
        let state = state_with_cert("CN=example.com,O=Example Corp", "CN=R3,O=Let's Encrypt");
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(out.contains("Subject: example.com "), "subject CN wrong:\n{}", out);
        assert!(out.contains("Issuer: R3 "), "issuer CN wrong:\n{}", out);
    }

    fn failed_tls_state(with_result: bool) -> AppState {
        let state = if with_result {
            state_with_tls(ScanStatus::Failed)
        } else {
            let state = AppState::new("example.com".to_string());
            state.scanners.insert(
                "tls".to_string(),
                ScanState {
                    result: None,
                    error: None,
                    status: ScanStatus::Failed,
                    last_updated: Instant::now(),
                    history: std::collections::VecDeque::new(),
                },
            );
            state
        };
        if let Some(mut tls_state) = state.scanners.get_mut("tls") {
            tls_state.error = Some(eyre::eyre!("timed out after 30s"));
        }
        state
    }

    #[test]
    fn render_failed_first_scan_shows_reason_not_analyzing() {
        let state = failed_tls_state(false);
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(out.contains("timed out after 30s"), "failure reason missing:\n{}", out);
        assert!(!out.contains("analyzing"), "failed scan still analyzing:\n{}", out);
        assert!(!out.contains("checking"), "failed scan still checking:\n{}", out);
    }

    #[test]
    fn render_failed_refresh_shows_reason_next_to_retained_data() {
        let state = failed_tls_state(true);
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 40, false);
        assert!(
            out.contains("failed: timed out after 30s"),
            "failure reason missing:\n{}",
            out
        );
        assert!(out.contains("TLSv1.3"), "retained result dropped:\n{}", out);
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
    fn long_cipher_is_fit_with_ellipsis_in_narrow_terminals() {
        let cipher = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_AND_A_LONG_VENDOR_SUFFIX";
        let state = state_with_tls(ScanStatus::Complete);
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.negotiated_cipher = Some(crate::scan::tls::CipherSuite {
                name: cipher.to_string(),
                protocol_version: "TLSv1.3".to_string(),
                key_exchange: "ECDHE".to_string(),
                authentication: "RSA".to_string(),
                encryption: "CHACHA20".to_string(),
                mac: "POLY1305".to_string(),
                is_secure: true,
            });
        }
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &SecurityPane::new(),
            &state,
            2,
            2,
            &format!("🔑 Cipher: {cipher}"),
        );
    }

    #[test]
    fn zoomed_content_lists_the_certificate_chain_and_dmarc_in_full() {
        let state = state_with_cert("CN=www.example.com, O=Example", "CN=Example Issuing CA, O=Example");
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.certificate_chain[0].serial_number = "0a:1b:2c".to_string();
            data.certificate_chain[0].san_domains = vec!["www.example.com".to_string(), "example.com".to_string()];
            data.supported_versions = vec![TlsVersion::V1_2, TlsVersion::V1_3];
        }
        let dmarc = "v=DMARC1; p=reject; rua=mailto:mailauth-reports@example.com; ruf=mailto:forensics@example.com";
        let mut dns_result = DnsResult::new();
        dns_result.email_security = Some(EmailSecurityAnalysis {
            spf_record: Some("v=spf1 include:_spf.example.com ~all".to_string()),
            dmarc_record: Some(dmarc.to_string()),
            has_mx: true,
            mx_count: 1,
        });
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let pane = SecurityPane::new();
        let rows = crate::tui::testing::content_rows(&pane, &state, 60, Detail::Zoomed);
        let text = rows.join("\n");
        for expected in [
            "Certificate Chain: 1 certificates",
            "Serial: 0a:1b:2c",
            "Subject: CN=www.example.com, O=Example",
            "Signature: SHA256withRSA",
            "SAN: www.example.com, example.com",
            "Supported Versions: TLSv1.2, TLSv1.3",
            "DMARC: configured",
        ] {
            assert!(text.contains(expected), "{expected}:\n{text}");
        }
        assert!(rows.concat().contains(dmarc), "DMARC text not whole:\n{text}");

        let normal = crate::tui::testing::content_rows(&pane, &state, 60, Detail::Normal).join("\n");
        assert!(!normal.contains("Certificate Chain"), "{normal}");
        assert!(!normal.contains("0a:1b:2c"), "{normal}");
    }

    #[test]
    fn zoomed_content_lists_every_tls_issue_past_the_grid_cap() {
        let state = state_with_tls(ScanStatus::Complete);
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.certificate_errors = (1..=MAX_TLS_VULNERABILITIES_DISPLAYED + 2)
                .map(|n| format!("certificate problem {n}"))
                .collect();
        }
        let pane = SecurityPane::new();
        let last = format!("certificate problem {}", MAX_TLS_VULNERABILITIES_DISPLAYED + 2);
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 80, Detail::Zoomed).join("\n");
        assert!(zoomed.contains(&last), "{zoomed}");
        let normal = crate::tui::testing::content_rows(&pane, &state, 80, Detail::Normal).join("\n");
        assert!(!normal.contains(&last), "{normal}");
    }
}
