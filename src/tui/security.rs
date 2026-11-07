use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::AppState;
use log;
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::any::Any;

const MAX_TLS_VULNERABILITIES_DISPLAYED: usize = 5;
const MIN_SECURITY_PANE_WIDTH: u16 = 50;
const MIN_SECURITY_PANE_HEIGHT: u16 = 35;

/// Observatory's result for one test of a graded host, colored by whether it passed; `None` when
/// the host has no grade.
fn observatory_label(
    outcome: &crate::scan::observatory::ObservatoryOutcome,
    test_name: &str,
) -> Option<(String, ratatui::style::Color)> {
    let crate::scan::observatory::ObservatoryOutcome::Graded(result) = outcome else {
        return None;
    };
    let test = result.tests.iter().find(|test| test.name == test_name)?;
    Some((
        test.result.as_str().to_string(),
        if test.pass { theme::GOOD } else { theme::BAD },
    ))
}

/// A header row with one verdict: Observatory's result for `test_name` when the host is graded.
/// With no grade the row is the target's own header value, or `missing`, in `MUTED`: a display of
/// what the target sent, never a pass or fail of its own.
fn observatory_row(
    label: &'static str,
    outcome: &crate::scan::observatory::ObservatoryOutcome,
    test_name: &str,
    header: Option<&str>,
) -> Line<'static> {
    let (value, color) = observatory_label(outcome, test_name)
        .unwrap_or_else(|| (header.unwrap_or("missing").to_string(), theme::MUTED));
    Line::from(vec![
        Span::styled(label, Style::default().fg(theme::LABEL)),
        Span::styled(value, Style::default().fg(color)),
    ])
}

/// SECURITY pane: the TLS handshake, its grade and issues, and the HTTP security headers. The
/// certificate is the cert pane's and the email posture the mail pane's.
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

        let tls_state = state.scanners.get("tls");
        let tls_scanner_present = tls_state.is_some();
        let tls_failed = tls_state
            .as_ref()
            .is_some_and(|tls_state| matches!(tls_state.status, crate::types::ScanStatus::Failed));
        let (label, label_color) = match tls_state.as_ref() {
            Some(tls_state) => crate::tui::status_label(tls_state, "analyzing...", "analyzed"),
            None => ("unavailable".to_string(), theme::BAD),
        };
        let tls_result = tls_state
            .as_ref()
            .and_then(|tls_state| match tls_state.result.as_ref() {
                Some(crate::types::ScanResult::Tls(tls_result)) => Some(tls_result.clone()),
                _ => None,
            });
        drop(tls_state);
        let primary = tls_result
            .as_ref()
            .and_then(|tls_result| tls_result.get_primary_result());

        // The status row carries the grade and the issue count: `Status: analyzed · A+ · 0 issues`.
        let mut status = vec![
            Span::styled("🔒 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled(label, Style::default().fg(label_color)),
        ];
        if let (Some(tls_result), Some(primary_data)) = (tls_result.as_ref(), primary) {
            let grade = tls_result
                .get_best_security_grade()
                .map(|g| g.as_str().to_string())
                .unwrap_or_else(|| "F".to_string());
            let grade_color = match grade.as_str() {
                "A+" | "A" => theme::GOOD,
                "B" => theme::WARN,
                _ => theme::BAD,
            };
            let issue_count = primary_data.issue_count();
            status.push(Span::styled(" · ", Style::default().fg(theme::MUTED)));
            status.push(Span::styled(grade, Style::default().fg(grade_color)));
            status.push(Span::styled(" · ", Style::default().fg(theme::MUTED)));
            status.push(Span::styled(
                crate::tui::text::plural(issue_count, "issue"),
                Style::default().fg(if issue_count == 0 { theme::GOOD } else { theme::BAD }),
            ));
        }
        let mut lines = vec![Line::from(status)];

        // The reasons the issue count counts sit right under it, so a failed handshake's cause is
        // above the fold.
        if let Some(primary_data) = primary {
            for issue in primary_data
                .vulnerabilities
                .iter()
                .map(|vuln| vuln.description())
                .chain(primary_data.certificate_errors.iter().cloned())
                .take(cap(MAX_TLS_VULNERABILITIES_DISPLAYED))
            {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(theme::BAD)),
                    Span::styled(issue, Style::default().fg(theme::BAD)),
                ]));
            }
        }

        // Empty line for spacing
        lines.push(Line::from(""));

        // Extract HTTP data upfront: the target's own headers, displayed; every verdict on them is
        // the host's Observatory result.
        let http_data = if let Some(http_state) = state.scanners.get("http") {
            if let Some(crate::types::ScanResult::Http(http_result)) = http_state.result.as_ref() {
                http_result.get_primary_result().map(|primary_data| {
                    let headers = &primary_data.security_headers;
                    (
                        headers.strict_transport_security.clone(),
                        headers.x_frame_options.clone(),
                        headers.x_content_type_options.clone(),
                        headers
                            .x_xss_protection
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        headers.referrer_policy.clone(),
                        headers
                            .permissions_policy
                            .clone()
                            .unwrap_or_else(|| "missing".to_string()),
                        primary_data.csp.as_ref().map(|csp| csp.header_value.clone()),
                        primary_data.cors.as_ref().map(|cors| {
                            (
                                cors.access_control_allow_origin.clone(),
                                cors.access_control_allow_methods.clone(),
                                cors.access_control_allow_credentials,
                            )
                        }),
                        http_result.observatory.clone(),
                    )
                })
            } else {
                None
            }
        } else {
            None
        };

        // A scan whose target observation failed can still carry a grade.
        let http_grade_only = state
            .scanners
            .get("http")
            .and_then(|http_state| match http_state.result.as_ref() {
                Some(crate::types::ScanResult::Http(http_result)) if http_result.get_primary_result().is_none() => {
                    Some(http_result.observatory.clone())
                }
                _ => None,
            });

        if let Some(primary_data) = primary {
            let connection_successful = primary_data.connection_successful;
            // TLS Connection
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled(
                    if connection_successful { "connected" } else { "failed" },
                    Style::default().fg(if connection_successful { theme::GOOD } else { theme::BAD }),
                ),
            ]));

            if let Some(version) = &primary_data.negotiated_version {
                lines.push(Line::from(vec![
                    Span::styled("🔐 Version: ", Style::default().fg(theme::LABEL)),
                    Span::styled(version.as_str(), Style::default().fg(theme::GOOD)),
                ]));
            }

            if let Some(cipher) = &primary_data.negotiated_cipher {
                lines.push(Line::from(vec![
                    Span::styled("🔑 Cipher: ", Style::default().fg(theme::LABEL)),
                    Span::styled(cipher.name.clone(), Style::default().fg(theme::WARN)),
                ]));
            }

            // PFS and OCSP share one row.
            let pfs = primary_data.perfect_forward_secrecy;
            lines.push(Line::from(vec![
                Span::styled("🔰 PFS: ", Style::default().fg(theme::LABEL)),
                if !connection_successful {
                    Span::styled("n/a", Style::default().fg(theme::MUTED))
                } else {
                    Span::styled(
                        if pfs { "yes" } else { "no" },
                        Style::default().fg(if pfs { theme::GOOD } else { theme::BAD }),
                    )
                },
                Span::styled(" · ", Style::default().fg(theme::MUTED)),
                Span::styled("OCSP: ", Style::default().fg(theme::LABEL)),
                // Stapling is never collected, so `no` would claim a check that did not happen.
                Span::styled("not checked", Style::default().fg(theme::MUTED)),
            ]));
        } else if tls_failed {
            // The first scan failed: the header's `Status:` row carries the reason and is the only
            // status row; a second `🔗 Status:` row would say the same thing again.
        } else if tls_scanner_present {
            // TLS scanner exists but no result yet
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("checking...", Style::default().fg(theme::MUTED)),
            ]));

            lines.push(Line::from(vec![
                Span::styled("🔐 Version: ", Style::default().fg(theme::LABEL)),
                Span::styled("detecting...", Style::default().fg(theme::MUTED)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("TLS scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        // HTTP Security Headers
        if let Some((
            hsts,
            x_frame,
            x_content,
            xss_protect,
            referrer_policy,
            permissions_policy,
            csp_policy,
            cors_data,
            http_grade,
        )) = http_data
        {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "🧱 HTTP Security",
                Style::default().fg(theme::VALUE),
            )]));

            lines.push(observatory_row(
                "  HSTS: ",
                &http_grade,
                "strict-transport-security",
                hsts.as_deref(),
            ));
            lines.push(observatory_row(
                "  X-Frame: ",
                &http_grade,
                "x-frame-options",
                x_frame.as_deref(),
            ));
            lines.push(observatory_row(
                "  X-Content: ",
                &http_grade,
                "x-content-type-options",
                x_content.as_deref(),
            ));

            // X-XSS-Protection: Observatory has no test for it, so the row is the target's header, ungraded.
            lines.push(Line::from(vec![
                Span::styled("  XSS-Protect: ", Style::default().fg(theme::LABEL)),
                Span::styled(xss_protect.clone(), Style::default().fg(theme::MUTED)),
            ]));

            lines.push(observatory_row(
                "  Referrer: ",
                &http_grade,
                "referrer-policy",
                referrer_policy.as_deref(),
            ));

            // Permissions-Policy: Observatory has no test for it, so the row is the target's header, ungraded.
            lines.push(Line::from(vec![
                Span::styled("  Permissions: ", Style::default().fg(theme::LABEL)),
                Span::styled(permissions_policy.clone(), Style::default().fg(theme::MUTED)),
            ]));

            // CSP: Observatory's result for the graded host; the policy below is the target's own.
            lines.push(observatory_row(
                "  CSP: ",
                &http_grade,
                "content-security-policy",
                csp_policy.as_deref(),
            ));
            if let Some(header_value) = csp_policy {
                lines.push(Line::from(vec![
                    Span::styled("    Policy: ", Style::default().fg(theme::LABEL)),
                    Span::styled(header_value, Style::default().fg(theme::MUTED)),
                ]));
            }

            // CORS
            if let Some((access_control_allow_origin, access_control_allow_methods, access_control_allow_credentials)) =
                cors_data
            {
                let (label, color) = observatory_label(&http_grade, "cross-origin-resource-sharing")
                    .unwrap_or(("present".to_string(), theme::MUTED));
                lines.push(Line::from(vec![
                    Span::styled("  CORS: ", Style::default().fg(theme::LABEL)),
                    Span::styled(label, Style::default().fg(color)),
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
            }

            // HTTP Security Grade: the same line the HTTP pane shows.
            lines.push(Line::from(""));
            lines.push(crate::tui::http::grade_line("📊 HTTP Grade: ", &http_grade));
        } else if let Some(observatory) = http_grade_only {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "🧱 HTTP Security",
                Style::default().fg(theme::VALUE),
            )]));
            lines.push(crate::tui::http::grade_line("📊 HTTP Grade: ", &observatory));
        }

        if detail == Detail::Zoomed {
            lines.extend(zoomed_tls_lines(state));
        }

        lines
    }
}

/// Zoomed only, after everything the grid shows: the negotiated family's supported TLS versions.
/// The certificate chain is the cert pane's.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::dns::{DnsResult, EmailSecurityAnalysis};
    use crate::scan::http::{CorsPolicy, CspPolicy, SecurityHeaders};
    use crate::scan::observatory::ObservatoryOutcome;
    use crate::scan::observatory::tests::google_com_result;
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
            issuer_organization: Some("Let's Encrypt".to_string()),
            issuer_common_name: Some("Let's Encrypt Authority X3".to_string()),
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
        };

        let cors_policy = CorsPolicy {
            access_control_allow_origin: Some("*".to_string()),
            access_control_allow_methods: vec!["GET".to_string(), "POST".to_string()],
            access_control_allow_headers: vec!["Content-Type".to_string()],
            access_control_allow_credentials: true,
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
            scan_duration: Duration::from_millis(300),
            target_ip: "1.2.3.4".to_string(),
            https_failure: None,
        };

        let http_result = crate::scan::http::HttpResult {
            ipv4_result: Some(http_data.clone()),
            ipv6_result: None,
            ipv4_status: crate::scan::http::HttpStatus::Success,
            ipv6_status: crate::scan::http::HttpStatus::NotQueried,
            observatory: ObservatoryOutcome::Graded(google_com_result()),
            lenses: crate::scan::http::Lenses::absent(),
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
            assert!(csp.header_value.contains("default-src 'self'"));

            // Test CORS
            let cors = primary_data.cors.as_ref().unwrap();
            assert_eq!(cors.access_control_allow_origin.as_ref().unwrap(), "*");
            assert_eq!(cors.access_control_allow_methods.len(), 2);
            assert!(cors.access_control_allow_credentials);

            assert_eq!(http_result.observatory.grade_text(), "C- (45) · google.com");
        }
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
            ..EmailSecurityAnalysis::fixture()
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
            issuer_organization: None,
            issuer_common_name: Some("DigiCert".to_string()),
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
            scan_duration: Duration::from_millis(200),
            target_ip: "1.2.3.4".to_string(),
            https_failure: None,
        };

        let http_result = crate::scan::http::HttpResult {
            ipv4_result: Some(http_data.clone()),
            ipv6_result: None,
            ipv4_status: crate::scan::http::HttpStatus::Success,
            ipv6_status: crate::scan::http::HttpStatus::NotQueried,
            observatory: ObservatoryOutcome::Graded(google_com_result()),
            lenses: crate::scan::http::Lenses::absent(),
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
                ..EmailSecurityAnalysis::fixture()
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
                assert_eq!(http_result.observatory.grade_text(), "C- (45) · google.com");
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
        assert!(
            out.contains("Status: analyzed · F · 1 issue "),
            "expected one issue:\n{}",
            out
        );
        assert!(out.contains("Certificate expired"), "missing expiry issue:\n{}", out);
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
            out.contains(" · 3 issues"),
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
            scan_duration: Duration::from_millis(300),
            target_ip: "192.0.2.1".to_string(),
            https_failure: None,
        };
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(crate::scan::http::HttpResult {
                    ipv4_status: crate::scan::http::HttpStatus::Success,
                    ipv4_result: Some(http_data),
                    ipv6_result: None,
                    ipv6_status: crate::scan::http::HttpStatus::NotQueried,
                    observatory: ObservatoryOutcome::failed("example.com", "site down"),
                    lenses: crate::scan::http::Lenses::absent(),
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
        assert!(out.contains(" · 1 issue "), "missing issue count:\n{}", out);
        assert!(out.contains("Certificate expired"), "reason below the fold:\n{}", out);
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
        assert!(out.contains("PFS: yes · OCSP: not checked"), "{out}");
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

    fn http_state_with_policies(observatory: ObservatoryOutcome) -> AppState {
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
            }),
            cors: Some(CorsPolicy {
                access_control_allow_origin: Some("*".to_string()),
                access_control_allow_methods: vec![],
                access_control_allow_headers: vec![],
                access_control_allow_credentials: false,
            }),
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            scan_duration: Duration::from_millis(300),
            target_ip: "192.0.2.1".to_string(),
            https_failure: None,
        };
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(crate::scan::http::HttpResult {
                    ipv4_status: crate::scan::http::HttpStatus::Success,
                    ipv4_result: Some(http_data),
                    ipv6_result: None,
                    ipv6_status: crate::scan::http::HttpStatus::NotQueried,
                    observatory,
                    lenses: crate::scan::http::Lenses::absent(),
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

    /// The Security pane's HTTP section shows the HTTP pane's grade line, and Observatory's CSP and
    /// CORS results in place of the deleted strength labels.
    #[test]
    fn http_grade_csp_and_cors_show_observatory_results() {
        let state = http_state_with_policies(ObservatoryOutcome::Graded(google_com_result()));
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 80, false);
        assert!(out.contains("HTTP Grade: C- (45) · google.com"), "{out}");
        let google = google_com_result();
        let result_of = |name: &str| {
            google
                .tests
                .iter()
                .find(|t| t.name == name)
                .unwrap()
                .result
                .as_str()
                .to_string()
        };
        assert!(
            out.contains(&format!("CSP: {}", result_of("content-security-policy"))),
            "{out}"
        );
        assert!(
            out.contains(&format!("CORS: {}", result_of("cross-origin-resource-sharing"))),
            "{out}"
        );
        for enum_name in ["CMinus", "CspStrength"] {
            assert!(!out.contains(enum_name), "enum name {enum_name} leaked:\n{out}");
        }
        let buffer = crate::tui::testing::render_buffer(&SecurityPane::new(), &state, 100, 80, false);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "C- (45) · google.com"), theme::WARN);
    }

    /// The google.com case: the target request (`scan/1.0`) gets no HSTS, X-Frame-Options,
    /// X-Content-Type-Options or Referrer-Policy, while Observatory's retrieval passes HSTS and
    /// X-Frame-Options. Each row is Observatory's result alone; nothing reads the target's
    /// missing headers as a second verdict.
    #[test]
    fn header_rows_show_only_observatorys_verdict_when_the_target_request_saw_none() {
        let state = http_state_with_policies(ObservatoryOutcome::Graded(google_com_result()));
        let pane = SecurityPane::new();
        let out = crate::tui::testing::render_pane(&pane, &state, 120, 80, false);
        let buffer = crate::tui::testing::render_buffer(&pane, &state, 120, 80, false);
        for (row, result, color) in [
            ("HSTS: ", "hsts-implemented-max-age-at-least-six-months", theme::GOOD),
            ("X-Frame: ", "x-frame-options-sameorigin-or-deny", theme::GOOD),
            ("X-Content: ", "x-content-type-options-not-implemented", theme::BAD),
            ("Referrer: ", "referrer-policy-unsafe", theme::BAD),
        ] {
            assert!(out.contains(&format!("{row}{result}")), "{row}{result}:\n{out}");
            assert_eq!(crate::tui::testing::fg_of(&buffer, result), color, "{result}");
        }
        for second_signal in ["HSTS: no", "X-Frame: missing", "Missing", "Vulnerabilities", "wildcard"] {
            assert!(!out.contains(second_signal), "`{second_signal}`:\n{out}");
        }
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Zoomed).join("\n");
        assert!(
            !zoomed.contains("Missing") && !zoomed.contains("Vulnerabilities"),
            "{zoomed}"
        );
    }

    /// Observatory has no test for X-XSS-Protection or Permissions-Policy, so those rows carry no
    /// verdict: present or missing, the target's header reads `MUTED`, never `GOOD` or `WARN`.
    #[test]
    fn xss_protect_and_permissions_rows_are_muted_present_or_missing() {
        let pane = SecurityPane::new();
        let missing = http_state_with_policies(ObservatoryOutcome::Graded(google_com_result()));
        let out = crate::tui::testing::render_pane(&pane, &missing, 120, 80, false);
        assert!(
            out.contains("XSS-Protect: missing") && out.contains("Permissions: missing"),
            "{out}"
        );
        let buffer = crate::tui::testing::render_buffer(&pane, &missing, 120, 80, false);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "missing"), theme::MUTED);

        let present = http_state_with_policies(ObservatoryOutcome::Graded(google_com_result()));
        if let Some(mut scan) = present.scanners.get_mut("http")
            && let Some(ScanResult::Http(http)) = scan.result.as_mut()
            && let Some(data) = http.ipv4_result.as_mut()
        {
            data.security_headers.x_xss_protection = Some("1; mode=block".to_string());
            data.security_headers.permissions_policy = Some("geolocation=()".to_string());
        }
        let buffer = crate::tui::testing::render_buffer(&pane, &present, 120, 80, false);
        for value in ["1; mode=block", "geolocation=()"] {
            assert_eq!(crate::tui::testing::fg_of(&buffer, value), theme::MUTED, "{value}");
        }
    }

    /// With no grade there is no verdict: the rows show what the target sent, uncolored.
    #[test]
    fn header_rows_with_no_grade_show_the_targets_headers_muted() {
        let state = http_state_with_policies(ObservatoryOutcome::NotApplicable("IP address".to_string()));
        let pane = SecurityPane::new();
        let out = crate::tui::testing::render_pane(&pane, &state, 120, 80, false);
        for row in [
            "HSTS: missing",
            "X-Frame: missing",
            "X-Content: missing",
            "Referrer: missing",
        ] {
            assert!(out.contains(row), "{row}:\n{out}");
        }
        assert!(out.contains("CSP: default-src 'self'"), "{out}");
        let buffer = crate::tui::testing::render_buffer(&pane, &state, 120, 80, false);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "missing"), theme::MUTED);
    }

    #[test]
    fn security_pane_grade_line_for_hosts_with_no_grade_and_a_failed_url() {
        for (outcome, line) in [
            (
                ObservatoryOutcome::NotApplicable("IP address".to_string()),
                "HTTP Grade: n/a (IP address)",
            ),
            (
                ObservatoryOutcome::failed("example.com", "site down"),
                "HTTP Grade: none (site down) · example.com",
            ),
            (
                ObservatoryOutcome::failed("example.com", "HTTP 500"),
                "HTTP Grade: none (HTTP 500) · example.com",
            ),
        ] {
            let state = http_state_with_policies(outcome);
            let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 80, false);
            assert!(out.contains(line), "{line}:\n{out}");
            let buffer = crate::tui::testing::render_buffer(&SecurityPane::new(), &state, 100, 80, false);
            assert_eq!(
                crate::tui::testing::fg_of(&buffer, line.trim_start_matches("HTTP Grade: ")),
                theme::MUTED
            );
        }

        // The URL failed but the host graded: the HTTP section is the grade alone.
        let state = AppState::new("example.com".to_string());
        let mut result = crate::scan::http::HttpResult::new(
            ObservatoryOutcome::Graded(google_com_result()),
            crate::scan::http::Lenses::absent(),
        );
        result.ipv4_status = crate::scan::http::HttpStatus::Failed("operation timed out".to_string());
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: Some(ScanResult::Http(result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 80, false);
        assert!(out.contains("HTTP Grade: C- (45) · google.com"), "{out}");
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

    /// Item 11: a failed TLS scan says so once, in the header; no second `🔗 Status:` row.
    #[test]
    fn failed_tls_scan_renders_one_status_row() {
        let state = AppState::new("dead.example".to_string());
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: None,
                error: Some(eyre::eyre!("connection refused")),
                status: ScanStatus::Failed,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        let out = crate::tui::testing::render_pane(&SecurityPane::new(), &state, 100, 20, false);
        assert!(out.contains("Status: failed: connection refused"), "{out}");
        assert_eq!(out.matches("Status:").count(), 1, "{out}");
        assert!(!out.contains("🔗"), "{out}");
    }

    /// The grade and the issue count fold into the status row; the features header and the
    /// separate grade and issue rows are gone.
    #[test]
    fn status_row_carries_the_grade_and_issue_count() {
        let rows = crate::tui::testing::content_rows(
            &SecurityPane::new(),
            &state_with_tls(ScanStatus::Complete),
            80,
            Detail::Normal,
        );
        assert_eq!(rows[0].trim_end(), "🔒 Status: analyzed · A · 0 issues", "{rows:#?}");
        let text = rows.join("\n");
        for gone in ["Security Features", "📊 Grade:", "Issues:"] {
            assert!(!text.contains(gone), "{gone}:\n{text}");
        }
        let buffer = crate::tui::testing::render_buffer(
            &SecurityPane::new(),
            &state_with_tls(ScanStatus::Complete),
            80,
            20,
            false,
        );
        assert_eq!(crate::tui::testing::fg_of(&buffer, "0 issues"), theme::GOOD);
    }

    /// The certificate and the email posture are the cert and mail panes' now.
    #[test]
    fn certificate_and_email_rows_are_not_securitys() {
        let state = state_with_tls(ScanStatus::Complete);
        let mut dns_result = DnsResult::new();
        dns_result.email_security = Some(EmailSecurityAnalysis {
            spf_record: Some("v=spf1 -all".to_string()),
            dmarc_record: Some("v=DMARC1; p=reject".to_string()),
            ..EmailSecurityAnalysis::fixture()
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
        for detail in [Detail::Normal, Detail::Zoomed] {
            let text = crate::tui::testing::content_rows(&SecurityPane::new(), &state, 100, detail).join("\n");
            for gone in [
                "Email Security",
                "SPF:",
                "DMARC:",
                "DKIM:",
                "Certificate",
                "Issuer:",
                "Chain",
            ] {
                assert!(!text.contains(gone), "{detail:?} {gone}:\n{text}");
            }
        }
    }

    #[test]
    fn zoom_lists_the_supported_versions() {
        let state = state_with_tls(ScanStatus::Complete);
        if let Some(mut tls_state) = state.scanners.get_mut("tls")
            && let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_mut()
            && let Some(data) = tls_result.ipv4_result.as_mut()
        {
            data.supported_versions = vec![TlsVersion::V1_2, TlsVersion::V1_3];
        }
        let zoomed = crate::tui::testing::content_rows(&SecurityPane::new(), &state, 80, Detail::Zoomed).join("\n");
        assert!(zoomed.contains("Supported Versions: TLSv1.2, TLSv1.3"), "{zoomed}");
        let normal = crate::tui::testing::content_rows(&SecurityPane::new(), &state, 80, Detail::Normal).join("\n");
        assert!(!normal.contains("Supported Versions"), "{normal}");
    }
}
