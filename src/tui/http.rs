use crate::tui::pane::{Pane, create_block};
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget, Wrap},
};
use std::any::Any;

const HTTP_SUCCESS_STATUS_MIN: u16 = 200;
const HTTP_SUCCESS_STATUS_MAX: u16 = 299;
const HTTP_REDIRECT_STATUS_MIN: u16 = 300;
const HTTP_REDIRECT_STATUS_MAX: u16 = 399;
const HTTP_CLIENT_ERROR_STATUS_MIN: u16 = 400;
const HTTP_CLIENT_ERROR_STATUS_MAX: u16 = 499;
const HTTP_SERVER_ERROR_STATUS_MIN: u16 = 500;
const HTTP_SERVER_ERROR_STATUS_MAX: u16 = 599;
const RESPONSE_TIME_FAST_THRESHOLD_MS: u128 = 100;
const RESPONSE_TIME_SLOW_THRESHOLD_MS: u128 = 500;
const MIN_HTTP_PANE_WIDTH: u16 = 30;
const MIN_HTTP_PANE_HEIGHT: u16 = 12;

/// HTTP pane displays web server response information
pub struct HttpPane {
    title: &'static str,
    id: &'static str,
}

impl HttpPane {
    pub fn new() -> Self {
        log::debug!("[tui::http] new:");
        Self {
            title: "http",
            id: "http",
        }
    }
}

impl Default for HttpPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for HttpPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!(
            "[tui::http] render: area={}x{} focused={}",
            area.width,
            area.height,
            focused
        );

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let mut wrapped = vec![0];

        // HTTP status header
        lines.push(Line::from(vec![
            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled("scanning...", Style::default().fg(Color::Gray)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get HTTP results and render them
        if let Some(http_state) = state.scanners.get("http") {
            // Update header with current status
            let (label, label_color) = crate::tui::status_label(&http_state, "scanning...", "completed");
            lines[0] = Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::Http(http_result)) = &http_state.result {
                if let Some(primary_data) = http_result.get_primary_result() {
                    if let Some(reason) = &primary_data.https_failure {
                        wrapped.push(lines.len());
                        lines.push(Line::from(vec![
                            Span::styled("⚠️  ", Style::default().fg(Color::Red)),
                            Span::styled(
                                format!("plain HTTP (HTTPS failed: {})", reason),
                                Style::default().fg(Color::Red),
                            ),
                        ]));
                    }

                    // Status code
                    let status_color = match primary_data.status_code {
                        HTTP_SUCCESS_STATUS_MIN..=HTTP_SUCCESS_STATUS_MAX => Color::Green,
                        HTTP_REDIRECT_STATUS_MIN..=HTTP_REDIRECT_STATUS_MAX => Color::Yellow,
                        HTTP_CLIENT_ERROR_STATUS_MIN..=HTTP_CLIENT_ERROR_STATUS_MAX => Color::Red,
                        HTTP_SERVER_ERROR_STATUS_MIN..=HTTP_SERVER_ERROR_STATUS_MAX => Color::Magenta,
                        _ => Color::Gray,
                    };

                    lines.push(Line::from(vec![
                        Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{}", primary_data.status_code),
                            Style::default().fg(status_color),
                        ),
                    ]));

                    // Response time
                    let response_time_ms = primary_data.response_time.as_millis();
                    let time_color = if response_time_ms < RESPONSE_TIME_FAST_THRESHOLD_MS {
                        Color::Green
                    } else if response_time_ms < RESPONSE_TIME_SLOW_THRESHOLD_MS {
                        Color::Yellow
                    } else {
                        Color::Red
                    };

                    lines.push(Line::from(vec![
                        Span::styled("⏱️  Time: ", Style::default().fg(Color::White)),
                        Span::styled(format!("{}ms", response_time_ms), Style::default().fg(time_color)),
                    ]));

                    // Content type
                    if let Some(content_type) = &primary_data.content_type {
                        lines.push(Line::from(vec![
                            Span::styled("📄 Type: ", Style::default().fg(Color::White)),
                            Span::styled(content_type.clone(), Style::default().fg(Color::Yellow)),
                        ]));
                    }

                    // Content length
                    lines.push(Line::from(vec![
                        Span::styled("📏 Size: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{} bytes", primary_data.content_length),
                            Style::default().fg(Color::Green),
                        ),
                    ]));

                    // Grade of the primary result: the same result whose fallback line shows above.
                    let security_grade = &primary_data.security_grade;
                    let grade_color = match security_grade {
                        crate::scan::http::SecurityGrade::APlus | crate::scan::http::SecurityGrade::A => Color::Green,
                        crate::scan::http::SecurityGrade::B | crate::scan::http::SecurityGrade::C => Color::Yellow,
                        crate::scan::http::SecurityGrade::D | crate::scan::http::SecurityGrade::F => Color::Red,
                    };

                    lines.push(Line::from(vec![
                        Span::styled("🔒 Grade: ", Style::default().fg(Color::White)),
                        Span::styled(security_grade.as_str(), Style::default().fg(grade_color)),
                    ]));

                    // Redirect chain - show details
                    if !primary_data.redirect_chain.is_empty() {
                        lines.push(Line::from(vec![
                            Span::styled("🔗 Redirects: ", Style::default().fg(Color::White)),
                            Span::styled(
                                primary_data.redirect_chain.len().to_string(),
                                Style::default().fg(Color::Magenta),
                            ),
                        ]));

                        // One row when it fits: the pane does not scroll, so a second row per
                        // redirect pushes issue names off the bottom. A redirect too wide for one
                        // row gets a row per URL, so a long source URL cannot push its target off.
                        for redirect in &primary_data.redirect_chain {
                            let code = Span::styled(
                                format!("  {} ", redirect.status_code),
                                Style::default().fg(Color::Yellow),
                            );
                            let from = Span::styled(redirect.from.clone(), Style::default().fg(Color::Gray));
                            let to = Span::styled(redirect.to.clone(), Style::default().fg(Color::Cyan));
                            let one_row = Line::from(vec![
                                code.clone(),
                                from.clone(),
                                Span::styled(" → ", Style::default().fg(Color::Magenta)),
                                to.clone(),
                            ]);
                            if one_row.width() <= usize::from(inner_area.width) {
                                lines.push(one_row);
                            } else {
                                lines.push(Line::from(vec![code, from]));
                                lines.push(Line::from(vec![
                                    Span::styled("    → ", Style::default().fg(Color::Magenta)),
                                    to,
                                ]));
                            }
                        }
                    }

                    // Vulnerabilities - show total from all protocols
                    let all_vulnerabilities = http_result.get_all_vulnerabilities();
                    if !all_vulnerabilities.is_empty() {
                        lines.push(Line::from(vec![
                            Span::styled("⚠️  Issues: ", Style::default().fg(Color::White)),
                            Span::styled(all_vulnerabilities.len().to_string(), Style::default().fg(Color::Red)),
                        ]));

                        // Show each vulnerability
                        for vulnerability in &all_vulnerabilities {
                            let vuln_text = match vulnerability {
                                crate::scan::http::HttpVulnerability::MissingHsts => "Missing HSTS",
                                crate::scan::http::HttpVulnerability::MissingXFrameOptions => "Missing X-Frame-Options",
                                crate::scan::http::HttpVulnerability::MissingXContentTypeOptions => {
                                    "Missing X-Content-Type-Options"
                                }
                                crate::scan::http::HttpVulnerability::MissingCsp => "Missing CSP",
                                crate::scan::http::HttpVulnerability::WeakCsp => "Weak CSP",
                                crate::scan::http::HttpVulnerability::InsecureCors => "Insecure CORS",
                                crate::scan::http::HttpVulnerability::InformationDisclosure => "Information Disclosure",
                            };

                            lines.push(Line::from(vec![
                                Span::styled("  • ", Style::default().fg(Color::Red)),
                                Span::styled(vuln_text, Style::default().fg(Color::Red)),
                            ]));
                        }
                    }
                } else {
                    // HTTP scan failed for all protocols
                    lines.push(Line::from(vec![
                        Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                        Span::styled("all protocols failed", Style::default().fg(Color::Red)),
                    ]));
                }
            } else if matches!(http_state.status, crate::types::ScanStatus::Failed) {
                // The header carries the reason; nothing is still being checked.
            } else {
                // No HTTP data available yet
                lines.push(Line::from(vec![
                    Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                    Span::styled("checking...", Style::default().fg(Color::Gray)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("⏱️  Time: ", Style::default().fg(Color::White)),
                    Span::styled("measuring...", Style::default().fg(Color::Gray)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("🖥️  Server: ", Style::default().fg(Color::White)),
                    Span::styled("detecting...", Style::default().fg(Color::Gray)),
                ]));
            }
        } else {
            // No HTTP scanner available
            lines[0] = Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📊 Status: ", Style::default().fg(Color::White)),
                Span::styled("HTTP scanner not available", Style::default().fg(Color::Red)),
            ]));
        }

        // Identifiers are fit to the width; the status header and the HTTPS failure reason wrap so
        // their cause stays readable.
        let lines = crate::tui::text::fit_lines_except(lines, inner_area.width, &wrapped);
        let paragraph = Paragraph::new(lines)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false });
        paragraph.render(inner_area, frame.buffer_mut());
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_HTTP_PANE_WIDTH, MIN_HTTP_PANE_HEIGHT) // Minimum width and height for HTTP information
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

    use crate::scan::http::{CachingPolicy, HttpData, HttpResult, HttpStatus, SecurityGrade, SecurityHeaders};
    use crate::tui::testing::render_pane;
    use crate::types::{ScanState, ScanStatus};
    use std::time::{Duration, Instant};

    // The HTTP pane at 200x55: a quarter of the width, the 35% middle row.
    const LIVE_PANE_WIDTH: u16 = 50;
    const LIVE_PANE_HEIGHT: u16 = 19;

    fn http_data(url: &str, https_failure: Option<&str>, grade: SecurityGrade) -> HttpData {
        HttpData {
            url: url.to_string(),
            status_code: 200,
            response_time: Duration::from_millis(40),
            content_length: 2,
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
            caching: CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![],
            security_grade: grade,
            scan_duration: Duration::from_millis(50),
            target_ip: "192.0.2.1".to_string(),
            https_failure: https_failure.map(String::from),
        }
    }

    fn state_with_http(data: HttpData) -> AppState {
        let state = AppState::new("example.com".to_string());
        let mut result = HttpResult::new();
        result.ipv4_status = HttpStatus::Success(data.security_grade.clone());
        result.ipv4_result = Some(data);
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
        state
    }

    #[test]
    fn render_plain_http_fallback_names_https_failure_and_grade_f() {
        let reason = "invalid peer certificate: UnknownIssuer";
        let state = state_with_http(http_data("http://example.com/", Some(reason), SecurityGrade::F));
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        let flat: String = out
            .lines()
            .map(|l| l.trim_matches(['│', ' ']))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            out.contains("plain HTTP (HTTPS failed:"),
            "fallback not shown:\n{}",
            out
        );
        assert!(flat.contains("UnknownIssuer"), "reason not visible:\n{}", out);
        assert!(out.contains("Grade: F"), "fallback must grade F:\n{}", out);
    }

    #[test]
    fn render_grade_comes_from_primary_result_not_best_family() {
        let reason = "invalid peer certificate: UnknownIssuer";
        let state = state_with_http(http_data("http://example.com/", Some(reason), SecurityGrade::F));
        if let Some(mut http_state) = state.scanners.get_mut("http")
            && let Some(ScanResult::Http(result)) = http_state.result.as_mut()
        {
            let ipv6 = http_data("https://example.com/", None, SecurityGrade::A);
            result.ipv6_status = HttpStatus::Success(ipv6.security_grade.clone());
            result.ipv6_result = Some(ipv6);
        }
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(out.contains("HTTPS failed"), "fallback not shown:\n{}", out);
        assert!(out.contains("Grade: F"), "primary (fallback) grade must show:\n{}", out);
        assert!(
            !out.contains("Grade: A"),
            "other family's grade must not show:\n{}",
            out
        );
    }

    #[test]
    fn render_a_plus_grade_as_a_plus() {
        let state = state_with_http(http_data("https://example.com/", None, SecurityGrade::APlus));
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(out.contains("Grade: A+"), "A+ label missing:\n{}", out);
        assert!(!out.contains("APlus"), "enum Debug leaked:\n{}", out);
    }

    #[test]
    fn render_https_success_has_no_fallback_line() {
        let state = state_with_http(http_data("https://example.com/", None, SecurityGrade::A));
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(!out.contains("HTTPS failed"), "unexpected fallback line:\n{}", out);
    }

    #[test]
    fn test_http_pane_creation() {
        let pane = HttpPane::new();
        assert_eq!(pane.title(), "http");
        assert_eq!(pane.id(), "http");
        assert_eq!(pane.min_size(), (MIN_HTTP_PANE_WIDTH, MIN_HTTP_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    const LONG_CONTENT_TYPE: &str = "application/vnd.example.a-very-long-vendor-media-type+json; charset=utf-8";
    const LONG_REDIRECT_TO: &str = "https://www.a-very-long-host-name.example.com/a/long/path/to/the/landing/page";

    #[test]
    fn long_content_type_is_fit_with_ellipsis_in_narrow_terminals() {
        let mut data = http_data("https://example.com/", None, SecurityGrade::A);
        data.content_type = Some(LONG_CONTENT_TYPE.to_string());
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &HttpPane::new(),
            &state_with_http(data),
            1,
            1,
            &format!("📄 Type: {LONG_CONTENT_TYPE}"),
        );
    }

    #[test]
    fn long_redirect_target_url_is_fit_on_its_own_row() {
        let mut data = http_data("https://example.com/", None, SecurityGrade::A);
        data.redirect_chain = vec![crate::scan::http::RedirectInfo {
            from: "http://example.com/".to_string(),
            to: LONG_REDIRECT_TO.to_string(),
            status_code: 301,
        }];
        // The middle row is too short at 80x24 to reach the redirect rows; 108x40 shows them.
        let (width, height) = crate::tui::testing::dashboard_pane_size(1, 1, 108, 40);
        let expected = crate::tui::testing::expected_clip(&format!("    → {LONG_REDIRECT_TO}"), width - 2);
        let out = render_pane(&HttpPane::new(), &state_with_http(data), width, height, false);
        assert!(
            out.contains("301 http://example.com/"),
            "redirect source row missing:\n{out}"
        );
        assert!(out.contains(&format!("│{expected}│")), "`{expected}` missing:\n{out}");
    }

    const ALL_ISSUES: [(crate::scan::http::HttpVulnerability, &str); 7] = [
        (crate::scan::http::HttpVulnerability::MissingHsts, "Missing HSTS"),
        (
            crate::scan::http::HttpVulnerability::MissingXFrameOptions,
            "Missing X-Frame-Options",
        ),
        (
            crate::scan::http::HttpVulnerability::MissingXContentTypeOptions,
            "Missing X-Content-Type-Options",
        ),
        (crate::scan::http::HttpVulnerability::MissingCsp, "Missing CSP"),
        (crate::scan::http::HttpVulnerability::WeakCsp, "Weak CSP"),
        (crate::scan::http::HttpVulnerability::InsecureCors, "Insecure CORS"),
        (
            crate::scan::http::HttpVulnerability::InformationDisclosure,
            "Information Disclosure",
        ),
    ];

    fn render_redirects_and_issues(redirects: &[(&str, &str)], issues: usize) -> String {
        let mut data = http_data("https://www.tatari.tv/", None, SecurityGrade::C);
        data.redirect_chain = redirects
            .iter()
            .map(|(from, to)| crate::scan::http::RedirectInfo {
                from: from.to_string(),
                to: to.to_string(),
                status_code: 301,
            })
            .collect();
        data.vulnerabilities = ALL_ISSUES[..issues].iter().map(|(v, _)| v.clone()).collect();
        render_pane(
            &HttpPane::new(),
            &state_with_http(data),
            LIVE_PANE_WIDTH,
            LIVE_PANE_HEIGHT,
            false,
        )
    }

    /// Audit round 1: a redirect that fits the pane takes one row, so at 200x55 the redirect rows
    /// do not push issue names off the bottom of the pane, which does not scroll.
    #[test]
    fn redirects_that_fit_take_one_row_and_every_issue_name_stays_visible() {
        type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, usize);
        let cases: [Case; 3] = [
            (
                "1 redirect, 7 issues",
                vec![("http://tatari.tv/", "https://tatari.tv/")],
                7,
            ),
            (
                "2 redirects, 5 issues",
                vec![
                    ("http://tatari.tv/", "https://tatari.tv/"),
                    ("https://tatari.tv/", "https://www.tatari.tv/"),
                ],
                5,
            ),
            (
                "4 short redirects, 4 issues",
                vec![
                    ("http://x/a", "http://x/b"),
                    ("http://x/b", "http://x/c"),
                    ("http://x/c", "http://x/d"),
                    ("http://x/d", "http://x/e"),
                ],
                4,
            ),
        ];
        for (name, redirects, issues) in cases {
            let out = render_redirects_and_issues(&redirects, issues);
            assert!(
                out.contains(&format!("301 {} → {}", redirects[0].0, redirects[0].1)),
                "{name}: redirect not on one row:\n{out}"
            );
            for (_, issue) in &ALL_ISSUES[..issues] {
                assert!(out.contains(issue), "{name}: `{issue}` not visible:\n{out}");
            }
        }
    }

    #[test]
    fn long_multibyte_redirect_url_is_fit_by_display_width() {
        let to = format!("https://ex.com/{}", "ü".repeat(40));
        let mut data = http_data("https://example.com/", None, SecurityGrade::A);
        data.redirect_chain = vec![crate::scan::http::RedirectInfo {
            from: "http://ex.com/".to_string(),
            to: to.clone(),
            status_code: 308,
        }];
        let out = render_pane(
            &HttpPane::new(),
            &state_with_http(data),
            LIVE_PANE_WIDTH,
            LIVE_PANE_HEIGHT,
            false,
        );
        let expected = crate::tui::testing::expected_clip(&format!("    → {to}"), LIVE_PANE_WIDTH - 2);
        assert!(out.contains(&format!("│{expected}│")), "`{expected}` missing:\n{out}");
    }
}
