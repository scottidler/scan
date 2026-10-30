use crate::scan::http::Lenses;
use crate::scan::http::disclosure::{SecurityTxt, SecurityTxtState};
use crate::scan::http::timing::HttpTiming;
use crate::scan::http::views::{CookieFlags, RouteHop, advertises_h3};
use crate::scan::lens::LensOutcome;
use crate::scan::observatory::{GradeLetter, ObservatoryOutcome, PRELOAD_UNAVAILABLE_NOTE};
use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use std::any::Any;
use std::time::Duration;

const HTTP_SUCCESS_STATUS_MIN: u16 = 200;
const HTTP_SUCCESS_STATUS_MAX: u16 = 299;
const HTTP_REDIRECT_STATUS_MIN: u16 = 300;
const HTTP_REDIRECT_STATUS_MAX: u16 = 399;
const HTTP_CLIENT_ERROR_STATUS_MIN: u16 = 400;
const HTTP_CLIENT_ERROR_STATUS_MAX: u16 = 499;
const HTTP_SERVER_ERROR_STATUS_MIN: u16 = 500;
const HTTP_SERVER_ERROR_STATUS_MAX: u16 = 599;
const RESPONSE_TIME_SLOW_THRESHOLD_MS: u128 = 500;
const GRADE_LABEL: &str = "🔒 Grade: ";
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

/// `<label>: <value>`, indented, with `missing` in place of a header that was not sent.
fn header_line(label: &str, value: Option<&str>) -> Line<'static> {
    let (text, color) = match value {
        Some(value) => (value.to_string(), theme::MUTED),
        None => ("missing".to_string(), theme::WARN),
    };
    Line::from(vec![
        Span::styled(format!("  {label}: "), Style::default().fg(theme::LABEL)),
        Span::styled(text, Style::default().fg(color)),
    ])
}

/// A lens's value, `none` in `MUTED` when there is nothing there, or `failed: <reason>` in `BAD`.
pub(crate) fn lens_value<T>(outcome: &LensOutcome<T>, present: impl FnOnce(&T) -> (String, Color)) -> Span<'static> {
    let (text, color) = match outcome {
        LensOutcome::Present(value) => present(value),
        LensOutcome::Absent => ("none".to_string(), theme::MUTED),
        LensOutcome::Failed(reason) => (format!("failed: {reason}"), theme::BAD),
    };
    Span::styled(text, Style::default().fg(color))
}

fn lens_row(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(label.to_string(), Style::default().fg(theme::LABEL)),
        value,
    ])
}

fn millis(duration: Duration) -> String {
    format!("{}ms", duration.as_millis())
}

/// `DNS: 3ms · Connect: 12ms · TLS: 20ms · TTFB: 45ms · Transfer: 2ms`; an IP host reads
/// `DNS: n/a`, a plain `http://` URL `TLS: n/a`.
pub(crate) fn timing_text(timing: &HttpTiming) -> String {
    let optional = |phase: Option<Duration>| phase.map_or_else(|| "n/a".to_string(), millis);
    format!(
        "DNS: {} · Connect: {} · TLS: {} · TTFB: {} · Transfer: {}",
        optional(timing.dns),
        millis(timing.connect),
        optional(timing.tls),
        millis(timing.ttfb),
        millis(timing.transfer)
    )
}

fn security_txt_text(txt: &SecurityTxt) -> (String, Color) {
    match &txt.state {
        SecurityTxtState::Present => (
            match &txt.contact {
                Some(contact) => format!("present · {contact}"),
                None => "present".to_string(),
            },
            theme::GOOD,
        ),
        SecurityTxtState::Expired => (
            format!("expired · Expires: {}", txt.expires.as_deref().unwrap_or_default()),
            theme::WARN,
        ),
        SecurityTxtState::Invalid(why) => (format!("invalid ({why})"), theme::BAD),
    }
}

fn route_text(hops: &[RouteHop]) -> String {
    hops.iter()
        .map(|hop| format!("{} {}", hop.url, hop.status))
        .collect::<Vec<_>>()
        .join(" → ")
}

fn cookie_line(cookie: &CookieFlags) -> Line<'static> {
    let flag = |set: bool, name: &str| if set { name.to_string() } else { format!("no {name}") };
    let same_site = cookie
        .same_site
        .map_or_else(|| "no SameSite".to_string(), |value| format!("SameSite={value}"));
    let flags = [
        flag(cookie.secure, "Secure"),
        flag(cookie.http_only, "HttpOnly"),
        same_site,
    ]
    .join(" · ");
    let color = if cookie.fully_flagged() { theme::GOOD } else { theme::WARN };
    Line::from(vec![
        Span::styled(format!("  {}: ", cookie.name), Style::default().fg(theme::LABEL)),
        Span::styled(flags, Style::default().fg(color)),
    ])
}

/// Zoomed only, before the header list: ALPN, the timing row, `alt-svc`, security.txt, the
/// `http://` route and the `auto` jar's cookie flags. The last three are read off the grade's
/// retrieval; with none, they say why the grade has none.
fn lens_lines(lenses: &Lenses, observatory: &ObservatoryOutcome) -> Vec<Line<'static>> {
    let mut lines = vec![lens_row(
        "🧬 ALPN: ",
        lens_value(&lenses.alpn, |protocol| {
            let color = if protocol == "h2" { theme::GOOD } else { theme::VALUE };
            (protocol.clone(), color)
        }),
    )];
    lines.push(match &lenses.timing {
        LensOutcome::Present(timing) => lens_row(
            "⏱ ",
            Span::styled(timing_text(timing), Style::default().fg(theme::VALUE)),
        ),
        LensOutcome::Absent => lens_row("⏱ Timing: ", Span::styled("none", Style::default().fg(theme::MUTED))),
        LensOutcome::Failed(reason) => lens_row(
            "⏱ Timing: ",
            Span::styled(format!("failed: {reason}"), Style::default().fg(theme::BAD)),
        ),
    });
    match &lenses.retrieval {
        Some(views) => lines.push(lens_row(
            "alt-svc: ",
            lens_value(&views.alt_svc, |value| {
                if advertises_h3(value) {
                    (format!("{value} (HTTP/3)"), theme::GOOD)
                } else {
                    (value.clone(), theme::VALUE)
                }
            }),
        )),
        None => lines.push(lens_row("alt-svc: ", no_retrieval(observatory))),
    }
    lines.push(lens_row(
        "security.txt: ",
        match &lenses.security_txt {
            LensOutcome::Absent => Span::styled("absent", Style::default().fg(theme::MUTED)),
            other => lens_value(other, security_txt_text),
        },
    ));
    match &lenses.retrieval {
        Some(views) => {
            lines.push(lens_row(
                "http:// route: ",
                lens_value(&views.http_route, |hops| (route_text(hops), theme::VALUE)),
            ));
            lines.push(lens_row(
                "Cookies: ",
                lens_value(&views.cookies, |cookies| {
                    (crate::tui::text::plural(cookies.len(), "cookie"), theme::VALUE)
                }),
            ));
            if let LensOutcome::Present(cookies) = &views.cookies {
                lines.extend(cookies.iter().map(cookie_line));
            }
        }
        None => {
            lines.push(lens_row("http:// route: ", no_retrieval(observatory)));
            lines.push(lens_row("Cookies: ", no_retrieval(observatory)));
        }
    }
    lines
}

/// Why a view of the retrieval has nothing: the host's grade was refused or failed.
fn no_retrieval(observatory: &ObservatoryOutcome) -> Span<'static> {
    match observatory {
        ObservatoryOutcome::NotApplicable(reason) => {
            Span::styled(format!("n/a ({reason})"), Style::default().fg(theme::MUTED))
        }
        ObservatoryOutcome::Failed(reason) => {
            Span::styled(format!("failed: {reason}"), Style::default().fg(theme::BAD))
        }
        ObservatoryOutcome::Graded(_) => Span::styled("failed: no retrieval", Style::default().fg(theme::BAD)),
    }
}

/// Zoomed only, after everything the grid shows: the request, the lenses, every security header
/// with its value, the CSP and CORS policies, and the caching headers.
fn zoomed_lines(
    data: &crate::scan::http::HttpData,
    lenses: &Lenses,
    observatory: &ObservatoryOutcome,
) -> Vec<Line<'static>> {
    let section = |title: &str| Line::from(Span::styled(title.to_string(), Style::default().fg(theme::VALUE)));
    let headers = &data.security_headers;
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("🔗 URL: ", Style::default().fg(theme::LABEL)),
            Span::styled(data.url.clone(), Style::default().fg(theme::VALUE)),
        ]),
        Line::from(vec![
            Span::styled("🎯 IP: ", Style::default().fg(theme::LABEL)),
            Span::styled(data.target_ip.clone(), Style::default().fg(theme::VALUE)),
        ]),
    ];
    lines.extend(lens_lines(lenses, observatory));
    lines.extend([
        Line::from(""),
        section("Security Headers"),
        header_line(
            "Strict-Transport-Security",
            headers.strict_transport_security.as_deref(),
        ),
        header_line("X-Frame-Options", headers.x_frame_options.as_deref()),
        header_line("X-Content-Type-Options", headers.x_content_type_options.as_deref()),
        header_line("X-XSS-Protection", headers.x_xss_protection.as_deref()),
        header_line("Referrer-Policy", headers.referrer_policy.as_deref()),
        header_line("Permissions-Policy", headers.permissions_policy.as_deref()),
        header_line(
            "Content-Security-Policy",
            data.csp.as_ref().map(|csp| csp.header_value.as_str()),
        ),
    ]);
    if let Some(cors) = &data.cors {
        lines.push(Line::from(""));
        lines.push(section("CORS"));
        lines.push(header_line("Allow-Origin", cors.access_control_allow_origin.as_deref()));
        let methods = cors.access_control_allow_methods.join(", ");
        lines.push(header_line(
            "Allow-Methods",
            (!methods.is_empty()).then_some(methods.as_str()),
        ));
        let allowed = cors.access_control_allow_headers.join(", ");
        lines.push(header_line(
            "Allow-Headers",
            (!allowed.is_empty()).then_some(allowed.as_str()),
        ));
        lines.push(header_line(
            "Allow-Credentials",
            Some(if cors.access_control_allow_credentials { "true" } else { "false" }),
        ));
    }
    let caching = &data.caching;
    lines.push(Line::from(""));
    lines.push(section("Caching"));
    lines.push(header_line("Cache-Control", caching.cache_control.as_deref()));
    lines.push(header_line("Expires", caching.expires.as_deref()));
    lines.push(header_line("ETag", caching.etag.as_deref()));
    lines.push(header_line("Last-Modified", caching.last_modified.as_deref()));
    lines
}

/// The grade line, `<label>C- (45) · google.com`, the grade colored by its letter (A good, B and C
/// warn, D and F bad), a missing preload list noted in `WARN`, and a host with no grade in `MUTED`.
pub(crate) fn grade_line(label: &str, observatory: &ObservatoryOutcome) -> Line<'static> {
    let color = match observatory {
        ObservatoryOutcome::Graded(result) => match result.grade {
            GradeLetter::APlus | GradeLetter::A | GradeLetter::AMinus => theme::GOOD,
            GradeLetter::BPlus | GradeLetter::B | GradeLetter::BMinus => theme::WARN,
            GradeLetter::CPlus | GradeLetter::C | GradeLetter::CMinus => theme::WARN,
            GradeLetter::DPlus | GradeLetter::D | GradeLetter::DMinus | GradeLetter::F => theme::BAD,
        },
        ObservatoryOutcome::NotApplicable(_) | ObservatoryOutcome::Failed(_) => theme::MUTED,
    };
    let mut spans = vec![
        Span::styled(label.to_string(), Style::default().fg(theme::LABEL)),
        Span::styled(observatory.grade_summary(), Style::default().fg(color)),
    ];
    if observatory.preload_unavailable() {
        spans.push(Span::styled(
            format!(" · {PRELOAD_UNAVAILABLE_NOTE}"),
            Style::default().fg(theme::WARN),
        ));
    }
    Line::from(spans)
}

/// Zoomed only: the 12 Observatory tests, each `name: result (modifier)`, colored by whether it
/// passed.
fn observatory_lines(observatory: &ObservatoryOutcome) -> Vec<Line<'static>> {
    let ObservatoryOutcome::Graded(result) = observatory else {
        return Vec::new();
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("Observatory tests (algorithm {})", result.algorithm_version),
            Style::default().fg(theme::VALUE),
        )),
    ];
    for test in &result.tests {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}: ", test.name), Style::default().fg(theme::LABEL)),
            Span::styled(
                format!("{} ({:+})", test.result.as_str(), test.score_modifier),
                Style::default().fg(if test.pass { theme::GOOD } else { theme::BAD }),
            ),
        ]));
    }
    lines
}

impl Pane for HttpPane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::http] content: width={} detail={:?}", width, detail);

        // Prepare content lines
        let mut lines = Vec::new();
        // Rows that wrap instead of being fit: the status header (it carries a failure reason).
        let mut wrapped = vec![0];

        // HTTP status header
        lines.push(Line::from(vec![
            Span::styled("🌐 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled("scanning...", Style::default().fg(theme::MUTED)),
        ]));

        // Empty line for spacing
        lines.push(Line::from(""));

        // Get HTTP results and render them
        if let Some(http_state) = state.scanners.get("http") {
            // Update header with current status
            let (label, label_color) = crate::tui::status_label(&http_state, "scanning...", "completed");
            lines[0] = Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::Http(http_result)) = &http_state.result {
                if let Some(primary_data) = http_result.get_primary_result() {
                    if let Some(reason) = &primary_data.https_failure {
                        wrapped.push(lines.len());
                        lines.push(Line::from(vec![
                            Span::styled("❗ ", Style::default().fg(theme::BAD)),
                            Span::styled(
                                format!("plain HTTP (HTTPS failed: {})", reason),
                                Style::default().fg(theme::BAD),
                            ),
                        ]));
                    }

                    // Status code
                    let status_color = match primary_data.status_code {
                        HTTP_SUCCESS_STATUS_MIN..=HTTP_SUCCESS_STATUS_MAX => theme::GOOD,
                        HTTP_REDIRECT_STATUS_MIN..=HTTP_REDIRECT_STATUS_MAX => theme::WARN,
                        HTTP_CLIENT_ERROR_STATUS_MIN..=HTTP_CLIENT_ERROR_STATUS_MAX => theme::BAD,
                        HTTP_SERVER_ERROR_STATUS_MIN..=HTTP_SERVER_ERROR_STATUS_MAX => theme::BAD,
                        _ => theme::MUTED,
                    };

                    lines.push(Line::from(vec![
                        Span::styled("📊 Status: ", Style::default().fg(theme::LABEL)),
                        Span::styled(
                            format!("{}", primary_data.status_code),
                            Style::default().fg(status_color),
                        ),
                    ]));

                    // Response time
                    let response_time_ms = primary_data.response_time.as_millis();
                    let time_color = if response_time_ms < RESPONSE_TIME_SLOW_THRESHOLD_MS {
                        theme::GOOD
                    } else {
                        theme::WARN
                    };

                    lines.push(Line::from(vec![
                        Span::styled("⏳ Time: ", Style::default().fg(theme::LABEL)),
                        Span::styled(format!("{}ms", response_time_ms), Style::default().fg(time_color)),
                    ]));

                    // Content type
                    if let Some(content_type) = &primary_data.content_type {
                        lines.push(Line::from(vec![
                            Span::styled("📄 Type: ", Style::default().fg(theme::LABEL)),
                            Span::styled(content_type.clone(), Style::default().fg(theme::WARN)),
                        ]));
                    }

                    // Content length
                    lines.push(Line::from(vec![
                        Span::styled("📏 Size: ", Style::default().fg(theme::LABEL)),
                        Span::styled(
                            format!("{} bytes", primary_data.content_length),
                            Style::default().fg(theme::GOOD),
                        ),
                    ]));

                    lines.push(grade_line(GRADE_LABEL, &http_result.observatory));

                    // Redirect chain - show details
                    if !primary_data.redirect_chain.is_empty() {
                        lines.push(Line::from(vec![
                            Span::styled("🔗 Redirects: ", Style::default().fg(theme::LABEL)),
                            Span::styled(
                                primary_data.redirect_chain.len().to_string(),
                                Style::default().fg(theme::ACCENT),
                            ),
                        ]));

                        // One row when it fits, so a second row per redirect does not push the issue
                        // names below the fold. A redirect too wide for one row gets a row per URL,
                        // so a long source URL cannot push its target off.
                        for redirect in &primary_data.redirect_chain {
                            let code =
                                Span::styled(format!("  {} ", redirect.status_code), Style::default().fg(theme::WARN));
                            let from = Span::styled(redirect.from.clone(), Style::default().fg(theme::MUTED));
                            let to = Span::styled(redirect.to.clone(), Style::default().fg(theme::VALUE));
                            let one_row = Line::from(vec![
                                code.clone(),
                                from.clone(),
                                Span::styled(" → ", Style::default().fg(theme::ACCENT)),
                                to.clone(),
                            ]);
                            if one_row.width() <= usize::from(width) {
                                lines.push(one_row);
                            } else {
                                lines.push(Line::from(vec![code, from]));
                                lines.push(Line::from(vec![
                                    Span::styled("    → ", Style::default().fg(theme::ACCENT)),
                                    to,
                                ]));
                            }
                        }
                    }

                    // Vulnerabilities - show total from all protocols
                    let all_vulnerabilities = http_result.get_all_vulnerabilities();
                    if !all_vulnerabilities.is_empty() {
                        lines.push(Line::from(vec![
                            Span::styled("❗ Issues: ", Style::default().fg(theme::LABEL)),
                            Span::styled(all_vulnerabilities.len().to_string(), Style::default().fg(theme::BAD)),
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
                            };

                            lines.push(Line::from(vec![
                                Span::styled("  • ", Style::default().fg(theme::BAD)),
                                Span::styled(vuln_text, Style::default().fg(theme::BAD)),
                            ]));
                        }
                    }

                    if detail == Detail::Zoomed {
                        lines.extend(zoomed_lines(
                            primary_data,
                            &http_result.lenses,
                            &http_result.observatory,
                        ));
                    }
                } else {
                    // No family got a target observation: the grade, if any, is all there is.
                    wrapped.push(lines.len());
                    lines.push(match http_result.target_failure() {
                        Some(reason) => Line::from(vec![
                            Span::styled("📊 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled(format!("failed: {reason}"), Style::default().fg(theme::BAD)),
                        ]),
                        None => Line::from(vec![
                            Span::styled("📊 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled("no address to request", Style::default().fg(theme::MUTED)),
                        ]),
                    });
                    lines.push(grade_line(GRADE_LABEL, &http_result.observatory));
                    if detail == Detail::Zoomed {
                        // The lenses do not need the URL to have answered.
                        lines.push(Line::from(""));
                        lines.extend(lens_lines(&http_result.lenses, &http_result.observatory));
                    }
                }
                if detail == Detail::Zoomed {
                    lines.extend(observatory_lines(&http_result.observatory));
                }
            } else if matches!(http_state.status, crate::types::ScanStatus::Failed) || http_state.error.is_some() {
                // The header carries the reason, failed or retrying after a failure; nothing is
                // being checked for the first time.
            } else {
                // No HTTP data available yet
                lines.push(Line::from(vec![
                    Span::styled("📊 Status: ", Style::default().fg(theme::LABEL)),
                    Span::styled("checking...", Style::default().fg(theme::MUTED)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("⏳ Time: ", Style::default().fg(theme::LABEL)),
                    Span::styled("measuring...", Style::default().fg(theme::MUTED)),
                ]));
            }
        } else {
            // No HTTP scanner available
            lines[0] = Line::from(vec![
                Span::styled("🌐 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled("unavailable", Style::default().fg(theme::BAD)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📊 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("HTTP scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        // Identifiers are fit to the width; the status header and the HTTPS failure reason wrap so
        // their cause stays readable.
        crate::tui::text::to_rows(lines, width, detail, &wrapped)
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

    use crate::scan::http::{CachingPolicy, HttpData, HttpResult, HttpStatus, SecurityHeaders};
    use crate::scan::observatory::tests::google_com_result;
    use crate::tui::testing::render_pane;
    use crate::types::{ScanState, ScanStatus};
    use std::time::{Duration, Instant};

    // The HTTP pane at 200x55: a quarter of the width, the 35% middle row.
    const LIVE_PANE_WIDTH: u16 = 50;
    const LIVE_PANE_HEIGHT: u16 = 19;

    fn http_data(url: &str, https_failure: Option<&str>) -> HttpData {
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
            scan_duration: Duration::from_millis(50),
            target_ip: "192.0.2.1".to_string(),
            https_failure: https_failure.map(String::from),
        }
    }

    fn state_with(data: Option<HttpData>, observatory: ObservatoryOutcome, ipv4_status: HttpStatus) -> AppState {
        let state = AppState::new("example.com".to_string());
        let mut result = HttpResult::new(observatory, crate::scan::http::Lenses::absent());
        result.ipv4_status = ipv4_status;
        result.ipv4_result = data;
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

    /// A succeeded target observation beside google.com's `C-` 45 grade.
    fn state_with_http(data: HttpData) -> AppState {
        state_with(
            Some(data),
            ObservatoryOutcome::Graded(google_com_result()),
            HttpStatus::Success,
        )
    }

    fn state_with_grade(observatory: ObservatoryOutcome) -> AppState {
        state_with(
            Some(http_data("https://example.com/", None)),
            observatory,
            HttpStatus::Success,
        )
    }

    #[test]
    fn render_plain_http_fallback_names_https_failure() {
        let reason = "invalid peer certificate: UnknownIssuer";
        let state = state_with_http(http_data("http://example.com/", Some(reason)));
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
        assert!(
            !out.contains("Grade: F"),
            "the fallback no longer forces an F:\n{}",
            out
        );
    }

    /// The grade is the host's: it reads the same whichever family's observation is primary.
    #[test]
    fn google_fixture_shows_the_grade_score_and_host_in_warn_and_zoom_lists_12_tests() {
        let state = state_with_http(http_data("https://google.com/", None));
        let buffer =
            crate::tui::testing::render_buffer(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(out.contains("Grade: C- (45) · google.com"), "{out}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "C- (45) · google.com"), theme::WARN);
        assert!(
            !out.contains("preload list unavailable"),
            "a loaded list adds no note:\n{out}"
        );

        let zoomed = crate::tui::testing::content_rows(&HttpPane::new(), &state, 120, Detail::Zoomed).join("\n");
        let google = google_com_result();
        assert_eq!(google.tests.len(), 12);
        for test in &google.tests {
            assert!(
                zoomed.contains(&format!(
                    "{}: {} ({:+})",
                    test.name,
                    test.result.as_str(),
                    test.score_modifier
                )),
                "{}:\n{zoomed}",
                test.name
            );
        }
        let normal = crate::tui::testing::content_rows(&HttpPane::new(), &state, 120, Detail::Normal).join("\n");
        assert!(!normal.contains("content-security-policy"), "{normal}");
    }

    #[test]
    fn every_grade_letter_is_colored_by_its_letter() {
        use GradeLetter::*;
        let cases = [
            (APlus, theme::GOOD),
            (A, theme::GOOD),
            (AMinus, theme::GOOD),
            (BPlus, theme::WARN),
            (B, theme::WARN),
            (BMinus, theme::WARN),
            (CPlus, theme::WARN),
            (C, theme::WARN),
            (CMinus, theme::WARN),
            (DPlus, theme::BAD),
            (D, theme::BAD),
            (DMinus, theme::BAD),
            (F, theme::BAD),
        ];
        for (letter, color) in cases {
            let mut result = google_com_result();
            result.grade = letter;
            let state = state_with_grade(ObservatoryOutcome::Graded(result));
            let buffer =
                crate::tui::testing::render_buffer(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
            let needle = format!("{} (45) · google.com", letter.as_str());
            assert_eq!(crate::tui::testing::fg_of(&buffer, &needle), color, "{needle}");
        }
    }

    #[test]
    fn hosts_with_no_grade_read_why_in_muted() {
        for (outcome, line) in [
            (
                ObservatoryOutcome::NotApplicable("IP address".to_string()),
                "Grade: n/a (IP address)",
            ),
            (
                ObservatoryOutcome::NotApplicable("not a public hostname".to_string()),
                "Grade: n/a (not a public hostname)",
            ),
            (
                ObservatoryOutcome::Failed("site down".to_string()),
                "Grade: none (site down)",
            ),
            (
                ObservatoryOutcome::Failed("HTTP 500".to_string()),
                "Grade: none (HTTP 500)",
            ),
        ] {
            let state = state_with_grade(outcome);
            let buffer =
                crate::tui::testing::render_buffer(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
            let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
            assert!(out.contains(line), "{line}:\n{out}");
            let value = line.trim_start_matches("Grade: ");
            assert_eq!(crate::tui::testing::fg_of(&buffer, value), theme::MUTED, "{line}");
        }
    }

    #[test]
    fn a_missing_preload_list_is_noted_in_warn_on_the_grade_line() {
        let mut result = google_com_result();
        result.preload_available = false;
        let state = state_with_grade(ObservatoryOutcome::Graded(result));
        let buffer = crate::tui::testing::render_buffer(&HttpPane::new(), &state, 80, LIVE_PANE_HEIGHT, false);
        let out = render_pane(&HttpPane::new(), &state, 80, LIVE_PANE_HEIGHT, false);
        assert!(
            out.contains("Grade: C- (45) · google.com · preload list unavailable"),
            "{out}"
        );
        assert_eq!(
            crate::tui::testing::fg_of(&buffer, "· preload list unavailable"),
            theme::WARN
        );
    }

    /// The URL fails while the host grades: both lines show, each with its own reason.
    #[test]
    fn a_failed_url_and_a_working_grade_show_together() {
        let state = state_with(
            None,
            ObservatoryOutcome::Graded(google_com_result()),
            HttpStatus::Failed("operation timed out".to_string()),
        );
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(out.contains("failed: IPv4: operation timed out"), "{out}");
        assert!(out.contains("Grade: C- (45) · google.com"), "{out}");
    }

    /// The grade fails while the URL works: the target block is intact and the grade line says why.
    #[test]
    fn a_working_url_and_a_failed_grade_show_together() {
        let state = state_with_grade(ObservatoryOutcome::Failed("site down".to_string()));
        let out = render_pane(&HttpPane::new(), &state, LIVE_PANE_WIDTH, LIVE_PANE_HEIGHT, false);
        assert!(out.contains("Status: 200"), "{out}");
        assert!(out.contains("Grade: none (site down)"), "{out}");
    }

    #[test]
    fn render_https_success_has_no_fallback_line() {
        let state = state_with_http(http_data("https://example.com/", None));
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
        let mut data = http_data("https://example.com/", None);
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
        let mut data = http_data("https://example.com/", None);
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

    const ALL_ISSUES: [(crate::scan::http::HttpVulnerability, &str); 4] = [
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
    ];

    fn render_redirects_and_issues(redirects: &[(&str, &str)], issues: usize) -> String {
        let mut data = http_data("https://www.tatari.tv/", None);
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
    /// do not push issue names below the fold.
    #[test]
    fn redirects_that_fit_take_one_row_and_every_issue_name_stays_visible() {
        type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, usize);
        let cases: [Case; 3] = [
            (
                "1 redirect, 4 issues",
                vec![("http://tatari.tv/", "https://tatari.tv/")],
                4,
            ),
            (
                "2 redirects, 3 issues",
                vec![
                    ("http://tatari.tv/", "https://tatari.tv/"),
                    ("https://tatari.tv/", "https://www.tatari.tv/"),
                ],
                3,
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
        let mut data = http_data("https://example.com/", None);
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

    #[test]
    fn zoomed_content_shows_header_values_policies_and_caching() {
        use crate::scan::http::{CorsPolicy, CspPolicy};
        use crate::tui::pane::Detail;
        let mut data = http_data("https://example.com/", None);
        data.security_headers.strict_transport_security = Some("max-age=31536000; includeSubDomains".to_string());
        data.csp = Some(CspPolicy {
            header_value: "default-src 'self'; script-src 'self' https://cdn.example.com".to_string(),
            directives: Default::default(),
            issues: vec![],
        });
        data.cors = Some(CorsPolicy {
            access_control_allow_origin: Some("https://app.example.com".to_string()),
            access_control_allow_methods: vec!["GET".to_string(), "POST".to_string()],
            access_control_allow_headers: vec![],
            access_control_allow_credentials: false,
            issues: vec![],
        });
        data.caching.cache_control = Some("private, max-age=0".to_string());
        let state = state_with_http(data);
        let pane = HttpPane::new();
        let zoomed = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Zoomed).join("\n");
        for expected in [
            "URL: https://example.com/",
            "IP: 192.0.2.1",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "X-Frame-Options: missing",
            "Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com",
            "Allow-Origin: https://app.example.com",
            "Allow-Methods: GET, POST",
            "Allow-Headers: missing",
            "Cache-Control: private, max-age=0",
            "ETag: missing",
        ] {
            assert!(zoomed.contains(expected), "{expected}:\n{zoomed}");
        }
        let normal = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Normal).join("\n");
        assert!(!normal.contains("Cache-Control"), "{normal}");
    }

    fn running_state(error: Option<eyre::Report>) -> AppState {
        let state = AppState::new("example.com:8443".to_string());
        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: None,
                error,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    /// Item 6: a scanner retrying after a failure shows the failure, never first-run placeholders
    /// under it.
    #[test]
    fn retrying_after_a_failure_shows_no_placeholders() {
        let state = running_state(Some(eyre::eyre!("operation timed out")));
        let out = render_pane(&HttpPane::new(), &state, 100, 20, false);
        assert!(out.contains("failed: operation timed out"), "{out}");
        for placeholder in ["checking...", "measuring...", "detecting..."] {
            assert!(!out.contains(placeholder), "{placeholder}:\n{out}");
        }
    }

    /// The first run still says what it is doing; the `Server:` row is gone, since nothing ever
    /// collects it.
    #[test]
    fn first_run_shows_placeholders_but_no_server_row() {
        let out = render_pane(&HttpPane::new(), &running_state(None), 100, 20, false);
        assert!(out.contains("checking..."), "{out}");
        assert!(out.contains("measuring..."), "{out}");
        assert!(!out.contains("Server:"), "{out}");
        assert!(!out.contains("detecting..."), "{out}");
    }

    fn timing(dns: Option<u64>, tls: Option<u64>) -> HttpTiming {
        HttpTiming {
            dns: dns.map(Duration::from_millis),
            connect: Duration::from_millis(12),
            tls: tls.map(Duration::from_millis),
            ttfb: Duration::from_millis(45),
            transfer: Duration::from_millis(2),
            status: 200,
        }
    }

    #[test]
    fn timing_reads_each_phase_and_n_a_for_the_phases_a_url_skips() {
        assert_eq!(
            timing_text(&timing(Some(3), Some(20))),
            "DNS: 3ms · Connect: 12ms · TLS: 20ms · TTFB: 45ms · Transfer: 2ms"
        );
        assert_eq!(
            timing_text(&timing(Some(3), None)),
            "DNS: 3ms · Connect: 12ms · TLS: n/a · TTFB: 45ms · Transfer: 2ms"
        );
        assert!(timing_text(&timing(None, Some(1))).starts_with("DNS: n/a · "));
    }

    fn state_with_lenses(lenses: Lenses, observatory: ObservatoryOutcome, data: Option<HttpData>) -> AppState {
        let state = state_with(data.clone(), observatory.clone(), HttpStatus::Success);
        let mut result = HttpResult::new(observatory, lenses);
        result.ipv4_status = if data.is_some() {
            HttpStatus::Success
        } else {
            HttpStatus::Failed("operation timed out".to_string())
        };
        result.ipv4_result = data;
        state.scanners.get_mut("http").unwrap().result = Some(ScanResult::Http(result));
        state
    }

    fn zoomed(state: &AppState) -> String {
        crate::tui::testing::content_rows(&HttpPane::new(), state, 160, Detail::Zoomed).join("\n")
    }

    /// Each lens row shows its value, `none`, or `failed: <reason>`, zoomed only.
    #[test]
    fn lens_rows_show_a_value_none_or_failed_in_zoom_only() {
        use crate::scan::http::disclosure::SecurityTxt;
        let present = Lenses {
            timing: LensOutcome::Present(timing(Some(3), Some(20))),
            alpn: LensOutcome::Present("h2".to_string()),
            security_txt: LensOutcome::Present(SecurityTxt {
                state: SecurityTxtState::Present,
                contact: Some("mailto:sec@example.com".to_string()),
                expires: Some("2099-01-01T00:00:00Z".to_string()),
            }),
            retrieval: None,
        };
        let state = state_with_lenses(
            present,
            ObservatoryOutcome::Graded(google_com_result()),
            Some(http_data("https://example.com/", None)),
        );
        let out = zoomed(&state);
        for expected in [
            "ALPN: h2",
            "DNS: 3ms · Connect: 12ms · TLS: 20ms · TTFB: 45ms · Transfer: 2ms",
            "security.txt: present · mailto:sec@example.com",
        ] {
            assert!(out.contains(expected), "{expected}:\n{out}");
        }
        let normal = crate::tui::testing::content_rows(&HttpPane::new(), &state, 160, Detail::Normal).join("\n");
        assert!(!normal.contains("ALPN:"), "{normal}");

        let missing = Lenses {
            timing: LensOutcome::Failed("timed out".to_string()),
            alpn: LensOutcome::Absent,
            security_txt: LensOutcome::Absent,
            retrieval: None,
        };
        let out = zoomed(&state_with_lenses(
            missing,
            ObservatoryOutcome::Failed("site down".to_string()),
            Some(http_data("https://example.com/", None)),
        ));
        for expected in [
            "ALPN: none",
            "Timing: failed: timed out",
            "security.txt: absent",
            "alt-svc: failed: site down",
            "http:// route: failed: site down",
            "Cookies: failed: site down",
        ] {
            assert!(out.contains(expected), "{expected}:\n{out}");
        }
    }

    #[test]
    fn expired_and_invalid_security_txt_say_so() {
        use crate::scan::http::disclosure::SecurityTxt;
        for (state, text) in [
            (
                SecurityTxtState::Expired,
                "security.txt: expired · Expires: 2020-01-01T00:00:00Z",
            ),
            (
                SecurityTxtState::Invalid("no Contact:".to_string()),
                "security.txt: invalid (no Contact:)",
            ),
        ] {
            let lenses = Lenses {
                security_txt: LensOutcome::Present(SecurityTxt {
                    state,
                    contact: None,
                    expires: Some("2020-01-01T00:00:00Z".to_string()),
                }),
                ..Lenses::absent()
            };
            let out = zoomed(&state_with_lenses(
                lenses,
                ObservatoryOutcome::Graded(google_com_result()),
                Some(http_data("https://example.com/", None)),
            ));
            assert!(out.contains(text), "{text}:\n{out}");
        }
    }

    /// The URL failed, the lenses did not: zoom still shows them, and a host Observatory refuses
    /// reads `n/a` for the retrieval's views.
    #[test]
    fn lenses_show_when_the_url_failed_and_views_read_n_a_for_a_refused_host() {
        let lenses = Lenses {
            alpn: LensOutcome::Present("http/1.1".to_string()),
            ..Lenses::absent()
        };
        let out = zoomed(&state_with_lenses(
            lenses,
            ObservatoryOutcome::NotApplicable("IP address".to_string()),
            None,
        ));
        assert!(out.contains("failed: IPv4: operation timed out"), "{out}");
        assert!(out.contains("ALPN: http/1.1"), "{out}");
        assert!(out.contains("alt-svc: n/a (IP address)"), "{out}");
        assert!(out.contains("Cookies: n/a (IP address)"), "{out}");
    }

    #[test]
    fn cookie_rows_list_each_flag_and_color_by_whether_all_are_set() {
        use crate::scan::http::views::RetrievalViews;
        let cookie = |name: &str, all: bool| CookieFlags {
            name: name.to_string(),
            secure: all,
            http_only: all,
            same_site: all.then_some("strict"),
        };
        let lenses = Lenses {
            retrieval: Some(RetrievalViews {
                alt_svc: LensOutcome::Absent,
                http_route: LensOutcome::Absent,
                cookies: LensOutcome::Present(vec![cookie("SID", true), cookie("pref", false)]),
            }),
            ..Lenses::absent()
        };
        let state = state_with_lenses(
            lenses,
            ObservatoryOutcome::Graded(google_com_result()),
            Some(http_data("https://example.com/", None)),
        );
        let out = zoomed(&state);
        assert!(out.contains("Cookies: 2 cookies"), "{out}");
        assert!(out.contains("SID: Secure · HttpOnly · SameSite=strict"), "{out}");
        assert!(out.contains("pref: no Secure · no HttpOnly · no SameSite"), "{out}");
        assert!(out.contains("alt-svc: none"), "{out}");
        assert!(out.contains("http:// route: none"), "{out}");
        let lines = HttpPane::new().content(&state, 160, Detail::Zoomed);
        let color_of = |text: &str| {
            lines
                .iter()
                .flat_map(|line| line.spans.iter())
                .find(|span| span.content == text)
                .and_then(|span| span.style.fg)
        };
        assert_eq!(color_of("Secure · HttpOnly · SameSite=strict"), Some(theme::GOOD));
        assert_eq!(color_of("no Secure · no HttpOnly · no SameSite"), Some(theme::WARN));
    }
}
