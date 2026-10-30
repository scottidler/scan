// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (scan and analyzeScan in src/scanner/index.js,
// src/constants.js, onlyIfWorse in src/analyzer/utils.js).

//! A port of MDN HTTP Observatory's analyzers and grader: the 12 tests run over one
//! [`Retrieval`], scored and graded exactly as Observatory's algorithm version 6 does.

pub mod charts;
pub mod coep;
pub mod cookies;
pub mod coop;
pub mod corp;
pub mod cors;
pub mod csp;
pub mod grade;
pub mod headers;
#[cfg(test)]
mod helpers;
pub mod hsts;
pub mod html;
pub mod js;
#[cfg(test)]
mod live;
pub mod redirection;
pub mod referrer;
pub mod retriever;
pub mod session;
pub mod sri;
pub mod structured;
pub mod types;
pub mod xcto;
pub mod xfo;

pub use grade::GradeLetter;
pub use hsts::HstsPreload;
pub use retriever::{Retrieval, Retriever};
pub use sri::RegistrableDomain;
pub use types::Expectation;

/// Observatory's `ALGORITHM_VERSION`; the live API reports the same.
pub const ALGORITHM_VERSION: u32 = 6;

/// One test's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    /// The test's name, e.g. `content-security-policy`.
    pub name: &'static str,
    pub result: Expectation,
    pub score_modifier: i32,
    pub pass: bool,
}

/// A graded host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryResult {
    pub host: String,
    pub algorithm_version: u32,
    /// Floored at 0, not capped: bonuses can lift it past 100.
    pub score: i32,
    pub grade: GradeLetter,
    /// In Observatory's order (`ALL_TESTS`).
    pub tests: Vec<TestResult>,
    /// The `auto` response came over a verified certificate chain.
    pub verified: bool,
    /// The HSTS preload list was available; without it every host reads as not preloaded.
    pub preload_available: bool,
}

/// What a scan's Observatory run came to, independent of the target observation beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservatoryOutcome {
    Graded(ObservatoryResult),
    /// Observatory refuses the host (an IP address, a name with no dot): no grade, never F.
    NotApplicable(String),
    /// No grade for `host`: site down, an unexpected status, a deadline, or a list the run needed.
    Failed {
        host: String,
        reason: String,
    },
}

/// The grade line's note when the HSTS preload list could not be loaded.
pub const PRELOAD_UNAVAILABLE_NOTE: &str = "preload list unavailable";

impl ObservatoryOutcome {
    /// No grade for `host`, for `reason`.
    pub fn failed(host: &str, reason: &str) -> Self {
        ObservatoryOutcome::Failed {
            host: host.to_string(),
            reason: reason.to_string(),
        }
    }

    /// The outcome of `observe` for `host`: an [`AnalyzeError`] is a failure, worded as it displays.
    pub fn from_analysis(host: &str, analysis: Result<ObservatoryResult, AnalyzeError>) -> Self {
        match analysis {
            Ok(result) => ObservatoryOutcome::Graded(result),
            Err(error) => ObservatoryOutcome::failed(host, &error.to_string()),
        }
    }

    /// The grade line after its `Grade: ` label, without the preload note: `C- (45) · google.com`,
    /// `n/a (IP address)`, `none (site down) · example.com`. A grade, or its absence, is a fact
    /// about a host, so the line names the host; a refused target (an IP address) has none to name.
    pub fn grade_summary(&self) -> String {
        match self {
            ObservatoryOutcome::Graded(result) => format!("{} ({}) · {}", result.grade, result.score, result.host),
            ObservatoryOutcome::NotApplicable(reason) => format!("n/a ({reason})"),
            ObservatoryOutcome::Failed { host, reason } => format!("none ({reason}) · {host}"),
        }
    }

    /// A graded run whose HSTS preload list was missing: every host read as not preloaded.
    pub fn preload_unavailable(&self) -> bool {
        matches!(self, ObservatoryOutcome::Graded(result) if !result.preload_available)
    }

    /// [`grade_summary`](Self::grade_summary) plus ` · preload list unavailable` when the list was
    /// missing.
    pub fn grade_text(&self) -> String {
        let mut text = self.grade_summary();
        if self.preload_unavailable() {
            text.push_str(&format!(" · {PRELOAD_UNAVAILABLE_NOTE}"));
        }
        text
    }
}

/// The host Observatory grades for a target host, or the reason it refuses it, as the API's
/// `validHostname` does (`src/api/v2/utils.js`): a trailing dot is dropped, an IP address and a
/// name with no dot get no grade. The API's TLD-list check is not ported: a name under an
/// unknown TLD is retrieved and reads as a site that is down.
pub fn eligible_host(host: &str) -> Result<String, String> {
    let host = host.trim().trim_end_matches('.');
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
        return Err("IP address".to_string());
    }
    if host.is_empty() || !host.contains('.') {
        return Err("not a public hostname".to_string());
    }
    Ok(host.to_string())
}

/// Why a retrieval gets no grade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalyzeError {
    /// Neither session got a response (`SiteIsDownError`).
    SiteIsDown,
    /// The `auto` status is not 2xx, 3xx, 401 or 403 (`UnexpectedStatusCodeError`).
    UnexpectedStatusCode(u16),
    /// A redirect hop's host is not a valid site; upstream's `Site.fromSiteString` throws.
    InvalidSite(String),
    /// A full-URL `<script src>` does not parse; upstream's `new URL` throws.
    InvalidScriptSrc(String),
}

impl std::fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalyzeError::SiteIsDown => write!(f, "site down"),
            AnalyzeError::UnexpectedStatusCode(status) => write!(f, "HTTP {status}"),
            AnalyzeError::InvalidSite(why) => write!(f, "invalid redirect host: {why}"),
            AnalyzeError::InvalidScriptSrc(why) => write!(f, "invalid script src: {why}"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

/// `onlyIfWorse`: `new` when it ranks worse than `old` in `order` (best first), else `old`. A
/// result missing from `order` ranks best, as `indexOf` gives it -1.
pub(crate) fn only_if_worse(new: Expectation, old: Option<Expectation>, order: &[Expectation]) -> Expectation {
    let rank = |e: Expectation| order.iter().position(|o| *o == e).map_or(-1, |i| i as i64);
    match old {
        None => new,
        Some(old) if rank(new) > rank(old) => new,
        Some(old) => old,
    }
}

fn test_result(name: &'static str, result: Expectation, pass: bool) -> TestResult {
    TestResult {
        name,
        result,
        score_modifier: grade::score_modifier(result),
        pass,
    }
}

/// The public suffix lists a scan reads: the ICANN section alone (`tldts` defaults, the SRI test)
/// and ICANN plus private (tough-cookie's jar rules).
#[derive(Clone, Copy)]
pub struct SuffixLists<'a> {
    pub icann: &'a (dyn RegistrableDomain + Sync),
    pub all: &'a (dyn RegistrableDomain + Sync),
}

/// `scan(site)`: retrieve, then [`analyze`].
pub async fn observe(
    retriever: &Retriever,
    host: &str,
    preload: &HstsPreload,
    lists: SuffixLists<'_>,
) -> Result<ObservatoryResult, AnalyzeError> {
    observe_retrieval(retriever, host, preload, lists).await.0
}

/// [`observe`], keeping the [`Retrieval`] the grade was computed from, for the lenses that read
/// it. The retrieval is `None` only for a host that makes no URL.
pub async fn observe_retrieval(
    retriever: &Retriever,
    host: &str,
    preload: &HstsPreload,
    lists: SuffixLists<'_>,
) -> (Result<ObservatoryResult, AnalyzeError>, Option<Retrieval>) {
    log::debug!("[observatory] observe: host={}", host);
    let retrieval = match retriever.retrieve(host, lists.all).await {
        Ok(retrieval) => retrieval,
        Err(error) => return (Err(error), None),
    };
    let result = analyze(&retrieval, preload, lists.icann);
    log::debug!(
        "[observatory] observe: host={} outcome={:?}",
        host,
        result.as_ref().map(|r| (r.score, r.grade))
    );
    (result, Some(retrieval))
}

/// `analyzeScan`: the status gate, the 12 tests, the score and the grade.
pub fn analyze(
    retrieval: &Retrieval,
    preload: &HstsPreload,
    domains: &dyn RegistrableDomain,
) -> Result<ObservatoryResult, AnalyzeError> {
    log::debug!(
        "[observatory] analyze: host={} http={} https={} cors={} cookies={} preload_available={}",
        retrieval.host,
        retrieval.http.is_some(),
        retrieval.https.is_some(),
        retrieval.cors.is_some(),
        retrieval.cookies.len(),
        preload.is_available()
    );
    let Some(auto) = retrieval.auto_response() else {
        log::debug!(
            "[observatory] analyze: host={} no auto response: site down",
            retrieval.host
        );
        return Err(AnalyzeError::SiteIsDown);
    };
    let status = auto.status;
    if status < 200 || (status >= 400 && status != 401 && status != 403) {
        log::debug!(
            "[observatory] analyze: host={} unexpected status {}",
            retrieval.host,
            status
        );
        return Err(AnalyzeError::UnexpectedStatusCode(status));
    }

    let csp = csp::content_security_policy_test(retrieval);
    let cookies = cookies::cookies_test(retrieval, preload);
    let coep = coep::cross_origin_embedder_policy_test(retrieval);
    let coop = coop::cross_origin_opener_policy_test(retrieval);
    let cors = cors::cross_origin_resource_sharing_test(retrieval);
    let redirection = redirection::redirection_test(retrieval, preload)?;
    let referrer = referrer::referrer_policy_test(retrieval);
    let hsts = hsts::strict_transport_security_test(retrieval, preload);
    let sri = sri::subresource_integrity_test(retrieval, domains)?;
    let xcto = xcto::x_content_type_options_test(retrieval);
    let xfo = xfo::x_frame_options_test(retrieval);
    let corp = corp::cross_origin_resource_policy_test(retrieval);

    let tests = vec![
        test_result("content-security-policy", csp.result, csp.pass),
        test_result("cookies", cookies.result, cookies.pass),
        test_result("cross-origin-embedder-policy", coep.result, coep.pass),
        test_result("cross-origin-opener-policy", coop.result, coop.pass),
        test_result("cross-origin-resource-sharing", cors.result, cors.pass),
        test_result("redirection", redirection.result, redirection.pass),
        test_result("referrer-policy", referrer.result, referrer.pass),
        test_result("strict-transport-security", hsts.result, hsts.pass),
        test_result("subresource-integrity", sri.result, sri.pass),
        test_result("x-content-type-options", xcto.result, xcto.pass),
        test_result("x-frame-options", xfo.result, xfo.pass),
        test_result("cross-origin-resource-policy", corp.result, corp.pass),
    ];
    let (score, grade) = grade::grade(&tests);
    log::debug!(
        "[observatory] analyze: host={} score={} grade={} passed={}",
        retrieval.host,
        score,
        grade,
        tests.iter().filter(|t| t.pass).count()
    );
    Ok(ObservatoryResult {
        host: retrieval.host.clone(),
        algorithm_version: ALGORITHM_VERSION,
        score,
        grade,
        tests,
        verified: auto.verified,
        preload_available: preload.is_available(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan::observatory::cookies::{Cookie, SameSite};
    use crate::scan::observatory::headers::{HeaderValue, Headers};
    use crate::scan::observatory::helpers::empty_requests;
    use crate::scan::observatory::html::{MetaTags, parse_http_equiv};
    use crate::scan::observatory::retriever::{RedirectEntry, Response, Session};
    use crate::scan::observatory::sri::tests::suffixes;
    use serde_json::Value;
    use url::Url;

    const GOOGLE: &str = include_str!("../../tests/fixtures/observatory/google-com.json");

    fn headers(json: &Value) -> Headers {
        let mut headers = Headers::new();
        for (name, value) in json.as_object().unwrap() {
            let value = match value {
                Value::Array(items) => {
                    HeaderValue::List(items.iter().map(|v| v.as_str().unwrap().to_string()).collect())
                }
                other => HeaderValue::Single(other.as_str().unwrap().to_string()),
            };
            headers.set(name, value);
        }
        headers
    }

    fn session(start: &str, response: &Value, redirects: &Value) -> Session {
        Session {
            url: Url::parse(start).unwrap(),
            response: Response {
                status: response["status"].as_u64().unwrap() as u16,
                verified: response["verified"].as_bool().unwrap(),
                headers: headers(&response["headers"]),
            },
            redirects: redirects
                .as_array()
                .unwrap()
                .iter()
                .map(|hop| RedirectEntry {
                    url: Url::parse(hop["url"].as_str().unwrap()).unwrap(),
                    status: hop["status"].as_u64().unwrap() as u16,
                })
                .collect(),
        }
    }

    /// A cookie from tough-cookie's `serializeSync()`: absent flags are false, absent `sameSite`
    /// unset.
    fn jar_cookie(json: &Value) -> Cookie {
        Cookie {
            key: json["key"].as_str().unwrap().to_string(),
            value: json["value"].as_str().unwrap_or_default().to_string(),
            // `serializeSync` writes a parsed date as ISO 8601 and an absent one as `Infinity`.
            expires: json["expires"]
                .as_str()
                .and_then(|date| chrono::DateTime::parse_from_rfc3339(date).ok())
                .map(std::time::SystemTime::from),
            max_age: json["maxAge"].as_f64(),
            domain: json["domain"].as_str().map(str::to_string),
            path: json["path"].as_str().map(str::to_string),
            secure: json["secure"].as_bool().unwrap_or(false),
            http_only: json["httpOnly"].as_bool().unwrap_or(false),
            same_site: match json["sameSite"].as_str() {
                Some("strict") => Some(SameSite::Strict),
                Some("lax") => Some(SameSite::Lax),
                Some("none") => Some(SameSite::None),
                _ => None,
            },
            host_only: json["hostOnly"].as_bool(),
        }
    }

    /// The Phase 0b capture of google.com (API scan 132240279) as a [`Retrieval`]. The meta tags
    /// come from parsing the captured body, not from the capture's own parse.
    fn google_retrieval(fixture: &Value) -> Retrieval {
        let responses = &fixture["responses"];
        let host = fixture["host"].as_str().unwrap();
        let body = responses["https"]["data"].as_str().unwrap().to_string();
        Retrieval {
            host: host.to_string(),
            http: Some(session(
                &format!("http://{host}/"),
                &responses["http"],
                &responses["http_redirects"],
            )),
            https: Some(session(
                &format!("https://{host}/"),
                &responses["https"],
                &responses["https_redirects"],
            )),
            cors: None,
            cookies: fixture["jar"]["cookies"]
                .as_array()
                .unwrap()
                .iter()
                .map(jar_cookie)
                .collect(),
            meta: parse_http_equiv(&body),
            auto_body: Some(body),
        }
    }

    /// google.com as the API graded it (`C-` 45), for the panes' fixtures.
    pub(crate) fn google_com_result() -> ObservatoryResult {
        let fixture: Value = serde_json::from_str(GOOGLE).unwrap();
        analyze(
            &google_retrieval(&fixture),
            &HstsPreload::from_entries(Vec::new()),
            &suffixes(),
        )
        .unwrap()
    }

    #[test]
    fn google_com_grades_c_minus_45_with_the_apis_12_results() {
        let fixture: Value = serde_json::from_str(GOOGLE).unwrap();
        assert_eq!(fixture["auto_session"], "https");
        assert!(fixture["responses"]["cors"].is_null());
        let retrieval = google_retrieval(&fixture);

        let result = analyze(&retrieval, &HstsPreload::from_entries(Vec::new()), &suffixes()).unwrap();

        let api = &fixture["api_result"];
        let cli = &fixture["observatory_cli_result"]["tests"];
        assert_eq!(result.grade.as_str(), "C-");
        assert_eq!(result.score, 45);
        assert_eq!(result.grade.as_str(), api["scan"]["grade"]);
        assert_eq!(i64::from(result.score), api["scan"]["score"].as_i64().unwrap());
        assert_eq!(
            u64::from(result.algorithm_version),
            api["scan"]["algorithm_version"].as_u64().unwrap()
        );
        assert_eq!(result.tests.len(), 12);
        for test in &result.tests {
            let expected = &api["tests"][test.name];
            assert_eq!(test.result.as_str(), expected["result"], "{}", test.name);
            assert_eq!(
                i64::from(test.score_modifier),
                expected["score_modifier"].as_i64().unwrap(),
                "{}",
                test.name
            );
            // The API nulls `pass` for not-applicable results (display only); the CLI keeps it.
            assert_eq!(test.pass, cli[test.name]["pass"].as_bool().unwrap(), "{}", test.name);
        }
        let passed = result.tests.iter().filter(|t| t.pass).count() as u64;
        assert_eq!(passed, api["scan"]["tests_passed"].as_u64().unwrap());
        assert!(result.verified);
        assert!(result.preload_available);
    }

    /// The meta tags parsed from google.com's body equal the ones Observatory's parser recorded.
    #[test]
    fn google_com_meta_tags_match_the_capture() {
        let fixture: Value = serde_json::from_str(GOOGLE).unwrap();
        let captured = &fixture["responses"]["auto"]["http_equiv"];
        let strings = |v: &Value| -> Vec<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        };
        let expected = MetaTags {
            content_security_policy: strings(&captured["content-security-policy"]),
            referrer_policy: strings(&captured["referrer-policy"]),
        };
        assert_eq!(google_retrieval(&fixture).meta, expected);
    }

    /// Each of google.com's `Set-Cookie` lines parses to the jar's flags.
    #[test]
    fn google_com_set_cookie_lines_parse_to_the_jar() {
        let fixture: Value = serde_json::from_str(GOOGLE).unwrap();
        let lines = fixture["responses"]["https"]["headers"]["set-cookie"]
            .as_array()
            .unwrap();
        let jar = google_retrieval(&fixture).cookies;
        assert_eq!(lines.len(), jar.len());
        for (line, stored) in lines.iter().zip(&jar) {
            let parsed = Cookie::parse(line.as_str().unwrap()).unwrap();
            assert_eq!(
                (
                    &parsed.key,
                    parsed.secure,
                    parsed.http_only,
                    parsed.same_site,
                    &parsed.domain
                ),
                (
                    &stored.key,
                    stored.secure,
                    stored.http_only,
                    stored.same_site,
                    &stored.domain
                ),
            );
        }
    }

    #[test]
    fn no_response_is_site_down() {
        let mut retrieval = empty_requests(None);
        retrieval.http = None;
        retrieval.https = None;
        assert_eq!(
            analyze(&retrieval, &HstsPreload::unavailable(), &suffixes()),
            Err(AnalyzeError::SiteIsDown)
        );
    }

    /// 2xx, 3xx, 401 and 403 grade; 1xx and every other 4xx/5xx do not.
    #[test]
    fn status_gate_admits_2xx_3xx_401_403() {
        for (status, graded) in [
            (200, true),
            (302, true),
            (401, true),
            (403, true),
            (404, false),
            (500, false),
            (101, false),
        ] {
            let mut retrieval = empty_requests(None);
            retrieval.https.as_mut().unwrap().response.status = status;
            let result = analyze(&retrieval, &HstsPreload::unavailable(), &suffixes());
            if graded {
                assert!(result.is_ok(), "{status}");
            } else {
                assert_eq!(result, Err(AnalyzeError::UnexpectedStatusCode(status)));
            }
        }
    }

    /// With no preload list the score is what a list lacking the host gives, flagged unavailable.
    #[test]
    fn unavailable_preload_scores_as_not_preloaded() {
        let retrieval = empty_requests(None);
        let with_list = analyze(&retrieval, &HstsPreload::from_entries(Vec::new()), &suffixes()).unwrap();
        let without = analyze(&retrieval, &HstsPreload::unavailable(), &suffixes()).unwrap();
        assert_eq!(with_list.score, without.score);
        assert_eq!(with_list.tests, without.tests);
        assert!(!without.preload_available);
    }

    #[test]
    fn grade_text_names_the_grade_score_and_host() {
        let graded = ObservatoryOutcome::Graded(google_com_result());
        assert_eq!(graded.grade_text(), "C- (45) · google.com");
        let mut no_list = google_com_result();
        no_list.preload_available = false;
        assert_eq!(
            ObservatoryOutcome::Graded(no_list).grade_text(),
            "C- (45) · google.com · preload list unavailable"
        );
        assert_eq!(
            ObservatoryOutcome::NotApplicable("IP address".into()).grade_text(),
            "n/a (IP address)"
        );
        assert_eq!(
            ObservatoryOutcome::from_analysis("example.com", Err(AnalyzeError::SiteIsDown)).grade_text(),
            "none (site down) · example.com"
        );
        assert_eq!(
            ObservatoryOutcome::from_analysis("example.com", Err(AnalyzeError::UnexpectedStatusCode(500))).grade_text(),
            "none (HTTP 500) · example.com"
        );
    }

    #[test]
    fn eligible_host_refuses_ips_and_dotless_names() {
        assert_eq!(eligible_host("google.com").as_deref(), Ok("google.com"));
        assert_eq!(eligible_host("www.tatari.tv.").as_deref(), Ok("www.tatari.tv"));
        for ip in ["127.0.0.1", "2606:4700:4700::1111", "[2606:4700:4700::1111]"] {
            assert_eq!(eligible_host(ip), Err("IP address".to_string()), "{ip}");
        }
        for name in ["localhost", "intranet", ""] {
            assert_eq!(
                eligible_host(name),
                Err("not a public hostname".to_string()),
                "{name:?}"
            );
        }
    }

    #[test]
    fn only_if_worse_keeps_the_worse_of_two() {
        let order = [
            Expectation::CookiesWithoutSecureFlag,
            Expectation::CookiesSessionWithoutSecureFlag,
        ];
        assert_eq!(
            only_if_worse(order[0], Some(order[1]), &order),
            Expectation::CookiesSessionWithoutSecureFlag
        );
        assert_eq!(
            only_if_worse(order[1], Some(order[0]), &order),
            Expectation::CookiesSessionWithoutSecureFlag
        );
        assert_eq!(only_if_worse(order[0], None, &order), order[0]);
        assert_eq!(
            only_if_worse(Expectation::CookiesNotFound, Some(order[0]), &order),
            order[0]
        );
    }
}
