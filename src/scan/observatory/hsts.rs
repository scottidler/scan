// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/hsts.js,
// src/retrieve-hsts.js, src/analyzer/tests/strict-transport-security.js,
// test/strict-transport-security.test.js).

//! The `strict-transport-security` test, the HSTS preload lookup it and the redirection test
//! share, and the Chromium preload list behind it.

use super::headers::{STRICT_TRANSPORT_SECURITY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;
use crate::scan::cache::{CachedSource, FETCH_TIMEOUT, Refreshing, default_cache_dir};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// `HSTS_URL`: Chromium's list, the file Observatory's build writes `conf/hsts-preload.json` from.
pub const PRELOAD_URL: &str =
    "https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json";
/// The raw Chromium file, cached under `~/.cache/scan`.
pub const PRELOAD_CACHE_FILE: &str = "transport_security_state_static.json";

/// One preload list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreloadEntry {
    /// The entry's `mode` is `force-https`.
    pub force_https: bool,
    pub include_subdomains: bool,
}

/// The Chromium HSTS preload list, by lowercase name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HstsPreload {
    entries: HashMap<String, PreloadEntry>,
    /// `false` when no copy of the list could be had: every lookup misses, and the result says so.
    available: bool,
}

impl HstsPreload {
    /// A list holding `entries`.
    pub fn from_entries(entries: Vec<(String, PreloadEntry)>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
            available: true,
        }
    }

    /// No list at all: every host reads as not preloaded.
    pub fn unavailable() -> Self {
        Self::default()
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    /// `isHstsPreloaded`: an exact `force-https` entry, else the nearest parent label whose entry is
    /// `force-https` with `include_subdomains`; a parent entry that does not qualify does not stop
    /// the walk.
    pub fn lookup(&self, host: &str) -> Option<PreloadEntry> {
        let host = js::trim(host).to_lowercase();
        if let Some(entry) = self.entries.get(&host).filter(|entry| entry.force_https) {
            return Some(*entry);
        }
        let labels: Vec<&str> = host.split('.').collect();
        (1..labels.len())
            .map(|skip| labels[skip..].join("."))
            .find_map(|parent| {
                self.entries
                    .get(&parent)
                    .filter(|entry| entry.force_https && entry.include_subdomains)
                    .copied()
            })
    }
}

/// One entry of Chromium's `entries` array; every other field is ignored.
#[derive(Deserialize)]
struct RawEntry {
    name: String,
    #[serde(default)]
    mode: Option<serde_json::Value>,
    #[serde(default)]
    include_subdomains: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawList {
    entries: Vec<RawEntry>,
}

/// JavaScript truthiness, for `!!entry.include_subdomains`.
fn truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => true,
    }
}

/// `removeJsonComments`: `/\/\/.*$/gm`, everything from `//` to the end of its line, inside
/// strings too (`.` stops at `\n`, `\r`, U+2028 and U+2029).
fn remove_json_comments(text: &str) -> String {
    let is_terminator = |c: char| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}');
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("//") {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        rest = &after[after.find(is_terminator).unwrap_or(after.len())..];
    }
    out.push_str(rest);
    out
}

/// `retrieveAndStoreHsts`'s parse: comments stripped, each name trimmed and lowercased, a later
/// duplicate winning, `mode` kept only as "is `force-https`", `include_subdomains` by truthiness.
pub fn parse_chromium(text: &str) -> eyre::Result<HstsPreload> {
    let list: RawList = serde_json::from_str(&remove_json_comments(text))
        .map_err(|e| eyre::eyre!("HSTS preload list does not parse: {e}"))?;
    log::debug!("[observatory::hsts] parse_chromium: entries={}", list.entries.len());
    Ok(HstsPreload::from_entries(
        list.entries
            .into_iter()
            .map(|entry| {
                (
                    js::trim(&entry.name).to_lowercase(),
                    PreloadEntry {
                        force_https: entry.mode.as_ref().and_then(|m| m.as_str()) == Some("force-https"),
                        include_subdomains: entry.include_subdomains.as_ref().is_some_and(truthy),
                    },
                )
            })
            .collect(),
    ))
}

/// Where the preload list comes from, and the parsed copy held between scans: one per
/// `HttpScanner`. A copy older than 24h is refreshed at the next scan; a failed refresh keeps it.
#[derive(Debug)]
pub struct PreloadSource {
    pub client: Client,
    pub url: String,
    /// `None` when the platform has no cache dir: every refresh fetches.
    pub cache_dir: Option<PathBuf>,
    pub fetch_timeout: Duration,
    held: Refreshing<HstsPreload>,
}

impl PreloadSource {
    /// Chromium's list, cached in `~/.cache/scan`.
    pub fn new(client: Client) -> Self {
        Self::from_url(client, PRELOAD_URL.to_string(), default_cache_dir())
    }

    pub fn from_url(client: Client, url: String, cache_dir: Option<PathBuf>) -> Self {
        Self {
            client,
            url,
            cache_dir,
            fetch_timeout: FETCH_TIMEOUT,
            held: Refreshing::new(),
        }
    }

    /// The list to grade with. With no copy at all (no cache, fetch failed), the unavailable list:
    /// every host reads as not preloaded and the result says so. Never an empty list by accident.
    pub async fn get(&self, deadline: tokio::time::Instant) -> Arc<HstsPreload> {
        let source = CachedSource {
            client: &self.client,
            url: &self.url,
            cache_dir: self.cache_dir.as_deref(),
            file_name: PRELOAD_CACHE_FILE,
            fetch_timeout: self.fetch_timeout,
        };
        match self.held.get(&source, deadline, parse_chromium).await {
            Ok(list) => list,
            Err(e) => {
                log::warn!(
                    "[observatory::hsts] preload_list_unavailable: url={} error={:#}",
                    self.url,
                    e
                );
                Arc::new(HstsPreload::unavailable())
            }
        }
    }
}

/// HSTS's own `max-age` floor: six months, rounded down the way most sites set it.
const SIX_MONTHS: f64 = 15_552_000.0;

/// What the `strict-transport-security` test found.
#[derive(Debug, Clone, PartialEq)]
pub struct HstsOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
    pub include_subdomains: bool,
    /// `NaN` for a `max-age=` that is not a number, as upstream's `parseInt` gives.
    pub max_age: Option<f64>,
    pub preload: bool,
    pub preloaded: bool,
}

/// `strictTransportSecurityTest`.
pub fn strict_transport_security_test(retrieval: &Retrieval, preload: &HstsPreload) -> HstsOutput {
    let expectation = Expectation::HstsImplementedMaxAgeAtLeastSixMonths;
    let mut output = HstsOutput {
        result: Expectation::HstsNotImplemented,
        pass: false,
        data: None,
        include_subdomains: false,
        max_age: None,
        preload: false,
        preloaded: false,
    };
    let response = retrieval.https.as_ref().map(|session| &session.response);
    let headers = get_http_headers(response, STRICT_TRANSPORT_SECURITY);
    match response {
        None => output.result = Expectation::HstsNotImplementedNoHttps,
        Some(response) if !response.verified => output.result = Expectation::HstsInvalidCert,
        Some(_) if !headers.is_empty() => {
            let data = js::slice(headers[0], 0, 1024);
            output.result = parse_sts(&data, &mut output).unwrap_or(Expectation::HstsHeaderInvalid);
            output.data = Some(data);
        }
        Some(_) => {}
    }

    if response.is_some()
        && let Some(entry) = preload.lookup(&retrieval.host)
    {
        output.result = Expectation::HstsPreloaded;
        output.include_subdomains = entry.include_subdomains;
        output.preloaded = true;
    }

    output.pass = [
        Expectation::HstsImplementedMaxAgeAtLeastSixMonths,
        Expectation::HstsPreloaded,
        expectation,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::hsts] strict_transport_security_test: host={} result={} max_age={:?}",
        retrieval.host,
        output.result,
        output.max_age
    );
    output
}

/// The header's directives into `output`; `None` when the header is invalid (set twice, i.e. it
/// holds a comma, or no `max-age`).
fn parse_sts(data: &str, output: &mut HstsOutput) -> Option<Expectation> {
    let directives: Vec<String> = data.split(';').map(|d| js::trim(d).to_lowercase()).collect();
    if data.contains(',') {
        return None;
    }
    for directive in &directives {
        if let Some(value) = directive.strip_prefix("max-age=") {
            output.max_age = Some(js::parse_int(&js::slice(value, 0, 120)));
        } else if directive == "includesubdomains" {
            output.include_subdomains = true;
        } else if directive == "preload" {
            output.preload = true;
        }
    }
    let max_age = output.max_age?;
    Some(if max_age < SIX_MONTHS {
        Expectation::HstsImplementedMaxAgeLessThanSixMonths
    } else {
        Expectation::HstsImplementedMaxAgeAtLeastSixMonths
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests, https_headers, no_preload};

    fn entry(force_https: bool, include_subdomains: bool) -> PreloadEntry {
        PreloadEntry {
            force_https,
            include_subdomains,
        }
    }

    /// The upstream list's entries the ported tests read (Chromium list, 2026-10-30).
    fn upstream_preload() -> HstsPreload {
        HstsPreload::from_entries(vec![
            ("bugzilla.mozilla.org".to_string(), entry(true, true)),
            ("facebook.com".to_string(), entry(true, false)),
        ])
    }

    /// Ported from test/strict-transport-security.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn missing() {
            let reqs = empty_requests(None);
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsNotImplemented);
            assert!(!result.pass);
        }

        #[test]
        fn header_invalid() {
            let mut reqs = empty_requests(None);
            https_headers(&mut reqs).set_single("strict-transport-security", "includeSubDomains; preload");
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsHeaderInvalid);
            assert!(!result.pass);

            https_headers(&mut reqs).set_single(
                "strict-transport-security",
                "max-age=15768000; includeSubDomains, max-age=15768000; includeSubDomains",
            );
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsHeaderInvalid);
            assert!(!result.pass);
        }

        #[test]
        fn no_https() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set_single("strict-transport-security", "max-age=15768000");
            reqs.http
                .as_mut()
                .unwrap()
                .response
                .headers
                .set_single("strict-transport-security", "max-age=15768000");
            reqs.https = None;
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsNotImplementedNoHttps);
            assert!(!result.pass);
        }

        #[test]
        fn invalid_cert() {
            let mut reqs = empty_requests(None);
            https_headers(&mut reqs).set_single(
                "strict-transport-security",
                "max-age=15768000; includeSubDomains; preload",
            );
            reqs.https.as_mut().unwrap().response.verified = false;
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsInvalidCert);
            assert!(!result.pass);
        }

        #[test]
        fn max_age_too_low() {
            let mut reqs = empty_requests(None);
            https_headers(&mut reqs).set_single("Strict-Transport-Security", "max-age=86400");
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsImplementedMaxAgeLessThanSixMonths);
            assert!(!result.pass);
        }

        #[test]
        fn implemented() {
            let mut reqs = empty_requests(None);
            https_headers(&mut reqs).set_single(
                "strict-transport-security",
                "max-age=15768000; includeSubDomains; preload",
            );
            let result = strict_transport_security_test(&reqs, &no_preload());
            assert_eq!(result.result, Expectation::HstsImplementedMaxAgeAtLeastSixMonths);
            assert_eq!(result.max_age, Some(15_768_000.0));
            assert!(result.include_subdomains);
            assert!(result.preload);
            assert!(result.pass);
        }

        #[test]
        fn preloaded() {
            let mut reqs = empty_requests(None);
            reqs.host = "bugzilla.mozilla.org".to_string();
            let result = strict_transport_security_test(&reqs, &upstream_preload());
            assert_eq!(result.result, Expectation::HstsPreloaded);
            assert!(result.include_subdomains);
            assert!(result.pass);
            assert!(result.preloaded);

            reqs.host = "facebook.com".to_string();
            let result = strict_transport_security_test(&reqs, &upstream_preload());
            assert_eq!(result.result, Expectation::HstsPreloaded);
            assert!(!result.include_subdomains);
            assert!(result.pass);
            assert!(result.preloaded);

            reqs.host = "dropboxusercontent.com".to_string();
            let result = strict_transport_security_test(&reqs, &upstream_preload());
            assert_eq!(result.result, Expectation::HstsNotImplemented);
            assert!(!result.include_subdomains);
            assert!(!result.pass);
            assert!(!result.preloaded);
        }
    }

    /// `max-age=` with no number parses to `NaN`, which is not below six months: upstream grades it
    /// at least six months.
    #[test]
    fn a_non_numeric_max_age_grades_at_least_six_months() {
        let mut reqs = empty_requests(None);
        https_headers(&mut reqs).set_single("strict-transport-security", "max-age=forever");
        let result = strict_transport_security_test(&reqs, &no_preload());
        assert_eq!(result.result, Expectation::HstsImplementedMaxAgeAtLeastSixMonths);
        assert!(result.max_age.unwrap().is_nan());
    }

    /// The shape of Chromium's file: comments, entries with fields the parse ignores.
    pub(crate) const CHROMIUM_FIXTURE: &str = r#"{
  // Chromium's file carries comments like this one.
  "pinsets": [{ "name": "google", "static_spki_hashes": ["GoogleBackup2048"] }],
  "entries": [
    // Exact force-https entry.
    { "name": "pre.com", "policy": "custom", "mode": "force-https" },
    { "name": "parent.com", "policy": "custom", "mode": "force-https", "include_subdomains": true },
    { "name": "noinc.com", "policy": "custom", "mode": "force-https" },
    { "name": "pinned.com", "policy": "custom", "include_subdomains": true, "pins": "google" },
    { "name": "  GitHub.COM ", "policy": "custom", "mode": "force-https", "include_subdomains": true }
  ]
}"#;

    #[test]
    fn chromium_list_parses_with_comments_names_trimmed_and_lowercased() {
        let list = parse_chromium(CHROMIUM_FIXTURE).unwrap();
        assert!(list.is_available());
        assert_eq!(list.lookup("pre.com"), Some(entry(true, false)));
        assert_eq!(list.lookup("www.parent.com"), Some(entry(true, true)));
        assert_eq!(list.lookup("www.noinc.com"), None);
        assert_eq!(list.lookup("pinned.com"), None);
        assert_eq!(list.lookup("github.com"), Some(entry(true, true)));
        assert_eq!(list.lookup("  GitHub.COM "), Some(entry(true, true)));
    }

    /// `removeJsonComments` cuts at any `//`, inside a string too, as upstream's regex does: such a
    /// file does not parse, and the list is not built from it.
    #[test]
    fn a_double_slash_inside_a_string_breaks_the_parse_as_upstream() {
        assert_eq!(remove_json_comments("a // x\nb\r// y\u{2028}c"), "a \nb\r\u{2028}c");
        let with_url = r#"{"entries": [{"name": "a.com", "mode": "force-https", "report_uri": "https://r.example/"}]}"#;
        assert!(parse_chromium(with_url).is_err());
        assert!(parse_chromium("{}").is_err());
        assert!(parse_chromium("not json").is_err());
    }

    /// Later duplicates win; `include_subdomains` by JavaScript truthiness.
    #[test]
    fn duplicates_take_the_last_entry_and_flags_follow_js_truthiness() {
        let list = parse_chromium(
            r#"{"entries": [
                {"name": "a.com", "mode": "force-https"},
                {"name": "A.com", "mode": "force-https", "include_subdomains": 1},
                {"name": "b.com", "mode": "force-https", "include_subdomains": ""},
                {"name": "c.com", "mode": "force-https", "include_subdomains": "yes"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(list.lookup("x.a.com"), Some(entry(true, true)));
        assert_eq!(list.lookup("x.b.com"), None);
        assert_eq!(list.lookup("x.c.com"), Some(entry(true, true)));
    }

    mod source {
        use super::*;
        use crate::scan::testing::{FakeHttp, dead_http_url, temp_dir};

        fn client() -> Client {
            Client::builder().no_proxy().build().unwrap()
        }

        fn far() -> tokio::time::Instant {
            tokio::time::Instant::now() + Duration::from_secs(5)
        }

        #[tokio::test]
        async fn the_list_is_fetched_cached_and_parsed_once() {
            let fake = FakeHttp::start(vec![("/hsts", 200, CHROMIUM_FIXTURE.to_string())]).await;
            let dir = temp_dir("hsts-source");
            let source = PreloadSource::from_url(client(), fake.url("/hsts"), Some(dir.clone()));
            let first = source.get(far()).await;
            let second = source.get(far()).await;
            assert!(first.is_available());
            assert!(first.lookup("pre.com").is_some());
            assert!(Arc::ptr_eq(&first, &second));
            assert_eq!(fake.hits("/hsts"), 1);
            assert!(dir.join(PRELOAD_CACHE_FILE).exists());
        }

        /// No cache and a dead URL: the unavailable list, never an empty one.
        #[tokio::test]
        async fn no_cache_and_a_dead_url_is_the_unavailable_list() {
            let source = PreloadSource::from_url(client(), dead_http_url().await, Some(temp_dir("hsts-dead")));
            let list = source.get(far()).await;
            assert!(!list.is_available());
            assert!(list.lookup("pre.com").is_none());
        }
    }

    #[test]
    fn preload_lookup_walks_parents_with_include_subdomains() {
        let list = HstsPreload::from_entries(vec![
            ("github.com".to_string(), entry(true, true)),
            ("example.com".to_string(), entry(true, false)),
            ("pinned.org".to_string(), entry(false, true)),
            ("b.pinned.org".to_string(), entry(false, false)),
        ]);
        assert!(list.lookup("  GitHub.COM ").is_some());
        assert!(list.lookup("api.github.com").is_some());
        assert!(list.lookup("example.com").is_some());
        assert!(list.lookup("www.example.com").is_none());
        assert!(list.lookup("pinned.org").is_none());
        assert!(list.lookup("a.b.pinned.org").is_none());
        assert!(HstsPreload::unavailable().lookup("github.com").is_none());
        assert!(!HstsPreload::unavailable().is_available());
    }
}
