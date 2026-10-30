// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/hsts.js,
// src/analyzer/tests/strict-transport-security.js, test/strict-transport-security.test.js).

//! The `strict-transport-security` test and the HSTS preload lookup it and the redirection test
//! share.

use super::headers::{STRICT_TRANSPORT_SECURITY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;
use std::collections::HashMap;

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
mod tests {
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
