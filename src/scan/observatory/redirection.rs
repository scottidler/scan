// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/redirection.js,
// Site.fromSiteString in src/site.js, test/redirection.test.js).

//! The `redirection` test: does `http://host/` lead to https, first hop included, and is every hop
//! on the HSTS preload list.

use super::AnalyzeError;
use super::hsts::HstsPreload;
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

/// What the `redirection` test found.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectionOutput {
    pub result: Expectation,
    pub pass: bool,
    /// The last URL of the http chain, else of the https chain.
    pub destination: Option<String>,
    pub redirects: bool,
    pub route: Vec<String>,
    pub status_code: Option<u16>,
}

/// `Site.fromSiteString(hostname).hostname`: a hop's host must have a dot with non-empty labels;
/// upstream throws, failing the whole scan, when it does not.
fn site_hostname(hostname: &str) -> Result<String, AnalyzeError> {
    let invalid = |why: &str| AnalyzeError::InvalidSite(format!("{hostname}: {why}"));
    if hostname.is_empty() {
        return Err(invalid("hostname cannot be empty"));
    }
    if idna::domain_to_ascii(hostname).map_or(hostname.len(), |ascii| ascii.len()) > 253 {
        return Err(invalid("hostname is too long"));
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return Err(invalid("hostname must have at least a host and TLD"));
    }
    Ok(hostname.to_lowercase())
}

/// `redirectionTest`.
pub fn redirection_test(retrieval: &Retrieval, preload: &HstsPreload) -> Result<RedirectionOutput, AnalyzeError> {
    let expectation = Expectation::RedirectionToHttps;
    let http_redirects = retrieval.http_redirects();
    let https_redirects = retrieval.https_redirects();
    let response = retrieval.http.as_ref().map(|session| &session.response);

    let destination = http_redirects
        .last()
        .or(https_redirects.last())
        .map(|entry| entry.url.to_string());
    let mut output = RedirectionOutput {
        result: Expectation::RedirectionNotNeededNoHttp,
        pass: false,
        destination,
        redirects: true,
        route: Vec::new(),
        status_code: response.map(|r| r.status),
    };

    match response {
        None => output.result = Expectation::RedirectionNotNeededNoHttp,
        Some(response) if !response.verified => output.result = Expectation::RedirectionInvalidCert,
        Some(_) => {
            let route = http_redirects;
            output.route = route.iter().map(|entry| entry.url.to_string()).collect();
            let mut all_preloaded = true;
            for entry in route {
                let host = site_hostname(entry.url.host_str().unwrap_or_default())?;
                if preload.lookup(&host).is_none() {
                    all_preloaded = false;
                    break;
                }
            }
            let scheme = |i: usize| route.get(i).map(|entry| entry.url.scheme());
            let host = |i: usize| route.get(i).and_then(|entry| entry.url.host_str());
            output.result = if all_preloaded {
                Expectation::RedirectionAllRedirectsPreloaded
            } else if route.len() == 1 {
                output.redirects = false;
                Expectation::RedirectionMissing
            } else if route.last().map(|entry| entry.url.scheme()) != Some("https") {
                Expectation::RedirectionNotToHttps
            } else if scheme(1) == Some("http") {
                output.status_code = route.last().map(|entry| entry.status).filter(|status| *status != 0);
                Expectation::RedirectionNotToHttpsOnInitialRedirection
            } else if scheme(0) == Some("http") && scheme(1) == Some("https") && host(0) != host(1) {
                Expectation::RedirectionOffHostFromHttp
            } else {
                Expectation::RedirectionToHttps
            };
        }
    }

    // Defend against routing loops, as upstream does.
    if serde_json::to_string(&output.route).map_or(0, |json| js::utf16_len(&json)) > 8192 {
        output.route.clear();
    }
    output.status_code = output.status_code.filter(|status| status.to_string().len() < 5);
    output.pass = [
        Expectation::RedirectionNotNeededNoHttp,
        Expectation::RedirectionAllRedirectsPreloaded,
        expectation,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::redirection] redirection_test: hops={} result={}",
        output.route.len(),
        output.result
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{empty_requests, no_preload, set_http_redirects};
    use crate::scan::observatory::hsts::PreloadEntry;

    /// Ported from test/redirection.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_no_http_but_does_have_https() {
            let mut reqs = empty_requests(None);
            reqs.http = None;
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionNotNeededNoHttp);
            assert!(res.pass);
        }

        #[test]
        fn checks_for_redirection_missing() {
            let mut reqs = empty_requests(None);
            set_http_redirects(&mut reqs, &[("http://mozilla.org", 200)]);
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionMissing);
            assert!(!res.pass);
        }

        #[test]
        fn checks_for_redirection_not_to_https() {
            let mut reqs = empty_requests(None);
            set_http_redirects(
                &mut reqs,
                &[("http://mozilla.org", 301), ("http://www.mozilla.org", 200)],
            );
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionNotToHttps);
            assert!(!res.pass);

            set_http_redirects(
                &mut reqs,
                &[
                    ("http://mozilla.org", 301),
                    ("http://www.mozilla.org", 302),
                    ("http://www.mozilla.org/en/", 200),
                ],
            );
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionNotToHttps);
            assert!(!res.pass);
        }

        #[test]
        fn checks_for_proper_redirection_to_https() {
            let res = redirection_test(&empty_requests(None), &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionToHttps);
            assert!(res.pass);
        }

        #[test]
        fn checks_for_proper_redirection_to_https_with_port_number() {
            let mut reqs = empty_requests(None);
            set_http_redirects(
                &mut reqs,
                &[("http://mozilla.org/", 301), ("https://mozilla.org:8443/", 200)],
            );
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionToHttps);
            assert!(res.pass);
            assert_eq!(res.route, vec!["http://mozilla.org/", "https://mozilla.org:8443/"]);
        }

        #[test]
        fn checks_for_first_redirection_to_http() {
            let mut reqs = empty_requests(None);
            set_http_redirects(
                &mut reqs,
                &[
                    ("http://mozilla.org/", 301),
                    ("http://www.mozilla.org/", 301),
                    ("https://www.mozilla.org/", 200),
                ],
            );
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionNotToHttpsOnInitialRedirection);
            assert!(!res.pass);
        }

        #[test]
        fn checks_for_first_redirection_off_host() {
            let mut reqs = empty_requests(None);
            set_http_redirects(
                &mut reqs,
                &[("http://mozilla.org/", 301), ("https://www.mozilla.org/", 200)],
            );
            let res = redirection_test(&reqs, &no_preload()).unwrap();
            assert_eq!(res.result, Expectation::RedirectionOffHostFromHttp);
            assert!(!res.pass);
        }

        #[test]
        fn checks_for_all_redirections_preloaded() {
            let mut reqs = empty_requests(None);
            set_http_redirects(
                &mut reqs,
                &[
                    ("http://cloudflare.com/", 301),
                    ("https://cloudflare.com/", 302),
                    ("https://www.cloudflare.com/", 302),
                    ("https://baz.cloudflare.com/foo", 200),
                ],
            );
            // cloudflare.com's entry in the Chromium list (2026-10-30).
            let preload = HstsPreload::from_entries(vec![(
                "cloudflare.com".to_string(),
                PreloadEntry {
                    force_https: true,
                    include_subdomains: true,
                },
            )]);
            let res = redirection_test(&reqs, &preload).unwrap();
            assert_eq!(res.result, Expectation::RedirectionAllRedirectsPreloaded);
            assert!(res.pass);
        }
    }

    #[test]
    fn an_unverified_http_chain_is_invalid_cert() {
        let mut reqs = empty_requests(None);
        reqs.http.as_mut().unwrap().response.verified = false;
        let res = redirection_test(&reqs, &no_preload()).unwrap();
        assert_eq!(res.result, Expectation::RedirectionInvalidCert);
        assert!(!res.pass);
    }

    /// A hop to a dotless host makes upstream's `Site.fromSiteString` throw: no grade.
    #[test]
    fn a_hop_to_a_dotless_host_fails_the_analysis() {
        let mut reqs = empty_requests(None);
        set_http_redirects(&mut reqs, &[("http://mozilla.org/", 301), ("http://intranet/", 200)]);
        let preload = HstsPreload::from_entries(vec![(
            "mozilla.org".to_string(),
            PreloadEntry {
                force_https: true,
                include_subdomains: true,
            },
        )]);
        assert!(matches!(
            redirection_test(&reqs, &preload),
            Err(AnalyzeError::InvalidSite(_))
        ));
    }
}
