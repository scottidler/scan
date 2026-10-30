// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308
// (src/analyzer/tests/subresource-integrity.js, test/subresource-integrity.test.js).

//! The `subresource-integrity` test: every `<script src>` in the `auto` body, judged on whether it
//! comes from the site's own registrable domain, over https, with an `integrity` attribute.

use super::AnalyzeError;
use super::headers::{CONTENT_TYPE, get_first_http_header};
use super::html::collect_elements;
use super::only_if_worse;
use super::retriever::Retrieval;
use super::types::{Expectation, HTML_TYPES};
use publicsuffix::Psl;
use std::collections::BTreeMap;
use std::net::IpAddr;
use url::Url;

/// Names a host's registrable domain (`tldts`'s `parse(..).domain`): ICANN suffixes only, no
/// domain for an IP address or a bare suffix.
pub trait RegistrableDomain {
    fn registrable_domain(&self, host: &str) -> Option<String>;
}

impl<T: Psl> RegistrableDomain for T {
    fn registrable_domain(&self, host: &str) -> Option<String> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.parse::<IpAddr>().is_ok() {
            return None;
        }
        let ascii = idna::domain_to_ascii(host.trim_end_matches('.')).ok()?;
        self.domain(ascii.as_bytes())
            .map(|domain| String::from_utf8_lossy(domain.as_bytes()).into_owned())
    }
}

/// Results from best to worst, for `onlyIfWorse`.
const GOODNESS: [Expectation; 6] = [
    Expectation::SriImplementedAndAllScriptsLoadedSecurely,
    Expectation::SriImplementedAndExternalScriptsLoadedSecurely,
    Expectation::SriImplementedButExternalScriptsNotLoadedSecurely,
    Expectation::SriNotImplementedButExternalScriptsLoadedSecurely,
    Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely,
    Expectation::SriNotImplementedResponseNotHtml,
];

/// One external script as the test reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptData {
    pub crossorigin: Option<String>,
    pub integrity: Option<String>,
}

/// What the `subresource-integrity` test found.
#[derive(Debug, Clone, PartialEq)]
pub struct SriOutput {
    pub result: Expectation,
    pub pass: bool,
    /// External scripts by `src`.
    pub data: BTreeMap<String, ScriptData>,
}

/// `^(\/\/)[^/]`.
fn is_relative_protocol(src: &str) -> bool {
    src.strip_prefix("//")
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c != '/')
}

/// `subresourceIntegrityTest`.
pub fn subresource_integrity_test(
    retrieval: &Retrieval,
    domains: &dyn RegistrableDomain,
) -> Result<SriOutput, AnalyzeError> {
    let expectation = Expectation::SriImplementedAndExternalScriptsLoadedSecurely;
    let mut output = SriOutput {
        result: Expectation::SriNotImplementedButNoScriptsLoaded,
        pass: false,
        data: BTreeMap::new(),
    };
    let Some(session) = retrieval.auto() else {
        return Ok(output);
    };

    let content_type = get_first_http_header(Some(&session.response), CONTENT_TYPE).unwrap_or_default();
    let mime = content_type.split(';').next().unwrap_or_default();
    let mut result: Option<Expectation> = None;
    if !mime.is_empty() && !HTML_TYPES.contains(&mime) {
        result = Some(Expectation::SriNotImplementedResponseNotHtml);
    } else {
        let scripts = collect_elements(retrieval.auto_body.as_deref().unwrap_or_default(), "script");
        let site_domain = domains.registrable_domain(&retrieval.host);
        let mut scripts_on_foreign_origin = false;
        for script in &scripts {
            let Some(src) = script.get("src").filter(|src| !src.is_empty()) else {
                continue;
            };
            let integrity = script.get("integrity").filter(|v| !v.is_empty()).map(str::to_string);
            let crossorigin = script.get("crossorigin").filter(|v| !v.is_empty()).map(str::to_string);

            let relative_protocol = is_relative_protocol(src);
            let full_url = src.starts_with("http://") || src.starts_with("https://");
            let relative_origin = !relative_protocol && !full_url;
            let mut scheme = None;
            let same_second_level_domain = if full_url {
                // upstream's `new URL(scriptSrc)` throws on a src it cannot parse, failing the scan.
                let url = Url::parse(src).map_err(|e| AnalyzeError::InvalidScriptSrc(format!("{src}: {e}")))?;
                scheme = Some(url.scheme().to_string());
                url.host_str().and_then(|host| domains.registrable_domain(host)) == site_domain
            } else {
                true
            };

            let secure_origin = relative_origin || (same_second_level_domain && !relative_protocol);
            if !secure_origin {
                scripts_on_foreign_origin = true;
            }
            let secure_scheme =
                scheme.as_deref() == Some("https") || (relative_origin && session.url.scheme() == "https");

            if !secure_origin {
                let worse = |finding| Some(only_if_worse(finding, result, &GOODNESS));
                if integrity.is_some() && !secure_scheme {
                    result = worse(Expectation::SriImplementedButExternalScriptsNotLoadedSecurely);
                } else if integrity.is_none() && secure_scheme {
                    result = worse(Expectation::SriNotImplementedButExternalScriptsLoadedSecurely);
                } else if integrity.is_none() && !secure_scheme {
                    result = worse(Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely);
                }
                output
                    .data
                    .insert(src.to_string(), ScriptData { crossorigin, integrity });
            } else if integrity.is_some() && secure_scheme && result.is_none() {
                // The bonus applies even when SRI is used on the same origin.
                result = Some(Expectation::SriImplementedAndAllScriptsLoadedSecurely);
            }
        }
        if scripts.is_empty() {
            result = Some(Expectation::SriNotImplementedButNoScriptsLoaded);
        } else if result.is_none() {
            result = Some(if scripts_on_foreign_origin {
                Expectation::SriImplementedAndExternalScriptsLoadedSecurely
            } else {
                Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin
            });
        }
    }

    output.result = result.unwrap_or(Expectation::SriNotImplementedButNoScriptsLoaded);
    output.pass = [
        Expectation::SriImplementedAndAllScriptsLoadedSecurely,
        Expectation::SriImplementedAndExternalScriptsLoadedSecurely,
        Expectation::SriNotImplementedResponseNotHtml,
        Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin,
        Expectation::SriNotImplementedButNoScriptsLoaded,
        expectation,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::sri] subresource_integrity_test: host={} external={} result={}",
        retrieval.host,
        output.data.len(),
        output.result
    );
    Ok(output)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};
    use publicsuffix::IcannList;

    /// The ICANN suffixes the tests' script hosts need.
    pub(crate) fn suffixes() -> IcannList {
        "// ===BEGIN ICANN DOMAINS===\ncom\norg\nme\nnet\n// ===END ICANN DOMAINS===\n"
            .parse::<IcannList>()
            .unwrap()
    }

    fn sri(reqs: &Retrieval) -> SriOutput {
        subresource_integrity_test(reqs, &suffixes()).unwrap()
    }

    /// Ported from test/subresource-integrity.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_no_scripts() {
            let result = sri(&empty_requests(Some("test-content-sri-no-scripts.html")));
            assert_eq!(result.result.as_str(), "sri-not-implemented-but-no-scripts-loaded");
        }

        #[test]
        fn checks_for_not_html() {
            let mut reqs = empty_requests(Some("test-content-sri-no-scripts.html"));
            reqs.auto_body = Some(r#"{"foo": "bar"}"#.to_string());
            auto_headers(&mut reqs).set_single("content-type", "application/json");
            let result = sri(&reqs);
            assert_eq!(result.result, Expectation::SriNotImplementedResponseNotHtml);
            assert!(result.pass);
        }

        #[test]
        fn checks_for_same_origin() {
            let result = sri(&empty_requests(Some("test-content-sri-sameorigin1.html")));
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin
            );
            assert!(result.pass);

            let result = sri(&empty_requests(Some("test-content-sri-sameorigin3.html")));
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely
            );
            assert!(!result.pass);

            let mut reqs = empty_requests(Some("test-content-sri-sameorigin2.html"));
            let result = sri(&reqs);
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin
            );
            assert!(result.pass);

            reqs.https.as_mut().unwrap().response.status = 404;
            let result = sri(&reqs);
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin
            );
            assert!(result.pass);
        }

        #[test]
        fn checks_if_implemented_with_external_scripts_and_https() {
            for file in [
                "test-content-sri-impl-external-https1.html",
                "test-content-sri-impl-external-https2.html",
            ] {
                let result = sri(&empty_requests(Some(file)));
                assert_eq!(
                    result.result,
                    Expectation::SriImplementedAndExternalScriptsLoadedSecurely,
                    "{file}"
                );
                assert!(result.pass);
            }
        }

        #[test]
        fn checks_if_implemented_with_same_origin() {
            let result = sri(&empty_requests(Some("test-content-sri-impl-sameorigin.html")));
            assert_eq!(result.result, Expectation::SriImplementedAndAllScriptsLoadedSecurely);
            assert!(result.pass);
        }

        #[test]
        fn checks_if_not_implemented_with_external_scripts_and_https() {
            let result = sri(&empty_requests(Some("test-content-sri-notimpl-external-https.html")));
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedButExternalScriptsLoadedSecurely
            );
            assert!(!result.pass);
        }

        #[test]
        fn checks_if_implemented_with_external_scripts_and_http() {
            let result = sri(&empty_requests(Some("test-content-sri-impl-external-http.html")));
            assert_eq!(
                result.result,
                Expectation::SriImplementedButExternalScriptsNotLoadedSecurely
            );
            assert!(!result.pass);
        }

        #[test]
        fn checks_if_implemented_with_external_scripts_and_no_protocol() {
            let result = sri(&empty_requests(Some("test-content-sri-impl-external-noproto.html")));
            assert_eq!(
                result.result,
                Expectation::SriImplementedButExternalScriptsNotLoadedSecurely
            );
            assert!(!result.pass);
        }

        #[test]
        fn checks_if_not_implemented_with_external_scripts_and_http() {
            let result = sri(&empty_requests(Some("test-content-sri-notimpl-external-http.html")));
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely
            );
            assert!(!result.pass);
        }

        #[test]
        fn checks_if_not_implemented_with_external_scripts_and_no_protocol() {
            let result = sri(&empty_requests(Some("test-content-sri-notimpl-external-noproto.html")));
            assert_eq!(
                result.result,
                Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely
            );
            assert!(!result.pass);
        }
    }

    #[test]
    fn registrable_domain_is_icann_only_and_none_for_addresses() {
        let list = suffixes();
        assert_eq!(
            list.registrable_domain("www.mozilla.org").as_deref(),
            Some("mozilla.org")
        );
        assert_eq!(list.registrable_domain("fb.me").as_deref(), Some("fb.me"));
        assert_eq!(list.registrable_domain("localhost"), None);
        assert_eq!(list.registrable_domain("192.0.2.1"), None);
        assert_eq!(list.registrable_domain("[2001:db8::1]"), None);
    }

    /// A `src` that `new URL` rejects makes upstream throw: no grade.
    #[test]
    fn an_unparseable_script_url_fails_the_analysis() {
        let mut reqs = empty_requests(None);
        reqs.auto_body = Some(r#"<script src="https://exa mple.com/a.js"></script>"#.to_string());
        assert!(matches!(
            subresource_integrity_test(&reqs, &suffixes()),
            Err(AnalyzeError::InvalidScriptSrc(_))
        ));
    }

    #[test]
    fn no_auto_response_reads_no_scripts_and_fails() {
        let mut reqs = empty_requests(None);
        reqs.http = None;
        reqs.https = None;
        let result = sri(&reqs);
        assert_eq!(result.result, Expectation::SriNotImplementedButNoScriptsLoaded);
        assert!(!result.pass);
    }
}
