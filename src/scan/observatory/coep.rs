// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308
// (src/analyzer/tests/cross-origin-embedder-policy.js, test/cross-origin-embedder-policy.test.js).

//! The `cross-origin-embedder-policy` test: the header's structured-field token.

use super::headers::{CROSS_ORIGIN_EMBEDDER_POLICY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::structured::parse_token_item;
use super::types::Expectation;

/// What the `cross-origin-embedder-policy` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoepOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
    pub http: bool,
}

/// `crossOriginEmbedderPolicyTest`.
pub fn cross_origin_embedder_policy_test(retrieval: &Retrieval) -> CoepOutput {
    let expectation = Expectation::CoepNotImplemented;
    let mut output = CoepOutput {
        result: Expectation::CoepNotImplemented,
        pass: false,
        data: None,
        http: false,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    let headers = get_http_headers(Some(response), CROSS_ORIGIN_EMBEDDER_POLICY);
    output.http = !headers.is_empty();
    if headers.len() > 1 {
        output.result = Expectation::CoepHeaderInvalid;
    } else if let Some(header) = headers.first().filter(|h| !h.is_empty()) {
        let value = js::trim(&js::slice(header, 0, 1024)).to_string();
        output.result = match parse_token_item(&value).as_deref() {
            Some("require-corp") => Expectation::CoepImplementedWithRequireCorp,
            Some("credentialless") => Expectation::CoepImplementedWithCredentialless,
            Some("unsafe-none") => Expectation::CoepImplementedWithUnsafeNone,
            _ => Expectation::CoepHeaderInvalid,
        };
        output.data = Some(value);
    }
    output.pass = [
        expectation,
        Expectation::CoepNotImplemented,
        Expectation::CoepImplementedWithRequireCorp,
        Expectation::CoepImplementedWithCredentialless,
        Expectation::CoepImplementedWithUnsafeNone,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::coep] cross_origin_embedder_policy_test: result={}",
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::headers::HeaderValue;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    fn with_header(value: &str) -> CoepOutput {
        let mut reqs = empty_requests(None);
        auto_headers(&mut reqs).set_single("cross-origin-embedder-policy", value);
        cross_origin_embedder_policy_test(&reqs)
    }

    /// Ported from test/cross-origin-embedder-policy.test.js, one test per upstream `it(`; the two
    /// `it(` inside loops are one test over the loop's values.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_missing() {
            let result = cross_origin_embedder_policy_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::CoepNotImplemented);
            assert!(result.pass);
        }

        #[test]
        fn rejects_invalid_headers() {
            for value in [
                "whimsy",
                "\"require-corp\"",
                "Require-Corp",
                "REQUIRE-CORP",
                "require-corp; report-to=coep endpoint",
            ] {
                let result = with_header(value);
                assert_eq!(result.result, Expectation::CoepHeaderInvalid, "{value}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn accepts_valid_headers() {
            for (value, expected) in [
                ("require-corp", Expectation::CoepImplementedWithRequireCorp),
                ("credentialless", Expectation::CoepImplementedWithCredentialless),
                ("unsafe-none", Expectation::CoepImplementedWithUnsafeNone),
                (
                    "require-corp; report-to=\"coep-endpoint\"",
                    Expectation::CoepImplementedWithRequireCorp,
                ),
                (
                    "credentialless; report-to=\"coep-endpoint\"",
                    Expectation::CoepImplementedWithCredentialless,
                ),
                ("require-corp; report-to", Expectation::CoepImplementedWithRequireCorp),
            ] {
                let result = with_header(value);
                assert_eq!(result.result, expected, "{value}");
                assert!(result.pass);
            }
        }

        #[test]
        fn checks_for_multiple_headers() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set(
                "cross-origin-embedder-policy",
                HeaderValue::List(vec!["require-corp".to_string(), "unsafe-none".to_string()]),
            );
            let result = cross_origin_embedder_policy_test(&reqs);
            assert_eq!(result.result, Expectation::CoepHeaderInvalid);
            assert!(!result.pass);
        }
    }

    /// Node joins a repeated header with `", "`, which is not one item.
    #[test]
    fn a_joined_duplicate_header_is_invalid() {
        assert_eq!(
            with_header("require-corp, require-corp").result,
            Expectation::CoepHeaderInvalid
        );
    }
}
