// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308
// (src/analyzer/tests/cross-origin-opener-policy.js, test/cross-origin-opener-policy.test.js).

//! The `cross-origin-opener-policy` test: the header's structured-field token.

use super::headers::{CROSS_ORIGIN_OPENER_POLICY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::structured::parse_token_item;
use super::types::Expectation;

/// What the `cross-origin-opener-policy` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoopOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
    pub http: bool,
}

/// `crossOriginOpenerPolicyTest`.
pub fn cross_origin_opener_policy_test(retrieval: &Retrieval) -> CoopOutput {
    let expectation = Expectation::CoopNotImplemented;
    let mut output = CoopOutput {
        result: Expectation::CoopNotImplemented,
        pass: false,
        data: None,
        http: false,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    let headers = get_http_headers(Some(response), CROSS_ORIGIN_OPENER_POLICY);
    output.http = !headers.is_empty();
    if headers.len() > 1 {
        output.result = Expectation::CoopHeaderInvalid;
    } else if let Some(header) = headers.first().filter(|h| !h.is_empty()) {
        let value = js::trim(&js::slice(header, 0, 1024)).to_string();
        output.result = match parse_token_item(&value).as_deref() {
            Some("same-origin") => Expectation::CoopImplementedWithSameOrigin,
            Some("same-origin-allow-popups") => Expectation::CoopImplementedWithSameOriginAllowPopups,
            Some("noopener-allow-popups") => Expectation::CoopImplementedWithNoopenerAllowPopups,
            Some("unsafe-none") => Expectation::CoopImplementedWithUnsafeNone,
            _ => Expectation::CoopHeaderInvalid,
        };
        output.data = Some(value);
    }
    output.pass = [
        expectation,
        Expectation::CoopNotImplemented,
        Expectation::CoopImplementedWithSameOrigin,
        Expectation::CoopImplementedWithSameOriginAllowPopups,
        Expectation::CoopImplementedWithNoopenerAllowPopups,
        Expectation::CoopImplementedWithUnsafeNone,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::coop] cross_origin_opener_policy_test: result={}",
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::headers::HeaderValue;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    fn with_header(value: &str) -> CoopOutput {
        let mut reqs = empty_requests(None);
        auto_headers(&mut reqs).set_single("cross-origin-opener-policy", value);
        cross_origin_opener_policy_test(&reqs)
    }

    /// Ported from test/cross-origin-opener-policy.test.js, one test per upstream `it(`; the two
    /// `it(` inside loops are one test over the loop's values.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_missing() {
            let result = cross_origin_opener_policy_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::CoopNotImplemented);
            assert!(result.pass);
        }

        #[test]
        fn rejects_invalid_headers() {
            for value in [
                "whimsy",
                "\"same-origin\"",
                "Same-Origin",
                "SAME-ORIGIN",
                "same-origin; report-to=coop endpoint",
            ] {
                let result = with_header(value);
                assert_eq!(result.result, Expectation::CoopHeaderInvalid, "{value}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn accepts_valid_headers() {
            for (value, expected) in [
                ("same-origin", Expectation::CoopImplementedWithSameOrigin),
                (
                    "same-origin-allow-popups",
                    Expectation::CoopImplementedWithSameOriginAllowPopups,
                ),
                (
                    "noopener-allow-popups",
                    Expectation::CoopImplementedWithNoopenerAllowPopups,
                ),
                ("unsafe-none", Expectation::CoopImplementedWithUnsafeNone),
                (
                    "same-origin; report-to=\"coop-endpoint\"",
                    Expectation::CoopImplementedWithSameOrigin,
                ),
                (
                    "same-origin-allow-popups; report-to=\"coop-endpoint\"",
                    Expectation::CoopImplementedWithSameOriginAllowPopups,
                ),
                ("same-origin; report-to", Expectation::CoopImplementedWithSameOrigin),
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
                "cross-origin-opener-policy",
                HeaderValue::List(vec!["same-origin".to_string(), "unsafe-none".to_string()]),
            );
            let result = cross_origin_opener_policy_test(&reqs);
            assert_eq!(result.result, Expectation::CoopHeaderInvalid);
            assert!(!result.pass);
        }
    }

    /// Node joins a repeated header with `", "`, which is not one item.
    #[test]
    fn a_joined_duplicate_header_is_invalid() {
        assert_eq!(
            with_header("same-origin, same-origin").result,
            Expectation::CoopHeaderInvalid
        );
    }
}
