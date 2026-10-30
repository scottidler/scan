// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/x-frame-options.js,
// test/x-frame-options.test.js).

//! The `x-frame-options` test: `DENY`/`SAMEORIGIN`, or a CSP `frame-ancestors` that makes the header
//! unnecessary.

use super::csp::content_security_policy_test;
use super::headers::{X_FRAME_OPTIONS, get_first_http_header};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

/// What the `x-frame-options` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XFrameOptionsOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
}

/// `xFrameOptionsTest`.
pub fn x_frame_options_test(retrieval: &Retrieval) -> XFrameOptionsOutput {
    let expectation = Expectation::XFrameOptionsSameoriginOrDeny;
    let mut output = XFrameOptionsOutput {
        result: Expectation::XFrameOptionsNotImplemented,
        pass: false,
        data: None,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    if let Some(header) = get_first_http_header(Some(response), X_FRAME_OPTIONS).filter(|h| !h.is_empty()) {
        let data = js::slice(header, 0, 1024);
        let xfo = js::trim(&data).to_lowercase();
        output.result = if xfo == "deny" || xfo == "sameorigin" {
            Expectation::XFrameOptionsSameoriginOrDeny
        } else if xfo.starts_with("allow-from") {
            Expectation::XFrameOptionsAllowFromOrigin
        } else {
            Expectation::XFrameOptionsHeaderInvalid
        };
        output.data = Some(data);
    }

    let csp = content_security_policy_test(retrieval);
    if csp.data.is_some_and(|data| data.contains_key("frame-ancestors")) {
        output.result = Expectation::XFrameOptionsImplementedViaCsp;
    }

    output.pass = [
        Expectation::XFrameOptionsAllowFromOrigin,
        Expectation::XFrameOptionsSameoriginOrDeny,
        Expectation::XFrameOptionsImplementedViaCsp,
        expectation,
    ]
    .contains(&output.result);
    log::debug!("[observatory::xfo] x_frame_options_test: result={}", output.result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::grade::score_modifier;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    fn reqs() -> Retrieval {
        empty_requests(Some("test-content-sri-no-scripts.html"))
    }

    /// Ported from test/x-frame-options.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_missing() {
            let result = x_frame_options_test(&reqs());
            assert_eq!(result.result, Expectation::XFrameOptionsNotImplemented);
            assert!(!result.pass);
        }

        #[test]
        fn checks_validity() {
            let mut reqs = reqs();
            for value in ["whimsy", "SAMEORIGIN, SAMEORIGIN"] {
                auto_headers(&mut reqs).set_single("x-frame-options", value);
                let result = x_frame_options_test(&reqs);
                assert_eq!(result.result, Expectation::XFrameOptionsHeaderInvalid, "{value}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn checks_allow_from_origin() {
            let mut reqs = reqs();
            auto_headers(&mut reqs).set_single("x-frame-options", "ALLOW-FROM https://mozilla.org");
            let result = x_frame_options_test(&reqs);
            assert_eq!(result.result, Expectation::XFrameOptionsAllowFromOrigin);
            assert!(result.pass);
        }

        #[test]
        fn checks_deny() {
            let mut reqs = reqs();
            for value in ["DENY", "SAMEORIGIN"] {
                auto_headers(&mut reqs).set_single("x-frame-options", value);
                let result = x_frame_options_test(&reqs);
                assert_eq!(result.result, Expectation::XFrameOptionsSameoriginOrDeny, "{value}");
                assert_eq!(score_modifier(result.result), 5);
                assert!(result.pass);
            }
        }

        #[test]
        fn checks_implemented_via_csp() {
            let mut reqs = reqs();
            auto_headers(&mut reqs).set_single("x-frame-options", "DENY");
            auto_headers(&mut reqs).set_single("content-security-policy", "frame-ancestors https://mozilla.org");
            let result = x_frame_options_test(&reqs);
            assert_eq!(result.result, Expectation::XFrameOptionsImplementedViaCsp);
            assert!(result.pass);
        }

        #[test]
        fn does_not_obey_x_frame_options_in_meta_equiv_tags() {
            let reqs = empty_requests(Some("test-parse-http-equiv-headers-x-frame-options.html"));
            let result = x_frame_options_test(&reqs);
            assert_eq!(result.result, Expectation::XFrameOptionsNotImplemented);
            assert!(!result.pass);
        }
    }
}
