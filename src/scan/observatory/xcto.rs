// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308
// (src/analyzer/tests/x-content-type-options.js, test/x-content-type-options.test.js).

//! The `x-content-type-options` test: `nosniff` or not.

use super::headers::{X_CONTENT_TYPE_OPTIONS, get_first_http_header};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

/// What the `x-content-type-options` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XContentTypeOptionsOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
}

/// `xContentTypeOptionsTest`.
pub fn x_content_type_options_test(retrieval: &Retrieval) -> XContentTypeOptionsOutput {
    let expectation = Expectation::XContentTypeOptionsNosniff;
    let mut output = XContentTypeOptionsOutput {
        result: Expectation::XContentTypeOptionsNotImplemented,
        pass: false,
        data: None,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    if let Some(header) = get_first_http_header(Some(response), X_CONTENT_TYPE_OPTIONS).filter(|h| !h.is_empty()) {
        let data = js::slice(header, 0, 256);
        output.result = if js::trim(&data).to_lowercase() == "nosniff" {
            Expectation::XContentTypeOptionsNosniff
        } else {
            Expectation::XContentTypeOptionsHeaderInvalid
        };
        output.data = Some(data);
    }
    output.pass = output.result == expectation;
    log::debug!(
        "[observatory::xcto] x_content_type_options_test: result={}",
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    /// Ported from test/x-content-type-options.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_missing() {
            let result = x_content_type_options_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::XContentTypeOptionsNotImplemented);
            assert!(!result.pass);
        }

        #[test]
        fn checks_header_validity() {
            let mut reqs = empty_requests(None);
            for value in ["whimsy", "nosniff, nosniff"] {
                auto_headers(&mut reqs).set_single("x-content-type-options", value);
                let result = x_content_type_options_test(&reqs);
                assert_eq!(result.result, Expectation::XContentTypeOptionsHeaderInvalid, "{value}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn checks_for_nosniff() {
            let mut reqs = empty_requests(None);
            for value in ["nosniff", "nosniff "] {
                auto_headers(&mut reqs).set_single("x-content-type-options", value);
                let result = x_content_type_options_test(&reqs);
                assert_eq!(result.result, Expectation::XContentTypeOptionsNosniff, "{value:?}");
                assert!(result.pass);
            }
        }
    }

    #[test]
    fn no_auto_response_is_not_implemented_and_fails() {
        let mut reqs = empty_requests(None);
        reqs.http = None;
        reqs.https = None;
        let result = x_content_type_options_test(&reqs);
        assert_eq!(result.result, Expectation::XContentTypeOptionsNotImplemented);
        assert!(!result.pass);
    }
}
