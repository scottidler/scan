// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308
// (src/analyzer/tests/cross-origin-resource-policy.js, test/cross-origin-resource-policy.test.js).

//! The `cross-origin-resource-policy` test. Upstream also reads a CORP meta tag, which its meta
//! parser never records, so only the header counts.

use super::headers::{CROSS_ORIGIN_RESOURCE_POLICY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

/// What the `cross-origin-resource-policy` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<String>,
    pub http: bool,
}

/// `crossOriginResourcePolicyTest`.
pub fn cross_origin_resource_policy_test(retrieval: &Retrieval) -> CorpOutput {
    let expectation = Expectation::CrossOriginResourcePolicyImplementedWithSameSite;
    let mut output = CorpOutput {
        result: Expectation::CrossOriginResourcePolicyNotImplemented,
        pass: false,
        data: None,
        http: false,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    let header = get_http_headers(Some(response), CROSS_ORIGIN_RESOURCE_POLICY).join(", ");
    output.http = !header.is_empty();
    if output.http {
        let corp = js::trim(&js::slice(&header, 0, 256)).to_lowercase();
        if !corp.is_empty() {
            output.result = match corp.as_str() {
                "same-site" => Expectation::CrossOriginResourcePolicyImplementedWithSameSite,
                "same-origin" => Expectation::CrossOriginResourcePolicyImplementedWithSameOrigin,
                "cross-origin" => Expectation::CrossOriginResourcePolicyImplementedWithCrossOrigin,
                _ => Expectation::CrossOriginResourcePolicyHeaderInvalid,
            };
            output.data = Some(corp);
        }
    }
    output.pass = [
        expectation,
        Expectation::CrossOriginResourcePolicyNotImplemented,
        Expectation::CrossOriginResourcePolicyImplementedWithSameSite,
        Expectation::CrossOriginResourcePolicyImplementedWithSameOrigin,
        Expectation::CrossOriginResourcePolicyImplementedWithCrossOrigin,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::corp] cross_origin_resource_policy_test: result={}",
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::headers::HeaderValue;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    fn with_header(value: &str) -> CorpOutput {
        let mut reqs = empty_requests(None);
        auto_headers(&mut reqs).set_single("cross-origin-resource-policy", value);
        cross_origin_resource_policy_test(&reqs)
    }

    /// Ported from test/cross-origin-resource-policy.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_missing() {
            let result = cross_origin_resource_policy_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::CrossOriginResourcePolicyNotImplemented);
            assert!(result.pass);
        }

        #[test]
        fn checks_header_validity() {
            let result = with_header("whimsy");
            assert_eq!(result.result, Expectation::CrossOriginResourcePolicyHeaderInvalid);
            assert!(!result.pass);
        }

        #[test]
        fn checks_for_same_site() {
            let result = with_header("same-site");
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourcePolicyImplementedWithSameSite
            );
            assert!(result.pass);
        }

        #[test]
        fn checks_for_same_origin() {
            let result = with_header("same-origin");
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourcePolicyImplementedWithSameOrigin
            );
            assert!(result.pass);
        }

        #[test]
        fn checks_for_cross_origin() {
            let result = with_header("cross-origin");
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourcePolicyImplementedWithCrossOrigin
            );
            assert!(result.pass);
        }

        #[test]
        fn checks_for_multiple_headers() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set(
                "cross-origin-resource-policy",
                HeaderValue::List(vec!["same-origin".to_string(), "cross-origin".to_string()]),
            );
            let result = cross_origin_resource_policy_test(&reqs);
            assert_eq!(result.result, Expectation::CrossOriginResourcePolicyHeaderInvalid);
            assert_eq!(result.data.as_deref(), Some("same-origin, cross-origin"));
            assert!(!result.pass);
        }
    }

    /// A whitespace-only header is present but holds no policy: not implemented.
    #[test]
    fn a_blank_header_is_not_implemented() {
        let result = with_header("   ");
        assert_eq!(result.result, Expectation::CrossOriginResourcePolicyNotImplemented);
        assert!(result.http);
    }
}
