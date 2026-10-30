// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/referrer-policy.js,
// test/referrer-policy.test.js).

//! The `referrer-policy` test: the last valid policy in the header followed by the meta tag.

use super::headers::{REFERRER_POLICY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

const GOODNESS: [&str; 4] = [
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
];
const BADNESS: [&str; 4] = [
    "origin",
    "origin-when-cross-origin",
    "unsafe-url",
    "no-referrer-when-downgrade",
];

/// What the `referrer-policy` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerOutput {
    pub result: Expectation,
    pub pass: bool,
    /// The header values, then the meta tag's, joined with `", "`.
    pub data: Option<String>,
    pub http: bool,
    pub meta: bool,
}

/// `referrerPolicyTest`.
pub fn referrer_policy_test(retrieval: &Retrieval) -> ReferrerOutput {
    let mut output = ReferrerOutput {
        result: Expectation::ReferrerPolicyNotImplemented,
        pass: false,
        data: None,
        http: false,
        meta: false,
    };
    let Some(response) = retrieval.auto_response() else {
        return output;
    };
    let http_headers = get_http_headers(Some(response), REFERRER_POLICY);
    let equiv_headers = &retrieval.meta.referrer_policy;
    output.http = !http_headers.is_empty();
    output.meta = !equiv_headers.is_empty();
    if !output.http && !output.meta {
        output.pass = true;
        return output;
    }

    // The meta tag comes last, so it takes precedence.
    let data = http_headers
        .iter()
        .copied()
        .chain(equiv_headers.iter().map(String::as_str))
        .collect::<Vec<&str>>()
        .join(", ");
    let is_valid = |p: &str| GOODNESS.contains(&p) || BADNESS.contains(&p);
    let policy = data
        .split(',')
        .map(|p| js::trim(&p.to_lowercase()).to_string())
        .rfind(|p| is_valid(p))
        .unwrap_or_default();
    output.result = if GOODNESS.contains(&policy.as_str()) {
        Expectation::ReferrerPolicyPrivate
    } else if BADNESS.contains(&policy.as_str()) {
        Expectation::ReferrerPolicyUnsafe
    } else {
        Expectation::ReferrerPolicyHeaderInvalid
    };
    output.data = Some(data);
    output.pass = [
        Expectation::ReferrerPolicyPrivate,
        Expectation::ReferrerPolicyNotImplemented,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::referrer] referrer_policy_test: http={} meta={} policy={:?} result={}",
        output.http,
        output.meta,
        policy,
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    /// Ported from test/referrer-policy.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_private_referrer_header() {
            let mut reqs = empty_requests(None);
            for v in [
                "no-referrer",
                "same-origin",
                "strict-origin",
                "STRICT-ORIGIN",
                "strict-origin-when-cross-origin",
            ] {
                auto_headers(&mut reqs).set_single("Referrer-Policy", v);
                let result = referrer_policy_test(&reqs);
                assert_eq!(result.result, Expectation::ReferrerPolicyPrivate, "{v}");
                assert!(result.http);
                assert!(!result.meta);
                assert!(result.pass);
            }

            let mut reqs = empty_requests(Some("test-parse-http-equiv-headers-referrer1.html"));
            let result = referrer_policy_test(&reqs);
            assert_eq!(result.result, Expectation::ReferrerPolicyPrivate);
            assert_eq!(result.data.as_deref(), Some("no-referrer, same-origin"));
            assert!(!result.http);
            assert!(result.meta);
            assert!(result.pass);

            auto_headers(&mut reqs).set_single("referrer-policy", "unsafe-url");
            let result = referrer_policy_test(&reqs);
            assert_eq!(result.result, Expectation::ReferrerPolicyPrivate);
            assert_eq!(result.data.as_deref(), Some("unsafe-url, no-referrer, same-origin"));
            assert!(result.http);
            assert!(result.meta);
            assert!(result.pass);
        }

        #[test]
        fn checks_for_missing_referrer_header() {
            let result = referrer_policy_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::ReferrerPolicyNotImplemented);
            assert!(result.pass);
        }

        #[test]
        fn checks_for_invalid_referrer_header() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set_single("referrer-policy", "whimsy");
            let result = referrer_policy_test(&reqs);
            assert_eq!(result.result, Expectation::ReferrerPolicyHeaderInvalid);
            assert!(!result.pass);
        }

        #[test]
        fn checks_for_unsafe_referrer_header() {
            let mut reqs = empty_requests(None);
            for policy in ["origin", "origin-when-cross-origin", "unsafe-url"] {
                auto_headers(&mut reqs).set_single("referrer-policy", policy);
                let result = referrer_policy_test(&reqs);
                assert_eq!(result.result, Expectation::ReferrerPolicyUnsafe, "{policy}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn checks_for_multiple_valid_referrer_headers() {
            let mut reqs = empty_requests(None);
            for policy in [
                "origin-when-cross-origin, no-referrer, unsafe-url",
                "no-referrer, unsafe-url",
            ] {
                auto_headers(&mut reqs).set_single("referrer-policy", policy);
                let result = referrer_policy_test(&reqs);
                assert_eq!(result.result, Expectation::ReferrerPolicyUnsafe, "{policy}");
                assert!(!result.pass);
            }
        }

        #[test]
        fn checks_for_multiple_referrer_headers_with_valid_and_invalid_mixed() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set_single("referrer-policy", "no-referrer, whimsy");
            let result = referrer_policy_test(&reqs);
            assert_eq!(result.result, Expectation::ReferrerPolicyPrivate);
            assert!(result.pass);
        }

        #[test]
        fn checks_for_multiple_invalid_referrer_headers() {
            let mut reqs = empty_requests(None);
            auto_headers(&mut reqs).set_single("referrer-policy", "whimsy, whimsy1, whimsy2");
            let result = referrer_policy_test(&reqs);
            assert_eq!(result.result, Expectation::ReferrerPolicyHeaderInvalid);
            assert!(!result.pass);
        }
    }

    /// The case-insensitivity page's `name="referRer"` meta counts as a referrer policy.
    #[test]
    fn a_meta_name_matches_case_insensitively() {
        let reqs = empty_requests(Some("test-parse-http-equiv-headers-case-insensitivity.html"));
        let result = referrer_policy_test(&reqs);
        assert_eq!(result.result, Expectation::ReferrerPolicyPrivate);
        assert!(result.meta);
    }
}
