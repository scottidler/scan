// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/cors.js,
// test/cors.test.js).

//! The `cross-origin-resource-sharing` test: the preflight's `Access-Control-Allow-Origin`.
//!
//! Production behavior wins over source (Phase 0c): upstream compares the allowed origin with the
//! request's `Origin` read from `response.request.headers`, a property Node's `ClientRequest` does
//! not have, so the deployed service never sees an origin and never grades universal access. The
//! port reads no request origin either: an echoed origin with credentials is restricted access.

use super::headers::{ACCESS_CONTROL_ALLOW_ORIGIN, get_first_http_header};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;

/// What the `cross-origin-resource-sharing` test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsOutput {
    pub result: Expectation,
    pub pass: bool,
    /// The allowed origin, lowercased.
    pub data: Option<String>,
}

/// `crossOriginResourceSharingTest`, as production runs it.
pub fn cross_origin_resource_sharing_test(retrieval: &Retrieval) -> CorsOutput {
    let expectation = Expectation::CrossOriginResourceSharingNotImplemented;
    let mut output = CorsOutput {
        result: Expectation::CrossOriginResourceSharingNotImplemented,
        pass: false,
        data: None,
    };
    if let Some(acao) =
        get_first_http_header(retrieval.cors.as_ref(), ACCESS_CONTROL_ALLOW_ORIGIN).filter(|acao| !acao.is_empty())
    {
        let data = js::trim(&js::slice(acao, 0, 256)).to_lowercase();
        output.result = if data == "*" {
            Expectation::CrossOriginResourceSharingImplementedWithPublicAccess
        } else {
            Expectation::CrossOriginResourceSharingImplementedWithRestrictedAccess
        };
        output.data = Some(data);
    }
    output.pass = [
        Expectation::CrossOriginResourceSharingImplementedWithPublicAccess,
        Expectation::CrossOriginResourceSharingImplementedWithRestrictedAccess,
        expectation,
    ]
    .contains(&output.result);
    log::debug!(
        "[observatory::cors] cross_origin_resource_sharing_test: preflight={} result={}",
        retrieval.cors.is_some(),
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::helpers::empty_requests;

    fn set_cors_header(reqs: &mut Retrieval, name: &str, value: &str) {
        reqs.cors.as_mut().unwrap().headers.set_single(name, value);
    }

    /// Ported from test/cors.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn checks_for_not_implemented() {
            let result = cross_origin_resource_sharing_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::CrossOriginResourceSharingNotImplemented);
            assert!(result.pass);
        }

        #[test]
        fn checks_for_public_access() {
            let mut reqs = empty_requests(None);
            set_cors_header(&mut reqs, "access-control-allow-origin", "*");
            let result = cross_origin_resource_sharing_test(&reqs);
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourceSharingImplementedWithPublicAccess
            );
            assert_eq!(result.data.as_deref(), Some("*"));
            assert!(result.pass);
        }

        #[test]
        fn checks_for_restricted_access() {
            let mut reqs = empty_requests(None);
            set_cors_header(&mut reqs, "access-control-allow-origin", "https://mozilla.org");
            let result = cross_origin_resource_sharing_test(&reqs);
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourceSharingImplementedWithRestrictedAccess
            );
            assert!(result.pass);
        }

        /// Inverted from upstream's "checks for universal access" (which expects universal access,
        /// failing): production never reads the request origin (Phase 0c, API scan 132239764), so
        /// an echoed origin with credentials grades restricted access and passes.
        #[test]
        fn checks_for_universal_access_grades_restricted_as_production_does() {
            let mut reqs = empty_requests(None);
            set_cors_header(
                &mut reqs,
                "access-control-allow-origin",
                "https://http-observatory.security.mozilla.org",
            );
            set_cors_header(&mut reqs, "access-control-allow-credentials", "true");
            let result = cross_origin_resource_sharing_test(&reqs);
            assert_eq!(
                result.result,
                Expectation::CrossOriginResourceSharingImplementedWithRestrictedAccess
            );
            assert!(result.pass);
        }
    }

    /// A preflight that got no 2xx answer is no preflight.
    #[test]
    fn no_preflight_response_is_not_implemented() {
        let mut reqs = empty_requests(None);
        reqs.cors = None;
        let result = cross_origin_resource_sharing_test(&reqs);
        assert_eq!(result.result, Expectation::CrossOriginResourceSharingNotImplemented);
        assert!(result.data.is_none());
    }
}
