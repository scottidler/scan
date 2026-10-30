// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/csp.js,
// test/csp.test.js).

//! The `content-security-policy` test: the header and meta-tag policies folded into one, then
//! judged on `unsafe-inline`, `unsafe-eval`, insecure schemes and `default-src 'none'`.

pub mod parser;

use super::headers::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, get_http_headers};
use super::js;
use super::retriever::Retrieval;
use super::types::Expectation;
use parser::{Csp, DUPLICATE_WARNINGS_KEY, parse_csp, parse_csp_meta};
use std::collections::{BTreeMap, BTreeSet};

const DANGEROUSLY_BROAD: [&str; 8] = [
    "ftp:",
    "http:",
    "https:",
    "*",
    "http://*",
    "http://*.*",
    "https://*",
    "https://*.*",
];
const UNSAFE_INLINE: [&str; 2] = ["'unsafe-inline'", "data:"];
const PASSIVE_DIRECTIVES: [&str; 2] = ["img-src", "media-src"];
const NONCES_HASHES: [&str; 4] = ["'sha256-", "'sha384-", "'sha512-", "'nonce-"];

/// What the policy allows, beyond the result (`Policy`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub anti_clickjacking: bool,
    pub default_none: bool,
    pub insecure_base_uri: bool,
    pub insecure_form_action: bool,
    pub insecure_scheme_active: bool,
    pub insecure_scheme_passive: bool,
    pub strict_dynamic: bool,
    pub unsafe_eval: bool,
    pub unsafe_inline: bool,
    pub unsafe_inline_style: bool,
    pub unsafe_objects: bool,
}

/// What the `content-security-policy` test found.
#[derive(Debug, Clone, PartialEq)]
pub struct CspOutput {
    pub result: Expectation,
    pub pass: bool,
    /// The effective policy, directive -> sorted sources.
    pub data: Option<BTreeMap<String, Vec<String>>>,
    /// A policy came from a header.
    pub http: bool,
    /// A policy came from a meta tag.
    pub meta: bool,
    pub policy: Option<Policy>,
    pub num_policies: usize,
}

/// Which source list a directive falls back to: its own, `default-src`, or `*` when neither is set.
/// The first two alias the map's entry, as upstream's shared `Set` objects do.
#[derive(Debug, Clone, Copy)]
enum SourceList {
    Directive(&'static str),
    Everything,
}

impl SourceList {
    fn resolve(csp: &Csp, directive: &'static str) -> Self {
        if csp.contains_key(directive) {
            SourceList::Directive(directive)
        } else if csp.contains_key("default-src") {
            SourceList::Directive("default-src")
        } else {
            SourceList::Everything
        }
    }

    fn sources(self, csp: &Csp) -> BTreeSet<String> {
        match self {
            SourceList::Directive(directive) => csp[directive].clone(),
            SourceList::Everything => BTreeSet::from(["*".to_string()]),
        }
    }
}

/// `splitCspHeaders`: a combined header is a comma-separated list of policies.
fn split_policies(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .flat_map(|v| v.split(',').map(|s| js::trim(s).to_string()))
        .collect()
}

fn starts_with_nonce_or_hash(sources: &BTreeSet<String>) -> bool {
    sources.iter().any(|s| NONCES_HASHES.iter().any(|p| s.starts_with(p)))
}

fn intersects(sources: &BTreeSet<String>, set: &[&str]) -> bool {
    sources.iter().any(|s| set.contains(&s.as_str()))
}

fn intersects_broad_or_inline(sources: &BTreeSet<String>) -> bool {
    intersects(sources, &DANGEROUSLY_BROAD) || intersects(sources, &UNSAFE_INLINE)
}

fn is_insecure_scheme(source: &str) -> bool {
    source.starts_with("http:") || source.starts_with("ftp:")
}

/// `contentSecurityPolicyTest`.
pub fn content_security_policy_test(retrieval: &Retrieval) -> CspOutput {
    let expectation = Expectation::CspImplementedWithNoUnsafe;
    let mut output = CspOutput {
        result: Expectation::CspNotImplemented,
        pass: false,
        data: None,
        http: false,
        meta: false,
        policy: None,
        num_policies: 0,
    };
    let Some(session) = retrieval.auto() else {
        return output;
    };
    let response = &session.response;

    let http_policies = split_policies(&get_http_headers(Some(response), CONTENT_SECURITY_POLICY));
    let meta_values: Vec<&str> = retrieval
        .meta
        .content_security_policy
        .iter()
        .map(String::as_str)
        .collect();
    let meta_policies = split_policies(&meta_values);
    output.num_policies = http_policies.len() + meta_policies.len();

    let all_policies: Vec<String> = http_policies.iter().chain(&meta_policies).cloned().collect();
    let Ok(mut csp) = parse_csp(&all_policies) else {
        output.result = Expectation::CspHeaderInvalid;
        return output;
    };
    let http_only = parse_csp(&http_policies).unwrap_or_default();
    let meta_csp = parse_csp_meta(&meta_policies).unwrap_or_default();

    // A meta tag holding only directives a meta tag may not set counts as no policy.
    if http_only.len() + meta_csp.len() == 0 {
        output.result = if response.headers.is_truthy(CONTENT_SECURITY_POLICY_REPORT_ONLY) {
            Expectation::CspNotImplementedButReportingEnabled
        } else {
            Expectation::CspNotImplemented
        };
        return output;
    }

    let mut policy = Policy::default();
    let mut result: Option<Expectation> = None;
    output.http = !http_policies.is_empty();
    output.meta = !meta_policies.is_empty();

    let base_uri = csp
        .get("base-uri")
        .cloned()
        .unwrap_or_else(|| BTreeSet::from(["*".to_string()]));
    // frame-ancestors only counts from a header.
    let frame_ancestors = http_only
        .get("frame-ancestors")
        .cloned()
        .unwrap_or_else(|| BTreeSet::from(["*".to_string()]));
    let form_action = csp
        .get("form-action")
        .cloned()
        .unwrap_or_else(|| BTreeSet::from(["*".to_string()]));
    let object_list = SourceList::resolve(&csp, "object-src");
    let script_list = SourceList::resolve(&csp, "script-src");
    let style_list = SourceList::resolve(&csp, "style-src");

    // A nonce or hash makes 'unsafe-inline' inert.
    for list in [script_list, style_list] {
        if let SourceList::Directive(directive) = list
            && let Some(sources) = csp.get_mut(directive)
            && starts_with_nonce_or_hash(sources)
        {
            sources.remove("'unsafe-inline'");
        }
    }

    // 'strict-dynamic' with a nonce or hash drops scheme sources, 'self' and 'unsafe-inline'.
    let script = script_list.sources(&csp);
    if starts_with_nonce_or_hash(&script) && script.contains("'strict-dynamic'") {
        if let SourceList::Directive(directive) = script_list
            && let Some(sources) = csp.get_mut(directive)
        {
            sources.retain(|source| {
                !(DANGEROUSLY_BROAD.iter().any(|broad| source.starts_with(broad))
                    || source == "'self'"
                    || source == "'unsafe-inline'")
            });
        }
        policy.strict_dynamic = true;
    } else if script.contains("'strict-dynamic'") && result.is_none() {
        result = Some(Expectation::CspHeaderInvalid);
    }

    let script_src = script_list.sources(&csp);
    let style_src = style_list.sources(&csp);
    let object_src = object_list.sources(&csp);

    let mut active_sources: Vec<&String> = csp
        .iter()
        .filter(|(directive, _)| !PASSIVE_DIRECTIVES.contains(&directive.as_str()) && *directive != "script-src")
        .flat_map(|(_, sources)| sources)
        .collect();
    active_sources.extend(&script_src);
    let passive_sources: Vec<&String> = PASSIVE_DIRECTIVES
        .iter()
        .flat_map(|directive| {
            csp.get(*directive)
                .or_else(|| csp.get("default-src"))
                .into_iter()
                .flatten()
        })
        .collect();
    let https = session.url.scheme() == "https";

    let set = |finding: Expectation, result: &mut Option<Expectation>| {
        if result.is_none() {
            *result = Some(finding);
        }
    };

    if intersects_broad_or_inline(&script_src) || intersects(&object_src, &DANGEROUSLY_BROAD) {
        set(Expectation::CspImplementedWithUnsafeInline, &mut result);
        policy.unsafe_inline = true;
    }
    if https && active_sources.iter().any(|s| is_insecure_scheme(s)) {
        set(Expectation::CspImplementedWithInsecureScheme, &mut result);
        policy.insecure_scheme_active = true;
    }
    if script_src.contains("'unsafe-eval'") || style_src.contains("'unsafe-eval'") {
        set(Expectation::CspImplementedWithUnsafeEval, &mut result);
        policy.unsafe_eval = true;
    }
    if https && passive_sources.iter().any(|s| is_insecure_scheme(s)) {
        set(
            Expectation::CspImplementedWithInsecureSchemeInPassiveContentOnly,
            &mut result,
        );
        policy.insecure_scheme_passive = true;
    }
    if intersects_broad_or_inline(&style_src) {
        set(Expectation::CspImplementedWithUnsafeInlineInStyleSrcOnly, &mut result);
        policy.unsafe_inline_style = true;
    }
    if csp
        .get("default-src")
        .is_some_and(|sources| sources.len() == 1 && sources.contains("'none'"))
    {
        set(Expectation::CspImplementedWithNoUnsafeDefaultSrcNone, &mut result);
        policy.default_none = true;
    } else {
        set(Expectation::CspImplementedWithNoUnsafe, &mut result);
    }

    policy.anti_clickjacking = !intersects(&frame_ancestors, &DANGEROUSLY_BROAD);
    policy.insecure_base_uri = intersects_broad_or_inline(&base_uri);
    policy.insecure_form_action = intersects(&form_action, &DANGEROUSLY_BROAD);
    policy.unsafe_objects = intersects(&object_src, &DANGEROUSLY_BROAD);

    let mut result = result.unwrap_or(Expectation::CspImplementedWithNoUnsafe);
    if [
        expectation,
        Expectation::CspImplementedWithNoUnsafeDefaultSrcNone,
        Expectation::CspImplementedWithUnsafeInlineInStyleSrcOnly,
        Expectation::CspImplementedWithInsecureSchemeInPassiveContentOnly,
    ]
    .contains(&result)
    {
        output.pass = true;
        if csp.contains_key(DUPLICATE_WARNINGS_KEY) {
            result = Expectation::CspImplementedButDuplicateDirectives;
        }
    }

    output.data = Some(
        csp.iter()
            .filter(|(directive, _)| *directive != DUPLICATE_WARNINGS_KEY)
            .map(|(directive, sources)| (directive.clone(), sources.iter().cloned().collect()))
            .collect(),
    );
    output.result = result;
    output.policy = Some(policy);
    log::debug!(
        "[observatory::csp] content_security_policy_test: policies={} http={} meta={} result={}",
        output.num_policies,
        output.http,
        output.meta,
        output.result
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests};

    fn with_header(html: Option<&str>, value: &str) -> CspOutput {
        let mut requests = empty_requests(html);
        auto_headers(&mut requests).set_single("Content-Security-Policy", value);
        content_security_policy_test(&requests)
    }

    fn policy_of(value: &str) -> Policy {
        with_header(None, value).policy.expect("a policy")
    }

    /// Ported from test/csp.test.js, one test per upstream `it(`; an `it(` inside a loop is one
    /// test over the loop's values.
    mod upstream {
        use super::*;

        #[test]
        fn missing() {
            let result = content_security_policy_test(&empty_requests(None));
            assert_eq!(result.result, Expectation::CspNotImplemented);
            assert_eq!(result.num_policies, 0);
            assert!(!result.pass);
        }

        #[test]
        fn header_invalid() {
            for value in [
                "  ",
                "",
                "default-src 'none'; default-src 'none'",
                "default-src 'none'; img-src 'self'; default-src 'none'",
                "default-src 'none'; script-src 'strict-dynamic'",
                "defa",
            ] {
                let result = with_header(None, value);
                assert_eq!(result.result, Expectation::CspHeaderInvalid, "{value:?}");
                assert_eq!(result.num_policies, 1, "{value:?}");
                assert!(!result.pass, "{value:?}");
            }
        }

        #[test]
        fn insecure_scheme_broad_and_unsafe() {
            for value in [
                "default-src 'none'; script-src https://*",
                "default-src 'none'; script-src 'unsafe-inline'",
            ] {
                let result = with_header(None, value);
                assert_eq!(result.result, Expectation::CspImplementedWithUnsafeInline, "{value}");
                assert!(!result.pass);
                assert!(result.policy.unwrap().unsafe_inline);
            }
        }

        #[test]
        fn insecure_scheme() {
            for value in [
                "default-src http://mozilla.org",
                "default-src 'none'; script-src http://mozilla.org",
                "default-src 'none'; script-src http://mozilla.org",
                "default-src 'none'; script-src ftp://mozilla.org",
            ] {
                let result = with_header(None, value);
                assert_eq!(result.result, Expectation::CspImplementedWithInsecureScheme, "{value}");
                assert!(!result.pass);
                assert!(result.policy.unwrap().insecure_scheme_active);
            }
        }

        #[test]
        fn insecure_scheme_in_passive_content_only() {
            for value in [
                "default-src 'none'; img-src http://mozilla.org",
                "default-src 'self'; img-src ftp:",
                "default-src 'self'; img-src http:",
                "default-src 'none'; img-src https:; media-src http://mozilla.org",
                "default-src 'none'; img-src http: https:; script-src 'self'; style-src 'self'",
                "default-src 'none'; img-src 'none'; media-src http:; script-src 'self'; style-src 'self'",
                "default-src 'none'; img-src 'none'; media-src http:; script-src 'self'; style-src 'unsafe-inline'",
            ] {
                let result = with_header(None, value);
                assert_eq!(
                    result.result,
                    Expectation::CspImplementedWithInsecureSchemeInPassiveContentOnly,
                    "{value}"
                );
                assert!(result.pass);
                assert!(result.policy.unwrap().insecure_scheme_passive);
            }
        }

        #[test]
        fn unsafe_inline() {
            for value in [
                "script-src 'unsafe-inline'",
                "script-src data:",
                "script-src http:",
                "script-src ftp:",
                "default-src 'unsafe-inline'",
                "default-src 'UNSAFE-INLINE'",
                "upgrade-insecure-requests",
                "script-src 'none'",
                "script-src https:",
                "script-src https://mozilla.org https:",
                "default-src https://mozilla.org https:",
                "default-src 'none'; script-src *",
                "default-src *; script-src *; object-src 'none'",
                "default-src 'none'; script-src 'none'; object-src *",
                "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'",
                "default-src 'none'; script-src 'unsafe-inline' http:",
                "object-src https:; script-src 'none'",
            ] {
                let result = with_header(None, value);
                assert_eq!(result.result, Expectation::CspImplementedWithUnsafeInline, "{value}");
                assert!(!result.pass);
                assert!(result.policy.unwrap().unsafe_inline);
            }
        }

        #[test]
        fn unsafe_eval() {
            let result = with_header(None, "default-src 'none'; script-src 'unsafe-eval'");
            assert_eq!(result.result, Expectation::CspImplementedWithUnsafeEval);
            assert_eq!(result.data.as_ref().unwrap()["script-src"], vec!["'unsafe-eval'"]);
            assert!(!result.pass);
            assert!(result.policy.unwrap().unsafe_eval);
        }

        #[test]
        fn unsafe_inline_in_style_src_only() {
            for value in [
                "object-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
                "default-src 'none'; script-src https://mozilla.org; style-src 'unsafe-inline'",
                "default-src 'unsafe-inline'; script-src https://mozilla.org",
                "default-src 'none';;; ;;;style-src 'self' 'unsafe-inline'",
                "default-src 'none'; style-src data:",
                "default-src 'none'; style-src *",
                "default-src 'none'; style-src https:",
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB=' 'unsafe-inline'",
            ] {
                let result = with_header(None, value);
                assert_eq!(
                    result.result,
                    Expectation::CspImplementedWithUnsafeInlineInStyleSrcOnly,
                    "{value}"
                );
                assert!(result.pass);
                assert!(result.policy.unwrap().unsafe_inline_style);
            }
        }

        #[test]
        fn no_unsafe() {
            for value in [
                "default-src https://mozilla.org",
                "default-src https://mozilla.org;;; ;;;script-src 'none'",
                "object-src 'none'; script-src https://mozilla.org; style-src https://mozilla.org; upgrade-insecure-requests;",
                "object-src 'none'; script-src 'strict-dynamic' 'nonce-abc' 'unsafe-inline'; style-src 'none'",
                "object-src 'none'; style-src 'self';script-src 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBA='",
                "object-src 'none'; style-src 'self'; script-src 'unsafe-inline' 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBA=''sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB='",
                "object-src 'none'; script-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'; style-src 'none'",
                "default-src https://mozilla.org; style-src 'unsafe-inline' 'nonce-abc123' 'unsafe-inline'",
                "default-src https://mozilla.org; style-src 'unsafe-inline' 'sha256-hqBEA/HXB3aJU2FgOnYN8rkAgEVgyfi3Vs1j2/XMPBB=' 'unsafe-inline'",
            ] {
                let result = with_header(None, value);
                assert_eq!(result.result, Expectation::CspImplementedWithNoUnsafe, "{value}");
                assert!(result.pass);
            }
        }

        #[test]
        fn no_unsafe_default_src_none() {
            let result = with_header(Some("test-parse-http-equiv-headers-csp2.html"), "default-src http:");
            assert_eq!(result.result, Expectation::CspImplementedWithNoUnsafeDefaultSrcNone);
            assert_eq!(result.num_policies, 2);
            assert!(result.http && result.meta && result.pass);

            for value in [
                "default-src",
                "default-src 'none'; script-src 'strict-dynamic' 'nonce-abc123' 'unsafe-inline'",
                "default-src 'none'; script-src https://mozilla.org; style-src https://mozilla.org; upgrade-insecure-requests;",
                "default-src 'none'; object-src https://mozilla.org",
            ] {
                let result = with_header(None, value);
                assert_eq!(
                    result.result,
                    Expectation::CspImplementedWithNoUnsafeDefaultSrcNone,
                    "{value}"
                );
                assert_eq!(result.num_policies, 1);
                assert!(result.http);
                assert!(!result.meta);
                assert!(result.pass);
                assert!(result.policy.unwrap().default_none);
            }

            let result = content_security_policy_test(&empty_requests(Some("test-parse-http-equiv-headers-csp1.html")));
            assert_eq!(result.result, Expectation::CspImplementedWithNoUnsafeDefaultSrcNone);
            assert_eq!(result.num_policies, 1);
            assert!(!result.http && result.meta && result.pass);

            let result = content_security_policy_test(&empty_requests(Some(
                "test-parse-http-equiv-headers-csp-multiple-http-equiv1.html",
            )));
            assert_eq!(result.result, Expectation::CspImplementedWithNoUnsafeDefaultSrcNone);
            assert_eq!(result.num_policies, 4);
            assert!(!result.http && result.meta && result.pass);

            for (file, header) in [
                ("test-parse-http-equiv-headers-csp1.html", "default-src 'none'"),
                ("test-parse-http-equiv-headers-csp2.html", "default-src 'none'"),
                ("test-parse-http-equiv-headers-csp1.html", "img-src 'none'"),
            ] {
                let result = with_header(Some(file), header);
                assert_eq!(
                    result.result,
                    Expectation::CspImplementedWithNoUnsafeDefaultSrcNone,
                    "{file} {header}"
                );
                assert_eq!(result.num_policies, 2);
                assert!(result.http && result.meta && result.pass);
            }
        }

        #[test]
        fn strict_dynamic() {
            for value in [
                "default-src 'none'; script-src 'strict-dynamic' 'nonce-abc123'",
                "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123'",
                "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123' https://*",
                "default-src 'none'; script-src 'strict-dynamic' 'sha256-abc123' 'unsafe-inline'",
            ] {
                let result = with_header(None, value);
                assert_eq!(
                    result.result,
                    Expectation::CspImplementedWithNoUnsafeDefaultSrcNone,
                    "{value}"
                );
                assert!(result.policy.unwrap().strict_dynamic);
            }
        }

        #[test]
        fn policy_analysis() {
            for value in [
                "default-src 'none'",
                "frame-ancestors *",
                "frame-ancestors http:",
                "frame-ancestors https:",
            ] {
                assert!(!policy_of(value).anti_clickjacking, "{value}");
            }
            assert!(policy_of("default-src *; frame-ancestors 'none'").anti_clickjacking);

            for value in [
                "default-src 'none'; base-uri *; object-src *",
                "default-src 'none'; base-uri https:; object-src https:",
                "default-src *",
            ] {
                let policy = policy_of(value);
                assert!(policy.insecure_base_uri, "{value}");
                assert!(policy.unsafe_objects, "{value}");
            }

            for value in [
                "default-src *; base-uri 'none'",
                "default-src 'none'; base-uri 'self'",
                "default-src 'none'; base-uri https://mozilla.org",
            ] {
                assert!(!policy_of(value).insecure_base_uri, "{value}");
            }

            for value in [
                "default-src * http: https: data: 'unsafe-inline' 'unsafe-eval'",
                "default-src 'none'; img-src http:",
                "default-src 'none' https://mozilla.org; img-src http://mozilla.org",
                "default-src https:; media-src http://mozilla.org; script-src http:",
            ] {
                assert!(policy_of(value).insecure_scheme_passive, "{value}");
            }

            for value in [
                "default-src *; form-action 'none'",
                "default-src *; form-action 'self'",
                "default-src 'none'; form-action 'self' https://mozilla.org",
                "form-action 'self' https://mozilla.org",
            ] {
                assert!(!policy_of(value).insecure_form_action, "{value}");
            }

            for value in ["default-src *", "default-src 'none'", "form-action https:"] {
                assert!(policy_of(value).insecure_form_action, "{value}");
            }
        }

        #[test]
        fn report_only() {
            let mut requests = empty_requests(None);
            auto_headers(&mut requests).set_single(
                "Content-Security-Policy-Report-Only",
                "default-src 'none'; report-to /_/csp-reports",
            );
            let result = content_security_policy_test(&requests);
            assert_eq!(result.result, Expectation::CspNotImplementedButReportingEnabled);
        }

        #[test]
        fn multiple_csp_headers_combined_per_rfc_9110_are_not_treated_as_invalid() {
            let result = with_header(
                None,
                "default-src 'none'; script-src 'self', default-src 'none'; script-src 'self'",
            );
            assert_ne!(result.result, Expectation::CspHeaderInvalid);
            assert_eq!(result.num_policies, 2);
            assert!(result.pass);
            let expected: BTreeMap<String, Vec<String>> = [
                ("default-src".to_string(), vec!["'none'".to_string()]),
                ("script-src".to_string(), vec!["'self'".to_string()]),
            ]
            .into();
            assert_eq!(result.data.unwrap(), expected);
        }

        #[test]
        fn multiple_csp_headers_with_differing_policies_produce_correct_intersection() {
            let result = with_header(
                None,
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline', default-src 'none'; style-src 'self', default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            );
            assert_ne!(result.result, Expectation::CspHeaderInvalid);
            assert_eq!(result.num_policies, 3);
            assert!(!result.policy.as_ref().unwrap().unsafe_inline_style);
            assert!(result.pass);
            let expected: BTreeMap<String, Vec<String>> = [
                ("default-src".to_string(), vec!["'none'".to_string()]),
                ("script-src".to_string(), vec!["'self'".to_string()]),
                ("style-src".to_string(), vec!["'self'".to_string()]),
            ]
            .into();
            assert_eq!(result.data.unwrap(), expected);
        }

        #[test]
        fn ignore_frame_anchestors_in_http_equiv() {
            let mut requests = empty_requests(Some("test-parse-http-equiv-headers-not-allowed.html"));
            let result = content_security_policy_test(&requests);
            assert_eq!(result.result, Expectation::CspNotImplemented);
            assert!(!result.pass);
            auto_headers(&mut requests).set_single("Content-Security-Policy", "frame-anchestors 'none'");
            let result = content_security_policy_test(&requests);
            assert_eq!(result.result, Expectation::CspImplementedWithUnsafeInline);
            assert!(!result.pass);
        }
    }

    /// Duplicate `report-uri` directives pass, under their own result.
    #[test]
    fn duplicate_report_uri_reads_duplicate_directives() {
        let result = with_header(None, "default-src 'none'; report-uri /a; report-uri /b");
        assert_eq!(result.result, Expectation::CspImplementedButDuplicateDirectives);
        assert!(result.pass);
    }

    /// Over plain http an `http:` source is not an insecure scheme.
    #[test]
    fn insecure_schemes_count_only_on_an_https_session() {
        let mut requests = empty_requests(None);
        requests.https = None;
        auto_headers(&mut requests).set_single("Content-Security-Policy", "default-src 'none'; img-src http:");
        let result = content_security_policy_test(&requests);
        assert_eq!(result.result, Expectation::CspImplementedWithNoUnsafeDefaultSrcNone);
    }
}
