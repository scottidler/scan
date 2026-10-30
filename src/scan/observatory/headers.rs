// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/headers.js, getHttpHeaders and
// getFirstHttpHeader in src/analyzer/utils.js, test/analyzer-utils.test.js).

//! Response headers as the analyzers read them: axios's merged header object, where a name maps to
//! one string (Node joins most duplicates with `", "`) or to a list (`set-cookie`).

use super::retriever::Response;

pub const CONTENT_SECURITY_POLICY: &str = "content-security-policy";
pub const CONTENT_SECURITY_POLICY_REPORT_ONLY: &str = "content-security-policy-report-only";
pub const REFERRER_POLICY: &str = "referrer-policy";
pub const SET_COOKIE: &str = "set-cookie";
pub const ACCESS_CONTROL_ALLOW_ORIGIN: &str = "access-control-allow-origin";
pub const CROSS_ORIGIN_RESOURCE_POLICY: &str = "cross-origin-resource-policy";
pub const CROSS_ORIGIN_OPENER_POLICY: &str = "cross-origin-opener-policy";
pub const CROSS_ORIGIN_EMBEDDER_POLICY: &str = "cross-origin-embedder-policy";
pub const STRICT_TRANSPORT_SECURITY: &str = "strict-transport-security";
pub const CONTENT_TYPE: &str = "content-type";
pub const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";
pub const X_FRAME_OPTIONS: &str = "x-frame-options";

/// One header's value: a single string, or a list (`set-cookie`, or a value set as an array).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    Single(String),
    List(Vec<String>),
}

/// Headers in arrival order, one entry per case-insensitive name, as `AxiosHeaders` keeps them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, HeaderValue)>,
}

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// `AxiosHeaders.set`: replaces any value under the same case-insensitive name.
    pub fn set(&mut self, name: &str, value: HeaderValue) {
        match self.entries.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((name.to_string(), value)),
        }
    }

    /// Shorthand for `set(name, HeaderValue::Single(value))`.
    pub fn set_single(&mut self, name: &str, value: &str) {
        self.set(name, HeaderValue::Single(value.to_string()));
    }

    /// `AxiosHeaders.get(name)` tested for truthiness: a list is truthy even when empty, a string
    /// only when non-empty.
    pub fn is_truthy(&self, name: &str) -> bool {
        match self.entries.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            Some((_, HeaderValue::Single(value))) => !value.is_empty(),
            Some((_, HeaderValue::List(_))) => true,
            None => false,
        }
    }

    /// Every value under `name`, case-insensitively, lists flattened.
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| match value {
                HeaderValue::Single(v) => vec![v.as_str()],
                HeaderValue::List(vs) => vs.iter().map(String::as_str).collect(),
            })
            .collect()
    }
}

/// `getHttpHeaders`: every value of `name` on `response`, none for an absent response.
pub fn get_http_headers<'a>(response: Option<&'a Response>, name: &str) -> Vec<&'a str> {
    response.map(|r| r.headers.all(name)).unwrap_or_default()
}

/// `getFirstHttpHeader`.
pub fn get_first_http_header<'a>(response: Option<&'a Response>, name: &str) -> Option<&'a str> {
    get_http_headers(response, name).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_response() -> Response {
        let mut headers = Headers::new();
        headers.set_single("Content-Type", "text/html");
        Response {
            status: 200,
            verified: true,
            headers,
        }
    }

    fn list(values: &[&str]) -> HeaderValue {
        HeaderValue::List(values.iter().map(|v| v.to_string()).collect())
    }

    /// Ported from test/analyzer-utils.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn gets_all_http_headers_for_a_header_name() {
            let response = empty_response();
            assert_eq!(get_http_headers(Some(&response), "content-type"), vec!["text/html"]);
            assert_eq!(get_http_headers(Some(&response), "Content-Type"), vec!["text/html"]);
            assert!(get_http_headers(Some(&response), "Non-Existing").is_empty());
        }

        #[test]
        fn gets_headers_correctly_when_set_multiple_times() {
            let mut response = empty_response();
            response.headers.set_single("X-Test", "hello");
            assert_eq!(get_http_headers(Some(&response), "x-test").len(), 1);
            response.headers.set("X-Test", list(&["hello", "world", "1234"]));
            assert_eq!(
                get_http_headers(Some(&response), "x-test"),
                vec!["hello", "world", "1234"]
            );
        }

        #[test]
        fn returns_an_empty_array_if_the_passed_in_value_is_null() {
            assert!(get_http_headers(None, "content-type").is_empty());
        }

        #[test]
        fn gets_the_first_header() {
            let response = empty_response();
            assert_eq!(
                get_first_http_header(Some(&response), "content-Type"),
                Some("text/html")
            );
        }

        #[test]
        fn gets_the_first_header_on_multiple_values() {
            let mut response = empty_response();
            response.headers.set("X-test", list(&["hello", "world", "1234"]));
            assert_eq!(get_first_http_header(Some(&response), "x-test"), Some("hello"));
        }
    }

    #[test]
    fn an_empty_string_is_falsy_and_a_list_is_truthy() {
        let mut headers = Headers::new();
        headers.set_single("A", "");
        headers.set("B", HeaderValue::List(vec![]));
        assert!(!headers.is_truthy("a"));
        assert!(headers.is_truthy("b"));
        assert!(!headers.is_truthy("c"));
    }
}
