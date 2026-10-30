// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (emptyRequests and setHeader in
// test/helpers.js).

//! The ported tests' starting point: a retrieval of `mozilla.org` where every session answered 200
//! `text/html`, optionally with one of upstream's `test/files` pages as the body.

use super::headers::Headers;
use super::hsts::HstsPreload;
use super::html::parse_http_equiv;
use super::retriever::{RedirectEntry, Response, Retrieval, Session};
use url::Url;

/// One of upstream's `test/files` pages (renamed with hyphens), by file name.
pub fn html_file(name: &str) -> &'static str {
    match name {
        "test-content-sri-impl-external-http.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-impl-external-http.html")
        }
        "test-content-sri-impl-external-https1.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-impl-external-https1.html")
        }
        "test-content-sri-impl-external-https2.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-impl-external-https2.html")
        }
        "test-content-sri-impl-external-noproto.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-impl-external-noproto.html")
        }
        "test-content-sri-impl-sameorigin.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-impl-sameorigin.html")
        }
        "test-content-sri-no-scripts.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-no-scripts.html")
        }
        "test-content-sri-notimpl-external-http.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-notimpl-external-http.html")
        }
        "test-content-sri-notimpl-external-https.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-notimpl-external-https.html")
        }
        "test-content-sri-notimpl-external-noproto.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-notimpl-external-noproto.html")
        }
        "test-content-sri-sameorigin1.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-sameorigin1.html")
        }
        "test-content-sri-sameorigin2.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-sameorigin2.html")
        }
        "test-content-sri-sameorigin3.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-content-sri-sameorigin3.html")
        }
        "test-parse-http-equiv-headers-case-insensitivity.html" => include_str!(
            "../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-case-insensitivity.html"
        ),
        "test-parse-http-equiv-headers-csp1.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-csp1.html")
        }
        "test-parse-http-equiv-headers-csp2.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-csp2.html")
        }
        "test-parse-http-equiv-headers-csp-multiple-http-equiv1.html" => include_str!(
            "../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-csp-multiple-http-equiv1.html"
        ),
        "test-parse-http-equiv-headers-not-allowed.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-not-allowed.html")
        }
        "test-parse-http-equiv-headers-referrer1.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-referrer1.html")
        }
        "test-parse-http-equiv-headers-x-frame-options.html" => {
            include_str!("../../../tests/fixtures/observatory/files/test-parse-http-equiv-headers-x-frame-options.html")
        }
        other => panic!("no observatory test file {other}"),
    }
}

fn redirects(entries: &[(&str, u16)]) -> Vec<RedirectEntry> {
    entries
        .iter()
        .map(|(url, status)| RedirectEntry {
            url: Url::parse(url).unwrap(),
            status: *status,
        })
        .collect()
}

/// A 200 `text/html` response with a verified certificate.
pub fn ok_response() -> Response {
    let mut headers = Headers::new();
    headers.set_single("Content-Type", "text/html");
    Response {
        status: 200,
        verified: true,
        headers,
    }
}

/// `emptyRequests(httpEquivFile)`.
pub fn empty_requests(html: Option<&str>) -> Retrieval {
    let body = html.map(html_file);
    Retrieval {
        host: "mozilla.org".to_string(),
        http: Some(Session {
            url: Url::parse("http://mozilla.org/").unwrap(),
            response: ok_response(),
            redirects: redirects(&[
                ("http://mozilla.org/", 301),
                ("https://mozilla.org/", 301),
                ("https://www.mozilla.org/", 200),
            ]),
        }),
        https: Some(Session {
            url: Url::parse("https://mozilla.org/").unwrap(),
            response: ok_response(),
            redirects: redirects(&[
                ("https://mozilla.org/", 301),
                ("https://www.mozilla.org/", 200),
                ("https://mozilla.org/", 301),
                ("https://www.mozilla.org/", 200),
                ("https://mozilla.org/robots.txt", 301),
                ("https://www.mozilla.org/robots.txt", 200),
            ]),
        }),
        cors: Some(ok_response()),
        cookies: Vec::new(),
        meta: body.map(parse_http_equiv).unwrap_or_default(),
        auto_body: body.map(str::to_string),
    }
}

/// The `auto` response's headers (`requests.responses.auto.headers`).
pub fn auto_headers(retrieval: &mut Retrieval) -> &mut Headers {
    let session = match retrieval.https.as_mut() {
        Some(session) => session,
        None => retrieval
            .http
            .as_mut()
            .expect("a retrieval with no session has no auto response"),
    };
    &mut session.response.headers
}

/// The `https` response's headers.
pub fn https_headers(retrieval: &mut Retrieval) -> &mut Headers {
    &mut retrieval.https.as_mut().expect("an https session").response.headers
}

/// The `http` session's redirect chain.
pub fn set_http_redirects(retrieval: &mut Retrieval, entries: &[(&str, u16)]) {
    retrieval.http.as_mut().expect("an http session").redirects = redirects(entries);
}

/// A list with nothing preloaded, which is what upstream's list says for `mozilla.org`.
pub fn no_preload() -> HstsPreload {
    HstsPreload::from_entries(Vec::new())
}
