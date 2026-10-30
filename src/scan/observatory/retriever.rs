// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (the `Requests`/`Responses` shapes in
// src/types.js and what src/retriever/retriever.js stores in them).

//! What one Observatory retrieval collected: the analyzers' whole input. The analyzers are pure
//! functions of a [`Retrieval`]; filling one over the network is the retriever's job.

use super::cookies::Cookie;
use super::headers::Headers;
use super::html::MetaTags;
use url::Url;

/// One HTTP response as the analyzers read it.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    /// `false` when the certificate chain failed and the session retried without verification.
    pub verified: bool,
    pub headers: Headers,
}

/// One hop of a session's redirect chain: the URL requested and the status it answered.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectEntry {
    pub url: Url,
    pub status: u16,
}

/// One session (`http://host/` or `https://host/`) that got a final response.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    /// The URL the session started from.
    pub url: Url,
    /// The final response, after the redirects.
    pub response: Response,
    /// Every hop, the first request included (`redirectHistory`).
    pub redirects: Vec<RedirectEntry>,
}

/// One retrieval of a host. A session that got no response is `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct Retrieval {
    /// The graded host (`site.hostname`), lowercase.
    pub host: String,
    pub http: Option<Session>,
    pub https: Option<Session>,
    /// The CORS preflight's response; `None` for no answer or a non-2xx one (Phase 0b).
    pub cors: Option<Response>,
    /// The `auto` session's cookie jar, every accepted cookie whatever its expiry (Phase 0c).
    pub cookies: Vec<Cookie>,
    /// Meta tags parsed from the `auto` body; empty when that body is not HTML.
    pub meta: MetaTags,
    /// The `auto` response's body (`resources.path`).
    pub auto_body: Option<String>,
}

impl Retrieval {
    /// The `auto` session: https when it answered, else http.
    pub fn auto(&self) -> Option<&Session> {
        self.https.as_ref().or(self.http.as_ref())
    }

    /// The `auto` session's final response.
    pub fn auto_response(&self) -> Option<&Response> {
        self.auto().map(|session| &session.response)
    }

    /// The `http` session's redirect chain, empty without one.
    pub fn http_redirects(&self) -> &[RedirectEntry] {
        self.http.as_ref().map_or(&[], |session| session.redirects.as_slice())
    }

    /// The `https` session's redirect chain, empty without one.
    pub fn https_redirects(&self) -> &[RedirectEntry] {
        self.https.as_ref().map_or(&[], |session| session.redirects.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(url: &str) -> Session {
        Session {
            url: Url::parse(url).unwrap(),
            response: Response {
                status: 200,
                verified: true,
                headers: Headers::new(),
            },
            redirects: vec![RedirectEntry {
                url: Url::parse(url).unwrap(),
                status: 200,
            }],
        }
    }

    fn retrieval(http: Option<Session>, https: Option<Session>) -> Retrieval {
        Retrieval {
            host: "example.com".to_string(),
            http,
            https,
            cors: None,
            cookies: vec![],
            meta: MetaTags::default(),
            auto_body: None,
        }
    }

    #[test]
    fn auto_is_https_when_it_answered_else_http() {
        let both = retrieval(
            Some(session("http://example.com/")),
            Some(session("https://example.com/")),
        );
        assert_eq!(both.auto().unwrap().url.scheme(), "https");
        let http_only = retrieval(Some(session("http://example.com/")), None);
        assert_eq!(http_only.auto().unwrap().url.scheme(), "http");
        assert!(retrieval(None, None).auto().is_none());
        assert!(retrieval(None, None).http_redirects().is_empty());
    }
}
