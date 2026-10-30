// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/retriever/retriever.js, the
// `Requests`/`Responses` shapes in src/types.js).

//! One Observatory retrieval: the `http` and `https` sessions in parallel, then robots.txt and
//! the CORS preflight on the `auto` session's auxiliary client, then the `auto` body's meta tags.
//! The analyzers are pure functions of the [`Retrieval`] it returns.

use super::AnalyzeError;
use super::cookies::Cookie;
use super::headers::{CONTENT_TYPE, Headers};
use super::html::{MetaTags, parse_http_equiv};
use super::session::transport::{ReqwestTransport, TransportOptions};
use super::session::{self, CORS_ORIGIN, Method, ROBOTS_ACCEPT, SessionRun, Transport};
use super::sri::RegistrableDomain;
use super::types::HTML_TYPES;
use std::sync::Arc;
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

/// Retrieves hosts over a [`Transport`], on ports 80 and 443 unless told otherwise (upstream's
/// `httpPort`/`httpsPort` options).
#[derive(Clone)]
pub struct Retriever {
    transport: Arc<dyn Transport>,
    http_port: Option<u16>,
    https_port: Option<u16>,
}

impl Retriever {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            http_port: None,
            https_port: None,
        }
    }

    /// The production retriever: reqwest, the built-in root store.
    pub fn standard() -> eyre::Result<Self> {
        Ok(Self::new(Arc::new(
            ReqwestTransport::new(&TransportOptions::default())?,
        )))
    }

    /// Non-default ports for the two sessions.
    pub fn with_ports(mut self, http_port: Option<u16>, https_port: Option<u16>) -> Self {
        self.http_port = http_port;
        self.https_port = https_port;
        self
    }

    fn start_url(&self, scheme: &str, host: &str, port: Option<u16>) -> Result<Url, AnalyzeError> {
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        Url::parse(&format!("{scheme}://{host}{port}/")).map_err(|e| AnalyzeError::InvalidSite(format!("{host}: {e}")))
    }

    /// `retrieve(site)`. `domains` names registrable domains for the cookie jars (tough-cookie
    /// reads the ICANN and private sections). `Err` only for a host that makes no URL.
    pub async fn retrieve(
        &self,
        host: &str,
        domains: &(dyn RegistrableDomain + Sync),
    ) -> Result<Retrieval, AnalyzeError> {
        let host = host.trim().to_lowercase();
        log::debug!("[observatory::retriever] retrieve: host={}", host);
        let http_url = self.start_url("http", &host, self.http_port)?;
        let https_url = self.start_url("https", &host, self.https_port)?;
        let transport = self.transport.as_ref();

        let (http, https) = tokio::join!(
            session::run(transport, http_url, domains),
            session::run(transport, https_url, domains)
        );
        let https_is_auto = https.response.is_some();
        let (mut auto, other) = if https_is_auto { (https, http) } else { (http, https) };

        let auto_body = auto.response.as_ref().map(|r| r.body.clone());

        // robots.txt lives at the root of the session's starting host.
        if let Ok(robots) = auto.url.join("/robots.txt") {
            auto.auxiliary(
                transport,
                Method::Get,
                &robots,
                vec![("accept", ROBOTS_ACCEPT.to_string())],
                domains,
            )
            .await;
        }

        let cors_url = auto
            .redirects
            .last()
            .map_or_else(|| auto.url.clone(), |hop| hop.url.clone());
        let preflight = auto
            .auxiliary(
                transport,
                Method::Options,
                &cors_url,
                vec![
                    ("access-control-request-method", "GET".to_string()),
                    ("origin", CORS_ORIGIN.to_string()),
                ],
                domains,
            )
            .await;
        let auto_verified = auto.response.as_ref().is_some_and(|r| r.response.verified);
        let cors = preflight.map(|answer| Response {
            verified: auto_verified,
            ..answer.response
        });

        let meta = match (&auto.response, &auto_body) {
            (Some(final_response), Some(body)) if is_html(&final_response.response.headers) && !body.is_empty() => {
                parse_http_equiv(body)
            }
            _ => MetaTags::default(),
        };
        let cookies = auto.jar.cookies();

        let (http, https) = if https_is_auto { (other, auto) } else { (auto, other) };
        let retrieval = Retrieval {
            host,
            http: into_session(http),
            https: into_session(https),
            cors,
            cookies,
            meta,
            auto_body,
        };
        log::debug!(
            "[observatory::retriever] retrieve: host={} http={:?} https={:?} cors={:?} cookies={}",
            retrieval.host,
            retrieval.http.as_ref().map(|s| s.response.status),
            retrieval.https.as_ref().map(|s| s.response.status),
            retrieval.cors.as_ref().map(|r| r.status),
            retrieval.cookies.len()
        );
        Ok(retrieval)
    }
}

/// `HTML_TYPES.has(headers["content-type"]?.split(";", 1)[0])`: no trimming, no lowercasing.
fn is_html(headers: &Headers) -> bool {
    headers
        .all(CONTENT_TYPE)
        .first()
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| HTML_TYPES.contains(&mime))
}

fn into_session(run: SessionRun) -> Option<Session> {
    let url = run.url;
    let redirects = run.redirects;
    run.response.map(|final_response| Session {
        url,
        response: final_response.response,
        redirects,
    })
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
    fn html_type_is_the_exact_mime_before_the_first_semicolon() {
        let with = |value: &str| {
            let mut headers = Headers::new();
            headers.set_single("content-type", value);
            is_html(&headers)
        };
        assert!(with("text/html"));
        assert!(with("text/html; charset=utf-8"));
        assert!(with("application/xhtml+xml;q=1"));
        assert!(!with("Text/HTML"));
        assert!(!with("text/html ; charset=utf-8"));
        assert!(!with("text/plain"));
        assert!(!is_html(&Headers::new()));
    }

    /// Retrievals over the reqwest transport against local fakes: an http server and a TLS server,
    /// every name resolved to 127.0.0.1, the TLS server's certificate from a test CA.
    mod network {
        use super::*;
        use crate::scan::observatory::hsts::{HstsPreload, PreloadEntry};
        use crate::scan::observatory::session::transport::{ReqwestTransport, TransportOptions};
        use crate::scan::observatory::session::{ACCEPT_ENCODING, STANDARD_ACCEPT, USER_AGENT};
        use crate::scan::observatory::types::Expectation;
        use crate::scan::observatory::{AnalyzeError, ObservatoryResult, SuffixLists, observe};
        use crate::scan::testing::{FakeHttp, FakeRoute, TestCa, dead_http_url};
        use publicsuffix::{IcannList, List};

        pub(crate) const NAMES: [&str; 12] = [
            "site.com",
            "www.site.com",
            "other.com",
            "pre.com",
            "www.pre.com",
            "parent.com",
            "www.parent.com",
            "noinc.com",
            "www.noinc.com",
            "pinned.com",
            "github.com",
            "www.github.com",
        ];

        const PSL: &str = "// ===BEGIN ICANN DOMAINS===\ncom\norg\n// ===END ICANN DOMAINS===\n\
                           // ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n";

        pub(crate) struct Lists {
            icann: IcannList,
            all: List,
        }

        impl Lists {
            pub(crate) fn new() -> Self {
                Self {
                    icann: PSL.parse().unwrap(),
                    all: PSL.parse().unwrap(),
                }
            }

            pub(crate) fn get(&self) -> SuffixLists<'_> {
                SuffixLists {
                    icann: &self.icann,
                    all: &self.all,
                }
            }
        }

        /// An http fake and a TLS fake for every name in [`NAMES`].
        pub(crate) struct Fixture {
            pub(crate) ca: TestCa,
            pub(crate) http: FakeHttp,
            pub(crate) https: FakeHttp,
        }

        impl Fixture {
            /// The TLS fake's certificate is signed by the trusted CA, or by another one.
            pub(crate) async fn new(trusted: bool) -> Self {
                let ca = TestCa::new("Retriever Test CA");
                let identity = if trusted {
                    ca.issue(&NAMES)
                } else {
                    TestCa::new("Untrusted CA").issue(&NAMES)
                };
                Self {
                    http: FakeHttp::start_routes(Vec::new()).await,
                    https: FakeHttp::start_tls(Vec::new(), &identity).await,
                    ca,
                }
            }

            pub(crate) fn http_url(&self, host: &str, path: &str) -> String {
                format!("http://{host}:{}{path}", self.http.port())
            }

            pub(crate) fn https_url(&self, host: &str, path: &str) -> String {
                format!("https://{host}:{}{path}", self.https.port())
            }

            pub(crate) fn transport(&self) -> ReqwestTransport {
                ReqwestTransport::new(&TransportOptions {
                    built_in_roots: false,
                    extra_roots: vec![self.ca.der()],
                    resolve: NAMES
                        .iter()
                        .map(|name| (name.to_string(), "127.0.0.1:0".parse().unwrap()))
                        .collect(),
                    env_proxy: false,
                })
                .unwrap()
            }

            pub(crate) fn retriever(&self) -> Retriever {
                Retriever::new(Arc::new(self.transport())).with_ports(Some(self.http.port()), Some(self.https.port()))
            }

            /// `GET /` on `host` over http answers `status` with `Location: location`.
            fn http_redirect(&self, host: &str, path: &str, status: u16, location: &str) {
                self.http
                    .add(FakeRoute::get(path, status).host(host).header("Location", location));
            }

            fn https_page(&self, host: &str, path: &str) {
                self.https.add(
                    FakeRoute::get(path, 200)
                        .host(host)
                        .header("Content-Type", "text/html")
                        .body("<html></html>"),
                );
            }

            fn http_page(&self, host: &str, path: &str) {
                self.http.add(
                    FakeRoute::get(path, 200)
                        .host(host)
                        .header("Content-Type", "text/html")
                        .body("<html></html>"),
                );
            }

            async fn observe(&self, host: &str, preload: &HstsPreload) -> Result<ObservatoryResult, AnalyzeError> {
                let lists = Lists::new();
                observe(&self.retriever(), host, preload, lists.get()).await
            }
        }

        pub(crate) fn test_result(result: &ObservatoryResult, name: &str) -> Expectation {
            result
                .tests
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("no test {name}"))
                .result
        }

        fn preload(names: &[&str]) -> HstsPreload {
            HstsPreload::from_entries(
                names
                    .iter()
                    .map(|n| {
                        (
                            n.to_string(),
                            PreloadEntry {
                                force_https: true,
                                include_subdomains: false,
                            },
                        )
                    })
                    .collect(),
            )
        }

        fn redirection(result: &ObservatoryResult) -> Expectation {
            test_result(result, "redirection")
        }

        #[tokio::test]
        async fn redirection_to_https() {
            let f = Fixture::new(true).await;
            f.http_redirect("site.com", "/", 301, &f.https_url("site.com", "/"));
            f.https_page("site.com", "/");
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionToHttps);
            assert!(result.verified);
        }

        #[tokio::test]
        async fn redirection_all_redirects_preloaded() {
            let f = Fixture::new(true).await;
            f.http_redirect("pre.com", "/", 301, &f.https_url("pre.com", "/"));
            f.https_page("pre.com", "/");
            let result = f.observe("pre.com", &preload(&["pre.com"])).await.unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionAllRedirectsPreloaded);
        }

        #[tokio::test]
        async fn redirection_not_needed_no_http() {
            let f = Fixture::new(true).await;
            f.https_page("site.com", "/");
            let dead = Url::parse(&dead_http_url().await).unwrap();
            let retriever = Retriever::new(Arc::new(f.transport())).with_ports(dead.port(), Some(f.https.port()));
            let lists = Lists::new();
            let result = observe(&retriever, "site.com", &preload(&[]), lists.get())
                .await
                .unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionNotNeededNoHttp);
        }

        #[tokio::test]
        async fn redirection_off_host_from_http() {
            let f = Fixture::new(true).await;
            f.http_redirect("site.com", "/", 301, &f.https_url("other.com", "/"));
            f.https_page("other.com", "/");
            f.https_page("site.com", "/");
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionOffHostFromHttp);
        }

        #[tokio::test]
        async fn redirection_not_to_https_on_initial_redirection() {
            let f = Fixture::new(true).await;
            f.http_redirect("site.com", "/", 301, &f.http_url("www.site.com", "/"));
            f.http_redirect("www.site.com", "/", 301, &f.https_url("www.site.com", "/"));
            f.https_page("www.site.com", "/");
            f.https_page("site.com", "/");
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(
                redirection(&result),
                Expectation::RedirectionNotToHttpsOnInitialRedirection
            );
        }

        #[tokio::test]
        async fn redirection_not_to_https() {
            let f = Fixture::new(true).await;
            f.http_redirect("site.com", "/", 302, &f.http_url("www.site.com", "/"));
            f.http_page("www.site.com", "/");
            f.https_page("site.com", "/");
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionNotToHttps);
        }

        #[tokio::test]
        async fn redirection_missing() {
            let f = Fixture::new(true).await;
            f.http_page("site.com", "/");
            f.https_page("site.com", "/");
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(redirection(&result), Expectation::RedirectionMissing);
        }

        /// A certificate the test CA did not sign: both sessions retry unverified. The http
        /// session's jar survives its retry: the cookie set before the certificate error goes out
        /// on the retried first request, and the history holds only the retry's hops.
        #[tokio::test]
        async fn untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry() {
            let f = Fixture::new(false).await;
            f.http.add(
                FakeRoute::get("/", 301)
                    .host("site.com")
                    .header("Set-Cookie", "hop=1")
                    .header("Location", &f.https_url("site.com", "/")),
            );
            f.https_page("site.com", "/");

            let lists = Lists::new();
            let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();

            let http = retrieval.http.as_ref().unwrap();
            assert!(!http.response.verified);
            let hops: Vec<(String, u16)> = http.redirects.iter().map(|h| (h.url.to_string(), h.status)).collect();
            assert_eq!(
                hops,
                [(f.http_url("site.com", "/"), 301), (f.https_url("site.com", "/"), 200)]
            );
            let firsts: Vec<Option<String>> = f
                .http
                .requests()
                .iter()
                .filter(|r| r.path == "/")
                .map(|r| r.header("cookie").map(str::to_string))
                .collect();
            assert_eq!(firsts, [None, Some("hop=1".to_string())]);
            assert!(!retrieval.https.as_ref().unwrap().response.verified);

            let result = crate::scan::observatory::analyze(&retrieval, &preload(&[]), lists.get().icann).unwrap();
            assert!(!result.verified);
            assert_eq!(redirection(&result), Expectation::RedirectionInvalidCert);
            assert_eq!(
                test_result(&result, "strict-transport-security"),
                Expectation::HstsInvalidCert
            );
        }

        /// On the normal path robots.txt goes through a client with no jar: its cookie is dropped
        /// and nothing is recorded. On the certificate-fallback path the client carries the jar and
        /// the recording interceptor: the cookie lands, robots.txt joins the redirect history, and
        /// the preflight goes to robots.txt (the history's last hop).
        #[tokio::test]
        async fn robots_cookie_reaches_the_jar_only_on_the_fallback_path() {
            for trusted in [true, false] {
                let f = Fixture::new(trusted).await;
                f.http_page("site.com", "/");
                f.https.add(
                    FakeRoute::get("/", 200)
                        .header("Content-Type", "text/html")
                        .header("Set-Cookie", "page=1; Secure"),
                );
                f.https.add(
                    FakeRoute::get("/robots.txt", 200)
                        .header("Content-Type", "text/plain")
                        .header("Set-Cookie", "robots=1; Secure"),
                );
                let lists = Lists::new();
                let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();
                let keys: Vec<&str> = retrieval.cookies.iter().map(|c| c.key.as_str()).collect();
                let https_hops: Vec<&str> = retrieval.https_redirects().iter().map(|h| h.url.path()).collect();
                let robots = f
                    .https
                    .requests()
                    .into_iter()
                    .find(|r| r.path == "/robots.txt")
                    .unwrap();
                let preflight = f.https.requests().into_iter().find(|r| r.method == "OPTIONS").unwrap();
                if trusted {
                    assert_eq!(keys, ["page"]);
                    assert_eq!(https_hops, ["/"]);
                    assert_eq!(robots.header("cookie"), None);
                    assert_eq!(preflight.path, "/");
                } else {
                    assert_eq!(keys, ["page", "robots"]);
                    assert_eq!(https_hops, ["/", "/robots.txt"]);
                    assert_eq!(robots.header("cookie"), Some("page=1"));
                    assert_eq!(preflight.path, "/robots.txt");
                }
            }
        }

        #[tokio::test]
        async fn a_500_is_an_unexpected_status() {
            let f = Fixture::new(true).await;
            f.http.add(FakeRoute::get("/", 500));
            f.https.add(FakeRoute::get("/", 500));
            assert_eq!(
                f.observe("site.com", &preload(&[])).await,
                Err(AnalyzeError::UnexpectedStatusCode(500))
            );
        }

        #[tokio::test]
        async fn nothing_answering_is_site_down() {
            let dead = Url::parse(&dead_http_url().await).unwrap();
            let f = Fixture::new(true).await;
            let retriever = Retriever::new(Arc::new(f.transport())).with_ports(dead.port(), dead.port());
            let lists = Lists::new();
            assert_eq!(
                observe(&retriever, "site.com", &preload(&[]), lists.get()).await,
                Err(AnalyzeError::SiteIsDown)
            );
        }

        /// Two `Strict-Transport-Security` lines join with `", "` the Node way: invalid.
        #[tokio::test]
        async fn two_sts_headers_grade_hsts_header_invalid() {
            let f = Fixture::new(true).await;
            f.http_redirect("site.com", "/", 301, &f.https_url("site.com", "/"));
            f.https.add(
                FakeRoute::get("/", 200)
                    .header("Content-Type", "text/html")
                    .header("Strict-Transport-Security", "max-age=31536000")
                    .header("Strict-Transport-Security", "max-age=31536000"),
            );
            let result = f.observe("site.com", &preload(&[])).await.unwrap();
            assert_eq!(
                test_result(&result, "strict-transport-security"),
                Expectation::HstsHeaderInvalid
            );
        }

        /// Session requests, robots.txt and the preflight carry Observatory's request shape.
        #[tokio::test]
        async fn requests_carry_observatorys_headers() {
            let f = Fixture::new(true).await;
            f.https_page("site.com", "/");
            f.https.add(FakeRoute::options("/", 200).header(
                "Access-Control-Allow-Origin",
                "https://http-observatory.security.mozilla.org",
            ));
            let lists = Lists::new();
            let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();
            let requests = f.https.requests();
            let session = requests.iter().find(|r| r.method == "GET" && r.path == "/").unwrap();
            assert_eq!(session.header("user-agent"), Some(USER_AGENT));
            assert_eq!(session.header("accept"), Some(STANDARD_ACCEPT));
            assert_eq!(session.header("accept-encoding"), Some(ACCEPT_ENCODING));
            assert_eq!(session.header("connection"), Some("close"));
            let robots = requests.iter().find(|r| r.path == "/robots.txt").unwrap();
            assert_eq!(robots.header("accept"), Some("text/plain,*/*;q=0.8"));
            assert_eq!(robots.header("user-agent"), Some(USER_AGENT));
            assert_eq!(robots.header("connection"), Some("keep-alive"));
            let preflight = requests.iter().find(|r| r.method == "OPTIONS").unwrap();
            assert_eq!(
                preflight.header("origin"),
                Some("https://http-observatory.security.mozilla.org")
            );
            assert_eq!(preflight.header("access-control-request-method"), Some("GET"));
            assert_eq!(preflight.header("accept"), Some(STANDARD_ACCEPT));
            let cors = retrieval.cors.unwrap();
            assert!(cors.verified);
            assert_eq!(
                cors.headers.all("access-control-allow-origin"),
                ["https://http-observatory.security.mozilla.org"]
            );
        }

        /// A non-2xx preflight answer is no CORS response at all (Phase 0b).
        #[tokio::test]
        async fn a_non_2xx_preflight_is_no_cors_response() {
            let f = Fixture::new(true).await;
            f.https_page("site.com", "/");
            f.https.add(FakeRoute::options("/", 405));
            let lists = Lists::new();
            let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();
            assert!(retrieval.cors.is_none());
            assert_eq!(f.https.requests().iter().filter(|r| r.method == "OPTIONS").count(), 1);
        }

        /// A brotli body (Phase 0b: google.com answers `br`) is decoded before the meta tags are
        /// read.
        #[tokio::test]
        async fn a_brotli_body_is_decoded_and_its_meta_tags_read() {
            let html = "<html><head><meta name=\"referrer\" content=\"origin\"></head></html>";
            let f = Fixture::new(true).await;
            f.https.add(
                FakeRoute::get("/", 200)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("Content-Encoding", "br")
                    .body(brotli_stored(html.as_bytes())),
            );
            let lists = Lists::new();
            let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();
            assert_eq!(retrieval.auto_body.as_deref(), Some(html));
            assert_eq!(retrieval.meta.referrer_policy, ["origin"]);
            assert!(!retrieval.https.unwrap().response.headers.is_truthy("content-encoding"));
        }

        /// Every https page answers with a six-month-plus HSTS header; http answers 404.
        async fn hsts_fixture() -> Fixture {
            let f = Fixture::new(true).await;
            f.https.add(
                FakeRoute::get("/", 200)
                    .header("Content-Type", "text/html")
                    .header("Strict-Transport-Security", "max-age=31536000"),
            );
            f
        }

        /// The five lookup rules, each through Chromium's file format and a full retrieval.
        #[tokio::test]
        async fn preload_fixtures_grade_through_the_chromium_list() {
            let list =
                crate::scan::observatory::hsts::parse_chromium(crate::scan::observatory::hsts::tests::CHROMIUM_FIXTURE)
                    .unwrap();
            let f = hsts_fixture().await;
            for (host, expected) in [
                ("pre.com", Expectation::HstsPreloaded),
                ("www.parent.com", Expectation::HstsPreloaded),
                ("www.noinc.com", Expectation::HstsImplementedMaxAgeAtLeastSixMonths),
                ("pinned.com", Expectation::HstsImplementedMaxAgeAtLeastSixMonths),
                ("  GitHub.COM ", Expectation::HstsPreloaded),
            ] {
                let result = f.observe(host, &list).await.unwrap();
                assert_eq!(test_result(&result, "strict-transport-security"), expected, "{host:?}");
                assert!(result.preload_available);
            }
            assert_eq!(f.observe("  GitHub.COM ", &list).await.unwrap().host, "github.com");
        }

        /// No cache and a dead URL: the result an empty list gives, the same score, flagged
        /// unavailable.
        #[tokio::test]
        async fn an_unavailable_list_scores_as_a_list_lacking_the_host() {
            let source = crate::scan::observatory::hsts::PreloadSource::from_url(
                reqwest::Client::builder().no_proxy().build().unwrap(),
                dead_http_url().await,
                Some(crate::scan::testing::temp_dir("preload-unavailable")),
            );
            let unavailable = source
                .get(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
                .await;
            let f = hsts_fixture().await;
            let lists = Lists::new();
            let retrieval = f.retriever().retrieve("site.com", lists.get().all).await.unwrap();
            let analyze =
                |list: &HstsPreload| crate::scan::observatory::analyze(&retrieval, list, lists.get().icann).unwrap();
            let without = analyze(&unavailable);
            let lacking = analyze(&preload(&["unrelated.com"]));
            assert_eq!(
                test_result(&without, "strict-transport-security"),
                Expectation::HstsImplementedMaxAgeAtLeastSixMonths
            );
            assert_eq!(without.score, lacking.score);
            assert_eq!(without.tests, lacking.tests);
            assert!(!without.preload_available);
            assert!(lacking.preload_available);
        }

        /// A brotli stream holding `data` in one uncompressed meta-block (RFC 7932 §9.2).
        fn brotli_stored(data: &[u8]) -> Vec<u8> {
            assert!(!data.is_empty() && data.len() <= 65536);
            let mut bits: Vec<bool> = Vec::new();
            let mut push = |value: u32, count: u32| (0..count).for_each(|i| bits.push(value >> i & 1 == 1));
            push(0, 1); // WBITS: 16
            push(0, 1); // ISLAST
            push(0, 2); // MNIBBLES: 4
            push(data.len() as u32 - 1, 16); // MLEN - 1
            push(1, 1); // ISUNCOMPRESSED
            let mut out: Vec<u8> = bits
                .chunks(8)
                .map(|byte| {
                    byte.iter()
                        .enumerate()
                        .fold(0u8, |acc, (i, &b)| acc | (u8::from(b) << i))
                })
                .collect();
            out.extend_from_slice(data);
            out.push(0b11); // ISLAST, ISLASTEMPTY
            out
        }
    }

    /// The Phase 5 budget, in paused time over a scripted transport.
    mod budget {
        use super::*;
        use crate::scan::observatory::hsts::HstsPreload;
        use crate::scan::observatory::session::tests::{Scripted, answer, no_domains};
        use crate::scan::observatory::session::{ABORT_TIMEOUT, CLIENT_TIMEOUT};
        use crate::scan::observatory::{SuffixLists, observe};
        use std::time::Duration;
        use tokio::time::Instant;

        /// The worst case the doc budgets: an `https` session that stalls past its 10s cap, then
        /// robots.txt and the preflight on the `http` session that each stall to their 9s limit.
        /// The scan still returns, graded from the `http` session, in 28s, inside 35s.
        #[tokio::test(start_paused = true)]
        async fn a_stalled_https_session_hits_its_cap_and_the_scan_still_returns() {
            let transport = Arc::new(Scripted::new(|r| match (r.method, r.url.scheme(), r.url.path()) {
                (Method::Get, "https", "/") => Some((Duration::from_secs(6), answer(301, &[("location", "/stall")]))),
                (Method::Get, "http", "/") => Some((Duration::ZERO, answer(200, &[("content-type", "text/html")]))),
                _ => None,
            }));
            let retriever = Retriever::new(transport.clone());
            let domains = no_domains();
            let lists = SuffixLists {
                icann: &domains,
                all: &domains,
            };
            let started = Instant::now();
            let result = observe(&retriever, "site.com", &HstsPreload::from_entries(Vec::new()), lists).await;
            let elapsed = started.elapsed();

            let result = result.expect("graded from the http session");
            assert_eq!(elapsed, ABORT_TIMEOUT + CLIENT_TIMEOUT * 2);
            assert!(elapsed < Duration::from_secs(35));
            assert_eq!(
                result
                    .tests
                    .iter()
                    .find(|t| t.name == "strict-transport-security")
                    .unwrap()
                    .result,
                crate::scan::observatory::types::Expectation::HstsNotImplementedNoHttps
            );
            assert_eq!(
                transport.urls(),
                [
                    "http://site.com/",
                    "https://site.com/",
                    "https://site.com/stall",
                    "http://site.com/robots.txt",
                    "http://site.com/",
                ]
            );
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
