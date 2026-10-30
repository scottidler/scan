// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/retriever/session.js, the
// retriever settings in src/config.js). The header join mirrors Node's `IncomingMessage`
// (`_addHeaderLine`), and the body decoding mirrors axios 1.20.0's http adapter.

//! One Observatory session: a GET of `http://host/` or `https://host/` with every redirect followed
//! by hand and recorded, a cookie jar filled from every hop, and the certificate retry. Also the
//! session's auxiliary client, which robots.txt and the CORS preflight go through.
//!
//! What the code does, quirks included:
//! - the retry after a certificate error keeps the jar and the redirect count and clears the
//!   redirect history (`session.js:173`), under the same 10s session deadline;
//! - the auxiliary client differs between the two paths (`session.js:103`, `:197`): normally a
//!   verifying client with no jar; after the retry a non-verifying one whose https requests use
//!   the session's jar, which records every 2xx answer in the session's redirect history, under
//!   its own 10s deadline from the retry;
//! - a missing `Location` resolves as the relative URL `undefined`, as `new URL(undefined, base)`
//!   does.

pub mod transport;

use super::cookies::CookieJar;
use super::headers::{HeaderValue, Headers};
use super::retriever::{RedirectEntry, Response};
use super::sri::RegistrableDomain;
use async_trait::async_trait;
use std::time::{Duration, SystemTime};
use tokio::time::Instant;
use url::Url;

/// `retrieverUserAgent`.
pub const USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0 Observatory/129.0";
/// `STANDARD_HEADERS`' `Accept`.
pub const STANDARD_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
/// `ROBOTS_HEADERS`' `Accept`.
pub const ROBOTS_ACCEPT: &str = "text/plain,*/*;q=0.8";
/// axios's default `Accept-Encoding` with brotli support (Phase 0b).
pub const ACCEPT_ENCODING: &str = "gzip, compress, deflate, br";
/// `corsOrigin`.
pub const CORS_ORIGIN: &str = "https://http-observatory.security.mozilla.org";
/// `clientTimeout`: one request.
pub const CLIENT_TIMEOUT: Duration = Duration::from_millis(9_000);
/// `abortTimeout`: one session, the certificate retry included.
pub const ABORT_TIMEOUT: Duration = Duration::from_millis(10_000);
/// `MAX_REDIRECTS`, for the session and for the auxiliary client.
pub const MAX_REDIRECTS: usize = 10;
/// `REDIRECT_STATUS_CODES`.
const REDIRECT_STATUS_CODES: [u16; 5] = [301, 302, 303, 307, 308];

/// Node discards every value after the first for these (`IncomingMessage` without
/// `joinDuplicateHeaders`).
const FIRST_WINS_HEADERS: [&str; 18] = [
    "age",
    "authorization",
    "content-length",
    "content-type",
    "etag",
    "expires",
    "from",
    "host",
    "if-modified-since",
    "if-unmodified-since",
    "last-modified",
    "location",
    "max-forwards",
    "proxy-authorization",
    "referer",
    "retry-after",
    "server",
    "user-agent",
];

/// The HTTP methods the retriever sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Options,
}

/// One request handed to the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingRequest {
    pub method: Method,
    pub url: Url,
    /// Lowercase names; the transport adds `Host` and nothing else.
    pub headers: Vec<(&'static str, String)>,
    /// `false` accepts any certificate (`rejectUnauthorized: false`).
    pub verify: bool,
}

/// One response from the transport, body decompressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingResponse {
    pub status: u16,
    /// Lowercase names in arrival order, duplicates kept, values decoded as latin1 (as Node does).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl IncomingResponse {
    /// Every value of `name`, in arrival order.
    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Node's `response.headers.location`: the first value.
    fn location(&self) -> Option<&str> {
        self.values("location").next()
    }
}

/// Why a request got no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The certificate chain did not verify: one of upstream's `CERT_ERROR_CODES`.
    Certificate(String),
    /// Anything else: connect, timeout, protocol, an unusable URL.
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Certificate(why) => write!(f, "certificate error: {why}"),
            TransportError::Other(why) => write!(f, "{why}"),
        }
    }
}

/// Sends one HTTP/1.1 request and reads the whole response. No redirects, no cookies: the
/// session does both.
#[allow(clippy::double_must_use)] // async_trait expansion trips newer clippy
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, request: OutgoingRequest) -> Result<IncomingResponse, TransportError>;
}

/// A session's final response and its body.
#[derive(Debug, Clone, PartialEq)]
pub struct FinalResponse {
    pub response: Response,
    /// Decoded as UTF-8 with a leading byte-order mark stripped (axios's `utf8` + `stripBOM`).
    pub body: String,
}

/// Which auxiliary client (`clientInstance`) a session ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aux {
    /// The constructor's: verifying, no jar, no deadline beyond each request's.
    Normal,
    /// The certificate retry's: no verification, the jar on https, and its own abort deadline.
    Fallback { deadline: Instant },
}

/// One finished session.
#[derive(Debug, Clone)]
pub struct SessionRun {
    /// The URL the session started from.
    pub url: Url,
    /// `None` when the session got no response (`this.response = null`).
    pub response: Option<FinalResponse>,
    /// `redirectHistory`: every hop, plus the auxiliary client's answers after a retry.
    pub redirects: Vec<RedirectEntry>,
    pub jar: CookieJar,
    /// `None` when the session failed (`clientInstance = null`).
    aux: Option<Aux>,
}

/// The recording client's state across hops and the certificate retry.
struct Chain {
    history: Vec<RedirectEntry>,
    count: usize,
    jar: CookieJar,
    verify: bool,
    fallback_at: Option<Instant>,
}

/// `Session.fromUrl(url)`: the chain from `url`, retried without verification after a certificate
/// error, all within [`ABORT_TIMEOUT`].
pub async fn run(transport: &dyn Transport, url: Url, domains: &(dyn RegistrableDomain + Sync)) -> SessionRun {
    log::debug!("[observatory::session] run: url={}", url);
    let deadline = Instant::now() + ABORT_TIMEOUT;
    let mut chain = Chain {
        history: Vec::new(),
        count: 0,
        jar: CookieJar::new(),
        verify: true,
        fallback_at: None,
    };
    let outcome = tokio::time::timeout_at(deadline, init(transport, &url, &mut chain, domains)).await;
    let response = match outcome {
        Ok(Ok(response)) => Some(response),
        Ok(Err(e)) => {
            log::debug!("[observatory::session] run: url={} failed: {}", url, e);
            None
        }
        Err(_) => {
            log::debug!(
                "[observatory::session] run: url={} aborted after {:?}",
                url,
                ABORT_TIMEOUT
            );
            None
        }
    };
    let aux = response.as_ref().map(|_| match chain.fallback_at {
        Some(at) => Aux::Fallback {
            deadline: at + ABORT_TIMEOUT,
        },
        None => Aux::Normal,
    });
    log::debug!(
        "[observatory::session] run: url={} status={:?} verified={} hops={} cookies={}",
        url,
        response.as_ref().map(|r| r.response.status),
        chain.verify,
        chain.history.len(),
        chain.jar.cookies().len()
    );
    SessionRun {
        url,
        response,
        redirects: chain.history,
        jar: chain.jar,
        aux,
    }
}

/// `init()`: the chain, and on a certificate error from the verifying client, the chain again
/// with verification off, history cleared, jar and redirect count kept.
async fn init(
    transport: &dyn Transport,
    url: &Url,
    chain: &mut Chain,
    domains: &(dyn RegistrableDomain + Sync),
) -> Result<FinalResponse, TransportError> {
    loop {
        match follow(transport, url, chain, domains).await {
            Err(TransportError::Certificate(why)) if chain.verify => {
                log::debug!(
                    "[observatory::session] init: url={} certificate error ({}): retrying unverified",
                    url,
                    why
                );
                chain.history.clear();
                chain.verify = false;
                chain.fallback_at = Some(Instant::now());
            }
            other => return other,
        }
    }
}

/// The recording client and its interceptor: GET, record the hop, follow a redirect status while
/// fewer than [`MAX_REDIRECTS`] have been followed.
async fn follow(
    transport: &dyn Transport,
    start: &Url,
    chain: &mut Chain,
    domains: &(dyn RegistrableDomain + Sync),
) -> Result<FinalResponse, TransportError> {
    let mut url = start.clone();
    loop {
        let headers = vec![
            ("accept", STANDARD_ACCEPT.to_string()),
            ("user-agent", USER_AGENT.to_string()),
            ("accept-encoding", ACCEPT_ENCODING.to_string()),
            ("connection", "close".to_string()),
        ];
        let response = send_with_jar(
            transport,
            Method::Get,
            &url,
            headers,
            chain.verify,
            &mut chain.jar,
            domains,
        )
        .await?;
        chain.history.push(RedirectEntry {
            url: url.clone(),
            status: response.status,
        });
        if chain.count < MAX_REDIRECTS && REDIRECT_STATUS_CODES.contains(&response.status) {
            let location = response.location().unwrap_or("undefined");
            url = url
                .join(location)
                .map_err(|e| TransportError::Other(format!("invalid redirect location {location:?}: {e}")))?;
            chain.count += 1;
            log::trace!(
                "[observatory::session] follow: {} -> {} ({})",
                chain.history.last().map_or("", |h| h.url.as_str()),
                url,
                response.status
            );
            continue;
        }
        return Ok(final_response(response, chain.verify));
    }
}

/// One request with the jar's `Cookie` header, storing every `Set-Cookie` of the answer, bounded
/// by [`CLIENT_TIMEOUT`].
async fn send_with_jar(
    transport: &dyn Transport,
    method: Method,
    url: &Url,
    mut headers: Vec<(&'static str, String)>,
    verify: bool,
    jar: &mut CookieJar,
    domains: &(dyn RegistrableDomain + Sync),
) -> Result<IncomingResponse, TransportError> {
    if let Some(cookie) = jar.cookie_header(url, domains, SystemTime::now()) {
        headers.push(("cookie", cookie));
    }
    let response = send(transport, method, url, headers, verify, CLIENT_TIMEOUT).await?;
    let now = SystemTime::now();
    for value in response.values("set-cookie") {
        jar.set_cookie(value, url, domains, now);
    }
    Ok(response)
}

/// One request bounded by `limit`.
async fn send(
    transport: &dyn Transport,
    method: Method,
    url: &Url,
    headers: Vec<(&'static str, String)>,
    verify: bool,
    limit: Duration,
) -> Result<IncomingResponse, TransportError> {
    let request = OutgoingRequest {
        method,
        url: url.clone(),
        headers,
        verify,
    };
    match tokio::time::timeout(limit, transport.send(request)).await {
        Ok(result) => result,
        Err(_) => Err(TransportError::Other(format!(
            "timeout of {}ms exceeded",
            limit.as_millis()
        ))),
    }
}

impl SessionRun {
    /// `Session.get` / `Session.options` on the auxiliary client: redirects followed the
    /// follow-redirects way, a non-2xx answer or any error is `None`. After a certificate retry a
    /// 2xx answer is also recorded in the session's redirect history (the retry's client carries
    /// the recording interceptor).
    pub async fn auxiliary(
        &mut self,
        transport: &dyn Transport,
        method: Method,
        url: &Url,
        extra: Vec<(&'static str, String)>,
        domains: &(dyn RegistrableDomain + Sync),
    ) -> Option<FinalResponse> {
        let Some(aux) = self.aux else {
            log::debug!(
                "[observatory::session] auxiliary: {:?} {} skipped: session has no client",
                method,
                url
            );
            return None;
        };
        let (verify, deadline) = match aux {
            Aux::Normal => (true, None),
            Aux::Fallback { deadline } => (false, Some(deadline)),
        };
        let mut headers = vec![
            ("accept", STANDARD_ACCEPT.to_string()),
            ("user-agent", USER_AGENT.to_string()),
            ("accept-encoding", ACCEPT_ENCODING.to_string()),
            ("connection", "keep-alive".to_string()),
        ];
        for (name, value) in extra {
            match headers.iter_mut().find(|(n, _)| *n == name) {
                Some(header) => header.1 = value,
                None => headers.push((name, value)),
            }
        }
        let limit = deadline.map_or(CLIENT_TIMEOUT, |d| {
            CLIENT_TIMEOUT.min(d.saturating_duration_since(Instant::now()))
        });
        let jar = &mut self.jar;
        let chase = async {
            let (mut url, mut method, mut hops) = (url.clone(), method, 0usize);
            loop {
                let response = if !verify && url.scheme() == "https" {
                    send_with_jar(transport, method, &url, headers.clone(), verify, jar, domains).await?
                } else {
                    send(transport, method, &url, headers.clone(), verify, CLIENT_TIMEOUT).await?
                };
                match response.location() {
                    Some(location) if (300..400).contains(&response.status) => {
                        hops += 1;
                        if hops > MAX_REDIRECTS {
                            return Err(TransportError::Other(
                                "maximum number of redirects exceeded".to_string(),
                            ));
                        }
                        if response.status == 303 && method != Method::Get {
                            method = Method::Get;
                        }
                        url = url.join(location).map_err(|e| {
                            TransportError::Other(format!("invalid redirect location {location:?}: {e}"))
                        })?;
                    }
                    _ => return Ok(response),
                }
            }
        };
        let response = match tokio::time::timeout(limit, chase).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                log::debug!("[observatory::session] auxiliary: {:?} {} failed: {}", method, url, e);
                return None;
            }
            Err(_) => {
                log::debug!(
                    "[observatory::session] auxiliary: {:?} {} timed out after {:?}",
                    method,
                    url,
                    limit
                );
                return None;
            }
        };
        if !(200..300).contains(&response.status) {
            log::debug!(
                "[observatory::session] auxiliary: {:?} {} status {}: rejected",
                method,
                url,
                response.status
            );
            return None;
        }
        if deadline.is_some() {
            self.redirects.push(RedirectEntry {
                url: url.clone(),
                status: response.status,
            });
        }
        Some(final_response(response, verify))
    }
}

/// A transport response as the analyzers see it.
fn final_response(response: IncomingResponse, verified: bool) -> FinalResponse {
    FinalResponse {
        response: Response {
            status: response.status,
            verified,
            headers: node_headers(&response.headers),
        },
        body: decode_body(&response.body),
    }
}

/// UTF-8 with replacement characters and a leading BOM stripped.
pub fn decode_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    text.strip_prefix('\u{FEFF}').unwrap_or(&text).to_string()
}

/// `IncomingMessage.headers`: `set-cookie` always a list; the first-wins set keeps its first
/// value; `cookie` joined with `"; "`; every other duplicate joined with `", "`.
pub fn node_headers(raw: &[(String, String)]) -> Headers {
    let mut joined: Vec<(String, HeaderValue)> = Vec::new();
    for (name, value) in raw {
        let name = name.to_lowercase();
        let existing = joined.iter_mut().find(|(n, _)| *n == name);
        match (existing, name.as_str()) {
            (Some((_, HeaderValue::List(values))), "set-cookie") => values.push(value.clone()),
            (None, "set-cookie") => joined.push((name, HeaderValue::List(vec![value.clone()]))),
            (Some(_), n) if FIRST_WINS_HEADERS.contains(&n) => {}
            (Some((_, HeaderValue::Single(old))), "cookie") => {
                old.push_str("; ");
                old.push_str(value);
            }
            (Some((_, HeaderValue::Single(old))), _) => {
                old.push_str(", ");
                old.push_str(value);
            }
            (Some((_, HeaderValue::List(_))), _) => {}
            (None, _) => joined.push((name, HeaderValue::Single(value.clone()))),
        }
    }
    let mut headers = Headers::new();
    for (name, value) in joined {
        headers.set(&name, value);
    }
    headers
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    type Script = dyn Fn(&OutgoingRequest) -> Option<(Duration, IncomingResponse)> + Send + Sync;

    /// A transport that answers from a script: `Some((delay, response))` answers after `delay`,
    /// `None` never answers. Every request is recorded.
    pub(crate) struct Scripted {
        script: Box<Script>,
        pub(crate) sent: Mutex<Vec<OutgoingRequest>>,
    }

    impl Scripted {
        pub(crate) fn new(
            script: impl Fn(&OutgoingRequest) -> Option<(Duration, IncomingResponse)> + Send + Sync + 'static,
        ) -> Self {
            Self {
                script: Box::new(script),
                sent: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn urls(&self) -> Vec<String> {
            self.sent.lock().unwrap().iter().map(|r| r.url.to_string()).collect()
        }
    }

    #[async_trait]
    impl Transport for Scripted {
        async fn send(&self, request: OutgoingRequest) -> Result<IncomingResponse, TransportError> {
            self.sent.lock().unwrap().push(request.clone());
            match (self.script)(&request) {
                Some((delay, response)) => {
                    tokio::time::sleep(delay).await;
                    Ok(response)
                }
                None => std::future::pending().await,
            }
        }
    }

    pub(crate) fn answer(status: u16, headers: &[(&str, &str)]) -> IncomingResponse {
        IncomingResponse {
            status,
            headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    pub(crate) fn no_domains() -> publicsuffix::List {
        "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"
            .parse()
            .unwrap()
    }

    /// `new URL(undefined, base)`: a redirect without `Location` goes to `<base dir>/undefined`.
    #[tokio::test]
    async fn a_redirect_without_location_goes_to_undefined() {
        let transport = Scripted::new(|r| match r.url.path() {
            "/a/b" => Some((Duration::ZERO, answer(302, &[]))),
            _ => Some((Duration::ZERO, answer(200, &[]))),
        });
        let run = run(&transport, Url::parse("http://site.com/a/b").unwrap(), &no_domains()).await;
        assert_eq!(transport.urls(), ["http://site.com/a/b", "http://site.com/a/undefined"]);
        assert_eq!(run.response.unwrap().response.status, 200);
    }

    /// Ten redirects are followed; the eleventh redirect answer is the session's response.
    #[tokio::test]
    async fn ten_redirects_are_followed_and_the_eleventh_is_the_response() {
        let transport = Scripted::new(|r| {
            let n: u32 = r.url.path().trim_start_matches('/').parse().unwrap_or(0);
            let next = format!("/{}", n + 1);
            Some((Duration::ZERO, answer(301, &[("location", next.as_str())])))
        });
        let run = run(&transport, Url::parse("http://site.com/0").unwrap(), &no_domains()).await;
        assert_eq!(run.redirects.len(), 11);
        assert_eq!(run.redirects.last().unwrap().url.path(), "/10");
        assert_eq!(run.response.unwrap().response.status, 301);
    }

    /// A Location that makes no URL fails the session.
    #[tokio::test]
    async fn an_unusable_location_fails_the_session() {
        let transport = Scripted::new(|_| Some((Duration::ZERO, answer(301, &[("location", "http://[bad")]))));
        let run = run(&transport, Url::parse("http://site.com/").unwrap(), &no_domains()).await;
        assert!(run.response.is_none());
        assert_eq!(run.redirects.len(), 1);
    }

    /// A request with no answer ends at the 9s request timeout; the session with it.
    #[tokio::test(start_paused = true)]
    async fn a_silent_request_ends_at_the_request_timeout() {
        let transport = Scripted::new(|_| None);
        let started = Instant::now();
        let run = run(&transport, Url::parse("https://site.com/").unwrap(), &no_domains()).await;
        assert!(run.response.is_none());
        assert_eq!(started.elapsed(), CLIENT_TIMEOUT);
    }

    /// Hops that each fit their 9s still end at the session's 10s cap.
    #[tokio::test(start_paused = true)]
    async fn slow_hops_end_at_the_session_cap() {
        let transport = Scripted::new(|r| match r.url.path() {
            "/" => Some((Duration::from_secs(6), answer(301, &[("location", "/next")]))),
            _ => Some((Duration::from_secs(6), answer(200, &[]))),
        });
        let started = Instant::now();
        let run = run(&transport, Url::parse("https://site.com/").unwrap(), &no_domains()).await;
        assert!(run.response.is_none());
        assert_eq!(started.elapsed(), ABORT_TIMEOUT);
        assert_eq!(transport.urls(), ["https://site.com/", "https://site.com/next"]);
    }

    /// The auxiliary client follows a 303 from OPTIONS as a GET (follow-redirects), and a
    /// non-2xx final answer is no response.
    #[tokio::test]
    async fn auxiliary_follows_redirects_and_rejects_non_2xx() {
        let transport = Scripted::new(|r| match (r.method, r.url.path()) {
            (Method::Get, "/") => Some((Duration::ZERO, answer(200, &[]))),
            (Method::Options, "/") => Some((Duration::ZERO, answer(303, &[("location", "/cors")]))),
            (Method::Get, "/cors") => Some((Duration::ZERO, answer(200, &[("x", "1")]))),
            _ => Some((Duration::ZERO, answer(404, &[]))),
        });
        let domains = no_domains();
        let mut session = run(&transport, Url::parse("https://site.com/").unwrap(), &domains).await;
        let start = Url::parse("https://site.com/").unwrap();
        let cors = session
            .auxiliary(&transport, Method::Options, &start, Vec::new(), &domains)
            .await
            .unwrap();
        assert_eq!(cors.response.headers.all("x"), ["1"]);
        let missing = Url::parse("https://site.com/missing").unwrap();
        assert!(
            session
                .auxiliary(&transport, Method::Get, &missing, Vec::new(), &domains)
                .await
                .is_none()
        );
        // The normal path records nothing.
        assert_eq!(session.redirects.len(), 1);
    }

    /// A failed session has no auxiliary client: nothing is sent.
    #[tokio::test]
    async fn a_failed_session_sends_no_auxiliary_request() {
        let transport = Scripted::new(|_| Some((Duration::ZERO, answer(301, &[("location", "http://[bad")]))));
        let domains = no_domains();
        let mut session = run(&transport, Url::parse("https://site.com/").unwrap(), &domains).await;
        let sent = transport.urls().len();
        let robots = Url::parse("https://site.com/robots.txt").unwrap();
        assert!(
            session
                .auxiliary(&transport, Method::Get, &robots, Vec::new(), &domains)
                .await
                .is_none()
        );
        assert_eq!(transport.urls().len(), sent);
    }

    fn raw(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    /// Two `Strict-Transport-Security` lines join with `", "`, which the HSTS test grades invalid.
    #[test]
    fn duplicate_headers_join_the_node_way() {
        let headers = node_headers(&raw(&[
            ("strict-transport-security", "max-age=31536000"),
            ("set-cookie", "a=1"),
            ("content-type", "text/html"),
            ("strict-transport-security", "max-age=0"),
            ("content-type", "text/plain"),
            ("cookie", "x=1"),
            ("set-cookie", "b=2"),
            ("cookie", "y=2"),
            ("location", "/one"),
            ("location", "/two"),
        ]));
        assert_eq!(
            headers.all("strict-transport-security"),
            ["max-age=31536000, max-age=0"]
        );
        assert_eq!(headers.all("set-cookie"), ["a=1", "b=2"]);
        assert_eq!(headers.all("content-type"), ["text/html"]);
        assert_eq!(headers.all("cookie"), ["x=1; y=2"]);
        assert_eq!(headers.all("location"), ["/one"]);
    }

    #[test]
    fn a_single_set_cookie_is_still_a_list() {
        let headers = node_headers(&raw(&[("set-cookie", "a=1")]));
        assert!(headers.is_truthy("set-cookie"));
        assert_eq!(headers.all("set-cookie"), ["a=1"]);
    }

    #[test]
    fn body_is_lossy_utf8_without_a_bom() {
        assert_eq!(decode_body(b"\xEF\xBB\xBFhi"), "hi");
        assert_eq!(decode_body(b"a\xFFb"), "a\u{FFFD}b");
        assert_eq!(decode_body(b""), "");
    }
}
