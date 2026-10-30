//! The timing and ALPN lenses: one timed HTTP/1.1 exchange against the target URL as given, split
//! into its phases, and one TLS handshake that only asks which protocol the server would speak.

use crate::scan::connect::TcpConnector;
use eyre::WrapErr;
use hickory_resolver::Resolver;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use url::Url;

/// The only protocol the timed request offers: an `h2` connection must speak HTTP/2 (RFC 9113
/// §3.4), and the probe writes HTTP/1.1.
const ALPN_HTTP1: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";
const READ_CHUNK: usize = 16 * 1024;
/// A response head larger than this is not a response the probe can time.
const MAX_HEAD_BYTES: usize = 64 * 1024;
const PROBE_USER_AGENT: &str = "scan/1.0";

/// One timed exchange, phase by phase. The phases are back to back: their sum is the exchange's
/// wall time less the time spent writing the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTiming {
    /// The host's name lookup; `None` for an IP address, which has nothing to look up.
    pub dns: Option<Duration>,
    pub connect: Duration,
    /// The TLS handshake; `None` for a plain `http://` URL.
    pub tls: Option<Duration>,
    /// Request written to the first response byte.
    pub ttfb: Duration,
    /// First response byte to the end of the body: `Content-Length` reached, the terminating
    /// chunk, or the server closing.
    pub transfer: Duration,
    /// The response's status code.
    pub status: u16,
}

pub type LookupFuture = Pin<Box<dyn Future<Output = eyre::Result<()>> + Send>>;

/// Looks a host name up, for the DNS phase. `system()` asks hickory with the system's resolver
/// configuration; the answer is not used, the connection goes to the pinned address.
#[derive(Clone)]
pub struct HostLookup(Arc<dyn Fn(String) -> LookupFuture + Send + Sync>);

impl HostLookup {
    pub fn system() -> Self {
        Self(Arc::new(|host| {
            Box::pin(async move {
                let resolver = Resolver::builder_tokio().wrap_err("creating DNS resolver")?.build();
                resolver.lookup_ip(host.as_str()).await.wrap_err("DNS lookup")?;
                Ok(())
            })
        }))
    }

    /// A lookup backed by `lookup`, for tests that need a chosen answer or delay.
    #[cfg(test)]
    pub fn from_fn(lookup: impl Fn(String) -> LookupFuture + Send + Sync + 'static) -> Self {
        Self(Arc::new(lookup))
    }

    fn lookup(&self, host: &str) -> LookupFuture {
        (self.0)(host.to_string())
    }
}

/// The network seams the two lenses use: the name lookup, the TCP connect and the TLS roots.
#[derive(Clone)]
pub struct Prober {
    lookup: HostLookup,
    connector: TcpConnector,
    roots: Arc<rustls::RootCertStore>,
}

impl Prober {
    /// The system resolver, real sockets, the built-in root store.
    pub fn system() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::new(HostLookup::system(), TcpConnector::system(), roots)
    }

    pub fn new(lookup: HostLookup, connector: TcpConnector, roots: rustls::RootCertStore) -> Self {
        Self {
            lookup,
            connector,
            roots: Arc::new(roots),
        }
    }

    /// A verifying client configuration offering `alpn`.
    fn tls_config(&self, alpn: &[&[u8]]) -> eyre::Result<Arc<ClientConfig>> {
        let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .wrap_err("TLS protocol versions")?
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(config))
    }

    /// One timed `GET` of `url` as given (scheme, host, port, path), connected to `ip`: a name
    /// lookup, the TCP connect, a TLS handshake offering `http/1.1` only for `https`, then the
    /// request with `Connection: close` and the whole response.
    pub async fn probe(&self, url: &Url, ip: IpAddr) -> eyre::Result<HttpTiming> {
        log::debug!("[scan::http::timing] probe: url={} ip={}", url, ip);
        let host = url.host().ok_or_else(|| eyre::eyre!("URL has no host: {url}"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| eyre::eyre!("URL has no port: {url}"))?;
        let tls = match url.scheme() {
            "https" => true,
            "http" => false,
            other => return Err(eyre::eyre!("cannot time a {other}:// URL")),
        };

        let started = Instant::now();
        let dns = match &host {
            url::Host::Domain(name) => {
                self.lookup.lookup(name).await?;
                Some(started.elapsed())
            }
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
        };
        let connect_started = Instant::now();
        let socket = self
            .connector
            .connect(SocketAddr::new(ip, port))
            .await
            .wrap_err("connect")?;
        let connected = Instant::now();
        let request = request_bytes(url);

        let (handshake, exchange) = if tls {
            let name = server_name(&host)?;
            let connector = tokio_rustls::TlsConnector::from(self.tls_config(&[ALPN_HTTP1])?);
            let mut stream = connector.connect(name, socket).await.wrap_err("TLS handshake")?;
            let handshake = connected.elapsed();
            log::trace!(
                "[scan::http::timing] probe_handshake: url={} alpn={:?}",
                url,
                stream.get_ref().1.alpn_protocol().map(String::from_utf8_lossy)
            );
            (Some(handshake), exchange(&mut stream, &request).await?)
        } else {
            let mut socket = socket;
            (None, exchange(&mut socket, &request).await?)
        };

        let timing = HttpTiming {
            dns,
            connect: connected - connect_started,
            tls: handshake,
            ttfb: exchange.first_byte - exchange.written,
            transfer: exchange.ended - exchange.first_byte,
            status: exchange.status,
        };
        log::debug!(
            "[scan::http::timing] probe_done: url={} status={} timing={:?} wall={:?}",
            url,
            timing.status,
            timing,
            started.elapsed()
        );
        Ok(timing)
    }

    /// The protocol `host` negotiates at `ip:port` when offered `h2` and `http/1.1`; `None` when
    /// it selects none. The connection closes right after the handshake: no request is sent.
    pub async fn alpn(&self, host: &str, ip: IpAddr, port: u16) -> eyre::Result<Option<String>> {
        log::debug!("[scan::http::timing] alpn: host={} ip={} port={}", host, ip, port);
        let host = url::Host::parse(host).wrap_err_with(|| format!("not a host: {host}"))?;
        let socket = self
            .connector
            .connect(SocketAddr::new(ip, port))
            .await
            .wrap_err("connect")?;
        let connector = tokio_rustls::TlsConnector::from(self.tls_config(&[ALPN_H2, ALPN_HTTP1])?);
        let mut stream = connector
            .connect(server_name(&host)?, socket)
            .await
            .wrap_err("TLS handshake")?;
        let protocol = stream
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        // close_notify only; a server that already hung up has nothing left to tell us.
        let _ = stream.shutdown().await;
        log::debug!("[scan::http::timing] alpn_done: host={} protocol={:?}", host, protocol);
        Ok(protocol)
    }
}

/// The name the certificate is verified against: the host name, or the address itself.
fn server_name<S: AsRef<str>>(host: &url::Host<S>) -> eyre::Result<ServerName<'static>> {
    Ok(match host {
        url::Host::Domain(name) => {
            ServerName::try_from(name.as_ref().to_string()).wrap_err("invalid TLS server name")?
        }
        url::Host::Ipv4(ip) => ServerName::IpAddress(IpAddr::V4(*ip).into()),
        url::Host::Ipv6(ip) => ServerName::IpAddress(IpAddr::V6(*ip).into()),
    })
}

/// `GET <path> HTTP/1.1` for `url`, `Host` with its port when the port is not the scheme's.
fn request_bytes(url: &Url) -> Vec<u8> {
    let host = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let path = match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => url.path().to_string(),
    };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {PROBE_USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// The instants one exchange's phases are cut at.
struct Exchange {
    written: Instant,
    first_byte: Instant,
    ended: Instant,
    status: u16,
}

/// Write `request`, then read the response to the end of its body.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &[u8]) -> eyre::Result<Exchange> {
    stream.write_all(request).await.wrap_err("writing the request")?;
    stream.flush().await.wrap_err("writing the request")?;
    let written = Instant::now();

    let mut buf = vec![0u8; READ_CHUNK];
    let mut first_byte = None;
    let mut head = Vec::new();
    let (status, mut body) = loop {
        let n = read_some(stream, &mut buf).await?;
        if n == 0 {
            eyre::bail!("connection closed before the response");
        }
        first_byte.get_or_insert_with(Instant::now);
        head.extend_from_slice(&buf[..n]);
        if let Some(found) = final_head(&mut head)? {
            break found;
        }
        if head.len() > MAX_HEAD_BYTES {
            eyre::bail!("response head larger than {MAX_HEAD_BYTES} bytes");
        }
    };
    let first_byte = first_byte.unwrap_or(written);
    while !body.complete() {
        let n = read_some(stream, &mut buf).await?;
        if n == 0 {
            if body.framing == Framing::Close {
                break;
            }
            eyre::bail!("connection closed {} bytes into the body", body.received);
        }
        body.feed(&buf[..n])?;
    }
    Ok(Exchange {
        written,
        first_byte,
        ended: Instant::now(),
        status,
    })
}

/// The final response head at the start of `head`, interim 1xx heads skipped, and a body fed
/// with whatever followed it; `None` until the final head has arrived.
fn final_head(head: &mut Vec<u8>) -> eyre::Result<Option<(u16, Body)>> {
    while let Some((status, framing, consumed)) = parse_head(head)? {
        head.drain(..consumed);
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let mut body = Body::new(framing);
        body.feed(head)?;
        head.clear();
        return Ok(Some((status, body)));
    }
    Ok(None)
}

/// One read; a TLS peer that closes without `close_notify` reads as a close, as it does for a
/// body that ends at the close.
async fn read_some<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> eyre::Result<usize> {
    match stream.read(buf).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e).wrap_err("reading the response"),
    }
}

/// How the body's end is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body at all (204, 304, 1xx).
    Empty,
    Length(u64),
    Chunked,
    /// Read until the server closes.
    Close,
}

/// The status and framing of the response head at the start of `bytes`, and the head's length;
/// `None` until the whole head has arrived.
fn parse_head(bytes: &[u8]) -> eyre::Result<Option<(u16, Framing, usize)>> {
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&bytes[..end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        eyre::bail!("not an HTTP response: {status_line:?}");
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| eyre::eyre!("no status code: {status_line:?}"))?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<u64>()
                    .wrap_err_with(|| format!("bad Content-Length: {value:?}"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
    }
    let framing = if (100..200).contains(&status) || status == 204 || status == 304 {
        Framing::Empty
    } else if chunked {
        Framing::Chunked
    } else if let Some(length) = length {
        Framing::Length(length)
    } else {
        Framing::Close
    };
    Ok(Some((status, framing, end + 4)))
}

/// Where a chunked body's decoder is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Chunk {
    /// Reading a chunk-size line.
    Size(Vec<u8>),
    /// This many data bytes left in the chunk.
    Data(u64),
    /// This many bytes of the CRLF after a chunk's data left.
    DataEnd(u8),
    /// Reading trailer lines after the last chunk; the current line so far.
    Trailer(Vec<u8>),
    Done,
}

/// Tracks a body's bytes until its framing says it ended. The bytes themselves are not kept.
#[derive(Debug)]
struct Body {
    framing: Framing,
    received: u64,
    chunk: Chunk,
}

impl Body {
    fn new(framing: Framing) -> Self {
        Self {
            framing,
            received: 0,
            chunk: Chunk::Size(Vec::new()),
        }
    }

    fn complete(&self) -> bool {
        match self.framing {
            Framing::Empty => true,
            Framing::Length(length) => self.received >= length,
            Framing::Chunked => self.chunk == Chunk::Done,
            Framing::Close => false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> eyre::Result<()> {
        self.received += bytes.len() as u64;
        if self.framing == Framing::Chunked {
            self.feed_chunked(bytes)?;
        }
        Ok(())
    }

    fn feed_chunked(&mut self, mut bytes: &[u8]) -> eyre::Result<()> {
        while !bytes.is_empty() {
            match &mut self.chunk {
                Chunk::Size(line) => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    if byte != b'\n' {
                        line.push(byte);
                        continue;
                    }
                    let text = String::from_utf8_lossy(line);
                    let size = text.split(';').next().unwrap_or_default().trim();
                    let size = u64::from_str_radix(size, 16).wrap_err_with(|| format!("bad chunk size: {size:?}"))?;
                    self.chunk = if size == 0 { Chunk::Trailer(Vec::new()) } else { Chunk::Data(size) };
                }
                Chunk::Data(left) => {
                    let take = (*left).min(bytes.len() as u64);
                    bytes = &bytes[take as usize..];
                    *left -= take;
                    if *left == 0 {
                        self.chunk = Chunk::DataEnd(2);
                    }
                }
                Chunk::DataEnd(left) => {
                    bytes = &bytes[1..];
                    *left -= 1;
                    if *left == 0 {
                        self.chunk = Chunk::Size(Vec::new());
                    }
                }
                Chunk::Trailer(line) => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    if byte != b'\n' {
                        line.push(byte);
                    } else if line.iter().all(|b| *b == b'\r') {
                        self.chunk = Chunk::Done;
                    } else {
                        line.clear();
                    }
                }
                Chunk::Done => bytes = &[],
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{ServerIdentity, TestCa, tls_acceptor};
    use tokio::net::TcpListener;

    const HOST: &str = "site.test";
    /// The fake's pauses before its first byte and before its body, so TTFB and transfer are
    /// measurably non-zero on loopback.
    const SERVER_PAUSE: Duration = Duration::from_millis(5);
    const LOOKUP_PAUSE: Duration = Duration::from_millis(2);
    const BODY: &[u8] = b"hello";

    /// What the fake saw on its one connection.
    #[derive(Debug, Default)]
    struct Seen {
        alpn: Option<Vec<u8>>,
        /// Every byte the client sent after the handshake, up to the end of the request head.
        request: Vec<u8>,
    }

    /// How the fake answers once the request head is in.
    #[derive(Clone, Copy, PartialEq)]
    enum Reply {
        /// A paused head, then a paused body.
        Answer,
        /// Nothing, ever.
        Stall,
        /// Read whatever arrives within a short window and close: for the ALPN handshake.
        Listen,
    }

    async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, reply: Reply) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        let window = if reply == Reply::Listen {
            Duration::from_millis(300)
        } else {
            Duration::from_secs(5)
        };
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match tokio::time::timeout(window, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => request.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        request
    }

    async fn answer<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, reply: Reply) -> Vec<u8> {
        let request = read_head(stream, reply).await;
        match reply {
            Reply::Answer => {
                tokio::time::sleep(SERVER_PAUSE).await;
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BODY.len());
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.flush().await;
                tokio::time::sleep(SERVER_PAUSE).await;
                let _ = stream.write_all(BODY).await;
                let _ = stream.shutdown().await;
            }
            Reply::Stall => std::future::pending::<()>().await,
            Reply::Listen => {}
        }
        request
    }

    /// One connection over TLS with `identity`, the server selecting from `alpn`.
    async fn tls_fake(identity: &ServerIdentity, alpn: &[&[u8]], reply: Reply) -> (u16, tokio::task::JoinHandle<Seen>) {
        let acceptor = tls_acceptor(identity, alpn);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            let request = answer(&mut stream, reply).await;
            Seen { alpn, request }
        });
        (port, task)
    }

    async fn plain_fake(reply: Reply) -> (u16, tokio::task::JoinHandle<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = answer(&mut socket, reply).await;
            Seen { alpn: None, request }
        });
        (port, task)
    }

    /// A prober trusting `ca`, whose lookup takes [`LOOKUP_PAUSE`] and counts as the DNS phase.
    fn prober(ca: &TestCa) -> Prober {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(ca.der())).unwrap();
        let lookup = HostLookup::from_fn(|_| {
            Box::pin(async {
                tokio::time::sleep(LOOKUP_PAUSE).await;
                Ok(())
            })
        });
        Prober::new(lookup, TcpConnector::system(), roots)
    }

    fn localhost() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn sum(timing: &HttpTiming) -> Duration {
        timing.dns.unwrap_or_default() + timing.connect + timing.tls.unwrap_or_default() + timing.ttfb + timing.transfer
    }

    #[tokio::test]
    async fn the_timed_request_is_a_valid_http1_exchange_whose_phases_sum_to_the_wall_time() {
        let ca = TestCa::new("timing CA");
        let (port, server) = tls_fake(&ca.issue(&[HOST]), &[ALPN_H2, ALPN_HTTP1], Reply::Answer).await;
        let url = Url::parse(&format!("https://{HOST}:{port}/path?q=1")).unwrap();

        let started = Instant::now();
        let timing = prober(&ca).probe(&url, localhost()).await.unwrap();
        let wall = started.elapsed();

        let seen = server.await.unwrap();
        assert_eq!(
            seen.alpn.as_deref(),
            Some(ALPN_HTTP1),
            "the timed request offers http/1.1 only"
        );
        let request = String::from_utf8(seen.request).unwrap();
        assert!(request.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{request}");
        assert!(request.contains(&format!("\r\nHost: {HOST}:{port}\r\n")), "{request}");
        assert!(request.contains("\r\nConnection: close\r\n"), "{request}");

        assert_eq!(timing.status, 200);
        for (phase, value) in [
            ("dns", timing.dns.unwrap()),
            ("connect", timing.connect),
            ("tls", timing.tls.unwrap()),
            ("ttfb", timing.ttfb),
            ("transfer", timing.transfer),
        ] {
            assert!(!value.is_zero(), "{phase} is zero: {timing:?}");
        }
        assert!(timing.dns.unwrap() >= LOOKUP_PAUSE, "{timing:?}");
        assert!(timing.ttfb >= SERVER_PAUSE, "{timing:?}");
        assert!(timing.transfer >= SERVER_PAUSE, "{timing:?}");
        let total = sum(&timing);
        assert!(total <= wall, "phases {total:?} exceed the wall time {wall:?}");
        assert!(
            wall - total < Duration::from_millis(5),
            "phases {total:?} vs wall {wall:?}: {timing:?}"
        );
    }

    #[tokio::test]
    async fn a_plain_http_url_has_no_tls_phase() {
        let (port, server) = plain_fake(Reply::Answer).await;
        let url = Url::parse(&format!("http://{HOST}:{port}/")).unwrap();
        let timing = prober(&TestCa::new("unused CA"))
            .probe(&url, localhost())
            .await
            .unwrap();
        assert_eq!(timing.tls, None);
        assert!(timing.dns.is_some());
        assert!(!timing.ttfb.is_zero() && !timing.transfer.is_zero(), "{timing:?}");
        assert!(
            String::from_utf8(server.await.unwrap().request)
                .unwrap()
                .starts_with("GET / HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn an_ip_url_has_no_dns_phase() {
        let (port, _server) = plain_fake(Reply::Answer).await;
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let timing = prober(&TestCa::new("unused CA"))
            .probe(&url, localhost())
            .await
            .unwrap();
        assert_eq!(timing.dns, None);
    }

    #[tokio::test]
    async fn the_alpn_handshake_reports_h2_and_sends_no_request() {
        let ca = TestCa::new("alpn CA");
        let (port, server) = tls_fake(&ca.issue(&[HOST]), &[ALPN_H2, ALPN_HTTP1], Reply::Listen).await;
        let protocol = prober(&ca).alpn(HOST, localhost(), port).await.unwrap();
        assert_eq!(protocol.as_deref(), Some("h2"));
        let seen = server.await.unwrap();
        assert_eq!(seen.alpn.as_deref(), Some(ALPN_H2));
        assert!(seen.request.is_empty(), "request bytes: {:?}", seen.request);
    }

    #[tokio::test]
    async fn a_server_without_alpn_negotiates_none() {
        let ca = TestCa::new("alpn CA");
        let (port, server) = tls_fake(&ca.issue(&[HOST]), &[], Reply::Listen).await;
        assert_eq!(prober(&ca).alpn(HOST, localhost(), port).await.unwrap(), None);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn an_untrusted_certificate_fails_the_probe() {
        let (trusted, other) = (TestCa::new("trusted CA"), TestCa::new("other CA"));
        let (port, _server) = tls_fake(&other.issue(&[HOST]), &[], Reply::Listen).await;
        let url = Url::parse(&format!("https://{HOST}:{port}/")).unwrap();
        let error = prober(&trusted).probe(&url, localhost()).await.unwrap_err();
        assert!(format!("{error:#}").contains("TLS handshake"), "{error:#}");
    }

    /// A server that completes the handshake and never answers holds the probe until its caller's
    /// timeout; the scan-level test shows the lens then reads `failed`.
    #[tokio::test]
    async fn a_server_that_stalls_after_the_handshake_never_completes_the_probe() {
        let ca = TestCa::new("stall CA");
        let (port, _server) = tls_fake(&ca.issue(&[HOST]), &[ALPN_HTTP1], Reply::Stall).await;
        let url = Url::parse(&format!("https://{HOST}:{port}/")).unwrap();
        let outcome = tokio::time::timeout(Duration::from_millis(300), prober(&ca).probe(&url, localhost())).await;
        assert!(outcome.is_err(), "{outcome:?}");
    }

    #[test]
    fn the_request_names_the_path_query_and_a_non_default_port() {
        let request = |url: &str| String::from_utf8(request_bytes(&Url::parse(url).unwrap())).unwrap();
        assert!(request("https://site.test/").starts_with("GET / HTTP/1.1\r\nHost: site.test\r\n"));
        assert!(request("http://site.test:8080/a?b=c").starts_with("GET /a?b=c HTTP/1.1\r\nHost: site.test:8080\r\n"));
        assert!(request("http://[::1]:81/").contains("\r\nHost: [::1]:81\r\n"));
    }

    #[test]
    fn heads_give_the_status_and_how_the_body_ends() {
        let head = |text: &str| {
            parse_head(text.as_bytes())
                .unwrap()
                .map(|(status, framing, _)| (status, framing))
        };
        assert_eq!(head("HTTP/1.1 200 OK\r\nContent-Length: 5"), None, "head not complete");
        assert_eq!(
            head("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n"),
            Some((200, Framing::Length(5)))
        );
        assert_eq!(
            head("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 5\r\n\r\n"),
            Some((200, Framing::Chunked))
        );
        assert_eq!(head("HTTP/1.0 200 OK\r\n\r\n"), Some((200, Framing::Close)));
        assert_eq!(head("HTTP/1.1 204 No Content\r\n\r\n"), Some((204, Framing::Empty)));
        assert_eq!(
            head("HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n"),
            Some((304, Framing::Empty))
        );
        assert!(parse_head(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n").is_err());
    }

    #[test]
    fn interim_heads_are_skipped_and_the_rest_feeds_the_body() {
        let mut bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab".to_vec();
        let (status, body) = final_head(&mut bytes).unwrap().unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.received, 2);
        assert!(!body.complete());
    }

    #[test]
    fn a_chunked_body_ends_at_its_terminating_chunk_across_reads() {
        let mut body = Body::new(Framing::Chunked);
        let wire = b"5;ext=1\r\nhello\r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\n";
        for piece in wire.chunks(3) {
            assert!(!body.complete());
            body.feed(piece).unwrap();
        }
        assert!(body.complete());

        let mut unfinished = Body::new(Framing::Chunked);
        unfinished.feed(b"5\r\nhello\r\n").unwrap();
        assert!(!unfinished.complete());
        assert!(Body::new(Framing::Chunked).feed(b"zz\r\n").is_err());
    }

    #[test]
    fn a_length_body_ends_at_its_length_and_a_close_body_never_by_itself() {
        let mut body = Body::new(Framing::Length(4));
        body.feed(b"ab").unwrap();
        assert!(!body.complete());
        body.feed(b"cd").unwrap();
        assert!(body.complete());
        let mut close = Body::new(Framing::Close);
        close.feed(b"anything").unwrap();
        assert!(!close.complete());
        assert!(Body::new(Framing::Empty).complete());
    }

    /// A body cut short by the server is an error, not a short transfer.
    #[tokio::test]
    async fn a_body_cut_short_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_head(&mut socket, Reply::Answer).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                .await;
            let _ = socket.shutdown().await;
        });
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let error = prober(&TestCa::new("unused CA"))
            .probe(&url, localhost())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("3 bytes into the body"), "{error:#}");
    }
}
