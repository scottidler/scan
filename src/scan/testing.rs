//! Test helpers shared by the scanner tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
/// Write `content` to `path` as an executable script, ready to exec.
///
/// A child `sh` does the write. If this process held the write fd, a sibling test's fork
/// could inherit it, and exec of the script would fail with `Text file busy (os error 26)`.
pub fn write_executable_script(path: &Path, content: &str) {
    let status = std::process::Command::new("sh")
        .args(["-c", r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#, "sh"])
        .arg(content)
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("spawning sh to write {}: {e}", path.display()));
    assert!(status.success(), "writing {}: {status}", path.display());
}

/// Bound on every fake-server accept and read, so a missed request ends the server instead of
/// hanging the test.
const FAKE_SERVER_WAIT: Duration = Duration::from_secs(5);

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory under the system temp dir, unique per call.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "scan-{name}-{}-{}",
        std::process::id(),
        TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

/// One route of a [`FakeHttp`]: what it matches (method, `Host`, path) and what it answers.
#[derive(Debug, Clone)]
pub struct FakeRoute {
    method: Option<String>,
    host: Option<String>,
    path: String,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    stall: bool,
}

impl FakeRoute {
    /// Any method on `path`, answering `status` with no headers and an empty body.
    pub fn new(path: &str, status: u16) -> Self {
        Self {
            method: None,
            host: None,
            path: path.to_string(),
            status,
            headers: Vec::new(),
            body: Vec::new(),
            stall: false,
        }
    }

    /// `GET` on `path` only.
    pub fn get(path: &str, status: u16) -> Self {
        Self::new(path, status).method("GET")
    }

    /// `OPTIONS` on `path` only.
    pub fn options(path: &str, status: u16) -> Self {
        Self::new(path, status).method("OPTIONS")
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = Some(method.to_string());
        self
    }

    /// Only requests whose `Host` names `host` (port ignored).
    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_lowercase());
        self
    }

    /// One response header line; repeat a name to send it twice.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Read the request, then never answer.
    pub fn stall(mut self) -> Self {
        self.stall = true;
        self
    }

    fn matches(&self, request: &FakeRequest) -> bool {
        self.path == request.path
            && self.method.as_deref().is_none_or(|m| m == request.method)
            && self.host.as_deref().is_none_or(|h| Some(h) == request.host.as_deref())
    }
}

/// One request a [`FakeHttp`] received.
#[derive(Debug, Clone)]
pub struct FakeRequest {
    pub method: String,
    pub path: String,
    /// The `Host` header's name, lowercase, port dropped.
    pub host: Option<String>,
    /// Lowercase names, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl FakeRequest {
    /// The first value of `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A certificate authority for TLS fakes: trust it in the client under test, and it signs
/// [`ServerIdentity`]s for any names.
pub struct TestCa {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    cert: openssl::x509::X509,
}

/// A server certificate chain and key, DER.
#[derive(Clone)]
pub struct ServerIdentity {
    pub chain: Vec<Vec<u8>>,
    /// PKCS#8.
    pub key: Vec<u8>,
}

static SERIAL_COUNTER: AtomicU64 = AtomicU64::new(1);

impl TestCa {
    pub fn new(common_name: &str) -> Self {
        use openssl::x509::extension::{BasicConstraints, KeyUsage};
        let key = test_key();
        let mut builder = cert_builder(common_name, &key);
        builder.set_issuer_name(&x509_name(common_name)).expect("issuer");
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .expect("basic constraints"),
            )
            .expect("append basic constraints");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("key usage"),
            )
            .expect("append key usage");
        builder
            .sign(&key, openssl::hash::MessageDigest::sha256())
            .expect("sign CA");
        Self {
            key,
            cert: builder.build(),
        }
    }

    /// The CA certificate, DER: what a client adds as a root.
    pub fn der(&self) -> Vec<u8> {
        self.cert.to_der().expect("CA to DER")
    }

    /// A leaf for `names` (DNS SANs) signed by this CA, chained leaf then CA.
    pub fn issue(&self, names: &[&str]) -> ServerIdentity {
        use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName};
        let key = test_key();
        let mut builder = cert_builder(names[0], &key);
        builder.set_issuer_name(self.cert.subject_name()).expect("issuer");
        builder
            .append_extension(BasicConstraints::new().build().expect("basic constraints"))
            .expect("append basic constraints");
        builder
            .append_extension(ExtendedKeyUsage::new().server_auth().build().expect("eku"))
            .expect("append eku");
        let mut san = SubjectAlternativeName::new();
        for name in names {
            san.dns(name);
        }
        let san = san.build(&builder.x509v3_context(Some(&self.cert), None)).expect("san");
        builder.append_extension(san).expect("append san");
        builder
            .sign(&self.key, openssl::hash::MessageDigest::sha256())
            .expect("sign leaf");
        ServerIdentity {
            chain: vec![builder.build().to_der().expect("leaf to DER"), self.der()],
            key: key.private_key_to_pkcs8().expect("key to PKCS#8"),
        }
    }
}

fn test_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).expect("P-256");
    openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).expect("EC key")).expect("PKey")
}

fn x509_name(common_name: &str) -> openssl::x509::X509Name {
    let mut name = openssl::x509::X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
        .expect("CN");
    name.build()
}

/// A v3 certificate for `common_name` valid from a day ago for 30 days, with a fresh serial.
fn cert_builder(common_name: &str, key: &openssl::pkey::PKey<openssl::pkey::Private>) -> openssl::x509::X509Builder {
    let mut builder = openssl::x509::X509Builder::new().expect("x509 builder");
    builder.set_version(2).expect("version");
    let serial = openssl::bn::BigNum::from_u32(SERIAL_COUNTER.fetch_add(1, Ordering::Relaxed) as u32)
        .and_then(|bn| bn.to_asn1_integer())
        .expect("serial");
    builder.set_serial_number(&serial).expect("set serial");
    builder.set_subject_name(&x509_name(common_name)).expect("subject");
    builder.set_pubkey(key).expect("pubkey");
    let now = chrono::Utc::now();
    builder
        .set_not_before(&openssl::asn1::Asn1Time::from_unix((now - chrono::Duration::days(1)).timestamp()).expect("nb"))
        .expect("set not_before");
    builder
        .set_not_after(&openssl::asn1::Asn1Time::from_unix((now + chrono::Duration::days(30)).timestamp()).expect("na"))
        .expect("set not_after");
    builder
}

/// A TLS acceptor serving `identity` that selects from `alpn` (in its order of preference) when
/// the client offers ALPN; an empty list negotiates none.
pub fn tls_acceptor(identity: &ServerIdentity, alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    use tokio_rustls::rustls;
    let chain = identity
        .chain
        .iter()
        .map(|der| rustls::pki_types::CertificateDer::from(der.clone()))
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(identity.key.clone().into());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server certificate");
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// A local HTTP/1.1 server answering fixed routes, one request per connection, and recording every
/// request. An unknown route gets 404. Plain, or TLS with a [`ServerIdentity`]. It stops when
/// dropped.
pub struct FakeHttp {
    addr: String,
    scheme: &'static str,
    routes: Arc<Mutex<Vec<FakeRoute>>>,
    requests: Arc<Mutex<Vec<FakeRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeHttp {
    /// Plain HTTP routes as `(path, status, body)`, any method.
    pub async fn start(routes: Vec<(&str, u16, String)>) -> Self {
        Self::start_routes(
            routes
                .into_iter()
                .map(|(path, status, body)| FakeRoute::new(path, status).body(body))
                .collect(),
        )
        .await
    }

    /// Plain HTTP.
    pub async fn start_routes(routes: Vec<FakeRoute>) -> Self {
        Self::launch(routes, None).await
    }

    /// TLS with `identity`.
    pub async fn start_tls(routes: Vec<FakeRoute>, identity: &ServerIdentity) -> Self {
        Self::start_tls_alpn(routes, identity, &[]).await
    }

    /// TLS with `identity`, selecting from `alpn` when the client offers ALPN. Every request is
    /// still answered as HTTP/1.1, so offer `h2` only to a client that never sends a request.
    pub async fn start_tls_alpn(routes: Vec<FakeRoute>, identity: &ServerIdentity, alpn: &[&[u8]]) -> Self {
        Self::launch(routes, Some(tls_acceptor(identity, alpn))).await
    }

    async fn launch(routes: Vec<FakeRoute>, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let routes = Arc::new(Mutex::new(routes));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (shared_routes, seen) = (routes.clone(), requests.clone());
        let scheme = if tls.is_some() { "https" } else { "http" };
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((socket, _)) = listener.accept().await {
                let (routes, seen, tls) = (shared_routes.clone(), seen.clone(), tls.clone());
                connections.spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            // A client that rejects the certificate aborts the handshake.
                            if let Ok(Ok(stream)) =
                                tokio::time::timeout(FAKE_SERVER_WAIT, acceptor.accept(socket)).await
                            {
                                serve(stream, &routes, &seen).await;
                            }
                        }
                        None => serve(socket, &routes, &seen).await,
                    }
                });
                while connections.try_join_next().is_some() {}
            }
        });
        Self {
            addr,
            scheme,
            routes,
            requests,
            task,
        }
    }

    /// Adds a route after start, for a body that names the server's own address.
    pub fn add_route(&self, path: &str, status: u16, body: String) {
        self.add(FakeRoute::new(path, status).body(body));
    }

    /// Adds a route after start.
    pub fn add(&self, route: FakeRoute) {
        self.routes.lock().unwrap().push(route);
    }

    /// `<scheme>://<addr><path>`
    pub fn url(&self, path: &str) -> String {
        format!("{}://{}{}", self.scheme, self.addr, path)
    }

    /// The bound port.
    pub fn port(&self) -> u16 {
        self.addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("bound port")
    }

    /// Requests received so far for `path`.
    pub fn hits(&self, path: &str) -> usize {
        self.requests.lock().unwrap().iter().filter(|r| r.path == path).count()
    }

    /// Requests received so far, on any path.
    pub fn total_hits(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<FakeRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// `<scheme>://<addr>`, for a client that appends its own paths.
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme, self.addr)
    }
}

/// One request on `stream`: record it, answer the first matching route.
async fn serve<S>(mut stream: S, routes: &Mutex<Vec<FakeRoute>>, seen: &Mutex<Vec<FakeRequest>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    seen.lock().unwrap().push(request.clone());
    let route = routes.lock().unwrap().iter().find(|r| r.matches(&request)).cloned();
    let route = route.unwrap_or_else(|| FakeRoute::new(&request.path, 404));
    if route.stall {
        std::future::pending::<()>().await;
    }
    let mut response = format!("HTTP/1.1 {} Fixture\r\n", route.status).into_bytes();
    for (name, value) in &route.headers {
        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    response.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", route.body.len()).as_bytes());
    response.extend_from_slice(&route.body);
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

/// The request line and headers, read up to the end of the headers; `None` when the client sends
/// nothing readable in time.
async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<FakeRequest> {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(FAKE_SERVER_WAIT, stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&request);
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
        .collect();
    let host = headers
        .iter()
        .find(|(name, _)| name == "host")
        .map(|(_, value)| value.rsplit_once(':').map_or(value.as_str(), |(h, _)| h).to_lowercase());
    Some(FakeRequest {
        method,
        path,
        host,
        headers,
    })
}

/// A URL on a local port nothing listens on, so a request to it is refused at once.
/// The port stays bound, never listening, for the life of the test process: freeing it let a
/// parallel test's server bind it, and the request was then accepted and reset, not refused.
pub async fn dead_http_url() -> String {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    std::mem::forget(socket);
    format!("http://{addr}/gone")
}

/// A URL whose server accepts one connection and never answers it.
pub async fn silent_http_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok(Ok((socket, _))) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(socket);
        }
    });
    format!("http://{addr}/silent")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn written_script_is_executable_and_runs() {
        let dir = std::env::temp_dir().join(format!("scan-testing-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("hello");
        write_executable_script(&script, "#!/bin/sh\necho \"hi $1\"\n");
        let out = std::process::Command::new(&script).arg("there").output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi there\n");
    }

    #[test]
    #[should_panic(expected = "writing")]
    fn unwritable_path_panics_loudly() {
        write_executable_script(Path::new("/nonexistent-dir/script"), "#!/bin/sh\n");
    }
}
