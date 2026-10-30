use super::connect::TcpConnector;
use super::{Family, classify_route_error, family_failure};
use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use crate::types::ScanResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use eyre::{Result, WrapErr};
use log;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::{X509, X509Ref};
use rustls::pki_types::ServerName;
use rustls::{CertificateError, ClientConfig, ProtocolVersion};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;
use webpki_roots;

const TLS_SCAN_INTERVAL_SECS: u64 = 300;
const TLS_CONNECTION_TIMEOUT_SECS: u64 = 10;
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const TLS_TOTAL_SCAN_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq)]
pub enum TlsVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
}

impl TlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::V1_0 => "TLSv1.0",
            TlsVersion::V1_1 => "TLSv1.1",
            TlsVersion::V1_2 => "TLSv1.2",
            TlsVersion::V1_3 => "TLSv1.3",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub key_size: Option<u32>,
    pub san_domains: Vec<String>, // Subject Alternative Names
    pub is_self_signed: bool,
    pub is_ca: bool,
}

#[derive(Debug, Clone)]
pub struct CipherSuite {
    pub name: String,
    pub protocol_version: String,
    pub key_exchange: String,
    pub authentication: String,
    pub encryption: String,
    pub mac: String,
    pub is_secure: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsVulnerability {
    Heartbleed,
    Poodle,
    Beast,
    Crime,
    WeakCipher(String),
    ExpiredCertificate,
    SelfSignedCertificate,
    UntrustedIssuer,
    HostnameMismatch,
    WeakSignatureAlgorithm(String),
    InsecureRenegotiation,
    WeakDhParams,
    SslV2Enabled,
    SslV3Enabled,
}

impl TlsVulnerability {
    /// The text the Security pane and `--no-tui` show for this issue.
    pub fn description(&self) -> String {
        match self {
            TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
            TlsVulnerability::Poodle => "POODLE (CVE-2014-3566)".to_string(),
            TlsVulnerability::Beast => "BEAST (CVE-2011-3389)".to_string(),
            TlsVulnerability::Crime => "CRIME (CVE-2012-4929)".to_string(),
            TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
            TlsVulnerability::ExpiredCertificate => "Certificate expired".to_string(),
            TlsVulnerability::SelfSignedCertificate => "Self-signed certificate".to_string(),
            TlsVulnerability::UntrustedIssuer => "Untrusted certificate issuer".to_string(),
            TlsVulnerability::HostnameMismatch => "Certificate hostname mismatch".to_string(),
            TlsVulnerability::WeakSignatureAlgorithm(alg) => format!("Weak signature: {}", alg),
            TlsVulnerability::InsecureRenegotiation => "Insecure renegotiation".to_string(),
            TlsVulnerability::WeakDhParams => "Weak DH parameters".to_string(),
            TlsVulnerability::SslV2Enabled => "SSLv2 enabled".to_string(),
            TlsVulnerability::SslV3Enabled => "SSLv3 enabled".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl SecurityGrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityGrade::APlus => "A+",
            SecurityGrade::A => "A",
            SecurityGrade::B => "B",
            SecurityGrade::C => "C",
            SecurityGrade::D => "D",
            SecurityGrade::F => "F",
        }
    }
}

// New IPv4/IPv6 first-class support structures
#[derive(Debug, Clone)]
pub struct TlsData {
    // Connection Info
    pub connection_successful: bool,
    pub handshake_time: Duration,
    pub supported_versions: Vec<TlsVersion>,
    pub negotiated_version: Option<TlsVersion>,

    // Certificate Analysis
    pub certificate_chain: Vec<CertificateInfo>,
    pub certificate_valid: bool,
    pub certificate_errors: Vec<String>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,

    // Cipher & Security
    pub supported_ciphers: Vec<CipherSuite>,
    pub negotiated_cipher: Option<CipherSuite>,
    pub perfect_forward_secrecy: bool,
    pub ocsp_stapling: bool,

    // Vulnerabilities
    pub vulnerabilities: Vec<TlsVulnerability>,
    pub security_grade: SecurityGrade,

    // Metadata
    pub scan_time: Duration,
    pub target_ip: String,
    pub queried_at: Instant,
}

impl TlsData {
    pub fn new(target_ip: String) -> Self {
        Self {
            connection_successful: false,
            handshake_time: Duration::from_millis(0),
            supported_versions: Vec::new(),
            negotiated_version: None,
            certificate_chain: Vec::new(),
            certificate_valid: false,
            certificate_errors: Vec::new(),
            expiry_date: None,
            days_until_expiry: None,
            supported_ciphers: Vec::new(),
            negotiated_cipher: None,
            perfect_forward_secrecy: false,
            ocsp_stapling: false,
            vulnerabilities: Vec::new(),
            security_grade: SecurityGrade::F,
            scan_time: Duration::from_millis(0),
            target_ip,
            queried_at: Instant::now(),
        }
    }

    /// Issues shown in the Security pane. One cause lives in exactly one list, so it counts once.
    pub fn issue_count(&self) -> usize {
        self.vulnerabilities.len() + self.certificate_errors.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsStatus {
    NotQueried,             // Protocol not attempted (due to protocol restrictions)
    Success(SecurityGrade), // TLS scan succeeded with security grade
    Failed(String),         // TLS scan failed with error message
    NoAddress,              // No address available for this protocol
}

impl TlsStatus {
    pub fn was_attempted(&self) -> bool {
        !matches!(self, TlsStatus::NotQueried)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, TlsStatus::Success(_))
    }

    pub fn security_grade(&self) -> Option<&SecurityGrade> {
        match self {
            TlsStatus::Success(grade) => Some(grade),
            _ => None,
        }
    }
}

// New dual-protocol TlsResult with helper methods
#[derive(Debug, Clone)]
pub struct TlsResult {
    // Protocol-specific results
    pub ipv4_result: Option<TlsData>,
    pub ipv6_result: Option<TlsData>,

    // Status tracking
    pub ipv4_status: TlsStatus,
    pub ipv6_status: TlsStatus,

    // Metadata
    pub queried_at: Instant,
    pub total_duration: Duration,
}

impl Default for TlsResult {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: TlsStatus::NotQueried,
            ipv6_status: TlsStatus::NotQueried,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn has_any_success(&self) -> bool {
        self.ipv4_status.is_success() || self.ipv6_status.is_success()
    }

    pub fn get_best_security_grade(&self) -> Option<&SecurityGrade> {
        let ipv4_grade = self.ipv4_status.security_grade();
        let ipv6_grade = self.ipv6_status.security_grade();

        match (ipv4_grade, ipv6_grade) {
            (Some(g4), Some(g6)) => {
                // Return the better grade (A+ > A > B > C > D > F)
                if matches!(g4, SecurityGrade::APlus) || matches!(g6, SecurityGrade::APlus) {
                    if matches!(g4, SecurityGrade::APlus) { Some(g4) } else { Some(g6) }
                } else if matches!(g4, SecurityGrade::A) || matches!(g6, SecurityGrade::A) {
                    if matches!(g4, SecurityGrade::A) { Some(g4) } else { Some(g6) }
                } else if matches!(g4, SecurityGrade::B) || matches!(g6, SecurityGrade::B) {
                    if matches!(g4, SecurityGrade::B) { Some(g4) } else { Some(g6) }
                } else if matches!(g4, SecurityGrade::C) || matches!(g6, SecurityGrade::C) {
                    if matches!(g4, SecurityGrade::C) { Some(g4) } else { Some(g6) }
                } else if matches!(g4, SecurityGrade::D) || matches!(g6, SecurityGrade::D) {
                    if matches!(g4, SecurityGrade::D) { Some(g4) } else { Some(g6) }
                } else {
                    Some(g4) // Both F, return either
                }
            }
            (Some(g), None) => Some(g),
            (None, Some(g)) => Some(g),
            (None, None) => None,
        }
    }

    /// Why every attempted family failed, e.g. `IPv6: no IPv6 route on this host`. Families with
    /// no address are left out.
    pub fn failure(&self, protocol: Protocol) -> eyre::Report {
        let failures: Vec<(Family, String)> = [(Family::Ipv4, &self.ipv4_status), (Family::Ipv6, &self.ipv6_status)]
            .into_iter()
            .filter_map(|(family, status)| match status {
                TlsStatus::Failed(reason) => Some((family, reason.clone())),
                _ => None,
            })
            .collect();
        family_failure(&failures, protocol)
    }

    pub fn get_primary_result(&self) -> Option<&TlsData> {
        // Prefer IPv4, then IPv6
        if let Some(ipv4_data) = &self.ipv4_result {
            Some(ipv4_data)
        } else if let Some(ipv6_data) = &self.ipv6_result {
            Some(ipv6_data)
        } else {
            None
        }
    }

    pub fn total_vulnerabilities(&self) -> usize {
        let ipv4_vulns = self.ipv4_result.as_ref().map(|r| r.vulnerabilities.len()).unwrap_or(0);
        let ipv6_vulns = self.ipv6_result.as_ref().map(|r| r.vulnerabilities.len()).unwrap_or(0);
        ipv4_vulns + ipv6_vulns
    }

    pub fn get_all_vulnerabilities(&self) -> Vec<&TlsVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(ipv4_data) = &self.ipv4_result {
            vulnerabilities.extend(&ipv4_data.vulnerabilities);
        }
        if let Some(ipv6_data) = &self.ipv6_result {
            vulnerabilities.extend(&ipv6_data.vulnerabilities);
        }

        vulnerabilities
    }
}

/// Socket address for a TLS connection. Built from parts, so an IPv6 literal needs no brackets.
pub fn connect_addr(target_ip: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = target_ip
        .parse()
        .wrap_err_with(|| format!("TLS target is not an IP address: {}", target_ip))?;
    Ok(SocketAddr::new(ip, port))
}

/// Name the rustls client verifies the certificate against: the domain when there is one, else the IP.
pub fn server_name(domain: Option<&str>, ip: IpAddr) -> Result<ServerName<'static>> {
    match domain {
        Some(domain) => ServerName::try_from(domain.to_string()).wrap_err("Invalid domain name for TLS"),
        None => Ok(ServerName::IpAddress(ip.into())),
    }
}

/// Convert an ASN.1 time to UTC by diffing it against the Unix epoch; no string parsing.
pub fn asn1_to_utc(t: &Asn1TimeRef) -> Result<DateTime<Utc>> {
    let epoch = Asn1Time::from_unix(0).wrap_err("Failed to build ASN.1 epoch")?;
    let diff = epoch.diff(t).wrap_err("Failed to diff ASN.1 time against epoch")?;
    let secs = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    DateTime::from_timestamp(secs, 0).ok_or_else(|| eyre::eyre!("ASN.1 time out of range: {}s since epoch", secs))
}

/// Forward secrecy: every TLS 1.3 suite has it; TLS 1.2 only with an ephemeral (EC)DHE key exchange.
pub fn has_pfs(version: ProtocolVersion, suite: rustls::CipherSuite) -> bool {
    match version {
        ProtocolVersion::TLSv1_3 => true,
        ProtocolVersion::TLSv1_2 => suite
            .as_str()
            .is_some_and(|name| name.starts_with("TLS_ECDHE_") || name.starts_with("TLS_DHE_")),
        _ => false,
    }
}

/// Describe the negotiated suite from its IANA name (`TLS_<kx>_<auth>_WITH_<enc>_<mac>` or `TLS13_<enc>_<mac>`).
fn cipher_suite_info(version: ProtocolVersion, suite: rustls::CipherSuite) -> CipherSuite {
    let name = suite
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("{:?}", suite));
    let (key_exchange, authentication, bulk) = if version == ProtocolVersion::TLSv1_3 {
        // rustls' ring provider only offers ECDHE groups; TLS 1.3 authenticates via the certificate.
        (
            "ECDHE".to_string(),
            "certificate".to_string(),
            name.trim_start_matches("TLS13_").to_string(),
        )
    } else if let Some((kx_auth, bulk)) = name.trim_start_matches("TLS_").split_once("_WITH_") {
        let (kx, auth) = kx_auth.split_once('_').unwrap_or((kx_auth, kx_auth));
        (kx.to_string(), auth.to_string(), bulk.to_string())
    } else {
        ("unknown".to_string(), "unknown".to_string(), name.clone())
    };
    let (encryption, mac) = match bulk.rsplit_once('_') {
        Some((enc, mac)) => (enc.to_string(), mac.to_string()),
        None => (bulk.clone(), "unknown".to_string()),
    };
    let aead = encryption.contains("GCM") || encryption.contains("CHACHA20");
    CipherSuite {
        protocol_version: format!("{:?}", version),
        is_secure: has_pfs(version, suite) && aead,
        name,
        key_exchange,
        authentication,
        encryption,
        mac,
    }
}

/// Map a certificate-verification failure from the handshake to the vulnerability it proves.
pub fn vulnerability_for_handshake_error(error: &rustls::Error) -> Option<TlsVulnerability> {
    match error {
        rustls::Error::InvalidCertificate(cert_error) => match cert_error {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                Some(TlsVulnerability::ExpiredCertificate)
            }
            CertificateError::UnknownIssuer => Some(TlsVulnerability::UntrustedIssuer),
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                Some(TlsVulnerability::HostnameMismatch)
            }
            _ => None,
        },
        _ => None,
    }
}

/// tokio-rustls surfaces handshake failures as `io::Error` wrapping the `rustls::Error`.
fn handshake_rejection(error: &std::io::Error) -> Option<TlsVulnerability> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .and_then(vulnerability_for_handshake_error)
}

/// Handshake rejection first, then detected causes not already present. A self-signed leaf is the
/// reason its issuer is untrusted, so it is one cause and keeps only `SelfSignedCertificate`.
fn merge_vulnerabilities(
    handshake: Option<TlsVulnerability>,
    detected: Vec<TlsVulnerability>,
) -> Vec<TlsVulnerability> {
    let mut merged: Vec<TlsVulnerability> = handshake.into_iter().collect();
    for vulnerability in detected {
        if !merged.contains(&vulnerability) {
            merged.push(vulnerability);
        }
    }
    if merged.contains(&TlsVulnerability::SelfSignedCertificate) {
        merged.retain(|v| *v != TlsVulnerability::UntrustedIssuer);
    }
    merged
}

/// The certificates the server presented, leaf first. On the client side OpenSSL's
/// `peer_cert_chain()` already starts with the leaf, so it is the whole answer; `peer_certificate()`
/// stands in only when there is no chain (a resumed session).
fn presented_chain<C>(leaf: Option<C>, chain: Option<Vec<C>>) -> Vec<C> {
    match chain {
        Some(chain) if !chain.is_empty() => chain,
        _ => leaf.into_iter().collect(),
    }
}

/// Leaf expiry fields derive from the chain's first certificate.
fn apply_certificate_chain(result: &mut TlsData, cert_chain: Vec<CertificateInfo>, now: DateTime<Utc>) {
    if let Some(leaf_cert) = cert_chain.first() {
        result.expiry_date = Some(leaf_cert.not_after);
        result.days_until_expiry = Some((leaf_cert.not_after - now).num_days());
    }
    result.certificate_chain = cert_chain;
}

struct Handshake {
    time: Duration,
    version: Option<TlsVersion>,
    cipher: Option<CipherSuite>,
    pfs: bool,
}

enum HandshakeOutcome {
    Established(Handshake),
    /// The server's certificate failed verification for a cause that maps to a vulnerability.
    Rejected(TlsVulnerability),
}

pub struct TlsScanner {
    interval: Duration,
    connection_timeout: Duration,
    handshake_timeout: Duration,
    total_scan_timeout: Duration,
    connector: TcpConnector,
}

impl Default for TlsScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsScanner {
    pub fn new() -> Self {
        log::debug!("[scan::tls] new: interval=300s connection_timeout=10s handshake_timeout=5s");
        Self {
            interval: Duration::from_secs(TLS_SCAN_INTERVAL_SECS), // TLS scans every 5 minutes
            connection_timeout: Duration::from_secs(TLS_CONNECTION_TIMEOUT_SECS),
            handshake_timeout: Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
            total_scan_timeout: Duration::from_secs(TLS_TOTAL_SCAN_TIMEOUT_SECS),
            connector: TcpConnector::system(),
        }
    }

    #[cfg(test)]
    fn with_connector(mut self, connector: TcpConnector) -> Self {
        self.connector = connector;
        self
    }

    async fn tls_protocol(&self, target: &Target, protocol: Protocol) -> Result<TlsData> {
        log::debug!(
            "[scan::tls] tls_protocol: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        // Check if target supports this protocol
        if !target.supports_protocol(protocol) {
            log::debug!(
                "[scan::tls] protocol_not_supported: target={} protocol={}",
                target.display_name(),
                protocol.as_str()
            );
            return Err(eyre::eyre!(
                "No {} address available for target: {}",
                protocol.as_str(),
                target.display_name()
            ));
        }

        // Get protocol-specific target
        let tls_target = match target.network_target_for_protocol(protocol) {
            Some(target_addr) => target_addr,
            None => {
                log::warn!(
                    "[scan::tls] no_target_for_protocol: target={} protocol={}",
                    target.display_name(),
                    protocol.as_str()
                );
                eyre::bail!(
                    "No {} address available for target: {}",
                    protocol.as_str(),
                    target.display_name()
                );
            }
        };

        log::debug!(
            "[scan::tls] protocol_target: {} -> {} ({})",
            target.display_name(),
            tls_target,
            protocol.as_str()
        );

        let tls_data = self.perform_tls_scan_for_ip(target, &tls_target).await?;
        Ok(tls_data)
    }

    /// A missing address is `NoAddress`; any other failure is classified by its full cause chain,
    /// so a missing route on this host reads `no <family> route on this host`.
    fn classify_tls_error(error: &eyre::Error, family: Family) -> TlsStatus {
        let error_msg = error.to_string();

        if error_msg.contains("No") && error_msg.contains("address available") {
            TlsStatus::NoAddress
        } else {
            TlsStatus::Failed(classify_route_error(&format!("{error:#}"), family).to_string())
        }
    }

    fn get_tls_ports(&self, target: &Target) -> Vec<u16> {
        // The https-scheme and fallback branches intentionally both default to the
        // HTTPS port; kept as separate branches for readability of intent.
        #[allow(clippy::if_same_then_else)]
        let ports = if let Some(port) = target.port {
            vec![port]
        } else if target.scheme.as_deref() == Some("https") {
            vec![DEFAULT_HTTPS_PORT]
        } else {
            vec![DEFAULT_HTTPS_PORT] // Default to HTTPS port
        };

        log::debug!(
            "[scan::tls] get_tls_ports: target={} ports={:?}",
            target.display_name(),
            ports
        );
        ports
    }

    async fn test_basic_connection(&self, target: &Target, target_ip: &str, port: u16) -> Result<HandshakeOutcome> {
        let addr = connect_addr(target_ip, port)?;
        let server_name = server_name(target.domain.as_deref(), addr.ip())?;

        let start_time = Instant::now();

        // Install default crypto provider if not already installed
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create rustls config with system root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        match tokio::time::timeout(self.connection_timeout, async {
            let socket = self.connector.connect(addr).await?;
            // Use handshake_timeout for the TLS handshake specifically
            let tls_stream =
                match tokio::time::timeout(self.handshake_timeout, connector.connect(server_name, socket)).await? {
                    Ok(stream) => stream,
                    Err(io_error) => {
                        if let Some(vulnerability) = handshake_rejection(&io_error) {
                            log::debug!(
                                "[scan::tls] handshake_rejected: addr={} vulnerability={:?} error={}",
                                addr,
                                vulnerability,
                                io_error
                            );
                            return Ok(HandshakeOutcome::Rejected(vulnerability));
                        }
                        return Err(io_error.into());
                    }
                };

            let (_, connection) = tls_stream.into_inner();
            let negotiated = match (connection.protocol_version(), connection.negotiated_cipher_suite()) {
                (Some(version), Some(suite)) => Some((version, suite.suite())),
                _ => None,
            };

            let version = match connection.protocol_version() {
                Some(ProtocolVersion::TLSv1_2) => Some(TlsVersion::V1_2),
                Some(ProtocolVersion::TLSv1_3) => Some(TlsVersion::V1_3),
                _ => None,
            };

            Ok::<HandshakeOutcome, eyre::Error>(HandshakeOutcome::Established(Handshake {
                time: start_time.elapsed(),
                version,
                cipher: negotiated.map(|(version, suite)| cipher_suite_info(version, suite)),
                pfs: negotiated.is_some_and(|(version, suite)| has_pfs(version, suite)),
            }))
        })
        .await
        {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(e)) => Err(e.wrap_err("TLS handshake failed")),
            Err(_) => Err(eyre::eyre!(
                "TLS connection timeout after {:?}",
                self.connection_timeout
            )),
        }
    }

    async fn test_tls_versions(&self, target: &Target, target_ip: &str, port: u16) -> Result<Vec<TlsVersion>> {
        let mut supported_versions = Vec::new();

        // Test TLS 1.2 and 1.3 with rustls (modern versions)
        if let Ok(HandshakeOutcome::Established(handshake)) = self.test_basic_connection(target, target_ip, port).await
            && let Some(v) = handshake.version
        {
            supported_versions.push(v);
        }

        // For older TLS versions (1.0, 1.1), we'd need OpenSSL
        // This is a simplified implementation focusing on modern TLS

        Ok(supported_versions)
    }

    /// Blocking OpenSSL work runs on the blocking pool so dropping the scan future never stalls a runtime worker.
    async fn analyze_certificate(&self, target: &Target, target_ip: &str, port: u16) -> Result<Vec<CertificateInfo>> {
        let sni = target.domain.clone();
        let addr = connect_addr(target_ip, port)?;
        let connection_timeout = self.connection_timeout;
        let io_timeout = self.total_scan_timeout;
        tokio::task::spawn_blocking(move || {
            Self::analyze_certificate_with_openssl(sni.as_deref(), addr, connection_timeout, io_timeout)
        })
        .await
        .wrap_err("Certificate analysis task failed")?
    }

    /// `sni` is the target's domain; an IP target sends no SNI, since RFC 6066 forbids an IP literal there.
    fn analyze_certificate_with_openssl(
        sni: Option<&str>,
        addr: SocketAddr,
        connection_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Vec<CertificateInfo>> {
        log::debug!(
            "[scan::tls] analyze_certificate_with_openssl: sni={:?} addr={} connection_timeout={}s io_timeout={}s",
            sni,
            addr,
            connection_timeout.as_secs(),
            io_timeout.as_secs()
        );

        // Create OpenSSL connector for detailed certificate analysis
        let mut builder = SslConnector::builder(SslMethod::tls()).wrap_err("Failed to create SSL connector")?;

        // Disable verification to get certificate details even for invalid certs
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        // Connect and get certificate chain
        let stream =
            std::net::TcpStream::connect_timeout(&addr, connection_timeout).wrap_err("TCP connection failed")?;
        stream
            .set_read_timeout(Some(io_timeout))
            .wrap_err("Failed to set socket read timeout")?;
        stream
            .set_write_timeout(Some(io_timeout))
            .wrap_err("Failed to set socket write timeout")?;

        let mut config = connector.configure().wrap_err("Failed to configure SSL connection")?;
        config.set_use_server_name_indication(sni.is_some());
        config.set_verify_hostname(false);
        let ssl_stream = config
            .connect(sni.unwrap_or_default(), stream)
            .wrap_err("SSL connection failed")?;

        let presented = presented_chain(
            ssl_stream.ssl().peer_certificate(),
            ssl_stream
                .ssl()
                .peer_cert_chain()
                .map(|chain| chain.iter().map(X509Ref::to_owned).collect()),
        );
        let cert_chain = presented
            .iter()
            .map(Self::parse_certificate)
            .collect::<Result<Vec<_>>>()?;

        log::debug!(
            "[scan::tls] analyze_certificate_with_openssl: addr={} cert_count={}",
            addr,
            cert_chain.len()
        );
        Ok(cert_chain)
    }

    fn parse_certificate(cert: &X509) -> Result<CertificateInfo> {
        let subject = cert
            .subject_name()
            .entries()
            .map(|entry| {
                format!(
                    "{}={}",
                    entry.object().nid().short_name().unwrap_or("?"),
                    entry
                        .data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "?".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        let issuer = cert
            .issuer_name()
            .entries()
            .map(|entry| {
                format!(
                    "{}={}",
                    entry.object().nid().short_name().unwrap_or("?"),
                    entry
                        .data()
                        .as_utf8()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|_| "?".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        let serial_number = cert
            .serial_number()
            .to_bn()
            .wrap_err("Failed to get serial number")?
            .to_hex_str()
            .wrap_err("Failed to convert serial to hex")?
            .to_string();

        // Convert ASN1 time to DateTime<Utc>
        let not_before = asn1_to_utc(cert.not_before())?;
        let not_after = asn1_to_utc(cert.not_after())?;

        let signature_algorithm = cert
            .signature_algorithm()
            .object()
            .nid()
            .short_name()
            .unwrap_or("Unknown")
            .to_string();

        let public_key = cert.public_key().wrap_err("Failed to get public key")?;
        let (public_key_algorithm, key_size) = match public_key.id() {
            openssl::pkey::Id::RSA => {
                let rsa = public_key.rsa().ok();
                let size = rsa.as_ref().map(|r| r.size() * 8);
                ("RSA".to_string(), size)
            }
            openssl::pkey::Id::EC => {
                let ec = public_key.ec_key().ok();
                let size = ec.as_ref().map(|e| e.group().degree());
                ("EC".to_string(), size)
            }
            _ => ("Unknown".to_string(), None),
        };

        // Extract Subject Alternative Names
        let mut san_domains = Vec::new();
        if let Some(san_ext) = cert.subject_alt_names() {
            for san in san_ext {
                if let Some(dns_name) = san.dnsname() {
                    san_domains.push(dns_name.to_string());
                }
            }
        }

        let is_self_signed = cert.issued(cert) == openssl::x509::X509VerifyResult::OK;
        // Check if certificate is a CA (simplified check)
        let is_ca = false; // TODO: Implement proper CA detection

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            signature_algorithm,
            public_key_algorithm,
            key_size,
            san_domains,
            is_self_signed,
            is_ca,
        })
    }

    fn detect_vulnerabilities(&self, result: &TlsData) -> Vec<TlsVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for expired certificates
        if let Some(expiry) = result.expiry_date
            && expiry < chrono::Utc::now()
        {
            vulnerabilities.push(TlsVulnerability::ExpiredCertificate);
        }

        // Check for self-signed certificates
        for cert in &result.certificate_chain {
            if cert.is_self_signed {
                vulnerabilities.push(TlsVulnerability::SelfSignedCertificate);
                break;
            }
        }

        // Check for weak signature algorithms
        for cert in &result.certificate_chain {
            if cert.signature_algorithm.contains("md5") || cert.signature_algorithm.contains("sha1") {
                vulnerabilities.push(TlsVulnerability::WeakSignatureAlgorithm(
                    cert.signature_algorithm.clone(),
                ));
            }
        }

        // Check for weak ciphers
        for cipher in &result.supported_ciphers {
            if !cipher.is_secure {
                vulnerabilities.push(TlsVulnerability::WeakCipher(cipher.name.clone()));
            }
        }

        // Check for old TLS versions
        for version in &result.supported_versions {
            match version {
                TlsVersion::V1_0 | TlsVersion::V1_1 => {
                    vulnerabilities.push(TlsVulnerability::WeakCipher(format!("Supports {}", version.as_str())));
                }
                _ => {}
            }
        }

        vulnerabilities
    }

    fn calculate_security_grade(&self, result: &TlsData) -> SecurityGrade {
        // If connection failed, automatic F
        if !result.connection_successful {
            return SecurityGrade::F;
        }

        let mut score = 100i32; // Use i32 to handle negative scores

        // Deduct points for vulnerabilities
        for vuln in &result.vulnerabilities {
            match vuln {
                TlsVulnerability::ExpiredCertificate => score -= 50,
                TlsVulnerability::SelfSignedCertificate => score -= 30,
                TlsVulnerability::WeakSignatureAlgorithm(_) => score -= 20,
                TlsVulnerability::WeakCipher(_) => score -= 15,
                TlsVulnerability::Heartbleed => score -= 50,
                TlsVulnerability::Poodle => score -= 30,
                _ => score -= 10,
            }
        }

        // Bonus for modern features
        if result.supported_versions.contains(&TlsVersion::V1_3) {
            score += 5;
        }
        if result.perfect_forward_secrecy {
            score += 5;
        }
        if result.ocsp_stapling {
            score += 5;
        }

        // Convert score to grade
        match score {
            90..=i32::MAX => SecurityGrade::APlus,
            80..=89 => SecurityGrade::A,
            70..=79 => SecurityGrade::B,
            60..=69 => SecurityGrade::C,
            50..=59 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }

    async fn perform_tls_scan_for_ip(&self, target: &Target, target_ip: &str) -> Result<TlsData> {
        log::debug!(
            "[scan::tls] perform_tls_scan_for_ip: target={} ip={}",
            target.display_name(),
            target_ip
        );

        let start_time = Instant::now();
        let mut result = TlsData::new(target_ip.to_string());

        let ports = self.get_tls_ports(target);
        let port = ports[0]; // Use first port for now
        log::debug!("[scan::tls] using_port: target={} port={}", target.display_name(), port);

        // Phase 1: Basic connectivity test
        log::debug!(
            "[scan::tls] phase1_basic_connection: target={} ip={} port={}",
            target.display_name(),
            target_ip,
            port
        );
        let phase1_start = Instant::now();
        let handshake_vulnerability = match self.test_basic_connection(target, target_ip, port).await {
            Ok(HandshakeOutcome::Established(handshake)) => {
                let phase1_duration = phase1_start.elapsed();
                result.connection_successful = true;
                result.handshake_time = handshake.time;
                result.perfect_forward_secrecy = handshake.pfs;
                result.negotiated_cipher = handshake.cipher;
                if let Some(v) = handshake.version {
                    result.negotiated_version = Some(v.clone());
                    result.supported_versions.push(v);
                }
                log::trace!(
                    "[scan::tls] phase1_completed: target={} port={} handshake_time={}ms phase_duration={}ms version={:?} pfs={}",
                    target.display_name(),
                    port,
                    result.handshake_time.as_millis(),
                    phase1_duration.as_millis(),
                    result.negotiated_version,
                    result.perfect_forward_secrecy
                );
                None
            }
            Ok(HandshakeOutcome::Rejected(vulnerability)) => {
                // The handshake reached certificate verification and failed it: keep going so the
                // certificate analysis below still fills in what the certificate says.
                result.handshake_time = phase1_start.elapsed();
                log::warn!(
                    "[scan::tls] phase1_rejected: target={} port={} vulnerability={:?}",
                    target.display_name(),
                    port,
                    vulnerability
                );
                Some(vulnerability)
            }
            Err(e) => {
                let phase1_duration = phase1_start.elapsed();
                log::error!(
                    "[scan::tls] phase1_failed: target={} port={} duration={}ms error={}",
                    target.display_name(),
                    port,
                    phase1_duration.as_millis(),
                    e
                );
                // No handshake means nothing to grade: the family fails instead of carrying
                // `TlsData::new`'s default F.
                return Err(e);
            }
        };

        // Phase 2: TLS version enumeration (a rejected handshake would only be rejected again)
        if handshake_vulnerability.is_none() {
            log::debug!(
                "[scan::tls] phase2_version_enumeration: target={} ip={} port={}",
                target.display_name(),
                target_ip,
                port
            );
            let phase2_start = Instant::now();
            match self.test_tls_versions(target, target_ip, port).await {
                Ok(versions) => {
                    let phase2_duration = phase2_start.elapsed();
                    result.supported_versions = versions.clone();
                    log::trace!(
                        "[scan::tls] phase2_completed: target={} port={} duration={}ms versions={:?}",
                        target.display_name(),
                        port,
                        phase2_duration.as_millis(),
                        versions
                    );
                }
                Err(e) => {
                    let phase2_duration = phase2_start.elapsed();
                    log::warn!(
                        "[scan::tls] phase2_failed: target={} port={} duration={}ms error={}",
                        target.display_name(),
                        port,
                        phase2_duration.as_millis(),
                        e
                    );
                    result
                        .certificate_errors
                        .push(format!("Version enumeration failed: {}", e));
                }
            }
        }

        // Phase 3: Certificate analysis
        log::debug!(
            "[scan::tls] phase3_certificate_analysis: target={} ip={} port={}",
            target.display_name(),
            target_ip,
            port
        );
        let phase3_start = Instant::now();
        match self.analyze_certificate(target, target_ip, port).await {
            Ok(cert_chain) => {
                let phase3_duration = phase3_start.elapsed();
                result.certificate_valid = !cert_chain.is_empty() && handshake_vulnerability.is_none();
                apply_certificate_chain(&mut result, cert_chain, chrono::Utc::now());
                log::trace!(
                    "[scan::tls] phase3_completed: target={} port={} duration={}ms cert_count={} valid={} days_until_expiry={:?}",
                    target.display_name(),
                    port,
                    phase3_duration.as_millis(),
                    result.certificate_chain.len(),
                    result.certificate_valid,
                    result.days_until_expiry
                );
            }
            Err(e) => {
                let phase3_duration = phase3_start.elapsed();
                log::error!(
                    "[scan::tls] phase3_failed: target={} port={} duration={}ms error={}",
                    target.display_name(),
                    port,
                    phase3_duration.as_millis(),
                    e
                );
                result
                    .certificate_errors
                    .push(format!("Certificate analysis failed: {}", e));
            }
        }

        // Phase 4: Vulnerability detection
        log::debug!(
            "[scan::tls] phase4_vulnerability_detection: target={}",
            target.display_name()
        );
        let phase4_start = Instant::now();
        result.vulnerabilities = merge_vulnerabilities(handshake_vulnerability, self.detect_vulnerabilities(&result));
        let phase4_duration = phase4_start.elapsed();
        log::trace!(
            "[scan::tls] phase4_completed: target={} duration={}μs vulnerabilities={:?}",
            target.display_name(),
            phase4_duration.as_micros(),
            result.vulnerabilities
        );

        // Phase 5: Security grading
        log::debug!("[scan::tls] phase5_security_grading: target={}", target.display_name());
        let phase5_start = Instant::now();
        result.security_grade = self.calculate_security_grade(&result);
        let phase5_duration = phase5_start.elapsed();
        log::trace!(
            "[scan::tls] phase5_completed: target={} duration={}μs grade={:?}",
            target.display_name(),
            phase5_duration.as_micros(),
            result.security_grade
        );

        result.scan_time = start_time.elapsed();
        result.queried_at = start_time;

        log::debug!(
            "[scan::tls] tls_scan_completed: target={} total_duration={}ms grade={:?} vulnerabilities={}",
            target.display_name(),
            result.scan_time.as_millis(),
            result.security_grade,
            result.vulnerabilities.len()
        );

        Ok(result)
    }
}

#[async_trait]
impl Scanner for TlsScanner {
    fn deadline(&self) -> Duration {
        self.total_scan_timeout
    }

    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!(
            "[scan::tls] scan: target={} protocol={} total_timeout={}s",
            target.display_name(),
            protocol.as_str(),
            self.total_scan_timeout.as_secs()
        );

        let scan_start = Instant::now();
        let mut result = TlsResult::new();

        match protocol {
            Protocol::Ipv4 => {
                // IPv4 only
                match self.tls_protocol(target, Protocol::Ipv4).await {
                    Ok(tls_data) => {
                        result.ipv4_status = TlsStatus::Success(tls_data.security_grade.clone());
                        result.ipv4_result = Some(tls_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_tls_error(&e, Family::Ipv4);
                    }
                }
            }
            Protocol::Ipv6 => {
                // IPv6 only
                match self.tls_protocol(target, Protocol::Ipv6).await {
                    Ok(tls_data) => {
                        result.ipv6_status = TlsStatus::Success(tls_data.security_grade.clone());
                        result.ipv6_result = Some(tls_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_tls_error(&e, Family::Ipv6);
                    }
                }
            }
            Protocol::Both => {
                // Both IPv4 and IPv6

                // Try IPv4
                match self.tls_protocol(target, Protocol::Ipv4).await {
                    Ok(tls_data) => {
                        result.ipv4_status = TlsStatus::Success(tls_data.security_grade.clone());
                        result.ipv4_result = Some(tls_data);
                    }
                    Err(e) => {
                        result.ipv4_status = Self::classify_tls_error(&e, Family::Ipv4);
                        log::debug!("[scan::tls] ipv4_tls_failed: error={}", e);
                    }
                }

                // Try IPv6
                match self.tls_protocol(target, Protocol::Ipv6).await {
                    Ok(tls_data) => {
                        result.ipv6_status = TlsStatus::Success(tls_data.security_grade.clone());
                        result.ipv6_result = Some(tls_data);
                    }
                    Err(e) => {
                        result.ipv6_status = Self::classify_tls_error(&e, Family::Ipv6);
                        log::debug!("[scan::tls] ipv6_tls_failed: error={}", e);
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if at least one protocol succeeded, or error if all failed
        if result.has_any_success() {
            log::trace!(
                "[scan::tls] tls_completed: target={} protocol={} duration={}ms best_grade={:?}",
                target.display_name(),
                protocol.as_str(),
                result.total_duration.as_millis(),
                result.get_best_security_grade()
            );
            Ok(ScanResult::Tls(result))
        } else {
            let error = result.failure(protocol);
            log::error!(
                "[scan::tls] all_tls_failed: target={} protocol={} duration={}ms error={}",
                target.display_name(),
                protocol.as_str(),
                result.total_duration.as_millis(),
                error
            );
            Err(error)
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "tls"
    }
}

/// In-memory certificates and TLS results for tests; no network.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Builder, X509Name, X509NameBuilder};

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
        PKey::from_ec_key(EcKey::generate(&group).expect("EC key")).expect("PKey")
    }

    fn name(common_name: &str) -> X509Name {
        let mut builder = X509NameBuilder::new().expect("name builder");
        builder
            .append_entry_by_nid(Nid::COMMONNAME, common_name)
            .expect("CN entry");
        builder.build()
    }

    /// A leaf for `fixture.test` signed by a separate CA key, so it is not self-signed.
    pub(crate) fn leaf_certificate(not_before_unix: i64, not_after_unix: i64) -> X509 {
        let ca_key = key();
        let leaf_key = key();
        let mut builder = X509Builder::new().expect("x509 builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name("fixture.test")).expect("subject");
        builder.set_issuer_name(&name("Fixture CA")).expect("issuer");
        builder.set_pubkey(&leaf_key).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::from_unix(not_before_unix).expect("not_before"))
            .expect("set not_before");
        builder
            .set_not_after(&Asn1Time::from_unix(not_after_unix).expect("not_after"))
            .expect("set not_after");
        builder.sign(&ca_key, MessageDigest::sha256()).expect("sign");
        builder.build()
    }

    /// A self-signed certificate for `common_name`, valid from yesterday for 30 days, with a
    /// distinct `serial`.
    fn self_signed(common_name: &str, key: &PKey<Private>, serial: u32) -> X509 {
        let now = Utc::now();
        let mut builder = X509Builder::new().expect("x509 builder");
        builder.set_version(2).expect("version");
        let serial = openssl::bn::BigNum::from_u32(serial)
            .and_then(|bn| bn.to_asn1_integer())
            .expect("serial");
        builder.set_serial_number(&serial).expect("set serial");
        builder.set_subject_name(&name(common_name)).expect("subject");
        builder.set_issuer_name(&name(common_name)).expect("issuer");
        builder.set_pubkey(key).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::from_unix((now - chrono::Duration::days(1)).timestamp()).expect("nb"))
            .expect("set not_before");
        builder
            .set_not_after(&Asn1Time::from_unix((now + chrono::Duration::days(30)).timestamp()).expect("na"))
            .expect("set not_after");
        builder.sign(key, MessageDigest::sha256()).expect("sign");
        builder.build()
    }

    /// Self-signed `fixture.test` identity that serves TLS on a loopback port, answering every
    /// connection until the test process exits. Returns the bound port.
    pub(crate) fn spawn_loopback_tls_server() -> u16 {
        spawn_loopback_tls_server_with_intermediates(0)
    }

    /// As [`spawn_loopback_tls_server`], sending `intermediates` extra certificates after the leaf,
    /// so the server presents `1 + intermediates` certificates.
    pub(crate) fn spawn_loopback_tls_server_with_intermediates(intermediates: u32) -> u16 {
        use openssl::ssl::{SslAcceptor, SslMethod};
        let server_key = key();
        let cert = self_signed("fixture.test", &server_key, 1);

        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor");
        acceptor.set_private_key(&server_key).expect("server key");
        acceptor.set_certificate(&cert).expect("server cert");
        for n in 1..=intermediates {
            let intermediate = self_signed(&format!("Fixture Intermediate {n}"), &key(), n + 1);
            acceptor.add_extra_chain_cert(intermediate).expect("extra chain cert");
        }
        let acceptor = acceptor.build();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                // A client that rejects the certificate aborts the handshake; that is expected.
                if let Ok(mut tls) = acceptor.accept(stream) {
                    let _ = tls.shutdown();
                }
            }
        });
        port
    }

    /// What `perform_tls_scan_for_ip` records when rustls rejects an expired certificate and the
    /// OpenSSL pass still reads it: the same functions, in the same order.
    pub(crate) fn expired_handshake_result() -> TlsData {
        let scanner = TlsScanner::new();
        let now = Utc::now();
        let handshake =
            vulnerability_for_handshake_error(&rustls::Error::InvalidCertificate(CertificateError::Expired));
        let leaf = leaf_certificate(
            (now - chrono::Duration::days(400)).timestamp(),
            (now - chrono::Duration::days(30)).timestamp(),
        );
        let mut result = TlsData::new("192.0.2.1".to_string());
        let chain = vec![TlsScanner::parse_certificate(&leaf).expect("parse fixture leaf")];
        result.certificate_valid = !chain.is_empty() && handshake.is_none();
        apply_certificate_chain(&mut result, chain, now);
        result.vulnerabilities = merge_vulnerabilities(handshake, scanner.detect_vulnerabilities(&result));
        result.security_grade = scanner.calculate_security_grade(&result);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_is_the_total_scan_timeout() {
        let scanner = TlsScanner::new();
        assert_eq!(scanner.deadline(), Duration::from_secs(TLS_TOTAL_SCAN_TIMEOUT_SECS));
        assert!(scanner.uses_protocol());
    }

    /// ENETUNREACH and ECONNREFUSED as Linux numbers them.
    #[cfg(target_os = "linux")]
    const ENETUNREACH: i32 = 101;
    #[cfg(target_os = "linux")]
    const ECONNREFUSED: i32 = 111;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enetunreach_is_an_err_never_a_graded_result() {
        let scanner = TlsScanner::new().with_connector(TcpConnector::failing_with(ENETUNREACH));
        for (literal, protocol, expected) in [
            ("192.0.2.1", Protocol::Ipv4, "IPv4: no IPv4 route on this host"),
            (
                "2606:4700:4700::1111",
                Protocol::Ipv6,
                "IPv6: no IPv6 route on this host",
            ),
        ] {
            let target = Target::parse(literal).unwrap();
            let ip = target.network_target_for_protocol(protocol).unwrap();
            assert!(
                scanner.perform_tls_scan_for_ip(&target, &ip).await.is_err(),
                "{literal}: a connect error must not produce TlsData"
            );
            let error = scanner.scan(&target, protocol).await.unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains("Grade"), "{error}");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn refused_connect_fails_the_family_with_its_cause() {
        let scanner = TlsScanner::new().with_connector(TcpConnector::failing_with(ECONNREFUSED));
        let target = Target::parse("192.0.2.1").unwrap();
        let error = scanner.scan(&target, Protocol::Ipv4).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "IPv4: TLS handshake failed: Connection refused (os error 111)"
        );
    }

    #[test]
    fn tls_failure_skips_families_without_an_address() {
        let mut result = TlsResult::new();
        result.ipv4_status = TlsStatus::Failed("operation timed out".to_string());
        result.ipv6_status = TlsStatus::NoAddress;
        assert_eq!(result.failure(Protocol::Both).to_string(), "IPv4: operation timed out");
    }

    #[test]
    fn test_tls_version_string() {
        assert_eq!(TlsVersion::V1_2.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::V1_3.as_str(), "TLSv1.3");
    }

    #[test]
    fn test_security_grade_string() {
        assert_eq!(SecurityGrade::APlus.as_str(), "A+");
        assert_eq!(SecurityGrade::A.as_str(), "A");
        assert_eq!(SecurityGrade::F.as_str(), "F");
    }

    #[test]
    fn test_tls_scanner_creation() {
        let scanner = TlsScanner::new();
        assert_eq!(scanner.interval(), Duration::from_secs(300));
        assert_eq!(scanner.name(), "tls");
    }

    #[test]
    fn test_get_tls_ports() {
        let scanner = TlsScanner::new();

        // Test with explicit port
        let target_with_port = Target::parse("example.com:8443").unwrap();
        assert_eq!(scanner.get_tls_ports(&target_with_port), vec![8443]);

        // Test with HTTPS scheme
        let target_https = Target::parse("https://example.com").unwrap();
        assert_eq!(scanner.get_tls_ports(&target_https), vec![443]);

        // Test default
        let target_default = Target::parse("example.com").unwrap();
        assert_eq!(scanner.get_tls_ports(&target_default), vec![443]);
    }

    #[test]
    fn test_tls_result_creation() {
        let result = TlsResult::new();
        assert!(!result.has_any_success());
        assert!(result.get_primary_result().is_none());
        assert_eq!(result.total_vulnerabilities(), 0);
    }

    #[test]
    fn test_vulnerability_detection() {
        let scanner = TlsScanner::new();
        let mut tls_data = TlsData::new("192.168.1.1".to_string());

        // Add expired certificate
        tls_data.expiry_date = Some(chrono::Utc::now() - chrono::Duration::days(1));

        let vulnerabilities = scanner.detect_vulnerabilities(&tls_data);
        assert!(vulnerabilities.contains(&TlsVulnerability::ExpiredCertificate));
    }

    #[test]
    fn test_security_grading() {
        let scanner = TlsScanner::new();
        let mut tls_data = TlsData::new("192.168.1.1".to_string());

        // Test with no vulnerabilities and modern features
        tls_data.supported_versions.push(TlsVersion::V1_3);
        tls_data.perfect_forward_secrecy = true;
        tls_data.ocsp_stapling = true;
        tls_data.connection_successful = true; // Need successful connection for good grade

        let grade = scanner.calculate_security_grade(&tls_data);
        assert_eq!(grade, SecurityGrade::APlus);

        // Test with vulnerabilities
        tls_data.vulnerabilities.push(TlsVulnerability::ExpiredCertificate);
        let grade_with_vuln = scanner.calculate_security_grade(&tls_data);
        assert_ne!(grade_with_vuln, SecurityGrade::APlus);
    }

    #[tokio::test]
    async fn test_tls_scan_google() {
        let scanner = TlsScanner::new();
        let mut target = Target::parse("google.com").expect("Failed to parse target");

        // Resolve target to get IP addresses for protocol support
        target.resolve().await.expect("Failed to resolve target");

        let result = scanner.scan(&target, Protocol::Both).await;

        assert!(result.is_ok());
        if let Ok(ScanResult::Tls(tls_result)) = result {
            // Google should have successful TLS connection
            assert!(tls_result.has_any_success());
            if let Some(primary_data) = tls_result.get_primary_result() {
                // Should support modern TLS
                assert!(!primary_data.supported_versions.is_empty());
                // Should have reasonable handshake time
                assert!(primary_data.handshake_time.as_millis() > 0);
                // Note: Certificate parsing may fail due to ASN1 format issues,
                // but connection should still succeed
            }
        }
    }

    #[tokio::test]
    async fn test_tls_scan_invalid_domain() {
        let scanner = TlsScanner::new();
        let target = Target::parse("invalid-domain-that-does-not-exist.com").expect("Failed to parse target");

        let result = scanner.scan(&target, Protocol::Both).await;

        // The result may succeed at the scanning level (returning Ok) but should not have successful TLS data
        if let Ok(ScanResult::Tls(tls_result)) = result {
            // Even if has_any_success() returns true due to DNS resolution,
            // the actual TLS data should show connection failures
            if let Some(primary_data) = tls_result.get_primary_result() {
                // If we got connection data, it should show errors or failures
                assert!(!primary_data.connection_successful || !primary_data.certificate_errors.is_empty());
            }
            // If no primary result, that's also acceptable for invalid domain
        } else {
            // Scanner returning error is also acceptable for invalid domain
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_certificate_info_structure() {
        let cert_info = CertificateInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Let's Encrypt Authority X3".to_string(),
            serial_number: "123456789".to_string(),
            not_before: chrono::Utc::now() - chrono::Duration::days(30),
            not_after: chrono::Utc::now() + chrono::Duration::days(60),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            san_domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        };

        assert_eq!(cert_info.subject, "CN=example.com");
        assert_eq!(cert_info.issuer, "CN=Let's Encrypt Authority X3");
        assert_eq!(cert_info.key_size, Some(2048));
        assert!(!cert_info.is_self_signed);
        assert!(!cert_info.is_ca);
        assert_eq!(cert_info.san_domains.len(), 2);
    }

    #[test]
    fn test_cipher_suite_structure() {
        let cipher = CipherSuite {
            name: "TLS_AES_256_GCM_SHA384".to_string(),
            protocol_version: "TLSv1.3".to_string(),
            key_exchange: "ECDHE".to_string(),
            authentication: "RSA".to_string(),
            encryption: "AES256-GCM".to_string(),
            mac: "SHA384".to_string(),
            is_secure: true,
        };

        assert_eq!(cipher.name, "TLS_AES_256_GCM_SHA384");
        assert_eq!(cipher.protocol_version, "TLSv1.3");
        assert!(cipher.is_secure);
        assert_eq!(cipher.encryption, "AES256-GCM");
    }

    #[test]
    fn test_vulnerability_types() {
        let vulnerabilities = vec![
            TlsVulnerability::Heartbleed,
            TlsVulnerability::Poodle,
            TlsVulnerability::Beast,
            TlsVulnerability::Crime,
            TlsVulnerability::WeakCipher("RC4".to_string()),
            TlsVulnerability::ExpiredCertificate,
            TlsVulnerability::SelfSignedCertificate,
            TlsVulnerability::WeakSignatureAlgorithm("MD5".to_string()),
            TlsVulnerability::InsecureRenegotiation,
            TlsVulnerability::WeakDhParams,
            TlsVulnerability::SslV2Enabled,
            TlsVulnerability::SslV3Enabled,
        ];

        assert_eq!(vulnerabilities.len(), 12);
        assert!(matches!(vulnerabilities[0], TlsVulnerability::Heartbleed));
        assert!(matches!(vulnerabilities[4], TlsVulnerability::WeakCipher(_)));
        assert!(matches!(
            vulnerabilities[7],
            TlsVulnerability::WeakSignatureAlgorithm(_)
        ));
    }

    #[test]
    fn test_security_grade_comparison() {
        let grades = [
            SecurityGrade::APlus,
            SecurityGrade::A,
            SecurityGrade::B,
            SecurityGrade::C,
            SecurityGrade::D,
            SecurityGrade::F,
        ];

        assert_eq!(grades[0].as_str(), "A+");
        assert_eq!(grades[1].as_str(), "A");
        assert_eq!(grades[5].as_str(), "F");
    }

    #[test]
    fn test_tls_result_defaults() {
        let result = TlsResult::new();

        assert!(!result.has_any_success());
        assert!(result.get_primary_result().is_none());
        assert_eq!(result.total_vulnerabilities(), 0);
        assert!(result.get_best_security_grade().is_none());
        assert!(result.get_all_vulnerabilities().is_empty());
    }

    #[test]
    fn test_vulnerability_detection_expired_cert() {
        let scanner = TlsScanner::new();
        let mut tls_data = TlsData::new("192.168.1.1".to_string());

        // Set expired certificate
        tls_data.expiry_date = Some(chrono::Utc::now() - chrono::Duration::days(1));
        tls_data.days_until_expiry = Some(-1);

        let vulnerabilities = scanner.detect_vulnerabilities(&tls_data);
        assert!(vulnerabilities.contains(&TlsVulnerability::ExpiredCertificate));
    }

    #[test]
    fn test_vulnerability_detection_soon_expiring_cert() {
        let scanner = TlsScanner::new();
        let mut tls_data = TlsData::new("192.168.1.1".to_string());

        // Set certificate expiring in 25 days (soon)
        tls_data.expiry_date = Some(chrono::Utc::now() + chrono::Duration::days(25));
        tls_data.days_until_expiry = Some(25);

        let vulnerabilities = scanner.detect_vulnerabilities(&tls_data);

        // This should not be flagged as expired, but might be flagged as "soon expiring"
        // depending on implementation
        assert!(!vulnerabilities.contains(&TlsVulnerability::ExpiredCertificate));
    }

    #[test]
    fn test_security_grading_with_vulnerabilities() {
        let scanner = TlsScanner::new();
        let mut tls_data = TlsData::new("192.168.1.1".to_string());

        // Set up a result with critical vulnerabilities
        tls_data.connection_successful = true;
        tls_data.supported_versions = vec![TlsVersion::V1_0, TlsVersion::V1_1]; // Old versions
        tls_data.vulnerabilities = vec![TlsVulnerability::Heartbleed, TlsVulnerability::ExpiredCertificate];

        let grade = scanner.calculate_security_grade(&tls_data);
        assert_eq!(grade, SecurityGrade::F);

        // Test with good security
        tls_data.vulnerabilities.clear();
        tls_data.supported_versions = vec![TlsVersion::V1_2, TlsVersion::V1_3];
        tls_data.perfect_forward_secrecy = true;
        tls_data.ocsp_stapling = true;

        let better_grade = scanner.calculate_security_grade(&tls_data);
        assert!(better_grade != SecurityGrade::F);
    }

    #[test]
    fn test_tls_port_detection() {
        let scanner = TlsScanner::new();

        // Test HTTPS URL
        let https_target = Target::parse("https://example.com").unwrap();
        let https_ports = scanner.get_tls_ports(&https_target);
        assert_eq!(https_ports, vec![443]);

        // Test explicit port
        let port_target = Target::parse("example.com:8443").unwrap();
        let explicit_ports = scanner.get_tls_ports(&port_target);
        assert_eq!(explicit_ports, vec![8443]);

        // Test default
        let default_target = Target::parse("example.com").unwrap();
        let default_ports = scanner.get_tls_ports(&default_target);
        assert_eq!(default_ports, vec![443]);
    }

    #[test]
    fn test_tls_version_ordering() {
        let versions = [TlsVersion::V1_0, TlsVersion::V1_1, TlsVersion::V1_2, TlsVersion::V1_3];

        assert_eq!(versions[0].as_str(), "TLSv1.0");
        assert_eq!(versions[1].as_str(), "TLSv1.1");
        assert_eq!(versions[2].as_str(), "TLSv1.2");
        assert_eq!(versions[3].as_str(), "TLSv1.3");
    }

    #[test]
    fn asn1_to_utc_round_trips_fixture_validity_exactly() {
        let not_before = 1_700_000_123;
        let not_after = 1_900_000_456;
        let cert = fixtures::leaf_certificate(not_before, not_after);
        let info = TlsScanner::parse_certificate(&cert).expect("fixture parses");
        assert_eq!(info.not_before.timestamp(), not_before);
        assert_eq!(info.not_after.timestamp(), not_after);
        assert_eq!(info.issuer, "CN=Fixture CA");
        assert!(!info.is_self_signed);
    }

    #[test]
    fn asn1_to_utc_handles_epoch_and_pre_epoch() {
        let epoch = Asn1Time::from_unix(0).unwrap();
        assert_eq!(asn1_to_utc(&epoch).unwrap().timestamp(), 0);
        let before = Asn1Time::from_unix(-86_400 * 365 - 17).unwrap();
        assert_eq!(asn1_to_utc(&before).unwrap().timestamp(), -86_400 * 365 - 17);
    }

    #[test]
    fn expired_fixture_certificate_yields_expired_vulnerability() {
        let now = Utc::now();
        let cert = fixtures::leaf_certificate(
            (now - chrono::Duration::days(400)).timestamp(),
            (now - chrono::Duration::days(30)).timestamp(),
        );
        let mut result = TlsData::new("192.0.2.1".to_string());
        apply_certificate_chain(&mut result, vec![TlsScanner::parse_certificate(&cert).unwrap()], now);
        assert_eq!(result.days_until_expiry, Some(-30));
        let vulnerabilities = TlsScanner::new().detect_vulnerabilities(&result);
        assert!(vulnerabilities.contains(&TlsVulnerability::ExpiredCertificate));
    }

    #[test]
    fn valid_fixture_certificate_is_not_expired() {
        let now = Utc::now();
        let cert = fixtures::leaf_certificate(
            (now - chrono::Duration::days(10)).timestamp(),
            (now + chrono::Duration::days(80) + chrono::Duration::hours(1)).timestamp(),
        );
        let mut result = TlsData::new("192.0.2.1".to_string());
        apply_certificate_chain(&mut result, vec![TlsScanner::parse_certificate(&cert).unwrap()], now);
        assert_eq!(result.days_until_expiry, Some(80));
        assert!(TlsScanner::new().detect_vulnerabilities(&result).is_empty());
    }

    #[test]
    fn has_pfs_true_for_tls13_and_ephemeral_tls12() {
        assert!(has_pfs(
            ProtocolVersion::TLSv1_3,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        ));
        assert!(has_pfs(
            ProtocolVersion::TLSv1_2,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ));
        assert!(has_pfs(
            ProtocolVersion::TLSv1_2,
            rustls::CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        ));
    }

    #[test]
    fn has_pfs_false_for_static_rsa_and_old_versions() {
        assert!(!has_pfs(
            ProtocolVersion::TLSv1_2,
            rustls::CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256
        ));
        assert!(!has_pfs(
            ProtocolVersion::TLSv1_1,
            rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        ));
    }

    #[test]
    fn cipher_suite_info_splits_iana_names() {
        let tls13 = cipher_suite_info(ProtocolVersion::TLSv1_3, rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(tls13.name, "TLS13_AES_128_GCM_SHA256");
        assert_eq!(tls13.encryption, "AES_128_GCM");
        assert_eq!(tls13.mac, "SHA256");
        assert!(tls13.is_secure);

        let tls12 = cipher_suite_info(
            ProtocolVersion::TLSv1_2,
            rustls::CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        );
        assert_eq!(tls12.key_exchange, "RSA");
        assert_eq!(tls12.authentication, "RSA");
        assert!(!tls12.is_secure);

        let ecdhe = cipher_suite_info(
            ProtocolVersion::TLSv1_2,
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        );
        assert_eq!(ecdhe.key_exchange, "ECDHE");
        assert_eq!(ecdhe.authentication, "ECDSA");
        assert!(ecdhe.is_secure);
    }

    #[test]
    fn handshake_verify_errors_map_to_vulnerabilities() {
        let cert = |e| rustls::Error::InvalidCertificate(e);
        assert_eq!(
            vulnerability_for_handshake_error(&cert(CertificateError::Expired)),
            Some(TlsVulnerability::ExpiredCertificate)
        );
        assert_eq!(
            vulnerability_for_handshake_error(&cert(CertificateError::UnknownIssuer)),
            Some(TlsVulnerability::UntrustedIssuer)
        );
        assert_eq!(
            vulnerability_for_handshake_error(&cert(CertificateError::NotValidForName)),
            Some(TlsVulnerability::HostnameMismatch)
        );
        assert_eq!(
            vulnerability_for_handshake_error(&cert(CertificateError::BadSignature)),
            None
        );
        assert_eq!(
            vulnerability_for_handshake_error(&rustls::Error::HandshakeNotComplete),
            None
        );
    }

    #[test]
    fn handshake_rejection_unwraps_tokio_rustls_io_error() {
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(CertificateError::Expired),
        );
        assert_eq!(
            handshake_rejection(&wrapped),
            Some(TlsVulnerability::ExpiredCertificate)
        );
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(handshake_rejection(&refused), None);
    }

    #[test]
    fn merge_vulnerabilities_records_each_cause_once() {
        let merged = merge_vulnerabilities(
            Some(TlsVulnerability::ExpiredCertificate),
            vec![TlsVulnerability::ExpiredCertificate],
        );
        assert_eq!(merged, vec![TlsVulnerability::ExpiredCertificate]);

        let self_signed = merge_vulnerabilities(
            Some(TlsVulnerability::UntrustedIssuer),
            vec![TlsVulnerability::SelfSignedCertificate],
        );
        assert_eq!(self_signed, vec![TlsVulnerability::SelfSignedCertificate]);

        let untrusted = merge_vulnerabilities(Some(TlsVulnerability::UntrustedIssuer), vec![]);
        assert_eq!(untrusted, vec![TlsVulnerability::UntrustedIssuer]);
    }

    #[test]
    fn expired_handshake_counts_one_issue_and_grades_f() {
        let result = fixtures::expired_handshake_result();
        assert_eq!(result.vulnerabilities, vec![TlsVulnerability::ExpiredCertificate]);
        assert!(result.certificate_errors.is_empty());
        assert_eq!(result.issue_count(), 1);
        assert!(!result.certificate_valid);
        assert_eq!(result.security_grade, SecurityGrade::F);
    }

    #[test]
    fn issue_count_sums_vulnerabilities_and_unmapped_errors() {
        let mut result = TlsData::new("192.0.2.1".to_string());
        assert_eq!(result.issue_count(), 0);
        result.vulnerabilities.push(TlsVulnerability::HostnameMismatch);
        result
            .certificate_errors
            .push("Version enumeration failed: x".to_string());
        assert_eq!(result.issue_count(), 2);
    }

    #[test]
    fn openssl_analysis_gives_up_on_a_silent_server_after_io_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        // Accept and hold the socket open without ever answering the ClientHello.
        let _server = std::thread::spawn(move || {
            let held = listener.accept();
            std::thread::sleep(Duration::from_secs(10));
            drop(held);
        });
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = TlsScanner::analyze_certificate_with_openssl(
                Some("fixture.test"),
                addr,
                Duration::from_secs(1),
                Duration::from_millis(200),
            );
            let _ = tx.send(outcome.is_err());
        });
        let errored = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("OpenSSL handshake hung past its socket timeout");
        assert!(errored);
    }

    #[test]
    fn connect_addr_builds_ipv6_socket_addr_without_brackets() {
        let addr = connect_addr("2606:4700:4700::1111", 443).expect("IPv6 literal");
        assert_eq!(addr, "[2606:4700:4700::1111]:443".parse::<SocketAddr>().unwrap());
        assert_eq!(
            connect_addr("1.1.1.1", 443).unwrap(),
            "1.1.1.1:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn connect_addr_rejects_a_hostname() {
        let err = connect_addr("example.com", 443).unwrap_err();
        assert!(err.to_string().contains("not an IP address"), "{}", err);
    }

    #[test]
    fn server_name_uses_ip_when_there_is_no_domain() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(matches!(server_name(None, ip).unwrap(), ServerName::IpAddress(_)));
        assert!(matches!(
            server_name(Some("example.com"), ip).unwrap(),
            ServerName::DnsName(_)
        ));
    }

    /// Item 3: client-side `peer_cert_chain()` already holds the leaf, so it is the chain;
    /// `peer_certificate()` is used only when there is no chain.
    #[test]
    fn presented_chain_is_the_peer_chain_and_the_leaf_only_without_one() {
        assert_eq!(
            presented_chain(Some("leaf"), Some(vec!["leaf", "int1", "int2"])),
            vec!["leaf", "int1", "int2"]
        );
        assert_eq!(presented_chain(Some("leaf"), None), vec!["leaf"]);
        assert_eq!(presented_chain(Some("leaf"), Some(Vec::new())), vec!["leaf"]);
        assert!(presented_chain::<&str>(None, None).is_empty());
    }

    /// Item 3: a server sending leaf + 2 intermediates yields 3 certificates, each once, and the
    /// zoomed Security pane says `3 certificates`.
    #[tokio::test]
    async fn chain_of_leaf_and_two_intermediates_counts_three_certificates() {
        use crate::tui::pane::Detail;
        use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
        let port = fixtures::spawn_loopback_tls_server_with_intermediates(2);
        let mut target = Target::parse("127.0.0.1").expect("IP target");
        target.port = Some(port);
        let data = TlsScanner::new()
            .perform_tls_scan_for_ip(&target, "127.0.0.1")
            .await
            .expect("scan returns data");
        let serials: Vec<&str> = data
            .certificate_chain
            .iter()
            .map(|c| c.serial_number.as_str())
            .collect();
        assert_eq!(serials, vec!["01", "02", "03"], "errors: {:?}", data.certificate_errors);

        let mut tls_result = TlsResult::new();
        tls_result.ipv4_result = Some(data);
        let state = AppState::new("127.0.0.1".to_string());
        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: Some(ScanResult::Tls(tls_result)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        let zoomed =
            crate::tui::testing::content_rows(&crate::tui::security::SecurityPane::new(), &state, 80, Detail::Zoomed)
                .join("\n");
        assert!(zoomed.contains("Certificate Chain: 3 certificates"), "{zoomed}");
    }

    #[tokio::test]
    async fn ip_target_tls_scan_reaches_the_certificate() {
        let port = fixtures::spawn_loopback_tls_server();
        let mut target = Target::parse("127.0.0.1").expect("IP target");
        target.port = Some(port);
        let result = TlsScanner::new()
            .perform_tls_scan_for_ip(&target, "127.0.0.1")
            .await
            .expect("scan returns data");
        assert!(
            !result.certificate_errors.iter().any(|e| e.contains("Domain required")),
            "{:?}",
            result.certificate_errors
        );
        assert_eq!(
            result.certificate_chain.first().map(|c| c.subject.as_str()),
            Some("CN=fixture.test"),
            "errors: {:?}",
            result.certificate_errors
        );
    }
}
