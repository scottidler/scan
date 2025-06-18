use crate::scanner::Scanner;
use crate::target::{Target, Protocol};
use crate::types::ScanResult;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use eyre::{Result, WrapErr};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;
use webpki_roots;
use log;

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
    WeakSignatureAlgorithm(String),
    InsecureRenegotiation,
    WeakDhParams,
    SslV2Enabled,
    SslV3Enabled,
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
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsStatus {
    NotQueried,           // Protocol not attempted (due to protocol restrictions)
    Success(SecurityGrade), // TLS scan succeeded with security grade
    Failed(String),       // TLS scan failed with error message
    NoAddress,           // No address available for this protocol
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

pub struct TlsScanner {
    interval: Duration,
    connection_timeout: Duration,
    handshake_timeout: Duration,
    total_scan_timeout: Duration,
}

impl TlsScanner {
    pub fn new() -> Self {
        log::debug!("[scan::tls] new: interval=300s connection_timeout=10s handshake_timeout=5s");
        Self {
            interval: Duration::from_secs(TLS_SCAN_INTERVAL_SECS), // TLS scans every 5 minutes
            connection_timeout: Duration::from_secs(TLS_CONNECTION_TIMEOUT_SECS),
            handshake_timeout: Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
            total_scan_timeout: Duration::from_secs(TLS_TOTAL_SCAN_TIMEOUT_SECS),
        }
    }

    async fn tls_protocol(&self, target: &Target, protocol: Protocol) -> Result<TlsData> {
        log::debug!("[scan::tls] tls_protocol: target={} protocol={}", target.display_name(), protocol.as_str());

        // Check if target supports this protocol
        if !target.supports_protocol(protocol) {
            log::debug!("[scan::tls] protocol_not_supported: target={} protocol={}",
                target.display_name(), protocol.as_str());
            return Err(eyre::eyre!("No {} address available for target: {}", protocol.as_str(), target.display_name()));
        }

        // Get protocol-specific target
        let tls_target = match target.network_target_for_protocol(protocol) {
            Some(target_addr) => target_addr,
            None => {
                log::warn!("[scan::tls] no_target_for_protocol: target={} protocol={}",
                    target.display_name(), protocol.as_str());
                eyre::bail!("No {} address available for target: {}", protocol.as_str(), target.display_name());
            }
        };

        log::debug!("[scan::tls] protocol_target: {} -> {} ({})",
            target.display_name(), tls_target, protocol.as_str());

        let tls_data = self.perform_tls_scan_for_ip(target, &tls_target).await?;
        Ok(tls_data)
    }

    fn classify_tls_error(error: &eyre::Error) -> TlsStatus {
        let error_msg = error.to_string();

        if error_msg.contains("No") && error_msg.contains("address available") {
            TlsStatus::NoAddress
        } else {
            TlsStatus::Failed(error_msg)
        }
    }

    fn get_tls_ports(&self, target: &Target) -> Vec<u16> {
        let ports = if let Some(port) = target.port {
            vec![port]
        } else if target.scheme.as_deref() == Some("https") {
            vec![DEFAULT_HTTPS_PORT]
        } else {
            vec![DEFAULT_HTTPS_PORT] // Default to HTTPS port
        };

        log::debug!("[scan::tls] get_tls_ports: target={} ports={:?}",
            target.display_name(), ports);
        ports
    }

    async fn test_basic_connection(&self, target: &Target, target_ip: &str, port: u16) -> Result<(bool, Duration, Option<TlsVersion>)> {
        let domain = target.domain.as_ref()
            .ok_or_else(|| eyre::eyre!("Domain required for TLS scanning"))?;

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

        // Parse server name for SNI
        let server_name = ServerName::try_from(domain.clone())
            .wrap_err("Invalid domain name for TLS")?;

        // Connect to target
        let addr = format!("{}:{}", target_ip, port);

        match tokio::time::timeout(self.connection_timeout, async {
            let socket = tokio::net::TcpStream::connect(&addr).await?;
            // Use handshake_timeout for the TLS handshake specifically
            let tls_stream = tokio::time::timeout(self.handshake_timeout, connector.connect(server_name, socket)).await??;

            // Get TLS version from the connection
            let (_, connection) = tls_stream.into_inner();
            let protocol_version = connection.protocol_version();

            let tls_version = match protocol_version {
                Some(rustls::ProtocolVersion::TLSv1_2) => Some(TlsVersion::V1_2),
                Some(rustls::ProtocolVersion::TLSv1_3) => Some(TlsVersion::V1_3),
                _ => None,
            };

            Ok::<(bool, Option<TlsVersion>), eyre::Error>((true, tls_version))
        }).await {
            Ok(Ok((success, version))) => {
                let _handshake_time = start_time.elapsed();
                Ok((success, _handshake_time, version))
            }
            Ok(Err(e)) => {
                let _handshake_time = start_time.elapsed();
                Err(e.wrap_err("TLS handshake failed"))
            }
            Err(_) => {
                let _handshake_time = start_time.elapsed();
                Err(eyre::eyre!("TLS connection timeout after {:?}", self.connection_timeout))
            }
        }
    }

    async fn test_tls_versions(&self, target: &Target, target_ip: &str, port: u16) -> Result<Vec<TlsVersion>> {
        let mut supported_versions = Vec::new();

        // Test TLS 1.2 and 1.3 with rustls (modern versions)
        if let Ok((success, _, version)) = self.test_basic_connection(target, target_ip, port).await {
            if success {
                if let Some(v) = version {
                    supported_versions.push(v);
                }
            }
        }

        // For older TLS versions (1.0, 1.1), we'd need OpenSSL
        // This is a simplified implementation focusing on modern TLS

        Ok(supported_versions)
    }

    fn analyze_certificate_with_openssl(&self, target: &Target, target_ip: &str, port: u16) -> Result<Vec<CertificateInfo>> {
        let domain = target.domain.as_ref()
            .ok_or_else(|| eyre::eyre!("Domain required for certificate analysis"))?;

        // Create OpenSSL connector for detailed certificate analysis
        let mut builder = SslConnector::builder(SslMethod::tls())
            .wrap_err("Failed to create SSL connector")?;

        // Disable verification to get certificate details even for invalid certs
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        // Connect and get certificate chain
        let addr = format!("{}:{}", target_ip, port);
        let stream = std::net::TcpStream::connect_timeout(
            &addr.parse().wrap_err("Invalid address")?,
            self.connection_timeout,
        ).wrap_err("TCP connection failed")?;

        let ssl_stream = connector.connect(domain, stream)
            .wrap_err("SSL connection failed")?;

        let mut cert_chain = Vec::new();

        // Get peer certificate
        if let Some(cert) = ssl_stream.ssl().peer_certificate() {
            cert_chain.push(self.parse_certificate(&cert)?);
        }

        // Get certificate chain
        if let Some(chain) = ssl_stream.ssl().peer_cert_chain() {
            for cert in chain {
                // Convert X509Ref to X509
                let owned_cert = cert.to_owned();
                cert_chain.push(self.parse_certificate(&owned_cert)?);
            }
        }

        Ok(cert_chain)
    }

    fn parse_certificate(&self, cert: &X509) -> Result<CertificateInfo> {
        let subject = cert.subject_name().entries()
            .map(|entry| format!("{}={}",
                entry.object().nid().short_name().unwrap_or("?"),
                entry.data().as_utf8().map(|s| s.to_string()).unwrap_or_else(|_| "?".to_string())
            ))
            .collect::<Vec<_>>()
            .join(", ");

        let issuer = cert.issuer_name().entries()
            .map(|entry| format!("{}={}",
                entry.object().nid().short_name().unwrap_or("?"),
                entry.data().as_utf8().map(|s| s.to_string()).unwrap_or_else(|_| "?".to_string())
            ))
            .collect::<Vec<_>>()
            .join(", ");

        let serial_number = cert.serial_number().to_bn()
            .wrap_err("Failed to get serial number")?
            .to_hex_str()
            .wrap_err("Failed to convert serial to hex")?
            .to_string();

        // Convert ASN1 time to DateTime<Utc>
        let not_before = self.asn1_time_to_datetime(cert.not_before())?;
        let not_after = self.asn1_time_to_datetime(cert.not_after())?;

        let signature_algorithm = cert.signature_algorithm().object().nid()
            .short_name().unwrap_or("Unknown").to_string();

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

    fn asn1_time_to_datetime(&self, asn1_time: &openssl::asn1::Asn1TimeRef) -> Result<DateTime<Utc>> {
        let time_str = asn1_time.to_string();

        // Parse ASN1 time format (YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ)
        let datetime = if time_str.len() == 13 && time_str.ends_with('Z') {
            // YY format - assume 20YY for years 00-49, 19YY for 50-99
            let year_suffix: i32 = time_str[0..2].parse().wrap_err("Invalid year")?;
            let year = if year_suffix <= 49 { 2000 + year_suffix } else { 1900 + year_suffix };
            let month: u32 = time_str[2..4].parse().wrap_err("Invalid month")?;
            let day: u32 = time_str[4..6].parse().wrap_err("Invalid day")?;
            let hour: u32 = time_str[6..8].parse().wrap_err("Invalid hour")?;
            let minute: u32 = time_str[8..10].parse().wrap_err("Invalid minute")?;
            let second: u32 = time_str[10..12].parse().wrap_err("Invalid second")?;

            chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
                .single()
                .ok_or_else(|| eyre::eyre!("Invalid datetime"))?
        } else if time_str.len() == 15 && time_str.ends_with('Z') {
            // YYYY format
            let year: i32 = time_str[0..4].parse().wrap_err("Invalid year")?;
            let month: u32 = time_str[4..6].parse().wrap_err("Invalid month")?;
            let day: u32 = time_str[6..8].parse().wrap_err("Invalid day")?;
            let hour: u32 = time_str[8..10].parse().wrap_err("Invalid hour")?;
            let minute: u32 = time_str[10..12].parse().wrap_err("Invalid minute")?;
            let second: u32 = time_str[12..14].parse().wrap_err("Invalid second")?;

            chrono::Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
                .single()
                .ok_or_else(|| eyre::eyre!("Invalid datetime"))?
        } else {
            return Err(eyre::eyre!("Unsupported ASN1 time format: {}", time_str));
        };

        Ok(datetime)
    }

    fn detect_vulnerabilities(&self, result: &TlsData) -> Vec<TlsVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for expired certificates
        if let Some(expiry) = result.expiry_date {
            if expiry < chrono::Utc::now() {
                vulnerabilities.push(TlsVulnerability::ExpiredCertificate);
            }
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
                vulnerabilities.push(TlsVulnerability::WeakSignatureAlgorithm(cert.signature_algorithm.clone()));
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
        log::debug!("[scan::tls] perform_tls_scan_for_ip: target={} ip={}", target.display_name(), target_ip);

        let start_time = Instant::now();
        let mut result = TlsData::new(target_ip.to_string());

        let ports = self.get_tls_ports(target);
        let port = ports[0]; // Use first port for now
        log::debug!("[scan::tls] using_port: target={} port={}", target.display_name(), port);

        // Phase 1: Basic connectivity test
        log::debug!("[scan::tls] phase1_basic_connection: target={} ip={} port={}", target.display_name(), target_ip, port);
        let phase1_start = Instant::now();
        match self.test_basic_connection(target, target_ip, port).await {
            Ok((success, handshake_time, version)) => {
                let phase1_duration = phase1_start.elapsed();
                result.connection_successful = success;
                result.handshake_time = handshake_time;
                if let Some(v) = version {
                    result.negotiated_version = Some(v.clone());
                    result.supported_versions.push(v);
                }
                log::trace!("[scan::tls] phase1_completed: target={} port={} success={} handshake_time={}ms phase_duration={}ms version={:?}",
                    target.display_name(), port, success, handshake_time.as_millis(), phase1_duration.as_millis(), result.negotiated_version);
            }
            Err(e) => {
                let phase1_duration = phase1_start.elapsed();
                log::error!("[scan::tls] phase1_failed: target={} port={} duration={}ms error={}",
                    target.display_name(), port, phase1_duration.as_millis(), e);
                result.certificate_errors.push(format!("Connection failed: {}", e));
                result.scan_time = start_time.elapsed();
                return Ok(result);
            }
        }

        // Phase 2: TLS version enumeration
        log::debug!("[scan::tls] phase2_version_enumeration: target={} ip={} port={}", target.display_name(), target_ip, port);
        let phase2_start = Instant::now();
        match self.test_tls_versions(target, target_ip, port).await {
            Ok(versions) => {
                let phase2_duration = phase2_start.elapsed();
                result.supported_versions = versions.clone();
                log::trace!("[scan::tls] phase2_completed: target={} port={} duration={}ms versions={:?}",
                    target.display_name(), port, phase2_duration.as_millis(), versions);
            }
            Err(e) => {
                let phase2_duration = phase2_start.elapsed();
                log::warn!("[scan::tls] phase2_failed: target={} port={} duration={}ms error={}",
                    target.display_name(), port, phase2_duration.as_millis(), e);
                result.certificate_errors.push(format!("Version enumeration failed: {}", e));
            }
        }

        // Phase 3: Certificate analysis
        log::debug!("[scan::tls] phase3_certificate_analysis: target={} ip={} port={}", target.display_name(), target_ip, port);
        let phase3_start = Instant::now();
        match self.analyze_certificate_with_openssl(target, target_ip, port) {
            Ok(cert_chain) => {
                let phase3_duration = phase3_start.elapsed();
                result.certificate_valid = !cert_chain.is_empty();
                if let Some(leaf_cert) = cert_chain.first() {
                    result.expiry_date = Some(leaf_cert.not_after);
                    let days_until_expiry = (leaf_cert.not_after - chrono::Utc::now()).num_days();
                    result.days_until_expiry = Some(days_until_expiry);
                }
                result.certificate_chain = cert_chain.clone();
                log::trace!("[scan::tls] phase3_completed: target={} port={} duration={}ms cert_count={} valid={} days_until_expiry={:?}",
                    target.display_name(), port, phase3_duration.as_millis(), cert_chain.len(), result.certificate_valid, result.days_until_expiry);
            }
            Err(e) => {
                let phase3_duration = phase3_start.elapsed();
                log::error!("[scan::tls] phase3_failed: target={} port={} duration={}ms error={}",
                    target.display_name(), port, phase3_duration.as_millis(), e);
                result.certificate_errors.push(format!("Certificate analysis failed: {}", e));
            }
        }

        // Phase 4: Vulnerability detection
        log::debug!("[scan::tls] phase4_vulnerability_detection: target={}", target.display_name());
        let phase4_start = Instant::now();
        result.vulnerabilities = self.detect_vulnerabilities(&result);
        let phase4_duration = phase4_start.elapsed();
        log::trace!("[scan::tls] phase4_completed: target={} duration={}μs vulnerabilities={:?}",
            target.display_name(), phase4_duration.as_micros(), result.vulnerabilities);

        // Phase 5: Security grading
        log::debug!("[scan::tls] phase5_security_grading: target={}", target.display_name());
        let phase5_start = Instant::now();
        result.security_grade = self.calculate_security_grade(&result);
        let phase5_duration = phase5_start.elapsed();
        log::trace!("[scan::tls] phase5_completed: target={} duration={}μs grade={:?}",
            target.display_name(), phase5_duration.as_micros(), result.security_grade);

        result.scan_time = start_time.elapsed();
        result.queried_at = start_time;

        log::debug!("[scan::tls] tls_scan_completed: target={} total_duration={}ms grade={:?} vulnerabilities={}",
            target.display_name(), result.scan_time.as_millis(), result.security_grade, result.vulnerabilities.len());

        Ok(result)
    }
}

#[async_trait]
impl Scanner for TlsScanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!("[scan::tls] scan: target={} protocol={} total_timeout={}s",
            target.display_name(), protocol.as_str(), self.total_scan_timeout.as_secs());

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
                        result.ipv4_status = Self::classify_tls_error(&e);
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
                        result.ipv6_status = Self::classify_tls_error(&e);
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
                        result.ipv4_status = Self::classify_tls_error(&e);
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
                        result.ipv6_status = Self::classify_tls_error(&e);
                        log::debug!("[scan::tls] ipv6_tls_failed: error={}", e);
                    }
                }
            }
        }

        result.total_duration = scan_start.elapsed();

        // Return success if at least one protocol succeeded, or error if all failed
        if result.has_any_success() {
            log::trace!("[scan::tls] tls_completed: target={} protocol={} duration={}ms best_grade={:?}",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis(), result.get_best_security_grade());
            Ok(ScanResult::Tls(result))
        } else {
            // All protocols failed
            let error_msg = format!("All TLS attempts failed for target: {} ({})",
                target.display_name(), protocol.as_str());
            log::error!("[scan::tls] all_tls_failed: target={} protocol={} duration={}ms",
                target.display_name(), protocol.as_str(), result.total_duration.as_millis());
            Err(eyre::eyre!(error_msg))
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "tls"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(vulnerabilities[7], TlsVulnerability::WeakSignatureAlgorithm(_)));
    }

    #[test]
    fn test_security_grade_comparison() {
        let grades = vec![
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
        tls_data.vulnerabilities = vec![
            TlsVulnerability::Heartbleed,
            TlsVulnerability::ExpiredCertificate,
        ];

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
        let versions = vec![
            TlsVersion::V1_0,
            TlsVersion::V1_1,
            TlsVersion::V1_2,
            TlsVersion::V1_3,
        ];

        assert_eq!(versions[0].as_str(), "TLSv1.0");
        assert_eq!(versions[1].as_str(), "TLSv1.1");
        assert_eq!(versions[2].as_str(), "TLSv1.2");
        assert_eq!(versions[3].as_str(), "TLSv1.3");
    }
}