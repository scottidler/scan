// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Part of scan's port of mdn/mdn-http-observatory at commit 2776308: the HTTP layer under
// src/retriever/session.js (Node's `http`/`https` agents, `CERT_ERROR_CODES`).

//! The reqwest transport the retriever runs on: HTTP/1.1 only, no automatic redirects or cookies,
//! bodies decompressed (gzip, deflate, brotli). A verifying client and one that accepts any
//! certificate, as the session's `rejectUnauthorized` true and false agents.

use super::{IncomingResponse, Method, OutgoingRequest, Transport, TransportError};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use std::net::SocketAddr;

/// How the transport's clients are built.
#[derive(Debug, Clone)]
pub struct TransportOptions {
    /// Trust the platform's built-in roots (webpki's Mozilla set, as Node bundles Mozilla's).
    pub built_in_roots: bool,
    /// Extra trust anchors, DER: a test CA.
    pub extra_roots: Vec<Vec<u8>>,
    /// Fixed addresses for names, ahead of DNS. The URL's port wins over the address's.
    pub resolve: Vec<(String, SocketAddr)>,
    /// Honor `HTTP_PROXY`/`HTTPS_PROXY`, as axios does.
    pub env_proxy: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            built_in_roots: true,
            extra_roots: Vec::new(),
            resolve: Vec::new(),
            env_proxy: true,
        }
    }
}

/// The production [`Transport`].
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    verifying: Client,
    insecure: Client,
}

impl ReqwestTransport {
    pub fn new(options: &TransportOptions) -> eyre::Result<Self> {
        log::debug!(
            "[observatory::transport] new: built_in_roots={} extra_roots={} resolve={}",
            options.built_in_roots,
            options.extra_roots.len(),
            options.resolve.len()
        );
        Ok(Self {
            verifying: client(options, true)?,
            insecure: client(options, false)?,
        })
    }
}

fn client(options: &TransportOptions, verify: bool) -> eyre::Result<Client> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .http1_only()
        .pool_max_idle_per_host(0)
        .tls_built_in_root_certs(options.built_in_roots)
        .danger_accept_invalid_certs(!verify);
    for der in &options.extra_roots {
        let certificate = reqwest::Certificate::from_der(der)
            .map_err(|e| eyre::eyre!("observatory transport: extra root does not parse: {e}"))?;
        builder = builder.add_root_certificate(certificate);
    }
    if !options.env_proxy {
        builder = builder.no_proxy();
    }
    for (name, addr) in &options.resolve {
        builder = builder.resolve(name, *addr);
    }
    builder
        .build()
        .map_err(|e| eyre::eyre!("observatory transport: building the reqwest client failed: {e}"))
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send(&self, request: OutgoingRequest) -> Result<IncomingResponse, TransportError> {
        log::trace!(
            "[observatory::transport] send: {:?} {} verify={}",
            request.method,
            request.url,
            request.verify
        );
        let client = if request.verify { &self.verifying } else { &self.insecure };
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Options => reqwest::Method::OPTIONS,
        };
        let mut builder = client.request(method, request.url.clone());
        for (name, value) in &request.headers {
            let value = HeaderValue::from_bytes(&latin1_encode(value))
                .map_err(|e| TransportError::Other(format!("header {name} unusable: {e}")))?;
            builder = builder.header(HeaderName::from_static(name), value);
        }
        let response = builder.send().await.map_err(|e| classify(&e))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), latin1_decode(value.as_bytes())))
            .collect();
        let body = response.bytes().await.map_err(|e| classify(&e))?.to_vec();
        log::trace!(
            "[observatory::transport] send: {} status={} body={}B",
            request.url,
            status,
            body.len()
        );
        Ok(IncomingResponse { status, headers, body })
    }
}

/// Node reads header bytes as latin1.
fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Node writes header strings as latin1: one byte per code point, the low byte kept.
fn latin1_encode(value: &str) -> Vec<u8> {
    value.chars().map(|c| (c as u32 & 0xFF) as u8).collect()
}

/// A rustls certificate rejection anywhere in the error's chain is a certificate error; anything
/// else is not.
fn classify(error: &reqwest::Error) -> TransportError {
    match certificate_error(error) {
        Some(why) => TransportError::Certificate(why),
        None => TransportError::Other(error_chain(error)),
    }
}

/// The rustls `InvalidCertificate` reason in `error`'s chain. hyper-util wraps the connector's
/// `io::Error` (kind `Other`) around tokio-rustls's `io::Error` (kind `InvalidData`) around the
/// rustls error, and `io::Error::source()` skips the error it wraps, so an `io::Error` is
/// descended through `get_ref`.
fn certificate_error(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut current = Some(error);
    while let Some(e) = current {
        if let Some(rustls::Error::InvalidCertificate(reason)) = e.downcast_ref::<rustls::Error>() {
            return Some(format!("{reason:?}"));
        }
        current = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io.get_ref().map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    None
}

/// `error` and its sources, `: `-joined.
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![error.to_string()];
    let mut current = error.source();
    while let Some(e) = current {
        parts.push(e.to_string());
        current = e.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_certificate_inside_an_io_error_is_a_certificate_error() {
        let rustls_error = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls_error);
        let wrapped = std::io::Error::other(io);
        assert_eq!(certificate_error(&wrapped).as_deref(), Some("UnknownIssuer"));
        let other = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(certificate_error(&other), None);
        let alert = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure),
        );
        assert_eq!(certificate_error(&alert), None);
    }

    #[test]
    fn header_values_round_trip_as_latin1() {
        assert_eq!(latin1_decode(&[0x61, 0xE9]), "a\u{E9}");
        assert_eq!(latin1_encode("a\u{E9}"), vec![0x61, 0xE9]);
    }
}
