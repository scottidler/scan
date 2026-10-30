//! The security.txt lens (RFC 9116): one `GET /.well-known/security.txt` on a verifying client,
//! classified as present, expired, invalid, absent, or failed.

use crate::scan::lens::LensOutcome;
use chrono::{DateTime, Utc};
use reqwest::Client;
use url::Url;

pub const SECURITY_TXT_PATH: &str = "/.well-known/security.txt";

/// What a served security.txt says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityTxtState {
    /// A `text/plain` file with a `Contact:` and no past or unparseable `Expires:`.
    Present,
    /// `Expires:` is in the past.
    Expired,
    /// Served, but not a usable security.txt; the reason says why.
    Invalid(String),
}

/// A served security.txt: its state, its first `Contact:` and its `Expires:` as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTxt {
    pub state: SecurityTxtState,
    pub contact: Option<String>,
    pub expires: Option<String>,
}

/// Fetch `https://<host>[:port]/.well-known/security.txt` from `base` with `client`, which must
/// verify certificates. The caller bounds the time.
pub async fn fetch(client: &Client, base: &Url) -> LensOutcome<SecurityTxt> {
    let url = match base.join(SECURITY_TXT_PATH) {
        Ok(url) => url,
        Err(e) => return LensOutcome::Failed(format!("bad URL: {e}")),
    };
    log::debug!("[scan::http::disclosure] fetch: url={}", url);
    let response = match client.get(url.clone()).send().await {
        Ok(response) => response,
        Err(e) => {
            let reason = innermost(&e);
            log::debug!("[scan::http::disclosure] fetch_failed: url={} reason={}", url, reason);
            return LensOutcome::Failed(reason);
        }
    };
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = match response.bytes().await {
        Ok(body) => String::from_utf8_lossy(&body).into_owned(),
        Err(e) => return LensOutcome::Failed(innermost(&e)),
    };
    let outcome = classify(status, content_type.as_deref(), &body, Utc::now());
    log::debug!(
        "[scan::http::disclosure] fetch_done: url={} status={} content_type={:?} outcome={:?}",
        url,
        status,
        content_type,
        outcome
    );
    outcome
}

/// The innermost cause of an error chain, e.g. `invalid peer certificate: UnknownIssuer`.
fn innermost(error: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = error;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// One answer, classified at `now`: 404/410 and a 2xx HTML page (a soft 404) are absent; any other
/// non-2xx failed; a 2xx `text/plain` body is read for `Contact:` and `Expires:`.
pub fn classify(status: u16, content_type: Option<&str>, body: &str, now: DateTime<Utc>) -> LensOutcome<SecurityTxt> {
    if status == 404 || status == 410 {
        return LensOutcome::Absent;
    }
    if !(200..300).contains(&status) {
        return LensOutcome::Failed(format!("HTTP {status}"));
    }
    let mime = content_type
        .and_then(|value| value.split(';').next())
        .map(|mime| mime.trim().to_ascii_lowercase());
    match mime.as_deref() {
        Some("text/html") => return LensOutcome::Absent,
        Some("text/plain") => {}
        Some(other) => return LensOutcome::Present(invalid(format!("served as {other}"))),
        None => return LensOutcome::Present(invalid("no Content-Type".to_string())),
    }

    let contact = field(body, "contact");
    let expires = field(body, "expires");
    let state = match (&contact, &expires) {
        (None, _) => SecurityTxtState::Invalid("no Contact:".to_string()),
        (Some(_), Some(expires)) => match DateTime::parse_from_rfc3339(expires) {
            Err(_) => SecurityTxtState::Invalid(format!("unparseable Expires: {expires}")),
            Ok(at) if at.with_timezone(&Utc) <= now => SecurityTxtState::Expired,
            Ok(_) => SecurityTxtState::Present,
        },
        (Some(_), None) => SecurityTxtState::Present,
    };
    LensOutcome::Present(SecurityTxt {
        state,
        contact,
        expires,
    })
}

fn invalid(reason: String) -> SecurityTxt {
    SecurityTxt {
        state: SecurityTxtState::Invalid(reason),
        contact: None,
        expires: None,
    }
}

/// The first `name:` field's value, the name matched case-insensitively; comments skipped.
fn field(body: &str, name: &str) -> Option<String> {
    body.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{FakeHttp, FakeRoute, TestCa, silent_http_url};
    use std::time::Duration;

    const CONTACT: &str = "mailto:security@site.com";

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn file(expires: &str) -> String {
        format!("# a comment\nContact: {CONTACT}\nExpires: {expires}\nPreferred-Languages: en\n")
    }

    #[test]
    fn a_text_file_with_a_contact_and_a_future_expiry_is_present() {
        let outcome = classify(
            200,
            Some("text/plain; charset=utf-8"),
            &file("2027-01-01T00:00:00Z"),
            now(),
        );
        assert_eq!(
            outcome,
            LensOutcome::Present(SecurityTxt {
                state: SecurityTxtState::Present,
                contact: Some(CONTACT.to_string()),
                expires: Some("2027-01-01T00:00:00Z".to_string()),
            })
        );
    }

    #[test]
    fn a_past_expiry_is_expired() {
        let outcome = classify(200, Some("text/plain"), &file("2025-01-01T00:00:00.000Z"), now());
        assert_eq!(
            outcome.present().map(|txt| &txt.state),
            Some(&SecurityTxtState::Expired)
        );
    }

    #[test]
    fn no_contact_or_a_bad_expiry_or_a_wrong_type_is_invalid() {
        for (content_type, body, why) in [
            (Some("text/plain"), "Expires: 2027-01-01T00:00:00Z\n", "no Contact:"),
            (
                Some("text/plain"),
                "Contact: mailto:a@b.c\nExpires: next year\n",
                "unparseable Expires: next year",
            ),
            (
                Some("application/octet-stream"),
                "Contact: x",
                "served as application/octet-stream",
            ),
            (None, "Contact: x", "no Content-Type"),
        ] {
            let outcome = classify(200, content_type, body, now());
            assert_eq!(
                outcome.present().map(|txt| &txt.state),
                Some(&SecurityTxtState::Invalid(why.to_string())),
                "{why}"
            );
        }
    }

    #[test]
    fn a_404_and_a_soft_404_html_page_are_absent() {
        assert_eq!(classify(404, Some("text/plain"), "", now()), LensOutcome::Absent);
        assert_eq!(classify(410, None, "", now()), LensOutcome::Absent);
        assert_eq!(
            classify(200, Some("Text/HTML; charset=utf-8"), "<html>Contact: no</html>", now()),
            LensOutcome::Absent
        );
    }

    #[test]
    fn another_error_status_failed() {
        assert_eq!(
            classify(503, Some("text/plain"), "", now()),
            LensOutcome::Failed("HTTP 503".to_string())
        );
    }

    #[test]
    fn fields_match_case_insensitively_and_skip_comments() {
        let body = "# Contact: mailto:commented@x\ncontact:   https://x/report  \n";
        assert_eq!(field(body, "Contact").as_deref(), Some("https://x/report"));
        assert_eq!(field(body, "expires"), None);
    }

    /// A verifying client that trusts `ca` and reaches `site.com` on loopback.
    fn client(ca: &TestCa) -> Client {
        Client::builder()
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_der(&ca.der()).unwrap())
            .resolve("site.com", "127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap()
    }

    async fn served(route: FakeRoute) -> LensOutcome<SecurityTxt> {
        let ca = TestCa::new("disclosure CA");
        let server = FakeHttp::start_tls(vec![route], &ca.issue(&["site.com"])).await;
        let base = Url::parse(&format!("https://site.com:{}/", server.port())).unwrap();
        let outcome = fetch(&client(&ca), &base).await;
        assert_eq!(server.hits(SECURITY_TXT_PATH), 1, "one GET of the file");
        outcome
    }

    #[tokio::test]
    async fn fetched_files_classify_over_tls() {
        let present = served(
            FakeRoute::get(SECURITY_TXT_PATH, 200)
                .header("Content-Type", "text/plain")
                .body(file("2099-01-01T00:00:00Z")),
        )
        .await;
        assert_eq!(present.present().map(|t| &t.state), Some(&SecurityTxtState::Present));

        let expired = served(
            FakeRoute::get(SECURITY_TXT_PATH, 200)
                .header("Content-Type", "text/plain")
                .body(file("2020-01-01T00:00:00Z")),
        )
        .await;
        assert_eq!(expired.present().map(|t| &t.state), Some(&SecurityTxtState::Expired));

        let invalid = served(
            FakeRoute::get(SECURITY_TXT_PATH, 200)
                .header("Content-Type", "text/plain")
                .body("Policy: https://x/\n"),
        )
        .await;
        assert_eq!(
            invalid.present().map(|t| &t.state),
            Some(&SecurityTxtState::Invalid("no Contact:".to_string()))
        );

        assert_eq!(
            served(FakeRoute::get(SECURITY_TXT_PATH, 404)).await,
            LensOutcome::Absent
        );
        let soft_404 = FakeRoute::get(SECURITY_TXT_PATH, 200)
            .header("Content-Type", "text/html")
            .body("<html>not found</html>");
        assert_eq!(served(soft_404).await, LensOutcome::Absent);
    }

    /// The client verifies: a certificate it does not trust is a failure, never a fallback.
    #[tokio::test]
    async fn an_untrusted_certificate_fails() {
        let (trusted, other) = (TestCa::new("trusted CA"), TestCa::new("other CA"));
        let route = FakeRoute::get(SECURITY_TXT_PATH, 200)
            .header("Content-Type", "text/plain")
            .body(file("2099-01-01T00:00:00Z"));
        let server = FakeHttp::start_tls(vec![route], &other.issue(&["site.com"])).await;
        let base = Url::parse(&format!("https://site.com:{}/", server.port())).unwrap();
        let LensOutcome::Failed(reason) = fetch(&client(&trusted), &base).await else {
            panic!("an untrusted certificate must fail");
        };
        assert!(reason.contains("certificate"), "{reason}");
        assert_eq!(server.hits(SECURITY_TXT_PATH), 0);
    }

    /// A server that never answers fails at the caller's timeout; the lens reads `failed`.
    #[tokio::test]
    async fn a_silent_server_fails_with_a_timeout() {
        let silent = Url::parse(&silent_http_url().await).unwrap();
        let base = Url::parse(&format!("http://127.0.0.1:{}/", silent.port().unwrap())).unwrap();
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let LensOutcome::Failed(reason) = fetch(&client, &base).await else {
            panic!("a silent server must fail");
        };
        assert!(reason.contains("timed out"), "{reason}");
    }
}
