//! Browser distrust actions against CA owners: the built-in table below, followed by any entries
//! the user adds in their config. A heuristic on what scan can see (the `O=` and `CN=` of each
//! presented certificate's issuer, and the leaf's `notBefore`), never a browser verdict: Chrome
//! keys on the root (or, for a blocked intermediate, its key) and, for the dated actions, the
//! leaf's earliest SCT. scan verifies no path and parses no SCTs, so `notBefore` stands in for the
//! SCT date. A server that sends only the leaf shows scan just the issuing CA's name, so an entry
//! that names only a root or its `Root TLS CA` cannot see that chain.

use crate::scan::tls::CertificateInfo;
use chrono::{DateTime, NaiveDate, Utc};
use eyre::{Result, bail};

/// One browser distrust action, matched against a presented certificate's issuer. Every list an
/// entry fills must match; an empty list is no constraint, and at least one must be filled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DistrustedCa {
    /// The CA owner or action, for logs.
    pub name: String,
    /// Issuer `O=` values: an `O=` containing any of them matches, ASCII-case-insensitively, as
    /// Chrome's own guidance reads the field.
    #[serde(default)]
    pub organizations: Vec<String>,
    /// Issuer `CN=` values: a `CN=` equal to any of them matches, trimmed and
    /// ASCII-case-insensitively. Exact, never containment: CA names are whole names.
    #[serde(default)]
    pub issuer_common_names: Vec<String>,
    /// Certificates whose leaf `notBefore` falls on a later UTC day are covered; `None` covers
    /// every certificate.
    #[serde(default)]
    pub distrusted_after: Option<NaiveDate>,
    /// Where the distrust action and its date were read.
    pub source: String,
}

fn entry(
    name: &str,
    organizations: &[&str],
    issuer_common_names: &[&str],
    distrusted_after: Option<NaiveDate>,
    source: &str,
) -> DistrustedCa {
    DistrustedCa {
        name: name.to_string(),
        organizations: organizations.iter().map(|s| s.to_string()).collect(),
        issuer_common_names: issuer_common_names.iter().map(|s| s.to_string()).collect(),
        distrusted_after,
        source: source.to_string(),
    }
}

const fn date(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
    Some(NaiveDate::from_ymd_opt(year, month, day).expect("valid date"))
}

const EMUDHRA_SOURCE: &str = "https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/";

/// The entries built into scan. Each was read from its `source` on 2026-11-07. Where the source
/// names the `O=` values that need action (Entrust, Chunghwa Telecom, NetLock), those are listed
/// verbatim; otherwise `organizations` are the `O=` values of the roots the action names, read
/// from the certificates themselves.
pub fn builtin_distrusted_cas() -> Vec<DistrustedCa> {
    vec![
        // Chrome 70 "fully remove[d] trust in Symantec's old infrastructure and all of the
        // certificates it has issued". The post names the brands Thawte, VeriSign, Equifax, GeoTrust
        // and RapidSSL; the O= values are those brands' roots in Chromium's
        // net/data/ssl/symantec/roots (tag 100.0.4896.60). DigiCert-run GeoTrust/Thawte/RapidSSL
        // intermediates carry O=DigiCert Inc and are not covered.
        entry(
            "Symantec",
            &[
                "Symantec Corporation",
                "VeriSign, Inc.",
                "GeoTrust Inc.",
                "thawte, Inc.",
                "Thawte Consulting",
                "Thawte Consulting cc",
                "Thawte",
                "Equifax",
                "Equifax Secure",
                "Equifax Secure Inc.",
            ],
            &[],
            None,
            "https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html",
        ),
        // The same Symantec action, for the TC TrustCenter roots the post does not name by brand.
        // Chromium's net/data/ssl/symantec README applies the policy to every root in roots/, by SPKI;
        // ten of them are TC TrustCenter's, under these two O= spellings (read from the certificates).
        entry(
            "Symantec (TC TrustCenter)",
            &[
                "TC TrustCenter GmbH",
                "TC TrustCenter for Security in Data Networks GmbH",
            ],
            &[],
            None,
            "https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.60/net/data/ssl/symantec/README.md",
        ),
        // Chrome 56 dropped certificates issued after 2016-10-21, "culminating in the full distrust
        // of these CAs"; Chromium's net/data/ssl/blocklist lists their roots under "WoSign/StartCom".
        // O= values from those blocklisted roots.
        entry(
            "WoSign/StartCom",
            &["WoSign CA Limited", "StartCom Ltd."],
            &[],
            None,
            "https://security.googleblog.com/2016/10/distrusting-wosign-and-startcom.html",
        ),
        // "trust in TLS server certificates from Camerfirma was fully removed". O= values from the
        // blocklisted Camerfirma roots (the 2016 roots spell it `AC CAMERFIRMA S.A.`).
        entry(
            "Camerfirma",
            &["AC Camerfirma S.A.", "AC Camerfirma SA CIF A82743287"],
            &[],
            None,
            "https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.60/net/data/ssl/blocklist/README.md",
        ),
        // Chrome 131: certificates "whose earliest Signed Certificate Timestamp (SCT) is dated after
        // November 11, 2024 (11:59:59 PM UTC)", under the Entrust and AffirmTrust roots it lists.
        // Its FAQ: action is required if the Issued By `O=` "contains "Entrust" or "AffirmTrust"".
        entry(
            "Entrust",
            &["Entrust", "AffirmTrust"],
            &[],
            date(2024, 11, 11),
            "https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html",
        ),
        // Chrome 139: earliest SCT "dated after July 31, 2025 11:59:59 PM UTC", under the ePKI and
        // HiPKI roots. Its FAQ: action is required if the Issued By `O=` contains "Chunghwa
        // Telecom", "行政院", "NETLOCK Ltd.", or "NETLOCK Kft.".
        entry(
            "Chunghwa Telecom",
            &["Chunghwa Telecom", "行政院"],
            &[],
            date(2025, 7, 31),
            "https://security.googleblog.com/2025/05/sustaining-digital-certificate-security-chrome-root-store-changes.html",
        ),
        // The same action and date, under the NetLock Arany (Class Gold) root.
        entry(
            "NetLock",
            &["NETLOCK Ltd.", "NETLOCK Kft."],
            &[],
            date(2025, 7, 31),
            "https://security.googleblog.com/2025/05/sustaining-digital-certificate-security-chrome-root-store-changes.html",
        ),
        // eMudhra, Oct 20, 2026: Chrome "removed emSign ECC Root CA - G3 (the root certificate that
        // signed the compromised CA certificates) from the Chrome Root Store", so every leaf under
        // it. Both emSign roots carry the same O=, so the CN tells them apart: the root's own CN,
        // and its `Root TLS CA` intermediate's for chains sent without the root-signed cert.
        entry(
            "eMudhra (emSign ECC Root CA - G3)",
            &["eMudhra Technologies Limited"],
            &["emSign ECC Root CA - G3", "emSign Root TLS CA - G3"],
            None,
            EMUDHRA_SOURCE,
        ),
        // Update, Nov 4, 2026: certificates "validating to CN= emSign Root CA - G1 [...] whose
        // earliest Signed Certificate Timestamp (SCT) is dated after November 16, 2026 11:59:59 PM
        // UTC, will no longer be trusted by default in Chrome 153 and higher". The InCommon
        // intermediates (O=Internet2) are issued by `emSign Root TLS CA - G1`, so they match here.
        entry(
            "eMudhra (emSign Root CA - G1)",
            &["eMudhra Technologies Limited"],
            &["emSign Root CA - G1", "emSign Root TLS CA - G1"],
            date(2026, 11, 16),
            EMUDHRA_SOURCE,
        ),
        // The same post: Chrome "landed a CRLSet update blocking the Subject Public Key Info (SPKI)
        // hashes of the affected intermediate CAs", "these six intermediate CAs" for TLS. Each is
        // also cross-signed by Sectigo's AAA Certificate Services, a path that names no emSign
        // root, so they are matched as the issuer by their own CNs and O= values (read from the
        // decoded certificates), undated because the keys are blocked.
        entry(
            "eMudhra (compromised intermediates)",
            &["eMudhra BV", "eMudhra Inc"],
            &[
                "EM DV TLS CA - G3B",
                "EM OV TLS CA - G3B",
                "EM EV TLS CA - G3B",
                "EM DV TLS CA - G3C",
                "EM OV TLS CA - G3C",
                "EM EV TLS CA - G3C",
            ],
            None,
            EMUDHRA_SOURCE,
        ),
    ]
}

/// Checks one entry, built in or from the user's config: a name, at least one matcher, no blank
/// matcher string, and an `https://` source.
pub fn validate(ca: &DistrustedCa) -> Result<()> {
    if ca.name.trim().is_empty() {
        bail!("distrusted CA entry has an empty name");
    }
    if ca.organizations.is_empty() && ca.issuer_common_names.is_empty() {
        bail!(
            "distrusted CA entry '{}' needs at least one of organizations and issuer-common-names",
            ca.name
        );
    }
    if ca.organizations.iter().any(|value| value.trim().is_empty()) {
        bail!("distrusted CA entry '{}' has an empty string in organizations", ca.name);
    }
    if ca.issuer_common_names.iter().any(|value| value.trim().is_empty()) {
        bail!(
            "distrusted CA entry '{}' has an empty string in issuer-common-names",
            ca.name
        );
    }
    if !ca.source.starts_with("https://") {
        bail!(
            "distrusted CA entry '{}' has source '{}', which does not start with https://",
            ca.name,
            ca.source
        );
    }
    Ok(())
}

/// Whether `ca` covers a certificate issued under `cert`'s issuer, in a chain whose leaf starts at
/// `leaf_not_before`. A filled list the issuer has no value for never matches.
fn covers(ca: &DistrustedCa, cert: &CertificateInfo, leaf_not_before: DateTime<Utc>) -> bool {
    let organization_matches = ca.organizations.is_empty()
        || cert.issuer_organization.as_deref().is_some_and(|organization| {
            let organization = organization.trim().to_ascii_lowercase();
            ca.organizations
                .iter()
                .any(|listed| organization.contains(&listed.to_ascii_lowercase()))
        });
    let common_name_matches = ca.issuer_common_names.is_empty()
        || cert.issuer_common_name.as_deref().is_some_and(|common_name| {
            let common_name = common_name.trim();
            ca.issuer_common_names
                .iter()
                .any(|listed| listed.trim().eq_ignore_ascii_case(common_name))
        });
    organization_matches
        && common_name_matches
        && ca
            .distrusted_after
            .is_none_or(|after| leaf_not_before.date_naive() > after)
}

/// The first entry in `cas` covering a certificate issued under `cert`'s issuer, in a chain whose
/// leaf starts at `leaf_not_before`, if any.
pub fn distrust_of<'a>(
    cas: &'a [DistrustedCa],
    cert: &CertificateInfo,
    leaf_not_before: DateTime<Utc>,
) -> Option<&'a DistrustedCa> {
    let found = cas.iter().find(|ca| covers(ca, cert, leaf_not_before));
    if let Some(ca) = found {
        log::debug!(
            "[scan::tls::distrust] distrusted_ca: organization={:?} common_name={:?} ca={} leaf_not_before={}",
            cert.issuer_organization,
            cert.issuer_common_name,
            ca.name,
            leaf_not_before
        );
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0).unwrap()
    }

    /// A certificate whose issuer carries `organization` and `common_name`; the rest is filler.
    fn issued_by(organization: Option<&str>, common_name: Option<&str>) -> CertificateInfo {
        CertificateInfo {
            subject: "CN=www.example.com".to_string(),
            issuer: String::new(),
            issuer_organization: organization.map(str::to_string),
            issuer_common_name: common_name.map(str::to_string),
            serial_number: "1".to_string(),
            not_before: at(2026, 1, 1, 0),
            not_after: at(2027, 1, 1, 0),
            signature_algorithm: "ecdsa-with-SHA256".to_string(),
            public_key_algorithm: "EC".to_string(),
            key_size: Some(256),
            san_domains: vec![],
            is_self_signed: false,
            is_ca: false,
        }
    }

    /// The built-in entry's name covering an issuer `O=` alone at `when`, if any.
    fn by_organization(organization: Option<&str>, when: DateTime<Utc>) -> Option<String> {
        by_issuer(organization, None, when)
    }

    fn by_issuer(organization: Option<&str>, common_name: Option<&str>, when: DateTime<Utc>) -> Option<String> {
        distrust_of(&builtin_distrusted_cas(), &issued_by(organization, common_name), when).map(|ca| ca.name.clone())
    }

    fn named(name: &str) -> Option<String> {
        Some(name.to_string())
    }

    #[test]
    fn entrust_is_covered_only_for_leaves_issued_after_its_date() {
        assert_eq!(
            by_organization(Some("Entrust, Inc."), at(2024, 11, 12, 0)),
            named("Entrust")
        );
        assert_eq!(by_organization(Some("Entrust, Inc."), at(2024, 11, 11, 23)), None);
        assert_eq!(
            by_organization(Some("AffirmTrust"), at(2025, 1, 1, 0)),
            named("Entrust")
        );
    }

    /// Every `O=` spelling the Chunghwa/NetLock and Entrust posts name, contained in the field.
    #[test]
    fn every_spelling_the_sources_name_is_matched_by_containment() {
        for (organization, ca) in [
            ("行政院", "Chunghwa Telecom"),
            ("Chunghwa Telecom Co., Ltd.", "Chunghwa Telecom"),
            ("NETLOCK Ltd.", "NetLock"),
            ("NetLock Kft.", "NetLock"),
            ("Entrust Limited", "Entrust"),
            ("Entrust.net", "Entrust"),
        ] {
            assert_eq!(
                by_organization(Some(organization), at(2025, 8, 1, 0)),
                named(ca),
                "{organization}"
            );
        }
        assert_eq!(by_organization(Some("NETLOCK Ltd."), at(2025, 7, 31, 23)), None);
    }

    #[test]
    fn an_undated_distrust_covers_every_leaf() {
        assert_eq!(
            by_organization(Some("thawte, Inc."), at(2010, 1, 1, 0)),
            named("Symantec")
        );
        assert_eq!(
            by_organization(Some("AC CAMERFIRMA S.A."), at(2026, 1, 1, 0)),
            named("Camerfirma")
        );
    }

    #[test]
    fn both_tc_trustcenter_spellings_are_covered_for_every_leaf() {
        for organization in [
            "TC TrustCenter GmbH",
            "TC TrustCenter for Security in Data Networks GmbH",
        ] {
            assert_eq!(
                by_organization(Some(organization), at(2026, 1, 1, 0)),
                named("Symantec (TC TrustCenter)"),
                "{organization}"
            );
        }
    }

    #[test]
    fn a_trusted_or_missing_organization_matches_nothing() {
        assert_eq!(by_organization(Some("Google Trust Services"), at(2026, 1, 1, 0)), None);
        assert_eq!(by_organization(Some("DigiCert Inc"), at(2026, 1, 1, 0)), None);
        assert_eq!(by_organization(None, at(2026, 1, 1, 0)), None);
        assert_eq!(by_issuer(None, Some("emSign Root CA - G1"), at(2027, 1, 1, 0)), None);
    }

    #[test]
    fn emsign_g3_is_distrusted_for_every_leaf() {
        for common_name in ["emSign ECC Root CA - G3", "emSign Root TLS CA - G3"] {
            assert_eq!(
                by_issuer(
                    Some("eMudhra Technologies Limited"),
                    Some(common_name),
                    at(2020, 1, 1, 0)
                ),
                named("eMudhra (emSign ECC Root CA - G3)"),
                "{common_name}"
            );
        }
    }

    #[test]
    fn emsign_g1_is_distrusted_only_after_2026_11_16() {
        let g1 = |when| {
            by_issuer(
                Some("eMudhra Technologies Limited"),
                Some("emSign Root TLS CA - G1"),
                when,
            )
        };
        assert_eq!(g1(at(2026, 11, 16, 23)), None);
        assert_eq!(g1(at(2026, 11, 17, 0)), named("eMudhra (emSign Root CA - G1)"));
        assert_eq!(
            by_issuer(
                Some("eMudhra Technologies Limited"),
                Some("emSign Root CA - G1"),
                at(2026, 11, 17, 0)
            ),
            named("eMudhra (emSign Root CA - G1)")
        );
    }

    #[test]
    fn an_emudhra_issuer_with_an_unlisted_cn_matches_nothing() {
        assert_eq!(
            by_issuer(
                Some("eMudhra Technologies Limited"),
                Some("emSign Root CA - C1"),
                at(2027, 1, 1, 0)
            ),
            None
        );
    }

    #[test]
    fn a_listed_cn_under_another_organization_matches_nothing() {
        assert_eq!(
            by_issuer(Some("Other CA"), Some("emSign Root CA - G1"), at(2027, 1, 1, 0)),
            None
        );
    }

    /// The leaf-only and AAA-cross-signed case: the leaf's own issuer is a compromised
    /// intermediate, at any date.
    #[test]
    fn emsign_compromised_intermediates_are_distrusted_as_the_leaf_issuer() {
        for (organization, common_name) in [
            ("eMudhra BV", "EM DV TLS CA - G3B"),
            ("eMudhra Inc", "EM EV TLS CA - G3C"),
        ] {
            for when in [at(2020, 1, 1, 0), at(2027, 1, 1, 0)] {
                assert_eq!(
                    by_issuer(Some(organization), Some(common_name), when),
                    named("eMudhra (compromised intermediates)"),
                    "{common_name} {when}"
                );
            }
        }
    }

    #[test]
    fn a_cn_only_entry_matches_a_cert_with_no_organization() {
        let cas = [entry("CN only", &[], &["Example Root"], None, "https://example.com")];
        let found = distrust_of(&cas, &issued_by(None, Some("Example Root")), at(2026, 1, 1, 0));
        assert_eq!(found.map(|ca| ca.name.as_str()), Some("CN only"));
        assert_eq!(
            distrust_of(&cas, &issued_by(Some("Example"), None), at(2026, 1, 1, 0)),
            None
        );
    }

    #[test]
    fn issuer_cn_matching_trims_ignores_ascii_case_and_never_uses_containment() {
        let org = Some("eMudhra Technologies Limited");
        assert_eq!(
            by_issuer(org, Some(" EMSIGN ROOT CA - G1 "), at(2027, 1, 1, 0)),
            named("eMudhra (emSign Root CA - G1)")
        );
        assert_eq!(
            by_issuer(org, Some("emSign Root CA - G1 SubCA"), at(2027, 1, 1, 0)),
            None
        );
    }

    #[test]
    fn every_builtin_entry_validates() {
        for ca in builtin_distrusted_cas() {
            validate(&ca).unwrap_or_else(|error| panic!("{}: {error}", ca.name));
        }
    }

    #[test]
    fn validate_rejects_an_entry_with_no_matcher() {
        let ca = entry("Nothing", &[], &[], None, "https://example.com");
        let error = validate(&ca).unwrap_err().to_string();
        assert!(error.contains("'Nothing'"), "{error}");
        assert!(error.contains("at least one"), "{error}");
    }

    #[test]
    fn validate_rejects_an_empty_string() {
        let ca = entry("Blank", &["Example"], &["  "], None, "https://example.com");
        let error = validate(&ca).unwrap_err().to_string();
        assert!(error.contains("issuer-common-names"), "{error}");
        let ca = entry("Blank", &[""], &[], None, "https://example.com");
        assert!(validate(&ca).unwrap_err().to_string().contains("organizations"));
        let ca = entry(" ", &["Example"], &[], None, "https://example.com");
        assert!(validate(&ca).unwrap_err().to_string().contains("empty name"));
    }

    #[test]
    fn validate_rejects_a_non_https_source() {
        let ca = entry("Plain", &["Example"], &[], None, "http://example.com");
        let error = validate(&ca).unwrap_err().to_string();
        assert!(error.contains("https://"), "{error}");
        assert!(validate(&entry("Plain", &["Example"], &[], None, "https://example.com")).is_ok());
    }
}
