//! Browser distrust actions against CA owners, as a static table. A heuristic on what scan can
//! see (the `O=` of each presented certificate's issuer, and the leaf's `notBefore`), never a
//! browser verdict: Chrome keys on the root and, for the dated actions, the leaf's earliest SCT.
//! scan verifies no path and parses no SCTs, so `notBefore` stands in for the SCT date.

use chrono::{DateTime, NaiveDate, Utc};

/// One CA owner a browser stopped trusting.
#[derive(Debug, PartialEq, Eq)]
pub struct DistrustedCa {
    /// The CA owner, for logs.
    pub name: &'static str,
    /// The issuer `O=` values the distrust covers: an `O=` containing any of them matches,
    /// ASCII-case-insensitively, as Chrome's own guidance reads the field.
    pub organizations: &'static [&'static str],
    /// Certificates whose leaf `notBefore` falls on a later UTC day are covered; `None` covers
    /// every certificate.
    pub distrusted_after: Option<NaiveDate>,
    /// Where the distrust action and its date were read.
    pub source: &'static str,
}

const fn date(year: i32, month: u32, day: u32) -> Option<NaiveDate> {
    Some(NaiveDate::from_ymd_opt(year, month, day).expect("valid date"))
}

/// Each entry was read from its `source` on 2026-11-07. Where the source names the `O=` values
/// that need action (Entrust, Chunghwa Telecom, NetLock), those are listed verbatim; otherwise
/// `organizations` are the `O=` values of
/// the roots the action names, read from the certificates themselves.
pub static DISTRUSTED_CAS: &[DistrustedCa] = &[
    // Chrome 70 "fully remove[d] trust in Symantec's old infrastructure and all of the
    // certificates it has issued". The post names the brands Thawte, VeriSign, Equifax, GeoTrust
    // and RapidSSL; the O= values are those brands' roots in Chromium's
    // net/data/ssl/symantec/roots (tag 100.0.4896.60). DigiCert-run GeoTrust/Thawte/RapidSSL
    // intermediates carry O=DigiCert Inc and are not covered.
    DistrustedCa {
        name: "Symantec",
        organizations: &[
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
        distrusted_after: None,
        source: "https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html",
    },
    // Chrome 56 dropped certificates issued after 2016-10-21, "culminating in the full distrust
    // of these CAs"; Chromium's net/data/ssl/blocklist lists their roots under "WoSign/StartCom".
    // O= values from those blocklisted roots.
    DistrustedCa {
        name: "WoSign/StartCom",
        organizations: &["WoSign CA Limited", "StartCom Ltd."],
        distrusted_after: None,
        source: "https://security.googleblog.com/2016/10/distrusting-wosign-and-startcom.html",
    },
    // "trust in TLS server certificates from Camerfirma was fully removed". O= values from the
    // blocklisted Camerfirma roots (the 2016 roots spell it `AC CAMERFIRMA S.A.`).
    DistrustedCa {
        name: "Camerfirma",
        organizations: &["AC Camerfirma S.A.", "AC Camerfirma SA CIF A82743287"],
        distrusted_after: None,
        source: "https://chromium.googlesource.com/chromium/src/+/refs/tags/100.0.4896.60/net/data/ssl/blocklist/README.md",
    },
    // Chrome 131: certificates "whose earliest Signed Certificate Timestamp (SCT) is dated after
    // November 11, 2024 (11:59:59 PM UTC)", under the Entrust and AffirmTrust roots it lists.
    // Its FAQ: action is required if the Issued By `O=` "contains "Entrust" or "AffirmTrust"".
    DistrustedCa {
        name: "Entrust",
        organizations: &["Entrust", "AffirmTrust"],
        distrusted_after: date(2024, 11, 11),
        source: "https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html",
    },
    // Chrome 139: earliest SCT "dated after July 31, 2025 11:59:59 PM UTC", under the ePKI and
    // HiPKI roots. Its FAQ: action is required if the Issued By `O=` contains "Chunghwa
    // Telecom", "行政院", "NETLOCK Ltd.", or "NETLOCK Kft.".
    DistrustedCa {
        name: "Chunghwa Telecom",
        organizations: &["Chunghwa Telecom", "行政院"],
        distrusted_after: date(2025, 7, 31),
        source: "https://security.googleblog.com/2025/05/sustaining-digital-certificate-security-chrome-root-store-changes.html",
    },
    // The same action and date, under the NetLock Arany (Class Gold) root.
    DistrustedCa {
        name: "NetLock",
        organizations: &["NETLOCK Ltd.", "NETLOCK Kft."],
        distrusted_after: date(2025, 7, 31),
        source: "https://security.googleblog.com/2025/05/sustaining-digital-certificate-security-chrome-root-store-changes.html",
    },
];

/// The distrust covering a certificate issued under `issuer_organization` in a chain whose leaf
/// starts at `leaf_not_before`, if any. No organization matches nothing.
pub fn distrust_of(issuer_organization: Option<&str>, leaf_not_before: DateTime<Utc>) -> Option<&'static DistrustedCa> {
    let organization = issuer_organization?.trim();
    let found = DISTRUSTED_CAS.iter().find(|ca| {
        ca.organizations
            .iter()
            .any(|listed| organization.to_ascii_lowercase().contains(&listed.to_ascii_lowercase()))
            && ca
                .distrusted_after
                .is_none_or(|after| leaf_not_before.date_naive() > after)
    });
    if let Some(ca) = found {
        log::debug!(
            "[scan::tls::distrust] distrusted_ca: organization={} ca={} leaf_not_before={}",
            organization,
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

    #[test]
    fn entrust_is_covered_only_for_leaves_issued_after_its_date() {
        assert_eq!(
            distrust_of(Some("Entrust, Inc."), at(2024, 11, 12, 0)).map(|ca| ca.name),
            Some("Entrust")
        );
        assert_eq!(distrust_of(Some("Entrust, Inc."), at(2024, 11, 11, 23)), None);
        assert_eq!(
            distrust_of(Some("AffirmTrust"), at(2025, 1, 1, 0)).map(|ca| ca.name),
            Some("Entrust")
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
                distrust_of(Some(organization), at(2025, 8, 1, 0)).map(|ca| ca.name),
                Some(ca),
                "{organization}"
            );
        }
        assert_eq!(distrust_of(Some("NETLOCK Ltd."), at(2025, 7, 31, 23)), None);
    }

    #[test]
    fn an_undated_distrust_covers_every_leaf() {
        assert_eq!(
            distrust_of(Some("thawte, Inc."), at(2010, 1, 1, 0)).map(|ca| ca.name),
            Some("Symantec")
        );
        assert_eq!(
            distrust_of(Some("AC CAMERFIRMA S.A."), at(2026, 1, 1, 0)).map(|ca| ca.name),
            Some("Camerfirma")
        );
    }

    #[test]
    fn a_trusted_or_missing_organization_matches_nothing() {
        assert_eq!(distrust_of(Some("Google Trust Services"), at(2026, 1, 1, 0)), None);
        assert_eq!(distrust_of(Some("DigiCert Inc"), at(2026, 1, 1, 0)), None);
        assert_eq!(distrust_of(None, at(2026, 1, 1, 0)), None);
    }

    #[test]
    fn every_entry_names_a_source_and_at_least_one_organization() {
        for ca in DISTRUSTED_CAS {
            assert!(ca.source.starts_with("https://"), "{}", ca.name);
            assert!(!ca.organizations.is_empty(), "{}", ca.name);
        }
    }
}
