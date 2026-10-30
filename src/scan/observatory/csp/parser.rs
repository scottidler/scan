// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/cspParser.js,
// test/csp-parser.test.js).

//! `parseCsp`: one or more policies folded into the directive -> sources map the CSP test reads.
//! With several policies a source survives only when every policy allows it.

use crate::scan::observatory::js;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// A parsed policy: directive -> sources, lowercased.
pub type Csp = BTreeMap<String, BTreeSet<String>>;

/// Holds the duplicated `report-uri`/`report-to` directive names, when there were any.
pub const DUPLICATE_WARNINGS_KEY: &str = "_observatory_duplicate_key_warnings";

/// The shortest policy accepted: one shorter than `img-src` is invalid.
const SHORTEST_DIRECTIVE_LENGTH: usize = "img-src".len() - 1;
const DIRECTIVES_DISALLOWED_IN_META: [&str; 3] = ["frame-ancestors", "report-uri", "sandbox"];
const ALLOWED_DUPLICATE_KEYS: [&str; 2] = ["report-uri", "report-to"];

/// Why a policy list does not parse: upstream throws, and the CSP test grades it invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspError(pub String);

impl std::fmt::Display for CspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `parseCspMeta`: [`parse_csp`] without the directives a meta tag may not set.
pub fn parse_csp_meta(policies: &[String]) -> Result<Csp, CspError> {
    let mut csp = parse_csp(policies)?;
    for directive in DIRECTIVES_DISALLOWED_IN_META {
        csp.remove(directive);
    }
    Ok(csp)
}

#[derive(Debug, Clone)]
struct Source {
    source: String,
    index: usize,
    keep: bool,
}

/// `parseCsp`. A repeated directive within one policy is an error, except `report-uri` and
/// `report-to`, which are recorded under [`DUPLICATE_WARNINGS_KEY`].
pub fn parse_csp(policies: &[String]) -> Result<Csp, CspError> {
    let clean: Vec<String> = policies
        .iter()
        .map(|policy| js::trim(&policy.replace(['\r', '\n'], "")).to_string())
        .collect();
    if clean.is_empty() {
        return Ok(Csp::new());
    }
    if let Some(policy) = clean
        .iter()
        .find(|policy| policy.is_empty() || js::utf16_len(policy) < SHORTEST_DIRECTIVE_LENGTH)
    {
        return Err(CspError(format!("Invalid policy: {policy}")));
    }

    let mut csp: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    let mut duplicate_warnings: BTreeSet<String> = BTreeSet::new();

    for (policy_index, policy) in clean.iter().enumerate() {
        let mut seen: HashSet<String> = HashSet::new();
        for entry in policy.split(';') {
            let parts = js::split_whitespace(js::trim(entry));
            let Some((directive_entry, value_entries)) = parts.split_first() else {
                continue;
            };
            if directive_entry.is_empty() {
                continue;
            }
            let directive = directive_entry.to_lowercase();
            if !seen.insert(directive.clone()) {
                if ALLOWED_DUPLICATE_KEYS.contains(&directive.as_str()) {
                    duplicate_warnings.insert(directive.clone());
                } else {
                    return Err(CspError(format!(
                        "Duplicate directive {directive} in policy {policy_index}"
                    )));
                }
            }

            let keep = policy_index == 0;
            let values: Vec<Source> = if !value_entries.is_empty() {
                value_entries
                    .iter()
                    .map(|raw| Source {
                        source: js::trim(raw).to_lowercase(),
                        index: policy_index,
                        keep,
                    })
                    .collect()
            } else if directive.ends_with("-src") {
                vec![Source {
                    source: "'none'".to_string(),
                    index: policy_index,
                    keep,
                }]
            } else {
                Vec::new()
            };

            let mut combined = if policy_index == 0 {
                values
            } else {
                let mut earlier = csp.get(&directive).cloned().unwrap_or_default();
                earlier.extend(values);
                earlier
            };
            combined.sort_by(|a, b| collate(&a.source, &b.source));

            for i in 1..combined.len() {
                let (prev_source, prev_index) = (combined[i - 1].source.clone(), combined[i - 1].index);
                let source = &mut combined[i];
                if source.index == prev_index && source.source.starts_with(&prev_source) {
                    source.keep = false;
                }
                if source.index != prev_index && path_part_match(&prev_source, &source.source)? {
                    source.keep = true;
                }
            }

            let mut kept: Vec<Source> = combined.into_iter().filter(|source| source.keep).collect();
            if policy_index == 0 && policies.len() > 1 {
                for source in &mut kept {
                    source.keep = false;
                }
            }
            csp.insert(directive, kept);
        }
    }

    let mut final_csp: Csp = csp
        .into_iter()
        .map(|(directive, sources)| {
            let set: BTreeSet<String> = if sources.is_empty() {
                BTreeSet::from(["'none'".to_string()])
            } else {
                sources.into_iter().map(|source| source.source).collect()
            };
            (directive, set)
        })
        .collect();
    if !duplicate_warnings.is_empty() {
        final_csp.insert(DUPLICATE_WARNINGS_KEY.to_string(), duplicate_warnings);
    }
    Ok(final_csp)
}

/// `pathPartMatch`: whether source `b` lies within source `a`, compared per `/`-separated piece
/// after percent-decoding. A malformed escape is an error, as `decodeURIComponent` throws.
fn path_part_match(a: &str, b: &str) -> Result<bool, CspError> {
    if a.is_empty() || (a == "/" && b.is_empty()) {
        return Ok(true);
    }
    let exact_match = !a.ends_with('/');
    let mut pieces_a: Vec<&str> = a.split('/').collect();
    let pieces_b: Vec<&str> = b.split('/').collect();
    if pieces_a.len() > pieces_b.len() || (exact_match && pieces_a.len() != pieces_b.len()) {
        return Ok(false);
    }
    if !exact_match {
        pieces_a.pop();
    }
    for (piece_a, piece_b) in pieces_a.iter().zip(&pieces_b) {
        if decode_uri_component(piece_a)? != decode_uri_component(piece_b)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `decodeURIComponent`: `%XX` escapes decoded as UTF-8, anything malformed an error.
fn decode_uri_component(s: &str) -> Result<String, CspError> {
    let malformed = || CspError(format!("URI malformed: {s}"));
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or_else(malformed)?;
            bytes.push(u8::from_str_radix(hex, 16).map_err(|_| malformed())?);
            i += 3;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).map_err(|_| malformed())
}

/// The primary weight of `c` under `Intl.Collator("en")` (CLDR root, punctuation not ignorable),
/// which upstream sorts sources with. Control characters are ignorable (`None`); characters
/// outside ASCII sort after it by code point.
fn primary_weight(c: char) -> Option<u32> {
    const ORDER: &str = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz";
    if c.is_control() {
        return None;
    }
    let lower = c.to_ascii_lowercase();
    match ORDER.find(lower) {
        Some(position) if lower.is_ascii() => Some(position as u32),
        _ => Some(ORDER.len() as u32 + u32::from(c)),
    }
}

/// `Intl.Collator("en").compare`: primary weights first, then lowercase before uppercase.
fn collate(a: &str, b: &str) -> Ordering {
    let primary = |s: &str| s.chars().filter_map(primary_weight).collect::<Vec<u32>>();
    primary(a).cmp(&primary(b)).then_with(|| {
        let tertiary = |s: &str| {
            s.chars()
                .filter(|c| !c.is_control())
                .map(|c| c.is_ascii_uppercase())
                .collect::<Vec<bool>>()
        };
        tertiary(a).cmp(&tertiary(b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(policies: &[&str]) -> Vec<String> {
        policies.iter().map(|p| p.to_string()).collect()
    }

    fn csp(entries: &[(&str, &[&str])]) -> Csp {
        entries
            .iter()
            .map(|(directive, sources)| {
                (
                    directive.to_string(),
                    sources.iter().map(|s| s.to_string()).collect::<BTreeSet<String>>(),
                )
            })
            .collect()
    }

    /// Ported from test/csp-parser.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn should_parse_policy_correctly() {
            let cases: [(&[&str], Csp); 14] = [
                (&["default-src 'none'"], csp(&[("default-src", &["'none'"])])),
                (
                    &["default-src 'none'; script-src 'self' https://mozilla.org"],
                    csp(&[
                        ("default-src", &["'none'"]),
                        ("script-src", &["'self'", "https://mozilla.org"]),
                    ]),
                ),
                (
                    &[
                        "default-src 'none'; script-src 'self' https://mozilla.org",
                        "default-src 'none'; script-src 'self' https://mozilla.org",
                    ],
                    csp(&[
                        ("default-src", &["'none'"]),
                        ("script-src", &["'self'", "https://mozilla.org"]),
                    ]),
                ),
                (
                    &[
                        "default-src 'none'; script-src 'self' https://mozilla.org",
                        "default-src 'none'; script-src 'self' https://mozilla.org https://example.com",
                    ],
                    csp(&[
                        ("default-src", &["'none'"]),
                        ("script-src", &["'self'", "https://mozilla.org"]),
                    ]),
                ),
                (
                    &[
                        "default-src 'none'; script-src 'self' https://mozilla.org",
                        "default-src 'none'; script-src https://example.com 'self' https://mozilla.org",
                    ],
                    csp(&[
                        ("default-src", &["'none'"]),
                        ("script-src", &["'self'", "https://mozilla.org"]),
                    ]),
                ),
                (
                    &["default-src https://mozilla.org", "default-src https://mozilla.com"],
                    csp(&[("default-src", &["'none'"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org https://mozilla.net",
                        "default-src https://mozilla.com https://mozilla.io",
                    ],
                    csp(&[("default-src", &["'none'"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org https://mozilla.net https://mozilla.com https://mozilla.io",
                        "default-src https://mozilla.pizza https://mozilla.ninja https://mozilla.net https://mozilla.org",
                    ],
                    csp(&[("default-src", &["https://mozilla.net", "https://mozilla.org"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org https://mozilla.net https://mozilla.com https://mozilla.io",
                        "default-src https://mozilla.pizza https://mozilla.ninja https://mozilla.net https://mozilla.org",
                        "default-src https://mozilla.net https://mozilla.fox https://mozilla.fire https://mozilla.org",
                        "default-src https://mozilla.browser https://mozilla.web https://mozilla.net https://mozilla.org",
                    ],
                    csp(&[("default-src", &["https://mozilla.net", "https://mozilla.org"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org/fire",
                        "default-src https://mozilla.org/firefox/",
                    ],
                    csp(&[("default-src", &["'none'"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org/firefox/",
                        "default-src https://mozilla.org/firefox/download/",
                    ],
                    csp(&[("default-src", &["https://mozilla.org/firefox/download/"])]),
                ),
                (
                    &[
                        "default-src https://mozilla.org/firefox/download/",
                        "default-src https://mozilla.org/firefox/",
                    ],
                    csp(&[("default-src", &["https://mozilla.org/firefox/download/"])]),
                ),
                (
                    &["default-src http:", "default-src https:"],
                    csp(&[("default-src", &["'none'"])]),
                ),
                (
                    &["default-src http: http:", "default-src https: https:"],
                    csp(&[("default-src", &["'none'"])]),
                ),
            ];
            for (policies, expected) in cases {
                assert_eq!(parse_csp(&policy(policies)).unwrap(), expected, "{policies:?}");
            }
        }

        #[test]
        fn should_throw_error_for_invalid_policies() {
            for invalid in [
                "  ",
                "\r\n",
                "\r\n\r\n\r\n\r\n\r\n\r\n",
                "",
                "default-src 'none'; default-src 'none'",
                "default-src 'none'; img-src 'self'; default-src 'none'",
                "defa",
            ] {
                assert!(parse_csp(&policy(&[invalid])).is_err(), "{invalid:?}");
            }
        }

        #[test]
        fn should_parse_this_example_header_correctly() {
            let example = "default-src 'self' blob: https://*.cnn.com:* http://*.cnn.com:* *.cnn.io:* *.cnn.net:* *.turner.com:* *.turner.io:* *.ugdturner.com:* courageousstudio.com *.vgtf.net:*; script-src 'unsafe-eval' 'unsafe-inline' 'self' *; style-src 'unsafe-inline' 'self' blob: *; child-src 'self' blob: *; frame-src 'self' *; object-src 'self' *; img-src 'self' data: blob: *; media-src 'self' data: blob: *; font-src 'self' data: *; connect-src 'self' data: *; frame-ancestors 'self' https://*.cnn.com:* http://*.cnn.com https://*.cnn.io:* http://*.cnn.io:* *.turner.com:* courageousstudio.com;";
            assert!(!parse_csp(&policy(&[example])).unwrap().is_empty());
        }

        #[test]
        fn should_parse_a_policy_with_duplicate_report_uri_entries_and_report_those_duplicates() {
            let res = parse_csp(&policy(&[
                "report-uri https://www.dropbox.com/csp_log?policy_name=metaserver-whitelist ; report-uri https://www.dropbox.com/csp_log?policy_name=metaserver-dynamic",
            ]))
            .unwrap();
            assert!(res[DUPLICATE_WARNINGS_KEY].contains("report-uri"));
        }

        #[test]
        fn should_parse_a_policy_with_duplicate_report_to_entries_and_report_those_duplicates() {
            let res = parse_csp(&policy(&["report-to some_name ; report-to some_other_name"])).unwrap();
            assert!(res[DUPLICATE_WARNINGS_KEY].contains("report-to"));
        }
    }

    /// The later duplicate `report-uri` replaces the earlier in the first policy: what the code
    /// does, though upstream's comment says the first is kept.
    #[test]
    fn a_duplicate_report_uri_keeps_the_last_value() {
        let res = parse_csp(&policy(&["report-uri /a; report-uri /b"])).unwrap();
        assert_eq!(res["report-uri"], BTreeSet::from(["/b".to_string()]));
    }

    #[test]
    fn a_malformed_percent_escape_across_policies_is_an_error() {
        assert!(
            parse_csp(&policy(&[
                "default-src https://a.org/%zz/",
                "default-src https://a.org/%zz/x"
            ]))
            .is_err()
        );
    }

    /// `Intl.Collator("en")` order: punctuation, then digits, then letters, case second.
    #[test]
    fn collation_matches_icu_en() {
        let mut sources = vec![
            "https://ab.com",
            "*",
            "https://a.com/x",
            "data:",
            "'self'",
            "https://a-b.com",
            "https://a.com",
        ];
        sources.sort_by(|a, b| collate(a, b));
        assert_eq!(
            sources,
            vec![
                "'self'",
                "*",
                "data:",
                "https://a-b.com",
                "https://a.com",
                "https://a.com/x",
                "https://ab.com"
            ]
        );
        assert_eq!(collate("a", "A"), Ordering::Less);
    }
}
