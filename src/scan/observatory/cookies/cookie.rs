// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Part of scan's port of mdn/mdn-http-observatory at commit 2776308. `Cookie::parse` mirrors
// `Cookie.parse` of tough-cookie 5.1.2 (BSD-3-Clause, © 2015 Salesforce.com, Inc.), the cookie
// parser behind upstream's jar.

//! One cookie as the jar stores it, and the `Set-Cookie` attribute parser that fills it.

use crate::scan::observatory::js;

/// A cookie's `SameSite`: only these three values are kept; anything else leaves it unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "strict",
            SameSite::Lax => "lax",
            SameSite::None => "none",
        }
    }
}

/// One cookie in the jar.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cookie {
    pub key: String,
    pub value: String,
    /// The raw `Expires` attribute. No analyzer reads the date, and the jar keeps a cookie whatever
    /// its expiry (Phase 0c), so it is not parsed.
    pub expires: Option<String>,
    /// `Max-Age` in seconds, a JS number as tough-cookie stores it.
    pub max_age: Option<f64>,
    /// Lowercased, the leading dot dropped.
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    /// Set by the jar: `Some(true)` when the cookie had no `Domain`.
    pub host_only: Option<bool>,
}

/// tough-cookie's `CONTROL_CHARS`: a name or value holding one is rejected.
fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| (c as u32) <= 0x1F)
}

/// tough-cookie's `trimTerminator`: `\n`, `\r` and `\0` end the pair.
fn trim_terminator(s: &str) -> &str {
    ['\n', '\r', '\0']
        .iter()
        .fold(s, |s, t| s.find(*t).map_or(s, |i| &s[..i]))
}

impl Cookie {
    /// `Cookie.parse(header)` in strict (non-loose) mode: `None` when the name-value pair is
    /// missing a name or holds a control character.
    pub fn parse(header: &str) -> Option<Cookie> {
        let header = js::trim(header);
        if header.is_empty() {
            return None;
        }
        let (pair, attributes) = match header.find(';') {
            Some(i) => (&header[..i], Some(&header[i + 1..])),
            None => (header, None),
        };
        let pair = trim_terminator(pair);
        let eq = pair.find('=').filter(|&i| i > 0)?;
        let key = js::trim(&pair[..eq]).to_string();
        let value = js::trim(&pair[eq + 1..]).to_string();
        if has_control_chars(&key) || has_control_chars(&value) {
            return None;
        }
        let mut cookie = Cookie {
            key,
            value,
            ..Cookie::default()
        };
        let Some(attributes) = attributes.map(js::trim).filter(|a| !a.is_empty()) else {
            return Some(cookie);
        };
        for av in attributes.split(';').map(js::trim).filter(|av| !av.is_empty()) {
            let (name, value) = match av.find('=') {
                Some(i) => (&av[..i], Some(&av[i + 1..])),
                None => (av, None),
            };
            let value = value.filter(|v| !v.is_empty()).map(js::trim);
            match js::trim(name).to_lowercase().as_str() {
                "expires" => {
                    if let Some(value) = value.filter(|v| !v.is_empty()) {
                        cookie.expires = Some(value.to_string());
                    }
                }
                "max-age" => {
                    if let Some(value) = value.filter(|v| is_delta_seconds(v)) {
                        cookie.max_age = Some(js::parse_int(value));
                    }
                }
                "domain" => {
                    if let Some(value) = value {
                        let domain = js::trim(value);
                        let domain = domain.strip_prefix('.').unwrap_or(domain);
                        if !domain.is_empty() {
                            cookie.domain = Some(domain.to_lowercase());
                        }
                    }
                }
                "path" => cookie.path = value.filter(|v| v.starts_with('/')).map(str::to_string),
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                "samesite" => {
                    cookie.same_site = match value.map(str::to_lowercase).as_deref() {
                        Some("strict") => Some(SameSite::Strict),
                        Some("lax") => Some(SameSite::Lax),
                        Some("none") => Some(SameSite::None),
                        _ => None,
                    }
                }
                _ => {}
            }
        }
        Some(cookie)
    }
}

/// `/^-?[0-9]+$/`.
fn is_delta_seconds(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_attributes_the_analyzer_reads() {
        let cookie =
            Cookie::parse("SESSIONID=bar; Domain=.Mozilla.org; Path=/; Secure; HttpOnly; SameSite=Lax").unwrap();
        assert_eq!(cookie.key, "SESSIONID");
        assert_eq!(cookie.value, "bar");
        assert_eq!(cookie.domain.as_deref(), Some("mozilla.org"));
        assert_eq!(cookie.path.as_deref(), Some("/"));
        assert!(cookie.secure && cookie.http_only);
        assert_eq!(cookie.same_site, Some(SameSite::Lax));
    }

    /// An unknown or empty `SameSite` leaves it unset; a later attribute overrides an earlier one.
    #[test]
    fn samesite_keeps_only_strict_lax_and_none() {
        for (header, expected) in [
            ("a=1; SameSite=", None),
            ("a=1; SameSite=True", None),
            ("a=1; SameSite", None),
            ("a=1; samesite=NONE", Some(SameSite::None)),
            ("a=1; SameSite=Strict; SameSite=Invalid", None),
        ] {
            assert_eq!(Cookie::parse(header).unwrap().same_site, expected, "{header}");
        }
    }

    #[test]
    fn a_pair_without_a_name_or_with_control_characters_is_rejected() {
        assert!(Cookie::parse("=bar").is_none());
        assert!(Cookie::parse("bar").is_none());
        assert!(Cookie::parse("a=b\u{1}c").is_none());
        assert!(Cookie::parse("").is_none());
        assert_eq!(Cookie::parse("a=b\nc=d").unwrap().value, "b");
    }

    #[test]
    fn max_age_must_be_an_integer() {
        assert_eq!(Cookie::parse("a=1; Max-Age=-1").unwrap().max_age, Some(-1.0));
        assert_eq!(Cookie::parse("a=1; Max-Age=1.5").unwrap().max_age, None);
        assert_eq!(Cookie::parse("a=1; Path=x").unwrap().path, None);
    }
}
