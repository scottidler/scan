// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Part of scan's port of mdn/mdn-http-observatory at commit 2776308 (the per-session jar of
// src/retriever/session.js). The store rules mirror tough-cookie 5.1.2 (BSD-3-Clause, © 2015
// Salesforce.com, Inc.): `CookieJar.setCookie` and `getCookies`, `MemoryCookieStore`,
// `canonicalDomain`, `domainMatch`, `defaultPath`, `pathMatch`, `permuteDomain`,
// `getPublicSuffix` and `parseDate`, as http-cookie-agent 8.0.0 drives them (`setCookieSync`
// with `ignoreError: true`, `getCookiesSync` for the `Cookie` header).

//! One session's cookie jar. Every accepted cookie stays whatever its expiry (Phase 0c); an
//! expired one leaves only when a later request's cookie lookup matches it, as tough-cookie's
//! `getCookies` removes it then.

use super::cookie::Cookie;
use crate::scan::observatory::sri::RegistrableDomain;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// RFC 6761 names tough-cookie lets a cookie domain end in (`allowSpecialUseDomain`, default on).
const SPECIAL_USE_DOMAINS: [&str; 5] = ["local", "example", "invalid", "localhost", "test"];
/// The special-use names that are their own public suffix as a single label.
const SPECIAL_TREATMENT_DOMAINS: [&str; 2] = ["localhost", "invalid"];

/// One stored cookie with the times tough-cookie keeps beside it.
#[derive(Debug, Clone)]
struct Stored {
    cookie: Cookie,
    /// `lastAccessed`: what `Max-Age` counts from.
    last_accessed: SystemTime,
}

/// A session's jar, in creation order (`serializeSync` sorts by `creationIndex`; a replaced
/// cookie keeps its place).
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    stored: Vec<Stored>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every cookie in the jar, expired ones included, in creation order.
    pub fn cookies(&self) -> Vec<Cookie> {
        self.stored.iter().map(|s| s.cookie.clone()).collect()
    }

    /// `setCookieSync(header, url, { ignoreError: true })`: `false` when the cookie is rejected,
    /// silently, as http-cookie-agent ignores the error.
    pub fn set_cookie(&mut self, header: &str, url: &Url, domains: &dyn RegistrableDomain, now: SystemTime) -> bool {
        let Some(host) = url.host_str().and_then(canonical_domain) else {
            log::debug!("[observatory::jar] set_cookie: url={} has no host: rejected", url);
            return false;
        };
        let Some(mut cookie) = Cookie::parse(header) else {
            log::debug!("[observatory::jar] set_cookie: host={} unparseable: rejected", host);
            return false;
        };

        if let Some(domain) = cookie.domain.clone() {
            let cdomain = canonical_domain(&domain).unwrap_or_default();
            if !has_public_suffix_room(&cdomain, domains) && domain.parse::<Ipv6Addr>().is_err() {
                log::debug!(
                    "[observatory::jar] set_cookie: key={} domain={} is a public suffix: rejected",
                    cookie.key,
                    domain
                );
                return false;
            }
            if !domain_match(&host, &cdomain) {
                log::debug!(
                    "[observatory::jar] set_cookie: key={} domain={} not in host {}: rejected",
                    cookie.key,
                    cdomain,
                    host
                );
                return false;
            }
            cookie.domain = Some(cdomain);
            if cookie.host_only.is_none() {
                cookie.host_only = Some(false);
            }
        } else {
            cookie.host_only = Some(true);
            cookie.domain = Some(host.clone());
        }

        if cookie.path.as_deref().is_none_or(|p| !p.starts_with('/')) {
            cookie.path = Some(default_path(url.path()));
        }

        if !secure_prefix_met(&cookie) || !host_prefix_met(&cookie) {
            log::debug!(
                "[observatory::jar] set_cookie: key={} prefix conditions unmet: rejected",
                cookie.key
            );
            return false;
        }

        let same =
            |s: &Stored| s.cookie.domain == cookie.domain && s.cookie.path == cookie.path && s.cookie.key == cookie.key;
        match self.stored.iter_mut().find(|s| same(s)) {
            Some(old) => {
                log::trace!("[observatory::jar] set_cookie: key={} replaced", cookie.key);
                *old = Stored {
                    cookie,
                    last_accessed: now,
                };
            }
            None => {
                log::trace!("[observatory::jar] set_cookie: key={} stored", cookie.key);
                self.stored.push(Stored {
                    cookie,
                    last_accessed: now,
                });
            }
        }
        true
    }

    /// The `Cookie` header http-cookie-agent sends to `url` (`getCookiesSync` then one value per
    /// key), `None` when no cookie matches. Like `getCookies`, it drops an expired cookie that
    /// matches the request from the jar.
    pub fn cookie_header(&mut self, url: &Url, domains: &dyn RegistrableDomain, now: SystemTime) -> Option<String> {
        let host = url.host_str().and_then(canonical_domain)?;
        let path = if url.path().is_empty() { "/" } else { url.path() };
        let secure = matches!(url.scheme(), "https" | "wss");
        let permutations = permute_domain(&host, domains).unwrap_or_else(|| vec![host.clone()]);

        let mut matched: Vec<usize> = Vec::new();
        let mut expired: Vec<usize> = Vec::new();
        for (i, stored) in self.stored.iter().enumerate() {
            let c = &stored.cookie;
            let (Some(domain), Some(cookie_path)) = (c.domain.as_deref(), c.path.as_deref()) else {
                continue;
            };
            if !permutations.iter().any(|p| p == domain) || !path_match(path, cookie_path) {
                continue;
            }
            let domain_ok = if c.host_only == Some(true) {
                domain == host
            } else {
                domain_match(&host, domain)
            };
            if !domain_ok || (c.secure && !secure) {
                continue;
            }
            if expiry_time(stored).is_some_and(|expiry| expiry <= now) {
                expired.push(i);
                continue;
            }
            matched.push(i);
        }

        // `cookieCompare`: longer paths first, then creation order.
        matched.sort_by_key(|&i| std::cmp::Reverse(self.stored[i].cookie.path.as_deref().map_or(0, str::len)));
        let mut pairs: Vec<(String, String)> = Vec::new();
        for &i in &matched {
            self.stored[i].last_accessed = now;
            let c = &self.stored[i].cookie;
            match pairs.iter_mut().find(|(key, _)| *key == c.key) {
                Some(pair) => pair.1 = cookie_string(c),
                None => pairs.push((c.key.clone(), cookie_string(c))),
            }
        }
        for i in expired.into_iter().rev() {
            log::trace!(
                "[observatory::jar] cookie_header: key={} expired: removed",
                self.stored[i].cookie.key
            );
            self.stored.remove(i);
        }
        log::trace!("[observatory::jar] cookie_header: url={} cookies={}", url, pairs.len());
        if pairs.is_empty() {
            None
        } else {
            Some(pairs.into_iter().map(|(_, s)| s).collect::<Vec<_>>().join("; "))
        }
    }
}

/// `cookieString()`: `key=value`, or the value alone for an empty key.
fn cookie_string(cookie: &Cookie) -> String {
    if cookie.key.is_empty() {
        cookie.value.clone()
    } else {
        format!("{}={}", cookie.key, cookie.value)
    }
}

/// `expiryTime()`: `Max-Age` counts from the last access and `<= 0` is already expired; else the
/// parsed `Expires`; `None` never expires.
fn expiry_time(stored: &Stored) -> Option<SystemTime> {
    if let Some(max_age) = stored.cookie.max_age {
        if max_age.is_nan() || max_age <= 0.0 {
            return Some(UNIX_EPOCH);
        }
        return Some(stored.last_accessed + Duration::from_secs_f64(max_age.min(1e12)));
    }
    stored.cookie.expires
}

/// `canonicalDomain`: trimmed, a leading dot dropped, lowercased (punycoded when non-ASCII).
fn canonical_domain(name: &str) -> Option<String> {
    let trimmed = crate::scan::observatory::js::trim(name);
    let name = trimmed.strip_prefix('.').unwrap_or(trimmed);
    let unbracketed = name.trim_start_matches('[').trim_end_matches(']');
    if unbracketed.parse::<Ipv6Addr>().is_ok() {
        return Some(unbracketed.to_lowercase());
    }
    if name.is_ascii() {
        Some(name.to_lowercase())
    } else {
        idna::domain_to_ascii(name).ok()
    }
}

/// `domainMatch(host, cookieDomain, false)`: equal, or the cookie domain is a dot-aligned suffix of
/// a host that is not an IP address.
fn domain_match(host: &str, cookie_domain: &str) -> bool {
    if host == cookie_domain {
        return true;
    }
    let Some(idx) = host.rfind(cookie_domain) else {
        return false;
    };
    idx > 0
        && host.len() == cookie_domain.len() + idx
        && host.as_bytes()[idx - 1] == b'.'
        && host.parse::<IpAddr>().is_err()
}

/// `getPublicSuffix(domain, { allowSpecialUseDomain: true, ignoreError: true }) != null`: the
/// domain sits below a public suffix, so a cookie may be set on it.
fn has_public_suffix_room(domain: &str, domains: &dyn RegistrableDomain) -> bool {
    public_suffix(domain, domains).is_some()
}

/// tough-cookie's `getPublicSuffix`, which names the registrable domain (tldts `getDomain`, ICANN
/// and private sections), with RFC 6761 special-use names allowed.
fn public_suffix(domain: &str, domains: &dyn RegistrableDomain) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    let tld = *parts.last()?;
    if SPECIAL_USE_DOMAINS.contains(&tld) {
        if parts.len() > 1 {
            return Some(format!("{}.{}", parts[parts.len() - 2], tld));
        } else if SPECIAL_TREATMENT_DOMAINS.contains(&tld) {
            return Some(tld.to_string());
        }
    }
    domains.registrable_domain(domain)
}

/// `permuteDomain`: the registrable domain and every name between it and `domain`.
fn permute_domain(domain: &str, domains: &dyn RegistrableDomain) -> Option<Vec<String>> {
    let suffix = public_suffix(domain, domains)?;
    if suffix == domain {
        return Some(vec![domain.to_string()]);
    }
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let prefix = domain.get(..domain.len().checked_sub(suffix.len() + 1)?)?;
    let mut current = suffix.clone();
    let mut permutations = vec![current.clone()];
    for part in prefix.split('.').rev() {
        current = format!("{part}.{current}");
        permutations.push(current.clone());
    }
    Some(permutations)
}

/// `defaultPath`: the request path up to, not including, its last `/`.
fn default_path(path: &str) -> String {
    if !path.starts_with('/') || path == "/" {
        return "/".to_string();
    }
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// `pathMatch`.
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/') || request_path[cookie_path.len()..].starts_with('/'))
}

/// `__Secure-` cookies need `Secure`.
fn secure_prefix_met(cookie: &Cookie) -> bool {
    !cookie.key.starts_with("__Secure-") || cookie.secure
}

/// `__Host-` cookies need `Secure`, no `Domain` and path `/`.
fn host_prefix_met(cookie: &Cookie) -> bool {
    !cookie.key.starts_with("__Host-")
        || (cookie.secure && cookie.host_only == Some(true) && cookie.path.as_deref() == Some("/"))
}

/// `parseDate`: RFC 6265 §5.1.1 cookie dates; `None` when a field is missing or out of range.
pub fn parse_date(date: &str) -> Option<SystemTime> {
    let is_delim = |c: char| matches!(c as u32, 0x09 | 0x20..=0x2F | 0x3B..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E);
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for token in date.split(is_delim).map(crate::scan::observatory::js::trim) {
        if token.is_empty() {
            continue;
        }
        if time.is_none()
            && let Some(t) = parse_time(token)
        {
            time = Some(t);
            continue;
        }
        if day.is_none()
            && let Some(d) = parse_digits(token, 1, 2, true)
        {
            day = Some(d);
            continue;
        }
        if month.is_none()
            && let Some(m) = parse_month(token)
        {
            month = Some(m);
            continue;
        }
        if year.is_none()
            && let Some(y) = parse_digits(token, 2, 4, true)
        {
            year = Some(match y {
                70..=99 => y + 1900,
                0..=69 => y + 2000,
                _ => y,
            });
        }
    }
    let ((hour, minute, second), day, month, year) = (time?, day?, month?, year?);
    if !(1..=31).contains(&day) || year < 1601 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // `Date.UTC` rolls an out-of-range day into the next month, as chrono's day arithmetic does.
    let first = chrono::NaiveDate::from_ymd_opt(year as i32, month + 1, 1)?;
    let date = first.checked_add_days(chrono::Days::new(u64::from(day - 1)))?;
    let seconds = date.and_hms_opt(hour, minute, second)?.and_utc().timestamp();
    if seconds >= 0 {
        Some(UNIX_EPOCH + Duration::from_secs(seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
}

/// `parseDigits`: `min..=max` leading ASCII digits, trailing text allowed only with `trailing_ok`.
fn parse_digits(token: &str, min: usize, max: usize, trailing_ok: bool) -> Option<u32> {
    let count = token.bytes().take_while(u8::is_ascii_digit).count();
    if count < min || count > max || (!trailing_ok && count != token.len()) {
        return None;
    }
    token[..count].parse().ok()
}

/// `parseTime`: `h:m:s`, one or two digits each, trailing text allowed after the seconds.
fn parse_time(token: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parse_digits(parts[0], 1, 2, false)?,
        parse_digits(parts[1], 1, 2, false)?,
        parse_digits(parts[2], 1, 2, true)?,
    ))
}

/// `parseMonth`: the first three letters, case-insensitively; 0-based.
fn parse_month(token: &str) -> Option<u32> {
    let prefix: String = token.chars().take(3).collect::<String>().to_lowercase();
    [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ]
    .iter()
    .position(|m| *m == prefix)
    .map(|i| i as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use publicsuffix::List;

    /// ICANN and private sections, as tldts reads them for tough-cookie.
    fn domains() -> List {
        "// ===BEGIN ICANN DOMAINS===\ncom\norg\nco.uk\nuk\n// ===END ICANN DOMAINS===\n\
         // ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
            .parse::<List>()
            .unwrap()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn jar_with(headers: &[&str], at: &str) -> CookieJar {
        let mut jar = CookieJar::new();
        for header in headers {
            jar.set_cookie(header, &url(at), &domains(), SystemTime::now());
        }
        jar
    }

    fn keys(jar: &CookieJar) -> Vec<String> {
        jar.cookies().into_iter().map(|c| c.key).collect()
    }

    /// Phase 0c (ii): expired cookies are stored; a later one with the same name, domain and path
    /// replaces the first in place.
    #[test]
    fn expired_cookies_are_kept_and_replacement_keeps_the_place() {
        let jar = jar_with(
            &[
                "deleted-later=1",
                "expired-1970=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                "maxage-zero=1; Max-Age=0",
                "maxage-negative=1; Max-Age=-1",
                "deleted-later=; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            ],
            "http://cookie.test.localhost/final",
        );
        assert_eq!(
            keys(&jar),
            ["deleted-later", "expired-1970", "maxage-zero", "maxage-negative"]
        );
        assert_eq!(jar.cookies()[0].value, "");
    }

    /// Phase 0c (iii): a cookie for another domain is dropped; a parent domain, a special-use
    /// single label and the host itself are kept with `hostOnly` false.
    #[test]
    fn cross_domain_cookies_are_rejected_and_parent_domains_kept() {
        let jar = jar_with(
            &[
                "xdomain=1; Domain=example.com",
                "xdomain-dot=1; Domain=.example.com",
                "parent-domain=1; Domain=test.localhost",
                "tld-domain=1; Domain=localhost",
                "host-domain=1; Domain=cookie.test.localhost",
                "plain=1",
            ],
            "http://cookie.test.localhost/",
        );
        let cookies = jar.cookies();
        let summary: Vec<(&str, &str, Option<bool>)> = cookies
            .iter()
            .map(|c| (c.key.as_str(), c.domain.as_deref().unwrap(), c.host_only))
            .collect();
        assert_eq!(
            summary,
            [
                ("parent-domain", "test.localhost", Some(false)),
                ("tld-domain", "localhost", Some(false)),
                ("host-domain", "cookie.test.localhost", Some(false)),
                ("plain", "cookie.test.localhost", Some(true)),
            ]
        );
    }

    /// A public suffix (ICANN or private) as `Domain` is rejected.
    #[test]
    fn public_suffix_domains_are_rejected() {
        let jar = jar_with(
            &[
                "icann=1; Domain=com",
                "private=1; Domain=github.io",
                "ok=1; Domain=user.github.io",
            ],
            "https://a.user.github.io/",
        );
        assert_eq!(keys(&jar), ["ok"]);
    }

    /// Phase 0c: `Secure` and the prefixes are kept over plain http; a prefix whose conditions
    /// fail is dropped.
    #[test]
    fn prefixes_are_checked_but_secure_over_http_is_kept() {
        let jar = jar_with(
            &[
                "secure-over-http=1; Secure",
                "__Secure-prefixed=1; Secure",
                "__Host-prefixed=1; Secure",
                "__Secure-no-secure=1",
                "__Host-with-domain=1; Secure; Domain=cookie.test.localhost",
                "__Host-deep-path=1; Secure; Path=/a",
            ],
            "http://cookie.test.localhost/final",
        );
        assert_eq!(keys(&jar), ["secure-over-http", "__Secure-prefixed", "__Host-prefixed"]);
    }

    #[test]
    fn default_path_is_the_directory_of_the_request() {
        let jar = jar_with(&["a=1", "b=1; Path=x", "c=1; Path=/c"], "http://h.example.com/dir/page");
        let paths: Vec<String> = jar.cookies().into_iter().map(|c| c.path.unwrap()).collect();
        assert_eq!(paths, ["/dir", "/dir", "/c"]);
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path("/page"), "/");
        assert_eq!(default_path(""), "/");
    }

    /// The `Cookie` header: domain, path and `Secure` matching, longest path first, and an expired
    /// match removed from the jar.
    #[test]
    fn cookie_header_matches_and_drops_expired_matches() {
        let mut jar = jar_with(
            &[
                "root=1",
                "deep=1; Path=/a",
                "secure=1; Secure",
                "gone=1; Max-Age=0",
                "elsewhere=1; Path=/b; Max-Age=0",
            ],
            "https://www.example.com/",
        );
        let now = SystemTime::now();
        assert_eq!(
            jar.cookie_header(&url("http://www.example.com/a/x"), &domains(), now)
                .as_deref(),
            Some("deep=1; root=1")
        );
        assert_eq!(keys(&jar), ["root", "deep", "secure", "elsewhere"]);
        assert_eq!(
            jar.cookie_header(&url("https://www.example.com/"), &domains(), now)
                .as_deref(),
            Some("root=1; secure=1")
        );
        assert_eq!(
            jar.cookie_header(&url("https://other.example.com/"), &domains(), now),
            None
        );
    }

    /// `Expires=<past>; Expires=garbage` is expired, as in tough-cookie: the garbage date is
    /// ignored, so the past one stands and a later matching lookup drops the cookie.
    #[test]
    fn a_past_expires_followed_by_garbage_is_expired_at_lookup() {
        let mut jar = jar_with(
            &[
                "stale=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Expires=garbage",
                "fresh=1; Expires=garbage",
            ],
            "https://www.example.com/",
        );
        assert_eq!(keys(&jar), ["stale", "fresh"], "both are stored (Phase 0c)");
        assert_eq!(
            jar.cookie_header(&url("https://www.example.com/"), &domains(), SystemTime::now())
                .as_deref(),
            Some("fresh=1")
        );
        assert_eq!(keys(&jar), ["fresh"]);
    }

    #[test]
    fn parent_domain_cookie_goes_to_subdomains_host_only_does_not() {
        let mut jar = jar_with(&["wide=1; Domain=example.com", "narrow=1"], "https://example.com/");
        let now = SystemTime::now();
        assert_eq!(
            jar.cookie_header(&url("https://www.example.com/"), &domains(), now)
                .as_deref(),
            Some("wide=1")
        );
        assert_eq!(
            jar.cookie_header(&url("https://example.com/"), &domains(), now)
                .as_deref(),
            Some("wide=1; narrow=1")
        );
    }

    #[test]
    fn parse_date_reads_rfc6265_dates_and_rejects_bad_ones() {
        let at = |s| parse_date(s).map(|t| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(-1));
        assert_eq!(at("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(at("Wed, 29 Oct 2025 00:00:00 GMT"), Some(1_761_696_000));
        assert_eq!(at("Wed, 29-Oct-25 00:00:00 GMT"), Some(1_761_696_000));
        assert_eq!(at("29 October 2025 00:00:00"), Some(1_761_696_000));
        assert_eq!(at("Wed, 29 Oct 2025"), None);
        assert_eq!(at("Wed, 32 Oct 2025 00:00:00 GMT"), None);
        assert_eq!(at("Wed, 29 Oct 1500 00:00:00 GMT"), None);
        assert_eq!(at(""), None);
    }

    #[test]
    fn domain_match_needs_a_dot_aligned_suffix_of_a_name() {
        assert!(domain_match("www.example.com", "example.com"));
        assert!(domain_match("example.com", "example.com"));
        assert!(!domain_match("badexample.com", "example.com"));
        assert!(!domain_match("example.com", "www.example.com"));
        assert!(!domain_match("1.2.3.4", "2.3.4"));
    }
}
