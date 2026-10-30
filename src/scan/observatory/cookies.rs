// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/analyzer/tests/cookies.js,
// test/cookies.test.js).

//! The `cookies` test: every cookie in the `auto` session's jar, expired ones included, judged on
//! `Secure`, `HttpOnly` and `SameSite`; the worst finding wins.

mod cookie;
mod jar;

pub use cookie::{Cookie, SameSite};
pub use jar::{CookieJar, parse_date};

use super::headers::{SET_COOKIE, get_http_headers};
use super::hsts::{HstsPreload, strict_transport_security_test};
use super::js;
use super::only_if_worse;
use super::retriever::Retrieval;
use super::types::Expectation;
use std::collections::BTreeMap;

/// Cookies upstream ignores (mozilla/http-observatory#282).
const COOKIES_TO_DELETE: [&str; 1] = ["heroku-session-affinity"];

/// Results from best to worst, for `onlyIfWorse`.
const GOODNESS: [Expectation; 7] = [
    Expectation::CookiesWithoutSecureFlagButProtectedByHsts,
    Expectation::CookiesWithoutSecureFlag,
    Expectation::CookiesSessionWithoutSecureFlagButProtectedByHsts,
    Expectation::CookiesSamesiteFlagInvalid,
    Expectation::CookiesAnticsrfWithoutSamesiteFlag,
    Expectation::CookiesSessionWithoutHttponlyFlag,
    Expectation::CookiesSessionWithoutSecureFlag,
];

/// One cookie as the test reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct CookieData {
    pub domain: Option<String>,
    pub expires: Option<std::time::SystemTime>,
    pub http_only: bool,
    pub max_age: Option<f64>,
    pub path: Option<String>,
    pub same_site: Option<SameSite>,
    pub secure: bool,
}

/// What the `cookies` test found.
#[derive(Debug, Clone, PartialEq)]
pub struct CookiesOutput {
    pub result: Expectation,
    pub pass: bool,
    pub data: Option<BTreeMap<String, CookieData>>,
    /// Whether every cookie set `SameSite`, when there were cookies.
    pub same_site: bool,
}

/// `containsInvalidSameSiteCookie`: a raw `Set-Cookie` with a `SameSite` that is empty or not
/// `lax`/`strict`/`none`.
fn contains_invalid_same_site(header: &str) -> bool {
    js::trim(header).split(';').any(|part| {
        let mut split = js::trim(part).split('=');
        let key = split.next().unwrap_or_default();
        if js::trim(key).to_lowercase() != "samesite" {
            return false;
        }
        match split.next() {
            Some(value) if !value.is_empty() => {
                !["lax", "strict", "none"].contains(&js::trim(value).to_lowercase().as_str())
            }
            _ => true,
        }
    })
}

/// `cookiesTest`.
pub fn cookies_test(retrieval: &Retrieval, preload: &HstsPreload) -> CookiesOutput {
    let expectation = Expectation::CookiesSecureWithHttponlySessions;
    let hsts = strict_transport_security_test(retrieval, preload).pass;
    let mut result: Option<Expectation> = None;
    let mut data = None;
    let mut same_site = false;

    for raw in get_http_headers(retrieval.auto_response(), SET_COOKIE) {
        if contains_invalid_same_site(raw) {
            result = Some(only_if_worse(
                Expectation::CookiesSamesiteFlagInvalid,
                result,
                &GOODNESS,
            ));
        }
    }

    let cookies: Vec<&Cookie> = retrieval
        .cookies
        .iter()
        .filter(|c| !c.key.is_empty() && !COOKIES_TO_DELETE.contains(&c.key.as_str()))
        .collect();

    if cookies.is_empty() {
        result = Some(Expectation::CookiesNotFound);
    } else {
        let mut missing_same_site = false;
        let worse = |finding: Expectation, result: &mut Option<Expectation>| {
            *result = Some(only_if_worse(finding, *result, &GOODNESS));
        };
        for cookie in &cookies {
            let key = cookie.key.to_lowercase();
            let session_id = key.contains("login") || key.contains("sess");
            let anticsrf = key.contains("csrf");

            if !cookie.secure && cookie.same_site == Some(SameSite::None) {
                worse(Expectation::CookiesSamesiteFlagInvalid, &mut result);
            }
            if !cookie.secure && hsts {
                worse(Expectation::CookiesWithoutSecureFlagButProtectedByHsts, &mut result);
            } else if !cookie.secure {
                worse(Expectation::CookiesWithoutSecureFlag, &mut result);
            }
            if anticsrf && cookie.same_site.is_none() {
                worse(Expectation::CookiesAnticsrfWithoutSamesiteFlag, &mut result);
            }
            if session_id && !cookie.secure && hsts {
                worse(
                    Expectation::CookiesSessionWithoutSecureFlagButProtectedByHsts,
                    &mut result,
                );
            } else if session_id && !cookie.secure {
                worse(Expectation::CookiesSessionWithoutSecureFlag, &mut result);
            }
            if session_id && !cookie.http_only {
                worse(Expectation::CookiesSessionWithoutHttponlyFlag, &mut result);
            }
            if cookie.same_site.is_none() {
                missing_same_site = true;
            }
        }
        if result.is_none() {
            same_site = !missing_same_site;
            result = Some(if missing_same_site {
                Expectation::CookiesSecureWithHttponlySessions
            } else {
                Expectation::CookiesSecureWithHttponlySessionsAndSamesite
            });
        }
        // Upstream measures `allCookies.join("")`, where each cookie object reads `[object Object]`.
        if cookies.len() * "[object Object]".len() < 32_768 {
            data = Some(
                cookies
                    .iter()
                    .map(|c| {
                        let item = CookieData {
                            domain: c.domain.clone(),
                            expires: c.expires,
                            http_only: c.http_only,
                            max_age: c.max_age,
                            path: c.path.clone(),
                            same_site: c.same_site,
                            secure: c.secure,
                        };
                        (c.key.clone(), item)
                    })
                    .collect(),
            );
        }
    }

    let result = result.unwrap_or(Expectation::CookiesNotFound);
    let pass = [
        Expectation::CookiesNotFound,
        Expectation::CookiesSecureWithHttponlySessionsAndSamesite,
        expectation,
    ]
    .contains(&result);
    log::debug!(
        "[observatory::cookies] cookies_test: cookies={} hsts={} result={}",
        cookies.len(),
        hsts,
        result
    );
    CookiesOutput {
        result,
        pass,
        data,
        same_site,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::headers::HeaderValue;
    use crate::scan::observatory::helpers::{auto_headers, empty_requests, https_headers, no_preload};

    /// upstream's `setCookieStrings`: the raw headers on the `auto` response, each parsed cookie
    /// stored as the jar stores a `Domain=mozilla.org` cookie set from `https://mozilla.org/`
    /// (host-only false, replacing one with the same key, domain and path).
    fn set_cookie_strings(reqs: &mut Retrieval, cookie_strings: &[&str]) {
        auto_headers(reqs).set(
            "Set-Cookie",
            HeaderValue::List(cookie_strings.iter().map(|s| s.to_string()).collect()),
        );
        for cookie_string in cookie_strings {
            let mut cookie = Cookie::parse(cookie_string).expect("a test cookie parses");
            cookie.host_only = Some(false);
            reqs.cookies
                .retain(|c| !(c.key == cookie.key && c.domain == cookie.domain && c.path == cookie.path));
            reqs.cookies.push(cookie);
        }
    }

    fn data_same_site(res: &CookiesOutput) -> Vec<(String, Option<SameSite>)> {
        res.data
            .as_ref()
            .expect("cookie data")
            .iter()
            .map(|(key, c)| (key.clone(), c.same_site))
            .collect()
    }

    /// Ported from test/cookies.test.js, one test per upstream `it(`.
    mod upstream {
        use super::*;

        #[test]
        fn detects_no_cookies_found() {
            let reqs = empty_requests(None);
            let res = cookies_test(&reqs, &no_preload());
            assert!(res.pass);
            assert_eq!(res.result.as_str(), "cookies-not-found");
        }

        #[test]
        fn checks_secure_with_httponly_sessions() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &[
                    "SESSIONID=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly",
                    "foo=bar; Domain=mozilla.org; Secure; Path=/",
                    "heroku-session-affinity=bar; Domain=mozilla.org; Path=/",
                ],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesSecureWithHttponlySessions);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_secure_with_httponly_sessions_and_samesite() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &[
                    "SESSIONID_SAMESITE_STRICT=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=Strict",
                    "SESSIONID_SAMESITE_LAX=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "SESSIONID_SAMESITE_NONE=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=None",
                ],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(
                data_same_site(&res),
                vec![
                    ("SESSIONID_SAMESITE_LAX".to_string(), Some(SameSite::Lax)),
                    ("SESSIONID_SAMESITE_NONE".to_string(), Some(SameSite::None)),
                    ("SESSIONID_SAMESITE_STRICT".to_string(), Some(SameSite::Strict)),
                ]
            );
            assert!(res.pass);
            assert!(res.same_site);
        }

        #[test]
        fn checks_secure_with_httponly_sessions_and_samesite_not_awarded_if_not_all_cookies_samesite() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &[
                    "SESSIONID_SAMESITE_STRICT=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=Strict",
                    "SESSIONID_SAMESITE_NO_SAMESITE=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly",
                    "SESSIONID_SAMESITE_LAX=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=Lax",
                    "SESSIONID_SAMESITE_NONE=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=None",
                ],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(
                data_same_site(&res),
                vec![
                    ("SESSIONID_SAMESITE_LAX".to_string(), Some(SameSite::Lax)),
                    ("SESSIONID_SAMESITE_NONE".to_string(), Some(SameSite::None)),
                    ("SESSIONID_SAMESITE_NO_SAMESITE".to_string(), None),
                    ("SESSIONID_SAMESITE_STRICT".to_string(), Some(SameSite::Strict)),
                ]
            );
            assert!(res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_anticsrf_without_samesite() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &["CSRFTOKEN=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly"],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesAnticsrfWithoutSamesiteFlag);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_samesite_invalid_empty() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &["SESSIONID=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite="],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesSamesiteFlagInvalid);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_samesite_invalid_true() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &["SESSIONID=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=True"],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesSamesiteFlagInvalid);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_samesite_invalid() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(
                &mut reqs,
                &["SESSIONID=bar; Domain=mozilla.org; Path=/; Secure; HttpOnly; SameSite=Invalid"],
            );
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesSamesiteFlagInvalid);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_regular_cookie_no_secure_but_hsts() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(&mut reqs, &["foo=bar; Domain=mozilla.org; Path=/"]);
            https_headers(&mut reqs).set_single("strict-transport-security", "max-age=15768000");
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesWithoutSecureFlagButProtectedByHsts);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_session_cookie_no_secure_but_hsts() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(&mut reqs, &["SESSIONID=bar; Domain=mozilla.org; Path=/; HttpOnly"]);
            https_headers(&mut reqs).set_single("strict-transport-security", "max-age=15768000");
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(
                res.result,
                Expectation::CookiesSessionWithoutSecureFlagButProtectedByHsts
            );
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_no_secure() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(&mut reqs, &["foo=bar; Domain=mozilla.org; Path=/"]);
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesWithoutSecureFlag);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_session_no_httponly() {
            let mut reqs = empty_requests(None);
            set_cookie_strings(&mut reqs, &["SESSIONID=bar; Domain=mozilla.org; Path=/; Secure"]);
            let res = cookies_test(&reqs, &no_preload());
            assert_eq!(res.result, Expectation::CookiesSessionWithoutHttponlyFlag);
            assert!(!res.pass);
            assert!(!res.same_site);
        }

        #[test]
        fn checks_session_no_secure() {
            for cookie in [
                "SESSIONID=bar; Domain=mozilla.org; Path=/; HttpOnly",
                // https://github.com/mozilla/http-observatory/issues/97
                "SESSIONID=bar; Domain=mozilla.org; Path=/",
            ] {
                let mut reqs = empty_requests(None);
                set_cookie_strings(&mut reqs, &[cookie]);
                let res = cookies_test(&reqs, &no_preload());
                assert_eq!(res.result, Expectation::CookiesSessionWithoutSecureFlag, "{cookie}");
                assert!(!res.pass);
                assert!(!res.same_site);
            }
        }
    }

    /// `SameSite=None` without `Secure` is invalid even when the raw header looked fine.
    #[test]
    fn samesite_none_without_secure_is_invalid() {
        let mut reqs = empty_requests(None);
        set_cookie_strings(&mut reqs, &["a=1; Domain=mozilla.org; Path=/; SameSite=None"]);
        let res = cookies_test(&reqs, &no_preload());
        assert_eq!(res.result, Expectation::CookiesSamesiteFlagInvalid);
    }
}
