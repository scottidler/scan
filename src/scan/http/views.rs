//! Lenses read off the Observatory retrieval, never fetched a second time: the `auto` response's
//! `alt-svc`, the `http://` session's route, and the `auto` session's cookie jar.

use crate::scan::lens::LensOutcome;
use crate::scan::observatory::Retrieval;

const ALT_SVC: &str = "alt-svc";
/// Why the views have nothing to show when neither session answered.
const NO_RESPONSE: &str = "site down";

/// One hop of the `http://` session: the URL requested and the status it answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHop {
    pub url: String,
    pub status: u16,
}

/// One cookie's name and the flags the cookies test grades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieFlags {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    /// `strict`, `lax` or `none`; `None` when the cookie set no valid `SameSite`.
    pub same_site: Option<&'static str>,
}

impl CookieFlags {
    /// Secure, HttpOnly and a SameSite: every flag the cookies test rewards.
    pub fn fully_flagged(&self) -> bool {
        self.secure && self.http_only && self.same_site.is_some()
    }
}

/// What the retrieval shows beside the grade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievalViews {
    /// The `auto` response's `alt-svc` header.
    pub alt_svc: LensOutcome<String>,
    /// The `http://` session's hops; `Absent` when port 80 gave no response.
    pub http_route: LensOutcome<Vec<RouteHop>>,
    /// The `auto` session's jar; `Absent` when it holds no cookie.
    pub cookies: LensOutcome<Vec<CookieFlags>>,
}

impl RetrievalViews {
    pub fn of(retrieval: &Retrieval) -> Self {
        let Some(auto) = retrieval.auto_response() else {
            return Self {
                alt_svc: LensOutcome::Failed(NO_RESPONSE.to_string()),
                http_route: LensOutcome::Failed(NO_RESPONSE.to_string()),
                cookies: LensOutcome::Failed(NO_RESPONSE.to_string()),
            };
        };
        let alt_svc = auto.headers.all(ALT_SVC);
        let alt_svc = if alt_svc.is_empty() {
            LensOutcome::Absent
        } else {
            LensOutcome::Present(alt_svc.join(", "))
        };
        let http_route = match &retrieval.http {
            Some(session) => LensOutcome::Present(
                session
                    .redirects
                    .iter()
                    .map(|hop| RouteHop {
                        url: hop.url.to_string(),
                        status: hop.status,
                    })
                    .collect(),
            ),
            None => LensOutcome::Absent,
        };
        let cookies = if retrieval.cookies.is_empty() {
            LensOutcome::Absent
        } else {
            LensOutcome::Present(
                retrieval
                    .cookies
                    .iter()
                    .map(|cookie| CookieFlags {
                        name: cookie.key.clone(),
                        secure: cookie.secure,
                        http_only: cookie.http_only,
                        same_site: cookie.same_site.map(|s| s.as_str()),
                    })
                    .collect(),
            )
        };
        let views = Self {
            alt_svc,
            http_route,
            cookies,
        };
        log::debug!(
            "[scan::http::views] of: host={} alt_svc={:?} http_hops={:?} cookies={:?}",
            retrieval.host,
            views.alt_svc.present(),
            views.http_route.present().map(Vec::len),
            views.cookies.present().map(Vec::len)
        );
        views
    }
}

/// An `alt-svc` value that offers HTTP/3 (`h3`, or a draft such as `h3-29`).
pub fn advertises_h3(alt_svc: &str) -> bool {
    alt_svc
        .split(',')
        .filter_map(|entry| entry.split('=').next())
        .any(|protocol| {
            let protocol = protocol.trim();
            protocol == "h3" || protocol.starts_with("h3-")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::observatory::cookies::{Cookie, SameSite};
    use crate::scan::observatory::headers::Headers;
    use crate::scan::observatory::html::MetaTags;
    use crate::scan::observatory::retriever::{RedirectEntry, Response, Session};
    use url::Url;

    fn session(start: &str, hops: &[(&str, u16)], headers: Headers) -> Session {
        Session {
            url: Url::parse(start).unwrap(),
            response: Response {
                status: hops.last().unwrap().1,
                verified: true,
                headers,
            },
            redirects: hops
                .iter()
                .map(|(url, status)| RedirectEntry {
                    url: Url::parse(url).unwrap(),
                    status: *status,
                })
                .collect(),
        }
    }

    fn cookie(key: &str, secure: bool, http_only: bool, same_site: Option<SameSite>) -> Cookie {
        Cookie {
            key: key.to_string(),
            secure,
            http_only,
            same_site,
            ..Cookie::default()
        }
    }

    fn retrieval(http: Option<Session>, https: Option<Session>, cookies: Vec<Cookie>) -> Retrieval {
        Retrieval {
            host: "site.com".to_string(),
            http,
            https,
            cors: None,
            cookies,
            meta: MetaTags::default(),
            auto_body: None,
        }
    }

    #[test]
    fn views_show_the_http_route_the_auto_jar_and_alt_svc() {
        let mut headers = Headers::new();
        headers.set_single("Alt-Svc", "h3=\":443\"; ma=86400");
        let http = session(
            "http://site.com/",
            &[("http://site.com/", 301), ("https://site.com/", 200)],
            Headers::new(),
        );
        let https = session("https://site.com/", &[("https://site.com/", 200)], headers);
        let jar = vec![
            cookie("SID", true, true, Some(SameSite::Lax)),
            cookie("pref", false, false, None),
        ];

        let views = RetrievalViews::of(&retrieval(Some(http), Some(https), jar));

        assert_eq!(views.alt_svc, LensOutcome::Present("h3=\":443\"; ma=86400".to_string()));
        assert_eq!(
            views.http_route,
            LensOutcome::Present(vec![
                RouteHop {
                    url: "http://site.com/".to_string(),
                    status: 301
                },
                RouteHop {
                    url: "https://site.com/".to_string(),
                    status: 200
                },
            ])
        );
        let cookies = views.cookies.present().unwrap();
        assert_eq!(
            cookies[0],
            CookieFlags {
                name: "SID".to_string(),
                secure: true,
                http_only: true,
                same_site: Some("lax")
            }
        );
        assert!(cookies[0].fully_flagged());
        assert!(!cookies[1].fully_flagged());
        assert_eq!(cookies[1].same_site, None);
    }

    #[test]
    fn nothing_on_port_80_no_cookies_and_no_header_are_absent() {
        let https = session("https://site.com/", &[("https://site.com/", 200)], Headers::new());
        let views = RetrievalViews::of(&retrieval(None, Some(https), vec![]));
        assert_eq!(views.alt_svc, LensOutcome::Absent);
        assert_eq!(views.http_route, LensOutcome::Absent);
        assert_eq!(views.cookies, LensOutcome::Absent);
    }

    #[test]
    fn a_site_with_no_response_fails_every_view() {
        let views = RetrievalViews::of(&retrieval(None, None, vec![]));
        let down = LensOutcome::Failed("site down".to_string());
        assert_eq!(views.alt_svc, down);
        assert_eq!(views.http_route, LensOutcome::Failed("site down".to_string()));
        assert_eq!(views.cookies, LensOutcome::Failed("site down".to_string()));
    }

    #[test]
    fn h3_and_its_drafts_advertise_http3() {
        assert!(advertises_h3("h3=\":443\"; ma=86400"));
        assert!(advertises_h3("h2=\":443\", h3-29=\":443\""));
        assert!(!advertises_h3("h2=\":443\"; ma=60"));
        assert!(!advertises_h3("clear"));
    }
}
