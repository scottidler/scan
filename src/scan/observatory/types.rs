// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/types.js).

//! Every result an Observatory test can give, named verbatim from upstream's `Expectation`: the live
//! comparison matches them as strings.

macro_rules! expectations {
    ($($variant:ident => $name:literal,)+) => {
        /// One test result, upstream's `Expectation` enum.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Expectation {
            $($variant,)+
        }

        impl Expectation {
            /// Every result, in upstream's declaration order.
            pub const ALL: &'static [Expectation] = &[$(Expectation::$variant,)+];

            /// The result name as upstream reports it, e.g. `csp-not-implemented`.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Expectation::$variant => $name,)+
                }
            }
        }
    };
}

expectations! {
    CspImplementedWithNoUnsafe => "csp-implemented-with-no-unsafe",
    CspImplementedWithNoUnsafeDefaultSrcNone => "csp-implemented-with-no-unsafe-default-src-none",
    CspImplementedWithUnsafeInlineInStyleSrcOnly => "csp-implemented-with-unsafe-inline-in-style-src-only",
    CspImplementedWithInsecureSchemeInPassiveContentOnly => "csp-implemented-with-insecure-scheme-in-passive-content-only",
    CspImplementedWithUnsafeInline => "csp-implemented-with-unsafe-inline",
    CspImplementedWithUnsafeEval => "csp-implemented-with-unsafe-eval",
    CspImplementedWithInsecureScheme => "csp-implemented-with-insecure-scheme",
    CspHeaderInvalid => "csp-header-invalid",
    CspNotImplemented => "csp-not-implemented",
    CspNotImplementedButReportingEnabled => "csp-not-implemented-but-reporting-enabled",
    CspImplementedButDuplicateDirectives => "csp-implemented-but-duplicate-directives",
    SriImplementedAndAllScriptsLoadedSecurely => "sri-implemented-and-all-scripts-loaded-securely",
    SriImplementedAndExternalScriptsLoadedSecurely => "sri-implemented-and-external-scripts-loaded-securely",
    SriImplementedButExternalScriptsNotLoadedSecurely => "sri-implemented-but-external-scripts-not-loaded-securely",
    SriNotImplementedAndExternalScriptsNotLoadedSecurely => "sri-not-implemented-and-external-scripts-not-loaded-securely",
    SriNotImplementedButAllScriptsLoadedFromSecureOrigin => "sri-not-implemented-but-all-scripts-loaded-from-secure-origin",
    SriNotImplementedButExternalScriptsLoadedSecurely => "sri-not-implemented-but-external-scripts-loaded-securely",
    SriNotImplementedButNoScriptsLoaded => "sri-not-implemented-but-no-scripts-loaded",
    SriNotImplementedResponseNotHtml => "sri-not-implemented-response-not-html",
    HtmlNotParseable => "html-not-parseable",
    HstsHeaderInvalid => "hsts-header-invalid",
    HstsImplementedMaxAgeAtLeastSixMonths => "hsts-implemented-max-age-at-least-six-months",
    HstsImplementedMaxAgeLessThanSixMonths => "hsts-implemented-max-age-less-than-six-months",
    HstsInvalidCert => "hsts-invalid-cert",
    HstsNotImplementedNoHttps => "hsts-not-implemented-no-https",
    HstsNotImplemented => "hsts-not-implemented",
    HstsPreloaded => "hsts-preloaded",
    CookiesAnticsrfWithoutSamesiteFlag => "cookies-anticsrf-without-samesite-flag",
    CookiesNotFound => "cookies-not-found",
    CookiesSamesiteFlagInvalid => "cookies-samesite-flag-invalid",
    CookiesSecureWithHttponlySessionsAndSamesite => "cookies-secure-with-httponly-sessions-and-samesite",
    CookiesSecureWithHttponlySessions => "cookies-secure-with-httponly-sessions",
    CookiesSessionWithoutHttponlyFlag => "cookies-session-without-httponly-flag",
    CookiesSessionWithoutSecureFlagButProtectedByHsts => "cookies-session-without-secure-flag-but-protected-by-hsts",
    CookiesSessionWithoutSecureFlag => "cookies-session-without-secure-flag",
    CookiesWithoutSecureFlagButProtectedByHsts => "cookies-without-secure-flag-but-protected-by-hsts",
    CookiesWithoutSecureFlag => "cookies-without-secure-flag",
    XFrameOptionsAllowFromOrigin => "x-frame-options-allow-from-origin",
    XFrameOptionsHeaderInvalid => "x-frame-options-header-invalid",
    XFrameOptionsImplementedViaCsp => "x-frame-options-implemented-via-csp",
    XFrameOptionsNotImplemented => "x-frame-options-not-implemented",
    XFrameOptionsSameoriginOrDeny => "x-frame-options-sameorigin-or-deny",
    RedirectionToHttps => "redirection-to-https",
    RedirectionNotToHttps => "redirection-not-to-https",
    RedirectionNotToHttpsOnInitialRedirection => "redirection-not-to-https-on-initial-redirection",
    RedirectionMissing => "redirection-missing",
    RedirectionNotNeededNoHttp => "redirection-not-needed-no-http",
    RedirectionOffHostFromHttp => "redirection-off-host-from-http",
    RedirectionInvalidCert => "redirection-invalid-cert",
    RedirectionAllRedirectsPreloaded => "redirection-all-redirects-preloaded",
    ReferrerPolicyPrivate => "referrer-policy-private",
    ReferrerPolicyUnsafe => "referrer-policy-unsafe",
    ReferrerPolicyNotImplemented => "referrer-policy-not-implemented",
    ReferrerPolicyHeaderInvalid => "referrer-policy-header-invalid",
    XContentTypeOptionsNosniff => "x-content-type-options-nosniff",
    XContentTypeOptionsNotImplemented => "x-content-type-options-not-implemented",
    XContentTypeOptionsHeaderInvalid => "x-content-type-options-header-invalid",
    CrossOriginResourceSharingNotImplemented => "cross-origin-resource-sharing-not-implemented",
    CrossOriginResourceSharingImplementedWithPublicAccess => "cross-origin-resource-sharing-implemented-with-public-access",
    CrossOriginResourceSharingImplementedWithRestrictedAccess => "cross-origin-resource-sharing-implemented-with-restricted-access",
    CrossOriginResourceSharingImplementedWithUniversalAccess => "cross-origin-resource-sharing-implemented-with-universal-access",
    CrossOriginResourcePolicyNotImplemented => "corp-not-implemented",
    CrossOriginResourcePolicyImplementedWithSameOrigin => "corp-implemented-with-same-origin",
    CrossOriginResourcePolicyImplementedWithSameSite => "corp-implemented-with-same-site",
    CrossOriginResourcePolicyImplementedWithCrossOrigin => "corp-implemented-with-cross-origin",
    CrossOriginResourcePolicyHeaderInvalid => "corp-header-invalid",
    CoopNotImplemented => "coop-not-implemented",
    CoopImplementedWithSameOrigin => "coop-implemented-with-same-origin",
    CoopImplementedWithSameOriginAllowPopups => "coop-implemented-with-same-origin-allow-popups",
    CoopImplementedWithNoopenerAllowPopups => "coop-implemented-with-noopener-allow-popups",
    CoopImplementedWithUnsafeNone => "coop-implemented-with-unsafe-none",
    CoopHeaderInvalid => "coop-header-invalid",
    CoepNotImplemented => "coep-not-implemented",
    CoepImplementedWithRequireCorp => "coep-implemented-with-require-corp",
    CoepImplementedWithCredentialless => "coep-implemented-with-credentialless",
    CoepImplementedWithUnsafeNone => "coep-implemented-with-unsafe-none",
    CoepHeaderInvalid => "coep-header-invalid",
}

impl std::fmt::Display for Expectation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The MIME types whose body is parsed for meta tags and scripts (`HTML_TYPES`).
pub const HTML_TYPES: [&str; 2] = ["text/html", "application/xhtml+xml"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn result_names_are_verbatim_and_unique() {
        assert_eq!(Expectation::ALL.len(), 77);
        assert_eq!(
            Expectation::CspNotImplementedButReportingEnabled.as_str(),
            "csp-not-implemented-but-reporting-enabled"
        );
        assert_eq!(
            Expectation::CrossOriginResourcePolicyNotImplemented.as_str(),
            "corp-not-implemented"
        );
        let names: HashSet<&str> = Expectation::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(names.len(), Expectation::ALL.len());
    }
}
