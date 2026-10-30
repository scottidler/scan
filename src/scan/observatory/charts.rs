// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/grader/charts.js).

//! Upstream's grading tables: the score-to-grade chart, the bonus threshold, and per result its
//! score modifier, description and recommendation (HTML, as upstream ships them).

use super::grade::GradeLetter;
use super::types::Expectation;

/// Score bucket -> grade: 100 A+; 95, 90 A; 85 A-; ... 20..0 F (`GRADE_CHART`).
pub const GRADE_CHART: [(i32, GradeLetter); 21] = [
    (100, GradeLetter::APlus),
    (95, GradeLetter::A),
    (90, GradeLetter::A),
    (85, GradeLetter::AMinus),
    (80, GradeLetter::BPlus),
    (75, GradeLetter::B),
    (70, GradeLetter::B),
    (65, GradeLetter::BMinus),
    (60, GradeLetter::CPlus),
    (55, GradeLetter::C),
    (50, GradeLetter::C),
    (45, GradeLetter::CMinus),
    (40, GradeLetter::DPlus),
    (35, GradeLetter::D),
    (30, GradeLetter::D),
    (25, GradeLetter::DMinus),
    (20, GradeLetter::F),
    (15, GradeLetter::F),
    (10, GradeLetter::F),
    (5, GradeLetter::F),
    (0, GradeLetter::F),
];

/// Bonuses count only when the penalty-only score reaches this.
pub const MINIMUM_SCORE_FOR_EXTRA_CREDIT: i32 = 90;

/// One `SCORE_TABLE` row.
pub struct ScoreEntry {
    pub expectation: Expectation,
    pub modifier: i32,
    pub description: &'static str,
    pub recommendation: &'static str,
}

pub const SCORE_TABLE: [ScoreEntry; 77] = [
    ScoreEntry {
        expectation: Expectation::CspImplementedWithNoUnsafeDefaultSrcNone,
        modifier: 10,
        description: r#"<p>
        Content Security Policy (CSP) implemented with <code>default-src 'none'</code>,
        no <code>'unsafe'</code> and form-action is set to <code>'none'</code> or <code>'self'</code>
        </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithNoUnsafe,
        modifier: 5,
        description: r#"<p>
        Content Security Policy (CSP) implemented without <code>'unsafe-inline'</code> or <code>'unsafe-eval'</code>
        </p>"#,
        recommendation: r#"<p>
      Set <code>default-src</code> to <code>'none'</code>
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithUnsafeInlineInStyleSrcOnly,
        modifier: 0,
        description: r#"<p>
      Content Security Policy (CSP) implemented with unsafe sources inside style-src. This includes <code>'unsafe-inline'</code>, <code>data:</code> or overly broad sources such as <code>https</code>. <code>'form-action'</code> is set to <code>'self'</code>, <code>'none'</code> or <code>'specific source'</code>
      </p>"#,
        recommendation: r#"
        <p>
          Lock down <code>style-src</code> directive, removing <code>'unsafe-inline'</code>, <code>data:</code> and broad sources.
        </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithInsecureSchemeInPassiveContentOnly,
        modifier: -10,
        description: r#"<p>
      Content Security Policy (CSP) implemented, but secure site allows images or media to be loaded over HTTP
      </p>"#,
        recommendation: r#"<p>
        Load images and media over HTTPS and prevent their loading over HTTP with the <code>img-src</code> and <code>media-src</code> or <code>default-src</code> directives
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithUnsafeEval,
        modifier: -10,
        description: r#"<p>
      Content Security Policy (CSP) implemented, but allows <code>'unsafe-eval'</code> and allows forms to be submitted to any source.
      </p>"#,
        recommendation: r#"<p>First remove the use of <code>eval()</code> from the codebase and once completed, remove <code>'unsafe-eval'</code> from the CSP header.</p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithUnsafeInline,
        modifier: -20,
        description: r#"<p>
      Content Security Policy (CSP) implemented unsafely. This includes <code>'unsafe-inline'</code> or <code>data:</code> inside <code>script-src</code>, overly broad sources such as <code>https:</code> inside <code>object-src</code> or <code>script-src</code>, or not restricting the sources for <code>object-src</code> or <code>script-src</code>.
      </p>"#,
        recommendation: r#"<p>
      Remove <code>unsafe-inline</code> and <code>data:</code> from <code>script-src</code>, overly broad sources from <code>object-src</code> and <code>script-src</code>, and ensure <code>object-src</code> and <code>script-src</code> are set.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedWithInsecureScheme,
        modifier: -20,
        description: r#"<p>
      Content Security Policy (CSP) implemented, but secure site allows resources to be loaded over HTTP
      </p>"#,
        recommendation: r#"<p>
      Load resources over HTTPS and remove any HTTP sources from your CSP.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspHeaderInvalid,
        modifier: -25,
        description: r#"<p>
        Content Security Policy (CSP) header cannot be parsed successfully
        </p>"#,
        recommendation: r#"<p>
      Check your CSP syntax with the <a href="https://csp-evaluator.withgoogle.com/" target="_blank" rel="noreferrer" class="external">CSP Evaluator</a>
      </p>."#,
    },
    ScoreEntry {
        expectation: Expectation::CspNotImplemented,
        modifier: -25,
        description: r#"<p>
      Content Security Policy (CSP) header not implemented
      </p>"#,
        recommendation: r#"<p>
      Implement one, see <a href="/en-US/docs/Web/HTTP/Guides/CSP">MDN's Content Security Policy (CSP) documentation</a>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspNotImplementedButReportingEnabled,
        modifier: -25,
        description: r#"<p>
      Content Security Policy (CSP) reporting implemented only, with <code>Content-Security-Policy-Report-Only</code> header.
      </p>"#,
        recommendation: r#"<p>
      Implement an enforced policy, see <a href="/en-US/docs/Web/HTTP/Guides/CSP">MDN's Content Security Policy (CSP) documentation</a>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CspImplementedButDuplicateDirectives,
        modifier: 0,
        description: r#"<p>
        Content Security Policy (CSP) implemented, but contains duplicate directives.
        </p>"#,
        recommendation: r#"<p>Remove duplicate directives from the CSP</p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSecureWithHttponlySessionsAndSamesite,
        modifier: 5,
        description: r#"<p>
        All cookies use the <code>Secure</code> flag, session cookies use the <code>HttpOnly</code> flag, and cross-origin restrictions are in place via the <code>SameSite</code> flag.
        </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSecureWithHttponlySessions,
        modifier: 0,
        description: r#"<p>
        All cookies use the <code>Secure</code> flag and all session cookies use the <code>HttpOnly</code> flag.
        </p>"#,
        recommendation: r#"<p>
      Use <code>SameSite</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesNotFound,
        modifier: 0,
        description: r#"<p>
      No cookies detected
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesWithoutSecureFlagButProtectedByHsts,
        modifier: -5,
        description: r#"<p>
        Cookies set without using the <code>Secure</code> flag, but transmission over HTTP prevented by HSTS.
        </p>"#,
        recommendation: r#"<p>
      Use <code>Secure</code> flag.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSessionWithoutSecureFlagButProtectedByHsts,
        modifier: -10,
        description: r#"<p>
        Session cookie set without the <code>Secure</code> flag, but transmission over HTTP prevented by HSTS.
        </p>"#,
        recommendation: r#"<p>
      Use <code>Secure</code> flag.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesWithoutSecureFlag,
        modifier: -20,
        description: r#"<p>
      Cookies set without using the <code>Secure</code> flag or set over HTTP.
      </p>"#,
        recommendation: r#"<p>
      Use <code>Secure</code> flag and set up HSTS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSamesiteFlagInvalid,
        modifier: -20,
        description: r#"<p>
        Cookies use <code>SameSite</code> flag, but set to something other than <code>Strict</code> or <code>Lax</code>
        </p>"#,
        recommendation: r#"<p>
      Use <code>SameSite</code> <code>Strict</code> or <code>Lax</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesAnticsrfWithoutSamesiteFlag,
        modifier: -20,
        description: r#"<p>
      Anti-CSRF tokens set without using the <code>SameSite</code> flag.
      </p>"#,
        recommendation: r#"<p>
      Use <code>SameSite</code> <code>Strict</code> or <code>Lax</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSessionWithoutHttponlyFlag,
        modifier: -30,
        description: r#"<p>
      Session cookie set without using the <code>HttpOnly</code> flag.
      </p>"#,
        recommendation: r#"<p>
      Use <code>HttpOnly</code>
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CookiesSessionWithoutSecureFlag,
        modifier: -40,
        description: r#"Session cookie set without using the <code>Secure</code> flag or set over HTTP."#,
        recommendation: r#"<p>
      Use <code>Secure</code> flag and set up HSTS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourceSharingNotImplemented,
        modifier: 0,
        description: r#"<p>
      Content is not visible via cross-origin resource sharing (CORS) files or headers.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourceSharingImplementedWithPublicAccess,
        modifier: 0,
        description: r#"<p>
        Public content is visible via cross-origin resource sharing (CORS) <code>Access-Control-Allow-Origin</code> header.
        </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourceSharingImplementedWithRestrictedAccess,
        modifier: 0,
        description: r#"<p>Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains.</p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourceSharingImplementedWithUniversalAccess,
        modifier: -50,
        description: r#"<p>
      Content is visible via cross-origin resource sharing (CORS) file or headers, and credentials can be sent. <em>Your site could be vulnerable to CSRF attacks</em>.
      </p>"#,
        recommendation: r#"
        <p>
          If credentialed access is required from specific origins, ensure <code>Access-Control-Allow-Origin</code> can only be set to those origins, rather than reflecting the Origin header. If public non-credentialed access is required, set <code>Access-Control-Allow-Origin</code> to <code>*</code> and omit the <code>Access-Control-Allow-Credentials</code> header. Otherwise, omit both headers.
        </p>
        "#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionAllRedirectsPreloaded,
        modifier: 0,
        description: r#"<p>
      All hosts redirected to are in the HTTP Strict Transport Security (HSTS) preload list.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionToHttps,
        modifier: 0,
        description: r#"<p>
      Initial redirection is to HTTPS on same host, final destination is HTTPS
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionNotNeededNoHttp,
        modifier: 0,
        description: r#"<p>
      Not able to connect via HTTP, so no redirection necessary.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionOffHostFromHttp,
        modifier: -5,
        description: r#"<p>
      Initial redirection from HTTP to HTTPS is to a different host, preventing HSTS.
      </p>"#,
        recommendation: r#"<p>
      HSTS headers aren't recognized when set over HTTP, so redirect to the same host on HTTPS first, then redirect to the final host.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionNotToHttpsOnInitialRedirection,
        modifier: -10,
        description: r#"<p>
      Redirects to HTTPS eventually, but initial redirection is to another HTTP URL.
      </p>"#,
        recommendation: r#"<p>
      Redirect to the same host on HTTPS first, then redirect to the final host on HTTPS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionNotToHttps,
        modifier: -20,
        description: r#"<p>
      Redirects, but final destination is not an HTTPS URL.
      </p>"#,
        recommendation: r#"<p>
      Redirect to the same host on HTTPS first, then redirect to the final host on HTTPS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionMissing,
        modifier: -20,
        description: r#"<p>
      Does not redirect to an HTTPS site.
      </p>"#,
        recommendation: r#"<p>
      Redirect to the same host on HTTPS first, then redirect to the final host on HTTPS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::RedirectionInvalidCert,
        modifier: -20,
        description: r#"<p>
      Invalid certificate chain encountered during redirection.
      </p>"#,
        recommendation: r#"<p>
      Install a valid TLS certificate on the server. <a href="https://letsencrypt.org/" target="_blank" rel="noreferrer" class="external">Let's Encrypt</a> is a good choice, as are certificates managed by your cloud provider or commercially sold ones.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::ReferrerPolicyPrivate,
        modifier: 5,
        description: r#"<p>
        <code>Referrer-Policy</code> header set to <code>no-referrer</code>, <code>same-origin</code>, <code>strict-origin</code> or <code>strict-origin-when-cross-origin</code>.
        </p>"#,
        recommendation: r#"<p class="obs-none">None<p>"#,
    },
    ScoreEntry {
        expectation: Expectation::ReferrerPolicyNotImplemented,
        modifier: 0,
        description: r#"<p>
      <code>Referrer-Policy</code> header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>strict-origin-when-cross-origin</code> at a minimum.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::ReferrerPolicyUnsafe,
        modifier: -5,
        description: r#"<p>
        <code>Referrer-Policy</code> header set unsafely to <code>origin</code>, <code>origin-when-cross-origin</code>, <code>unsafe-url</code> or <code>no-referrer-when-downgrade</code>.
        </p>"#,
        recommendation: r#"<p>
      Set to strict-origin-when-cross-origin at a minimum
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::ReferrerPolicyHeaderInvalid,
        modifier: -5,
        description: r#"<p>
      <code>Referrer-Policy</code> header cannot be recognized.
      </p>"#,
        recommendation: r#"<p>
      Set to strict-origin-when-cross-origin at a minimum
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsPreloaded,
        modifier: 5,
        description: r#"<p>
        Preloaded via the HTTP Strict Transport Security (HSTS) preloading process.
        </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::HstsImplementedMaxAgeAtLeastSixMonths,
        modifier: 0,
        description: r#"<p>
        <code>Strict-Transport-Security</code> header set to a minimum of six months (15768000).
        </p>"#,
        recommendation: r#"<p>
      Consider preloading: this requires adding the <code>preload</code> and <code>includeSubDomains</code> directives and setting <code>max-age</code> to at least <code>31536000</code> (1 year), and submitting your site to <a href="https://hstspreload.org/" target="_blank" rel="noreferrer" class="external">https://hstspreload.org/</a>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsImplementedMaxAgeLessThanSixMonths,
        modifier: -10,
        description: r#"<p>
      <code>Strict-Transport-Security</code> header set to less than six months (15768000).
      </p>"#,
        recommendation: r#"<p>
      Increase HSTS period.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsNotImplemented,
        modifier: -20,
        description: r#"<p>
      <code>Strict-Transport-Security</code> header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Add HSTS. Consider rolling out with shorter periods first (as suggested on <a href="https://hstspreload.org/#deployment-recommendations" target="_blank" rel="noreferrer" class="external">https://hstspreload.org/</a>).
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsHeaderInvalid,
        modifier: -20,
        description: r#"<p>
        <code>Strict-Transport-Security</code> header cannot be recognized
        </p>"#,
        recommendation: r#"<p>
      Read <a href="/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security">MDN's documentation on HTTP Strict Transport Security</a>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsNotImplementedNoHttps,
        modifier: -20,
        description: r#"<p>
        <code>Strict-Transport-Security</code> header cannot be set for sites not available over HTTPS.
       </p>"#,
        recommendation: r#"<p>
      Make your site available over <a href="/en-US/docs/Glossary/HTTPS">HTTPS</a>. <a href="https://letsencrypt.org/getting-started/" target="_blank" rel="noreferrer" class="external">Let's Encrypt docs</a> are a good starting point.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HstsInvalidCert,
        modifier: -20,
        description: r#"<p>
      <code>Strict-Transport-Security</code> header cannot be set, as site contains an invalid certificate chain.
      </p>"#,
        recommendation: r#"<p>
      HSTS can only work with a valid TLS certificate on the server. <a href="https://letsencrypt.org/" target="_blank" rel="noreferrer" class="external">Let's Encrypt</a> is a good choice, as are certificates managed by your cloud provider or commercially sold ones.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::SriImplementedAndAllScriptsLoadedSecurely,
        modifier: 5,
        description: r#"<p>
      Subresource Integrity (SRI) is implemented and all scripts are loaded from a similar origin.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::SriImplementedAndExternalScriptsLoadedSecurely,
        modifier: 5,
        description: r#"<p>
      Subresource Integrity (SRI) is implemented and all scripts are loaded securely.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::SriNotImplementedResponseNotHtml,
        modifier: 0,
        description: r#"<p>
      Subresource Integrity (SRI) is only needed for HTML resources.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::SriNotImplementedButNoScriptsLoaded,
        modifier: 0,
        description: r#"<p>
      Subresource Integrity (SRI) is not needed since site contains no script tags.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::SriNotImplementedButAllScriptsLoadedFromSecureOrigin,
        modifier: 0,
        description: r#"<p>
      Subresource Integrity (SRI) not implemented, but all scripts are loaded from a similar origin.
      </p>"#,
        recommendation: r#"<p>
      Add SRI for bonus points.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::SriNotImplementedButExternalScriptsLoadedSecurely,
        modifier: -5,
        description: r#"<p>
      Subresource Integrity (SRI) not implemented, but all external scripts are loaded over HTTPS.
      </p>"#,
        recommendation: r#"<p>
      Add SRI to external scripts.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::SriImplementedButExternalScriptsNotLoadedSecurely,
        modifier: -20,
        description: r#"<p>
      Subresource Integrity (SRI) implemented, but external scripts are loaded over HTTP or they use protocol-relative URLs via <code>src="//..."</code>.
      </p>"#,
        recommendation: r#"<p>
      Load external scripts over HTTPS.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::SriNotImplementedAndExternalScriptsNotLoadedSecurely,
        modifier: -50,
        description: r#"<p>
        Subresource Integrity (SRI) not implemented, and external scripts are loaded over HTTP or they use protocol-relative URLs via <code>src="//..."</code>.
        </p>"#,
        recommendation: r#"<p>
      Load external scripts over HTTPS, and add SRI to them.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::XContentTypeOptionsNosniff,
        modifier: 0,
        description: r#"<p>
      <code>X-Content-Type-Options</code> header set to <code>nosniff</code>.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::XContentTypeOptionsNotImplemented,
        modifier: -5,
        description: r#"<p>
      <code>X-Content-Type-Options</code> header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>nosniff</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::XContentTypeOptionsHeaderInvalid,
        modifier: -5,
        description: r#"<p>
      <code>X-Content-Type-Options</code> header cannot be recognized.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>nosniff</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::XFrameOptionsImplementedViaCsp,
        modifier: 5,
        description: r#"<p>
      <code>X-Frame-Options</code> (XFO) implemented via the CSP frame-ancestors directive.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::XFrameOptionsSameoriginOrDeny,
        modifier: 5,
        description: r#"<p>
      <code>X-Frame-Options</code> (XFO) header set to <code>SAMEORIGIN</code> or <code>DENY</code>.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::XFrameOptionsAllowFromOrigin,
        modifier: 0,
        description: r#"<p>
      <code>X-Frame-Options</code> (XFO) header uses <code>ALLOW-FROM</code> uri directive.
      </p>"#,
        recommendation: r#"<p>
      Implement frame-ancestors CSP.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::XFrameOptionsNotImplemented,
        modifier: -20,
        description: r#"<p>
      <code>X-Frame-Options</code> (XFO) header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Implement frame-ancestors CSP.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::XFrameOptionsHeaderInvalid,
        modifier: -20,
        description: r#"<p>
      <code>X-Frame-Options</code> (XFO) header cannot be recognized.
      </p>"#,
        recommendation: r#"<p>
      Implement frame-ancestors CSP.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourcePolicyHeaderInvalid,
        modifier: -5,
        description: r#"<p>
        Cross-Origin-Resource-Policy (CORP) header cannot be recognized.
        </p>"#,
        recommendation: r#"<p>
      Implement <a href="/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy">Cross Origin Resource Policy</a>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourcePolicyImplementedWithCrossOrigin,
        modifier: 0,
        description: r#"<p>
      Cross Origin Resource Policy (CORP) implemented, but allows cross-origin resource sharing by default.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourcePolicyImplementedWithSameOrigin,
        modifier: 10,
        description: r#"<p>
      Cross Origin Resource Policy (CORP) implemented, prevents leaks into cross-origin contexts.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourcePolicyImplementedWithSameSite,
        modifier: 10,
        description: r#"<p>
        Cross Origin Resource Policy (CORP) implemented, prevents leaks into cross-site contexts.
        </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CrossOriginResourcePolicyNotImplemented,
        modifier: 0,
        description: r#"<p>
      Cross Origin Resource Policy (CORP) is not implemented (defaults to <code>cross-origin</code>).
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoepImplementedWithRequireCorp,
        modifier: 10,
        description: r#"<p>
      <code>Cross-Origin-Embedder-Policy</code> header set to <code>require-corp</code>, restricting loading cross-origin resources.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoepImplementedWithCredentialless,
        modifier: 10,
        description: r#"<p>
      <code>Cross-Origin-Embedder-Policy</code> header set to <code>credentialless</code>, allowing loading cross-origin resources but without sending credentials in the requests.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoepImplementedWithUnsafeNone,
        modifier: 0,
        description: r#"<p>
      <code>Cross-Origin-Embedder-Policy</code> header set to <code>unsafe-none</code>, allowing loading cross-origin resources, which is the default value.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>require-corp</code> or <code>credentialless</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CoepNotImplemented,
        modifier: 0,
        description: r#"<p>
      <code>Cross-Origin-Embedder-Policy</code> header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>require-corp</code> or <code>credentialless</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CoepHeaderInvalid,
        modifier: -5,
        description: r#"<p>
      <code>Cross-Origin-Embedder-Policy</code> header cannot be recognized.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>require-corp</code>, <code>credentialless</code>, or <code>unsafe-none</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CoopImplementedWithSameOrigin,
        modifier: 10,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header set to <code>same-origin</code>, enforcing site isolation from the opener.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoopImplementedWithSameOriginAllowPopups,
        modifier: 10,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header set to <code>same-origin-allow-popups</code>, enforcing site isolation from the opener but allowing trusted resources such as for OAuth or payments.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoopImplementedWithNoopenerAllowPopups,
        modifier: 10,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header set to <code>noopener-allow-popups</code>, enforcing site isolation from the opener even if they are same origin.
      </p>"#,
        recommendation: r#""#,
    },
    ScoreEntry {
        expectation: Expectation::CoopImplementedWithUnsafeNone,
        modifier: 0,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header set to <code>unsafe-none</code>, the document permits sharing its browsing context group with any other document, and may therefore be unsafe.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>same-origin</code>, <code>same-origin-allow-popups</code>, or <code>noopener-allow-popups</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CoopNotImplemented,
        modifier: 0,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header not implemented.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>same-origin</code>, <code>same-origin-allow-popups</code>, or <code>noopener-allow-popups</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::CoopHeaderInvalid,
        modifier: -5,
        description: r#"<p>
      <code>Cross-Origin-Opener-Policy</code> header cannot be recognized.
      </p>"#,
        recommendation: r#"<p>
      Set to <code>same-origin</code>, <code>same-origin-allow-popups</code>, <code>noopener-allow-popups</code>, or <code>unsafe-none</code>.
      </p>"#,
    },
    ScoreEntry {
        expectation: Expectation::HtmlNotParseable,
        modifier: -20,
        description: r#"<p>
      Claims to be html, but cannot be parsed.
      </p>"#,
        recommendation: r#"<p>
      Make sure the server returns correct HTML.
      </p>"#,
    },
];

pub const TEST_TITLES: [(&str, &str); 12] = [
    ("cross-origin-resource-sharing", "Cross Origin Resource Sharing (CORS)"),
    ("cross-origin-opener-policy", "Cross Origin Opener Policy"),
    ("cross-origin-embedder-policy", "Cross Origin Embedder Policy"),
    ("cross-origin-resource-policy", "Cross Origin Resource Policy"),
    ("content-security-policy", "Content Security Policy (CSP)"),
    ("redirection", "Redirection"),
    ("referrer-policy", "Referrer Policy"),
    ("strict-transport-security", "Strict Transport Security (HSTS)"),
    ("subresource-integrity", "Subresource Integrity"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("cookies", "Cookies"),
];

pub const TEST_TOPIC_LINKS: [(&str, &str); 14] = [
    (
        "content-security-policy",
        "/en-US/docs/Web/Security/Practical_implementation_guides/CSP",
    ),
    (
        "cookies",
        "/en-US/docs/Web/Security/Practical_implementation_guides/Cookies",
    ),
    (
        "cross-origin-embedder-policy",
        "/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy",
    ),
    (
        "cross-origin-opener-policy",
        "/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy",
    ),
    (
        "cross-origin-resource-policy",
        "/en-US/docs/Web/Security/Practical_implementation_guides/CORP",
    ),
    (
        "cross-origin-resource-sharing",
        "/en-US/docs/Web/Security/Practical_implementation_guides/CORS",
    ),
    (
        "redirection",
        "/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_redirection",
    ),
    (
        "referrer-policy",
        "/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy",
    ),
    (
        "strict-transport-security",
        "/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_strict_transport_security_implementation",
    ),
    (
        "subresource-integrity",
        "/en-US/docs/Web/Security/Subresource_Integrity",
    ),
    (
        "x-content-type-options",
        "/en-US/docs/Web/Security/Practical_implementation_guides/MIME_types",
    ),
    ("x-frame-options", "/en-US/docs/Web/Security/Attacks/Clickjacking"),
    ("contribute", "/en-US/"),
    (
        "x-xss-protection",
        "/en-US/docs/Web/HTTP/Reference/Headers/X-XSS-Protection",
    ),
];
