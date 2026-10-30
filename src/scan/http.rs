use super::cache::Refreshing;
use super::observatory::{
    HstsPreload, ObservatoryOutcome, Retriever, SuffixLists, eligible_host, hsts::PreloadSource, observe,
};
use super::psl::{SuffixList, Suffixes, parse_suffixes};
use super::{Family, classify_route_error, family_failure};
use crate::scanner::Scanner;
use crate::target::{Protocol, Target, TargetType};
use crate::types::ScanResult;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use url::Url;

const HTTP_CLIENT_TIMEOUT_SECS: u64 = 10;
const HTTP_REDIRECT_LIMIT: usize = 10;
const ASSUMED_REDIRECT_STATUS: u16 = 301;
const HTTP_SCAN_INTERVAL_SECS: u64 = 60;
/// The runner's deadline for one HTTP scan; the inner budget sits under it so a scan that runs
/// long still returns what finished.
const HTTP_SCAN_DEADLINE: Duration = Duration::from_secs(40);
const HTTP_SCAN_BUDGET: Duration = Duration::from_secs(35);

/// Probes the target as given and grades its host as MDN HTTP Observatory does, concurrently.
pub struct HttpScanner {
    timeout: Duration,
    /// Inner budget for one scan, under the runner's deadline.
    budget: Duration,
    retriever: Retriever,
    /// The Chromium preload list, owned for the scanner's life and refreshed after 24h.
    preload: PreloadSource,
    suffix_source: SuffixList,
    /// Both readings of the public suffix file, parsed once per refresh.
    suffixes: Refreshing<Suffixes>,
}

impl Default for HttpScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// The URLs one family attempt requests, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestPlan {
    /// Requested first; its scheme is the one the target asked for (HTTPS for bare targets).
    pub primary: Url,
    /// Plain-HTTP URL tried only when `primary` fails; `None` for URL targets.
    pub plain_http_fallback: Option<Url>,
}

/// Build the request URLs for `target`. The host stays the target's name, so SNI, `Host:`
/// and certificate validation all use it; the IP is pinned separately in the client.
pub fn request_plan(target: &Target) -> eyre::Result<RequestPlan> {
    let plan = match &target.target_type {
        TargetType::Url(url) => RequestPlan {
            primary: url.clone(),
            plain_http_fallback: None,
        },
        TargetType::Domain(domain) => RequestPlan {
            primary: Url::parse(&format!("https://{}/", domain))?,
            plain_http_fallback: Some(Url::parse(&format!("http://{}/", domain))?),
        },
        TargetType::IpAddress(ip) => {
            let host = match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{}]", v6),
            };
            RequestPlan {
                primary: Url::parse(&format!("https://{}/", host))?,
                plain_http_fallback: Some(Url::parse(&format!("http://{}/", host))?),
            }
        }
    };
    log::debug!(
        "[scan::http] request_plan: target={} primary={} fallback={:?}",
        target.display_name(),
        plan.primary,
        plan.plain_http_fallback.as_ref().map(Url::as_str)
    );
    Ok(plan)
}

/// The host name to pin to the resolved IP, or `None` when the URL host is already an IP.
fn pinned_host(url: &Url) -> Option<&str> {
    match url.host() {
        Some(url::Host::Domain(domain)) => Some(domain),
        _ => None,
    }
}

/// The innermost cause of an error chain, e.g. `invalid peer certificate: UnknownIssuer`.
fn root_cause(error: &eyre::Error) -> String {
    error
        .chain()
        .last()
        .map(|cause| cause.to_string())
        .unwrap_or_else(|| error.to_string())
}

impl HttpScanner {
    pub fn new() -> Self {
        log::debug!("[scan::http] new: timeout={}s", HTTP_CLIENT_TIMEOUT_SECS);
        let fetch_client = Client::builder()
            .user_agent("scan/1.0")
            .build()
            .expect("Failed to create HTTP client");
        Self::with_observatory(
            Retriever::standard().expect("Failed to create Observatory retriever"),
            PreloadSource::new(fetch_client.clone()),
            SuffixList::new(fetch_client),
        )
    }

    /// A scanner whose Observatory run uses `retriever` and reads its lists from the given sources.
    pub fn with_observatory(retriever: Retriever, preload: PreloadSource, suffix_source: SuffixList) -> Self {
        Self {
            timeout: Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS),
            budget: HTTP_SCAN_BUDGET,
            retriever,
            preload,
            suffix_source,
            suffixes: Refreshing::new(),
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// One client per family attempt: `resolve` is builder-level, and one pin is one family.
    /// The pin covers only `host`; redirects to other hosts resolve normally.
    fn pinned_client(&self, host: Option<&str>, ip: IpAddr) -> eyre::Result<Client> {
        log::debug!("[scan::http] pinned_client: host={:?} ip={}", host, ip);
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::limited(HTTP_REDIRECT_LIMIT))
            .user_agent("scan/1.0");
        if let Some(host) = host {
            builder = builder.resolve(host, SocketAddr::new(ip, 0));
        }
        Ok(builder.build()?)
    }

    async fn http_protocol(&self, target: &Target, protocol: Protocol) -> eyre::Result<HttpData> {
        log::debug!(
            "[scan::http] http_protocol: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        let ip = match target.primary_ip_for_protocol(protocol) {
            Some(ip) if target.supports_protocol(protocol) => ip,
            _ => {
                log::debug!(
                    "[scan::http] protocol_not_supported: target={} protocol={}",
                    target.display_name(),
                    protocol.as_str()
                );
                return Err(eyre::eyre!(
                    "No {} address available for target: {}",
                    protocol.as_str(),
                    target.display_name()
                ));
            }
        };

        self.perform_http_scan_for_ip(target, ip).await
    }

    /// `NoAddress` when the family had nothing to request, else the failure's root cause run
    /// through the route classifier, e.g. `operation timed out` or `no IPv6 route on this host`.
    fn classify_http_error(error: &eyre::Error, family: Family) -> HttpStatus {
        let error_msg = error.to_string();

        if error_msg.contains("No") && error_msg.contains("address available") {
            HttpStatus::NoAddress
        } else {
            HttpStatus::Failed(classify_route_error(&root_cause(error), family).to_string())
        }
    }

    async fn perform_http_scan_for_ip(&self, target: &Target, ip: IpAddr) -> eyre::Result<HttpData> {
        log::debug!(
            "[scan::http] perform_http_scan_for_ip: target={} ip={}",
            target.display_name(),
            ip
        );

        let plan = request_plan(target)?;
        self.scan_plan(&plan, ip).await
    }

    /// Request `plan.primary` pinned to `ip`; on failure, try the plain-HTTP fallback (if any)
    /// and keep the HTTPS failure reason on the result.
    async fn scan_plan(&self, plan: &RequestPlan, ip: IpAddr) -> eyre::Result<HttpData> {
        log::debug!("[scan::http] scan_plan: primary={} ip={}", plan.primary, ip);

        let scan_start = Instant::now();
        let client = self.pinned_client(pinned_host(&plan.primary), ip)?;

        let mut result = match self.perform_scan(&client, &plan.primary, ip).await {
            Ok(result) => result,
            Err(https_error) => {
                let Some(fallback) = &plan.plain_http_fallback else {
                    log::debug!(
                        "[scan::http] request_failed: url={} error={}",
                        plan.primary,
                        root_cause(&https_error)
                    );
                    return Err(https_error);
                };
                let reason = root_cause(&https_error);
                log::debug!(
                    "[scan::http] https_failed_trying_plain_http: url={} reason={}",
                    plan.primary,
                    reason
                );
                match self.perform_scan(&client, fallback, ip).await {
                    Ok(mut result) => {
                        result.https_failure = Some(reason);
                        result
                    }
                    Err(http_error) => {
                        log::debug!(
                            "[scan::http] both_schemes_failed: https_error={} http_error={}",
                            reason,
                            root_cause(&http_error)
                        );
                        return Err(eyre::eyre!(
                            "HTTPS failed: {}; plain HTTP failed: {}",
                            reason,
                            root_cause(&http_error)
                        ));
                    }
                }
            }
        };
        result.scan_duration = scan_start.elapsed();

        log::debug!(
            "[scan::http] scan_completed: url={} status={} duration={}ms https_failure={:?}",
            result.url,
            result.status_code,
            result.scan_duration.as_millis(),
            result.https_failure
        );

        Ok(result)
    }

    async fn perform_scan(&self, client: &Client, url: &Url, ip: IpAddr) -> eyre::Result<HttpData> {
        log::debug!("[scan::http] perform_scan: url={} ip={}", url, ip);

        let start_time = Instant::now();

        log::trace!("[scan::http] sending_request: url={}", url);
        let request_start = Instant::now();
        let response = client.get(url.clone()).send().await?;
        let request_duration = request_start.elapsed();

        let status_code = response.status().as_u16();
        let final_url = response.url().clone();
        let headers = response.headers().clone();

        log::trace!(
            "[scan::http] response_received: url={} status={} request_duration={}ms final_url={}",
            url,
            status_code,
            request_duration.as_millis(),
            final_url
        );

        // Analyze redirects
        let redirect_chain = self.analyze_redirects(url, &final_url);
        log::trace!(
            "[scan::http] redirect_analysis: url={} redirect_count={}",
            url,
            redirect_chain.len()
        );

        // Get response body for content analysis
        let body_start = Instant::now();
        let body = response.bytes().await?;
        let body_duration = body_start.elapsed();
        let content_length = body.len();

        log::trace!(
            "[scan::http] body_received: url={} content_length={} body_duration={}ms",
            url,
            content_length,
            body_duration.as_millis()
        );

        // Extract content type
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Security analysis
        log::debug!("[scan::http] security_analysis_starting: url={}", url);
        let security_start = Instant::now();

        let security_headers = self.analyze_security_headers(&headers);
        let csp = self.analyze_csp(&headers);
        let cors = self.analyze_cors(&headers);
        let caching = self.analyze_caching(&headers);

        let vulnerabilities = self.assess_vulnerabilities(&security_headers, &csp);

        let security_duration = security_start.elapsed();
        log::trace!(
            "[scan::http] security_analysis_completed: url={} duration={}μs vulnerabilities={}",
            url,
            security_duration.as_micros(),
            vulnerabilities.len()
        );

        let result = HttpData {
            url: final_url.to_string(),
            status_code,
            response_time: request_duration,
            content_length,
            content_type,
            redirect_chain,
            security_headers,
            csp,
            cors,
            caching,
            vulnerabilities,
            scan_duration: start_time.elapsed(),
            target_ip: ip.to_string(),
            https_failure: None,
        };

        log::debug!(
            "[scan::http] scan_result: url={} status={} content_length={}",
            result.url,
            result.status_code,
            result.content_length
        );

        Ok(result)
    }

    fn analyze_redirects(&self, original: &Url, final_url: &Url) -> Vec<RedirectInfo> {
        if original.as_str() == final_url.as_str() {
            return vec![];
        }

        // For now, just record the final redirect
        // In a more complete implementation, we'd track the full chain
        vec![RedirectInfo {
            from: original.to_string(),
            to: final_url.to_string(),
            status_code: ASSUMED_REDIRECT_STATUS, // Assumption - would need to track actual codes
        }]
    }

    fn analyze_security_headers(&self, headers: &reqwest::header::HeaderMap) -> SecurityHeaders {
        SecurityHeaders {
            strict_transport_security: headers
                .get("strict-transport-security")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            x_frame_options: headers
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            x_content_type_options: headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            x_xss_protection: headers
                .get("x-xss-protection")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            referrer_policy: headers
                .get("referrer-policy")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            permissions_policy: headers
                .get("permissions-policy")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }

    fn analyze_csp(&self, headers: &reqwest::header::HeaderMap) -> Option<CspPolicy> {
        let csp_header = headers
            .get("content-security-policy")
            .or_else(|| headers.get("content-security-policy-report-only"))
            .and_then(|v| v.to_str().ok())?;

        let directives = self.parse_csp_directives(csp_header);
        let issues = self.analyze_csp_issues(&directives);

        Some(CspPolicy {
            header_value: csp_header.to_string(),
            directives,
            issues,
        })
    }

    fn parse_csp_directives(&self, csp: &str) -> HashMap<String, Vec<String>> {
        let mut directives = HashMap::new();

        for directive in csp.split(';') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            let parts: Vec<&str> = directive.split_whitespace().collect();
            if let Some(name) = parts.first() {
                let values = parts[1..].iter().map(|s| s.to_string()).collect();
                directives.insert(name.to_string(), values);
            }
        }

        directives
    }

    fn analyze_csp_issues(&self, directives: &HashMap<String, Vec<String>>) -> Vec<CspIssue> {
        let mut issues = Vec::new();

        // Check for unsafe-inline
        for (directive, values) in directives {
            if values.contains(&"'unsafe-inline'".to_string()) {
                issues.push(CspIssue::UnsafeInline(directive.clone()));
            }
            if values.contains(&"'unsafe-eval'".to_string()) {
                issues.push(CspIssue::UnsafeEval(directive.clone()));
            }
            if values.contains(&"*".to_string()) {
                issues.push(CspIssue::WildcardSource(directive.clone()));
            }
        }

        // Check for missing important directives
        if !directives.contains_key("default-src") && !directives.contains_key("script-src") {
            issues.push(CspIssue::MissingDirective("script-src".to_string()));
        }
        if !directives.contains_key("object-src") {
            issues.push(CspIssue::MissingDirective("object-src".to_string()));
        }

        issues
    }

    fn analyze_cors(&self, headers: &reqwest::header::HeaderMap) -> Option<CorsPolicy> {
        let access_control_allow_origin = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Check for any CORS-related headers, not just allow-origin
        let has_cors_headers = access_control_allow_origin.is_some()
            || headers.contains_key("access-control-allow-methods")
            || headers.contains_key("access-control-allow-headers")
            || headers.contains_key("access-control-allow-credentials")
            || headers.contains_key("access-control-expose-headers")
            || headers.contains_key("access-control-max-age");

        if !has_cors_headers {
            return None;
        }

        let access_control_allow_methods = headers
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').map(|m| m.trim().to_string()).collect::<Vec<String>>())
            .unwrap_or_default();

        let access_control_allow_headers = headers
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').map(|h| h.trim().to_string()).collect::<Vec<String>>())
            .unwrap_or_default();

        let access_control_allow_credentials = headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .map(|s| s == "true")
            .unwrap_or(false);

        let issues = self.analyze_cors_issues(
            &access_control_allow_origin,
            &access_control_allow_methods,
            &access_control_allow_headers,
            access_control_allow_credentials,
        );

        Some(CorsPolicy {
            access_control_allow_origin,
            access_control_allow_methods,
            access_control_allow_headers,
            access_control_allow_credentials,
            issues,
        })
    }

    fn analyze_cors_issues(
        &self,
        origin: &Option<String>,
        methods: &[String],
        headers: &[String],
        credentials: bool,
    ) -> Vec<CorsIssue> {
        let mut issues = Vec::new();

        if let Some(origin) = origin
            && origin == "*"
        {
            if credentials {
                issues.push(CorsIssue::WildcardWithCredentials);
            } else {
                issues.push(CorsIssue::WildcardOrigin);
            }
        }

        if methods.contains(&"*".to_string()) {
            issues.push(CorsIssue::WildcardMethods);
        }

        if headers.contains(&"*".to_string()) {
            issues.push(CorsIssue::WildcardHeaders);
        }

        issues
    }

    fn analyze_caching(&self, headers: &reqwest::header::HeaderMap) -> CachingPolicy {
        CachingPolicy {
            cache_control: headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            expires: headers
                .get("expires")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            etag: headers.get("etag").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            last_modified: headers
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }

    /// The headers the target's own response did not send. What is wrong with the ones it did
    /// send is Observatory's to say, in the grade's 12 tests.
    fn assess_vulnerabilities(
        &self,
        security_headers: &SecurityHeaders,
        csp: &Option<CspPolicy>,
    ) -> Vec<HttpVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Missing security headers
        if security_headers.strict_transport_security.is_none() {
            vulnerabilities.push(HttpVulnerability::MissingHsts);
        }
        if security_headers.x_frame_options.is_none() {
            vulnerabilities.push(HttpVulnerability::MissingXFrameOptions);
        }
        if security_headers.x_content_type_options.is_none() {
            vulnerabilities.push(HttpVulnerability::MissingXContentTypeOptions);
        }

        if csp.is_none() {
            vulnerabilities.push(HttpVulnerability::MissingCsp);
        }

        vulnerabilities
    }
}

/// What the target observation found per family, before it is joined with the grade.
struct Observation {
    ipv4: (HttpStatus, Option<HttpData>),
    ipv6: (HttpStatus, Option<HttpData>),
}

impl HttpScanner {
    /// One family's observation of the target, cut off at `budget_end` with a timeout.
    async fn observe_family(
        &self,
        target: &Target,
        protocol: Protocol,
        family: Family,
        budget_end: tokio::time::Instant,
    ) -> (HttpStatus, Option<HttpData>) {
        match tokio::time::timeout_at(budget_end, self.http_protocol(target, protocol)).await {
            Ok(Ok(data)) => (HttpStatus::Success, Some(data)),
            Ok(Err(error)) => {
                log::debug!(
                    "[scan::http] observe_family_failed: family={} error={}",
                    family,
                    root_cause(&error)
                );
                (Self::classify_http_error(&error, family), None)
            }
            Err(_) => {
                log::debug!("[scan::http] observe_family_budget_spent: family={}", family);
                let error = eyre::eyre!("operation timed out");
                (Self::classify_http_error(&error, family), None)
            }
        }
    }

    /// The URL as given, per family, the selected families concurrently.
    async fn observe_target(
        &self,
        target: &Target,
        protocol: Protocol,
        budget_end: tokio::time::Instant,
    ) -> Observation {
        let skipped = || (HttpStatus::NotQueried, None);
        match protocol {
            Protocol::Ipv4 => Observation {
                ipv4: self
                    .observe_family(target, Protocol::Ipv4, Family::Ipv4, budget_end)
                    .await,
                ipv6: skipped(),
            },
            Protocol::Ipv6 => Observation {
                ipv4: skipped(),
                ipv6: self
                    .observe_family(target, Protocol::Ipv6, Family::Ipv6, budget_end)
                    .await,
            },
            Protocol::Both => {
                let (ipv4, ipv6) = tokio::join!(
                    self.observe_family(target, Protocol::Ipv4, Family::Ipv4, budget_end),
                    self.observe_family(target, Protocol::Ipv6, Family::Ipv6, budget_end),
                );
                Observation { ipv4, ipv6 }
            }
        }
    }

    /// Both readings of the public suffix file, held in memory between scans.
    async fn suffix_lists(&self, deadline: tokio::time::Instant) -> eyre::Result<std::sync::Arc<Suffixes>> {
        self.suffixes
            .get(&self.suffix_source.cached_source(), deadline, parse_suffixes)
            .await
    }

    /// The Observatory run for `host`: the lists it needs, then `observe`.
    pub async fn grade_host(&self, host: &str, deadline: tokio::time::Instant) -> ObservatoryOutcome {
        log::debug!("[scan::http] grade_host: host={}", host);
        let (preload, suffixes) = tokio::join!(self.preload.get(deadline), self.suffix_lists(deadline));
        let suffixes = match suffixes {
            Ok(suffixes) => suffixes,
            Err(error) => {
                log::debug!(
                    "[scan::http] grade_host_no_suffix_list: host={} error={:#}",
                    host,
                    error
                );
                return ObservatoryOutcome::Failed(format!("public suffix list unavailable: {}", root_cause(&error)));
            }
        };
        let lists = SuffixLists {
            icann: &suffixes.icann,
            all: &suffixes.all,
        };
        let preload: &HstsPreload = &preload;
        ObservatoryOutcome::from_analysis(observe(&self.retriever, host, preload, lists).await)
    }

    /// The target's graded host, cut off at `budget_end`; no grade for a host Observatory refuses.
    async fn grade_target(&self, target: &Target, budget_end: tokio::time::Instant) -> ObservatoryOutcome {
        let host = match observatory_host(target) {
            Ok(host) => host,
            Err(reason) => {
                log::debug!(
                    "[scan::http] grade_target_not_applicable: target={} reason={}",
                    target.display_name(),
                    reason
                );
                return ObservatoryOutcome::NotApplicable(reason);
            }
        };
        match tokio::time::timeout_at(budget_end, self.grade_host(&host, budget_end)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                log::debug!("[scan::http] grade_target_budget_spent: host={}", host);
                ObservatoryOutcome::Failed("timed out".to_string())
            }
        }
    }
}

/// The host Observatory grades for `target`, or why it refuses: the URL's host for a URL target,
/// never its port or path.
fn observatory_host(target: &Target) -> Result<String, String> {
    match &target.target_type {
        TargetType::Url(url) => match url.host() {
            Some(url::Host::Domain(domain)) => eligible_host(domain),
            Some(_) => Err("IP address".to_string()),
            None => Err("no host".to_string()),
        },
        TargetType::Domain(domain) => eligible_host(domain),
        TargetType::IpAddress(_) => Err("IP address".to_string()),
    }
}

/// Join the target observation and the grade. The scan fails only when neither part produced
/// anything: the target observation failed and the host got no grade. Each part keeps its own
/// failure reason; a part that worked is never reported failed because the other did not.
fn assemble(protocol: Protocol, observation: Observation, observatory: ObservatoryOutcome) -> eyre::Result<ScanResult> {
    let mut result = HttpResult::new(observatory);
    (result.ipv4_status, result.ipv4_result) = observation.ipv4;
    (result.ipv6_status, result.ipv6_result) = observation.ipv6;

    if result.has_any_success() || matches!(result.observatory, ObservatoryOutcome::Graded(_)) {
        return Ok(ScanResult::Http(result));
    }
    let target_failure = result.failure(protocol);
    Err(match &result.observatory {
        ObservatoryOutcome::Failed(reason) => eyre::eyre!("{target_failure}; grade: {reason}"),
        _ => target_failure,
    })
}

#[async_trait]
impl Scanner for HttpScanner {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(HTTP_SCAN_INTERVAL_SECS)
    }

    fn deadline(&self) -> Duration {
        HTTP_SCAN_DEADLINE
    }

    async fn scan(&self, target: &Target, protocol: Protocol) -> eyre::Result<ScanResult> {
        log::debug!(
            "[scan::http] scan: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        let scan_start = Instant::now();
        let budget_end = tokio::time::Instant::now() + self.budget;
        let (observation, observatory) = tokio::join!(
            self.observe_target(target, protocol, budget_end),
            self.grade_target(target, budget_end),
        );
        log::debug!(
            "[scan::http] scan_parts: target={} ipv4={:?} ipv6={:?} grade={}",
            target.display_name(),
            observation.ipv4.0,
            observation.ipv6.0,
            observatory.grade_text()
        );

        let mut outcome = assemble(protocol, observation, observatory);
        match &mut outcome {
            Ok(ScanResult::Http(result)) => {
                result.total_duration = scan_start.elapsed();
                log::trace!(
                    "[scan::http] http_completed: target={} protocol={} duration={}ms",
                    target.display_name(),
                    protocol.as_str(),
                    result.total_duration.as_millis()
                );
            }
            Ok(_) => {}
            Err(error) => log::error!(
                "[scan::http] all_http_failed: target={} protocol={} duration={}ms error={}",
                target.display_name(),
                protocol.as_str(),
                scan_start.elapsed().as_millis(),
                error
            ),
        }
        outcome
    }
}

// Data structures

/// One family's observation of the target as given.
#[derive(Debug, Clone)]
pub struct HttpData {
    pub url: String,
    pub status_code: u16,
    pub response_time: Duration,
    pub content_length: usize,
    pub content_type: Option<String>,
    pub redirect_chain: Vec<RedirectInfo>,
    pub security_headers: SecurityHeaders,
    pub csp: Option<CspPolicy>,
    pub cors: Option<CorsPolicy>,
    pub caching: CachingPolicy,
    pub vulnerabilities: Vec<HttpVulnerability>,
    pub scan_duration: Duration,
    /// The pinned IP of the first request.
    pub target_ip: String,
    /// Why HTTPS failed when this result came from the plain-HTTP fallback.
    pub https_failure: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HttpStatus {
    NotQueried,     // Protocol not attempted (due to protocol restrictions)
    Success,        // The target observation succeeded
    Failed(String), // The target observation failed with this reason
    NoAddress,      // No address available for this protocol
}

impl HttpStatus {
    pub fn was_attempted(&self) -> bool {
        !matches!(self, HttpStatus::NotQueried)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, HttpStatus::Success)
    }
}

/// A scan's three independent parts: the target observation per family, and the host's Observatory
/// outcome, which no family changes.
#[derive(Debug, Clone)]
pub struct HttpResult {
    // Protocol-specific results
    pub ipv4_result: Option<HttpData>,
    pub ipv6_result: Option<HttpData>,

    // Status tracking
    pub ipv4_status: HttpStatus,
    pub ipv6_status: HttpStatus,

    /// The host's Observatory grade, or why it has none.
    pub observatory: ObservatoryOutcome,

    // Metadata
    pub queried_at: Instant,
    pub total_duration: Duration,
}

impl HttpResult {
    pub fn new(observatory: ObservatoryOutcome) -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: HttpStatus::NotQueried,
            ipv6_status: HttpStatus::NotQueried,
            observatory,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn has_any_success(&self) -> bool {
        self.ipv4_status.is_success() || self.ipv6_status.is_success()
    }

    /// Each attempted family's failure; families with no address are left out.
    fn family_failures(&self) -> Vec<(Family, String)> {
        [(Family::Ipv4, &self.ipv4_status), (Family::Ipv6, &self.ipv6_status)]
            .into_iter()
            .filter_map(|(family, status)| match status {
                HttpStatus::Failed(reason) => Some((family, reason.clone())),
                _ => None,
            })
            .collect()
    }

    /// Why every attempted family failed, e.g. `IPv4: operation timed out; IPv6: no IPv6 route
    /// on this host`. Families with no address are left out.
    pub fn failure(&self, protocol: Protocol) -> eyre::Report {
        family_failure(&self.family_failures(), protocol)
    }

    /// The target observation's failures as one line, `None` when no family failed.
    pub fn target_failure(&self) -> Option<String> {
        let failures = self.family_failures();
        (!failures.is_empty()).then(|| {
            failures
                .iter()
                .map(|(family, reason)| format!("{family}: {reason}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    pub fn get_primary_result(&self) -> Option<&HttpData> {
        // Prefer IPv4, then IPv6
        if let Some(ipv4_data) = &self.ipv4_result {
            Some(ipv4_data)
        } else if let Some(ipv6_data) = &self.ipv6_result {
            Some(ipv6_data)
        } else {
            None
        }
    }

    pub fn total_vulnerabilities(&self) -> usize {
        let ipv4_vulns = self.ipv4_result.as_ref().map(|r| r.vulnerabilities.len()).unwrap_or(0);
        let ipv6_vulns = self.ipv6_result.as_ref().map(|r| r.vulnerabilities.len()).unwrap_or(0);
        ipv4_vulns + ipv6_vulns
    }

    pub fn get_all_vulnerabilities(&self) -> Vec<&HttpVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Some(ipv4_data) = &self.ipv4_result {
            for vuln in &ipv4_data.vulnerabilities {
                if seen.insert(vuln) {
                    vulnerabilities.push(vuln);
                }
            }
        }
        if let Some(ipv6_data) = &self.ipv6_result {
            for vuln in &ipv6_data.vulnerabilities {
                if seen.insert(vuln) {
                    vulnerabilities.push(vuln);
                }
            }
        }

        vulnerabilities
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectInfo {
    pub from: String,
    pub to: String,
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub strict_transport_security: Option<String>,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspPolicy {
    pub header_value: String,
    pub directives: HashMap<String, Vec<String>>,
    pub issues: Vec<CspIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CspIssue {
    UnsafeInline(String),
    UnsafeEval(String),
    WildcardSource(String),
    MissingDirective(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub access_control_allow_origin: Option<String>,
    pub access_control_allow_methods: Vec<String>,
    pub access_control_allow_headers: Vec<String>,
    pub access_control_allow_credentials: bool,
    pub issues: Vec<CorsIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorsIssue {
    WildcardOrigin,
    WildcardMethods,
    WildcardHeaders,
    WildcardWithCredentials,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachingPolicy {
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum HttpVulnerability {
    MissingHsts,
    MissingXFrameOptions,
    MissingXContentTypeOptions,
    MissingCsp,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener that accepts and never answers, so a request to it times out. Accepted
    /// sockets are held open until the task is dropped with the runtime.
    async fn silent_listener() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok(Ok((socket, _))) = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await {
                held.push(socket);
            }
        });
        addr
    }

    #[test]
    fn classify_http_error_keeps_the_root_cause_per_family() {
        let error = eyre::Report::new(std::io::Error::from_raw_os_error(101)).wrap_err("error sending request");
        match HttpScanner::classify_http_error(&error, Family::Ipv6) {
            HttpStatus::Failed(reason) => assert_eq!(reason, "no IPv6 route on this host"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let error = eyre::eyre!("operation timed out").wrap_err("error sending request for url");
        match HttpScanner::classify_http_error(&error, Family::Ipv4) {
            HttpStatus::Failed(reason) => assert_eq!(reason, "operation timed out"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let error = eyre::eyre!("No IPv6 address available for target: x");
        assert!(matches!(
            HttpScanner::classify_http_error(&error, Family::Ipv6),
            HttpStatus::NoAddress
        ));
    }

    #[test]
    fn failure_names_each_attempted_family_and_skips_no_address() {
        let mut result = HttpResult::new(ObservatoryOutcome::Failed("site down".to_string()));
        result.ipv4_status = HttpStatus::Failed("operation timed out".to_string());
        result.ipv6_status = HttpStatus::Failed("no IPv6 route on this host".to_string());
        assert_eq!(
            result.failure(Protocol::Both).to_string(),
            "IPv4: operation timed out; IPv6: no IPv6 route on this host"
        );
        result.ipv6_status = HttpStatus::NoAddress;
        assert_eq!(result.failure(Protocol::Both).to_string(), "IPv4: operation timed out");
    }

    #[tokio::test]
    async fn timed_out_scan_renders_operation_timed_out_in_the_pane() {
        use crate::tui::HttpPane;
        use crate::tui::testing::render_pane;
        use crate::types::{AppState, ScanState, ScanStatus};
        use std::sync::{Arc, Mutex};

        let addr = silent_listener().await;
        let scanner = HttpScanner {
            timeout: Duration::from_millis(300),
            ..HttpScanner::new()
        };
        let mut target = Target::parse(&format!("http://{addr}/")).unwrap();
        target.resolve().await.unwrap();

        let outcome = Scanner::scan(&scanner, &target, Protocol::Ipv4).await;
        let error = outcome.as_ref().expect_err("a silent server must fail the scan");
        assert_eq!(error.to_string(), "IPv4: operation timed out");

        let state = Arc::new(Mutex::new(AppState::new(target.original.clone())));
        state.lock().unwrap().scanners.insert(
            "http".to_string(),
            ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        crate::scanner::record_outcome("http", 10, Protocol::Ipv4, Instant::now(), outcome, &state);

        let guard = state.lock().unwrap();
        let pane = render_pane(&HttpPane::new(), &guard, 100, 30, false);
        assert!(pane.contains("operation timed out"), "{pane}");
        assert!(!pane.contains("All HTTP attempts failed"), "{pane}");
    }

    #[test]
    fn test_csp_directive_parsing() {
        let scanner = HttpScanner::new();
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'";
        let directives = scanner.parse_csp_directives(csp);

        assert_eq!(directives.get("default-src"), Some(&vec!["'self'".to_string()]));
        assert_eq!(
            directives.get("script-src"),
            Some(&vec!["'self'".to_string(), "'unsafe-inline'".to_string()])
        );
        assert_eq!(directives.get("object-src"), Some(&vec!["'none'".to_string()]));
    }

    #[test]
    fn test_csp_issue_detection() {
        let scanner = HttpScanner::new();
        let mut directives = HashMap::new();
        directives.insert(
            "script-src".to_string(),
            vec!["'self'".to_string(), "'unsafe-inline'".to_string()],
        );
        directives.insert("style-src".to_string(), vec!["*".to_string()]);

        let issues = scanner.analyze_csp_issues(&directives);

        assert!(issues.iter().any(|i| matches!(i, CspIssue::UnsafeInline(_))));
        assert!(issues.iter().any(|i| matches!(i, CspIssue::WildcardSource(_))));
    }

    #[test]
    fn test_cors_issue_detection() {
        let scanner = HttpScanner::new();
        let origin = Some("*".to_string());
        let methods = vec!["GET".to_string(), "POST".to_string()];
        let headers = vec!["*".to_string()];
        let credentials = true;

        let issues = scanner.analyze_cors_issues(&origin, &methods, &headers, credentials);

        assert!(issues.iter().any(|i| matches!(i, CorsIssue::WildcardWithCredentials)));
        assert!(issues.iter().any(|i| matches!(i, CorsIssue::WildcardHeaders)));
    }

    #[test]
    fn test_security_header_parsing() {
        let scanner = HttpScanner::new();
        let mut headers = reqwest::header::HeaderMap::new();

        // Add security headers
        headers.insert(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
        headers.insert("x-frame-options", "DENY".parse().unwrap());
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
        headers.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
        headers.insert("permissions-policy", "geolocation=(), camera=()".parse().unwrap());

        let security_headers = scanner.analyze_security_headers(&headers);

        assert!(security_headers.strict_transport_security.is_some());
        assert!(security_headers.x_frame_options.is_some());
        assert!(security_headers.x_content_type_options.is_some());
        assert!(security_headers.x_xss_protection.is_some());
        assert!(security_headers.referrer_policy.is_some());
        assert!(security_headers.permissions_policy.is_some());

        assert_eq!(security_headers.x_frame_options.as_ref().unwrap(), "DENY");
        assert_eq!(security_headers.x_content_type_options.as_ref().unwrap(), "nosniff");
    }

    #[test]
    fn test_caching_policy_analysis() {
        let scanner = HttpScanner::new();
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert("cache-control", "max-age=3600, public".parse().unwrap());
        headers.insert("expires", "Wed, 21 Oct 2025 07:28:00 GMT".parse().unwrap());
        headers.insert("etag", "\"abc123\"".parse().unwrap());
        headers.insert("last-modified", "Wed, 21 Oct 2020 07:28:00 GMT".parse().unwrap());

        let caching = scanner.analyze_caching(&headers);

        assert!(caching.cache_control.is_some());
        assert!(caching.expires.is_some());
        assert!(caching.etag.is_some());
        assert!(caching.last_modified.is_some());

        assert_eq!(caching.cache_control.as_ref().unwrap(), "max-age=3600, public");
        assert_eq!(caching.etag.as_ref().unwrap(), "\"abc123\"");
    }

    #[test]
    fn test_redirect_info() {
        let redirect = RedirectInfo {
            from: "http://example.com".to_string(),
            to: "https://example.com".to_string(),
            status_code: 301,
        };

        assert_eq!(redirect.from, "http://example.com");
        assert_eq!(redirect.to, "https://example.com");
        assert_eq!(redirect.status_code, 301);
    }

    #[test]
    fn request_plan_keeps_github_host_for_url_target() {
        let target = Target::parse("https://github.com/scottidler/scan").unwrap();
        let plan = request_plan(&target).unwrap();
        assert_eq!(plan.primary.host_str(), Some("github.com"));
        assert_eq!(plan.primary.as_str(), "https://github.com/scottidler/scan");
        assert_eq!(plan.plain_http_fallback, None);
        assert_eq!(pinned_host(&plan.primary), Some("github.com"));
    }

    #[test]
    fn request_plan_uses_http_url_scheme_as_given() {
        let target = Target::parse("http://example.com/path").unwrap();
        let plan = request_plan(&target).unwrap();
        assert_eq!(plan.primary.as_str(), "http://example.com/path");
        assert_eq!(plan.plain_http_fallback, None);
    }

    #[test]
    fn request_plan_brackets_ipv6_ip_target() {
        let target = Target::parse("2606:4700:4700::1111").unwrap();
        let plan = request_plan(&target).unwrap();
        assert_eq!(plan.primary.as_str(), "https://[2606:4700:4700::1111]/");
        assert_eq!(
            plan.plain_http_fallback.as_ref().map(Url::as_str),
            Some("http://[2606:4700:4700::1111]/")
        );
        assert_eq!(pinned_host(&plan.primary), None);
    }

    #[test]
    fn request_plan_domain_target_keeps_hostname_and_falls_back_to_plain_http() {
        let target = Target::parse("google.com").unwrap();
        let plan = request_plan(&target).unwrap();
        assert_eq!(plan.primary.as_str(), "https://google.com/");
        assert_eq!(
            plan.plain_http_fallback.as_ref().map(Url::as_str),
            Some("http://google.com/")
        );
        assert_eq!(pinned_host(&plan.primary), Some("google.com"));
    }

    #[test]
    fn root_cause_returns_innermost_error() {
        let error = eyre::eyre!("connection refused").wrap_err("error sending request");
        assert_eq!(root_cause(&error), "connection refused");
    }

    /// Serves `connections` requests on loopback with a fixed plain-HTTP 200, returning each
    /// connection's raw request bytes. A TLS ClientHello gets the same plain-HTTP reply.
    async fn plain_http_server(connections: usize) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..connections {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                requests.push(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
                let _ = socket.shutdown().await;
            }
            requests
        });
        (port, handle)
    }

    #[tokio::test]
    async fn pinned_request_keeps_hostname_and_connects_to_pinned_ip() {
        let (port, server) = plain_http_server(1).await;
        let plan = RequestPlan {
            primary: Url::parse(&format!("http://pinned.invalid:{}/", port)).unwrap(),
            plain_http_fallback: None,
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let result = HttpScanner::new().scan_plan(&plan, ip).await.unwrap();

        assert_eq!(result.status_code, 200);
        assert_eq!(result.target_ip, "127.0.0.1");
        assert_eq!(result.https_failure, None);
        let requests = server.await.unwrap();
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains(&format!("host: pinned.invalid:{}", port)),
            "Host header should carry the name: {:?}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn https_failure_falls_back_to_plain_http_visibly() {
        let (port, server) = plain_http_server(2).await;
        let plan = RequestPlan {
            primary: Url::parse(&format!("https://pinned.invalid:{}/", port)).unwrap(),
            plain_http_fallback: Some(Url::parse(&format!("http://pinned.invalid:{}/", port)).unwrap()),
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let result = HttpScanner::new().scan_plan(&plan, ip).await.unwrap();

        assert!(result.url.starts_with("http://pinned.invalid"), "url={}", result.url);
        assert!(result.https_failure.is_some(), "fallback must record why HTTPS failed");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_url_target_does_not_fall_back() {
        let (port, server) = plain_http_server(1).await;
        let plan = RequestPlan {
            primary: Url::parse(&format!("https://pinned.invalid:{}/", port)).unwrap(),
            plain_http_fallback: None,
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        assert!(HttpScanner::new().scan_plan(&plan, ip).await.is_err());
        server.await.unwrap();
    }

    use crate::scan::cache::FETCH_TIMEOUT;
    use crate::scan::observatory::hsts::PRELOAD_CACHE_FILE;
    use crate::scan::observatory::session::transport::{ReqwestTransport, TransportOptions};
    use crate::scan::observatory::session::{IncomingResponse, OutgoingRequest, Transport, TransportError};
    use crate::scan::observatory::tests::google_com_result;
    use crate::scan::psl::{PSL_CACHE_FILE, PSL_FIXTURE};
    use crate::scan::testing::{FakeHttp, FakeRoute, dead_http_url, temp_dir};
    use std::sync::Arc;

    const SITE: &str = "site.com";

    async fn dead_port() -> u16 {
        Url::parse(&dead_http_url().await).unwrap().port().unwrap()
    }

    fn graded(host: &str) -> ObservatoryOutcome {
        let mut result = google_com_result();
        result.host = host.to_string();
        ObservatoryOutcome::Graded(result)
    }

    fn observation(ipv4: (HttpStatus, Option<HttpData>)) -> Observation {
        Observation {
            ipv4,
            ipv6: (HttpStatus::NotQueried, None),
        }
    }

    fn data() -> HttpData {
        HttpData {
            url: "https://site.com/".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(5),
            content_length: 2,
            content_type: None,
            redirect_chain: vec![],
            security_headers: SecurityHeaders {
                strict_transport_security: None,
                x_frame_options: None,
                x_content_type_options: None,
                x_xss_protection: None,
                referrer_policy: None,
                permissions_policy: None,
            },
            csp: None,
            cors: None,
            caching: CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![],
            scan_duration: Duration::from_millis(5),
            target_ip: "127.0.0.1".to_string(),
            https_failure: None,
        }
    }

    fn http_result(outcome: eyre::Result<ScanResult>) -> HttpResult {
        match outcome.expect("the scan returns Ok") {
            ScanResult::Http(result) => result,
            other => panic!("not an HTTP result: {other:?}"),
        }
    }

    #[test]
    fn the_scan_deadline_leaves_the_inner_budget_room_to_return_partial_results() {
        let scanner = HttpScanner::new();
        assert_eq!(Scanner::deadline(&scanner), Duration::from_secs(40));
        assert_eq!(scanner.budget, Duration::from_secs(35));
        assert!(scanner.budget < Scanner::deadline(&scanner));
    }

    #[test]
    fn assemble_returns_ok_when_the_url_fails_and_the_host_grades() {
        let failed = observation((HttpStatus::Failed("operation timed out".to_string()), None));
        let result = http_result(assemble(Protocol::Ipv4, failed, graded("example.com")));
        assert_eq!(result.target_failure().as_deref(), Some("IPv4: operation timed out"));
        assert_eq!(result.observatory.grade_text(), "C- (45) · example.com");
    }

    #[test]
    fn assemble_returns_ok_when_the_url_works_and_the_grade_fails() {
        let worked = observation((HttpStatus::Success, Some(data())));
        let result = http_result(assemble(
            Protocol::Ipv4,
            worked,
            ObservatoryOutcome::Failed("site down".to_string()),
        ));
        assert!(result.has_any_success());
        assert_eq!(result.observatory.grade_text(), "none (site down)");
    }

    #[test]
    fn assemble_returns_err_only_when_the_url_and_the_grade_both_fail() {
        let failed = || observation((HttpStatus::Failed("operation timed out".to_string()), None));
        let error = assemble(
            Protocol::Ipv4,
            failed(),
            ObservatoryOutcome::Failed("site down".to_string()),
        )
        .expect_err("both failed");
        assert_eq!(error.to_string(), "IPv4: operation timed out; grade: site down");

        // A host Observatory refuses is not a failure to mention: the URL's failure stands alone.
        let error = assemble(
            Protocol::Ipv4,
            failed(),
            ObservatoryOutcome::NotApplicable("IP address".to_string()),
        )
        .expect_err("the URL failed and nothing graded");
        assert_eq!(error.to_string(), "IPv4: operation timed out");

        // No address to probe stays the typed, not-a-fault error.
        let none = observation((HttpStatus::NoAddress, None));
        let error = assemble(
            Protocol::Ipv4,
            none,
            ObservatoryOutcome::NotApplicable("IP address".to_string()),
        )
        .expect_err("nothing to probe");
        assert!(error.downcast_ref::<crate::scan::NoAddress>().is_some(), "{error}");
    }

    #[test]
    fn observatory_host_is_the_urls_host_never_its_port_or_path() {
        for (input, expected) in [
            ("google.com", Ok("google.com")),
            ("https://example.com:8443/a/b?c=d", Ok("example.com")),
            ("www.tatari.tv", Ok("www.tatari.tv")),
            ("1.1.1.1", Err("IP address")),
            ("2606:4700:4700::1111", Err("IP address")),
            ("http://127.0.0.1:8080/", Err("IP address")),
            ("localhost", Err("not a public hostname")),
            ("http://localhost:3000/", Err("not a public hostname")),
        ] {
            let target = Target::parse(input).unwrap();
            assert_eq!(
                observatory_host(&target),
                expected.map(str::to_string).map_err(str::to_string),
                "{input}"
            );
        }
    }

    /// The lists a scan reads, served from a fake so nothing touches the network or `~/.cache`.
    struct Lists {
        fake: FakeHttp,
    }

    impl Lists {
        async fn new() -> Self {
            Self {
                fake: FakeHttp::start(vec![
                    ("/preload", 200, r#"{"entries": []}"#.to_string()),
                    ("/psl", 200, PSL_FIXTURE.to_string()),
                ])
                .await,
            }
        }

        fn client() -> reqwest::Client {
            reqwest::Client::builder().no_proxy().build().unwrap()
        }

        fn preload(&self) -> PreloadSource {
            PreloadSource::from_url(
                Self::client(),
                self.fake.url("/preload"),
                Some(temp_dir("http-preload")),
            )
        }

        fn suffixes(&self) -> SuffixList {
            SuffixList {
                client: Self::client(),
                url: self.fake.url("/psl"),
                cache_dir: Some(temp_dir("http-psl")),
                fetch_timeout: FETCH_TIMEOUT,
            }
        }
    }

    /// An Observatory retriever whose sessions reach `http_port` and `https_port` on loopback for
    /// `site.com`.
    fn retriever(http_port: u16, https_port: u16) -> Retriever {
        let transport = ReqwestTransport::new(&TransportOptions {
            built_in_roots: false,
            extra_roots: vec![],
            resolve: vec![(SITE.to_string(), "127.0.0.1:0".parse().unwrap())],
            env_proxy: false,
        })
        .unwrap();
        Retriever::new(Arc::new(transport)).with_ports(Some(http_port), Some(https_port))
    }

    fn site_target(port: u16) -> Target {
        let mut target = Target::parse(&format!("http://{SITE}:{port}/")).unwrap();
        target.update_resolved_ips(vec!["127.0.0.1".parse().unwrap()]);
        target
    }

    async fn page_server() -> FakeHttp {
        FakeHttp::start_routes(vec![
            FakeRoute::get("/", 200)
                .header("Content-Type", "text/html")
                .body("<html></html>"),
        ])
        .await
    }

    /// End to end over loopback: the URL as given and the host's grade both land in the result.
    #[tokio::test]
    async fn scan_grades_the_host_and_observes_the_url() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let scanner = HttpScanner::with_observatory(
            retriever(site.port(), dead_port().await),
            lists.preload(),
            lists.suffixes(),
        );

        let result = http_result(Scanner::scan(&scanner, &site_target(site.port()), Protocol::Ipv4).await);

        assert!(result.ipv4_status.is_success());
        let ObservatoryOutcome::Graded(graded) = &result.observatory else {
            panic!("the host should grade: {:?}", result.observatory);
        };
        assert_eq!(graded.host, SITE);
        assert_eq!(graded.tests.len(), 12);
        assert!(graded.preload_available);
        assert!(result.observatory.grade_text().ends_with(" · site.com"));
        let requests = site.requests();
        assert!(
            requests.iter().any(|r| r
                .header("user-agent")
                .is_some_and(|ua| ua.contains("Observatory/129.0"))),
            "Observatory's request shape: {requests:?}"
        );
        assert!(
            requests.iter().any(|r| r.header("user-agent") == Some("scan/1.0")),
            "the target observation's own request: {requests:?}"
        );
    }

    /// The doc's example: the URL's port times out, the host still grades; nothing is painted failed
    /// for the other's sake.
    #[tokio::test]
    async fn a_failed_url_with_a_working_grade_returns_ok_with_both() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let scanner = HttpScanner::with_observatory(
            retriever(site.port(), dead_port().await),
            lists.preload(),
            lists.suffixes(),
        );

        let result = http_result(Scanner::scan(&scanner, &site_target(dead_port().await), Protocol::Ipv4).await);

        assert!(
            matches!(result.ipv4_status, HttpStatus::Failed(_)),
            "{:?}",
            result.ipv4_status
        );
        assert!(result.get_primary_result().is_none());
        assert!(
            matches!(result.observatory, ObservatoryOutcome::Graded(_)),
            "{:?}",
            result.observatory
        );
    }

    #[tokio::test]
    async fn a_working_url_with_a_down_site_returns_ok_with_both() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let scanner = HttpScanner::with_observatory(
            retriever(dead_port().await, dead_port().await),
            lists.preload(),
            lists.suffixes(),
        );

        let result = http_result(Scanner::scan(&scanner, &site_target(site.port()), Protocol::Ipv4).await);

        assert!(result.ipv4_status.is_success());
        assert_eq!(result.observatory, ObservatoryOutcome::Failed("site down".to_string()));
        assert_eq!(result.observatory.grade_text(), "none (site down)");
    }

    #[tokio::test]
    async fn a_failed_url_and_a_down_site_return_err() {
        let lists = Lists::new().await;
        let scanner = HttpScanner::with_observatory(
            retriever(dead_port().await, dead_port().await),
            lists.preload(),
            lists.suffixes(),
        );

        let outcome = Scanner::scan(&scanner, &site_target(dead_port().await), Protocol::Ipv4).await;

        let error = outcome.expect_err("both parts failed");
        assert!(error.to_string().starts_with("IPv4: "), "{error}");
        assert!(error.to_string().ends_with("; grade: site down"), "{error}");
    }

    /// An IP target gets no grade and no Observatory traffic at all.
    #[tokio::test]
    async fn an_ip_target_is_not_graded_and_sends_no_observatory_request() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let scanner = HttpScanner::with_observatory(
            retriever(site.port(), dead_port().await),
            lists.preload(),
            lists.suffixes(),
        );
        let mut target = Target::parse(&format!("http://127.0.0.1:{}/", site.port())).unwrap();
        target.resolve().await.unwrap();

        let result = http_result(Scanner::scan(&scanner, &target, Protocol::Ipv4).await);

        assert_eq!(
            result.observatory,
            ObservatoryOutcome::NotApplicable("IP address".to_string())
        );
        assert!(result.ipv4_status.is_success());
        assert!(
            site.requests()
                .iter()
                .all(|r| r.header("user-agent") == Some("scan/1.0")),
            "only the target observation's request: {:?}",
            site.requests()
        );
    }

    #[tokio::test]
    async fn a_missing_preload_list_grades_and_says_so() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let dead_list = PreloadSource::from_url(Lists::client(), dead_http_url().await, None);
        let scanner =
            HttpScanner::with_observatory(retriever(site.port(), dead_port().await), dead_list, lists.suffixes());

        let result = http_result(Scanner::scan(&scanner, &site_target(site.port()), Protocol::Ipv4).await);

        let ObservatoryOutcome::Graded(graded) = &result.observatory else {
            panic!("a missing list must not stop the grade: {:?}", result.observatory);
        };
        assert!(!graded.preload_available);
        assert!(result.observatory.grade_text().ends_with(" · preload list unavailable"));
    }

    /// The cookie jars need the public suffix list; without it the run fails loudly, not silently
    /// with a wrong jar.
    #[tokio::test]
    async fn a_missing_suffix_list_fails_the_grade_with_its_reason() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let dead_list = SuffixList {
            client: Lists::client(),
            url: dead_http_url().await,
            cache_dir: None,
            fetch_timeout: FETCH_TIMEOUT,
        };
        let scanner =
            HttpScanner::with_observatory(retriever(site.port(), dead_port().await), lists.preload(), dead_list);

        let result = http_result(Scanner::scan(&scanner, &site_target(site.port()), Protocol::Ipv4).await);

        let ObservatoryOutcome::Failed(reason) = &result.observatory else {
            panic!("{:?}", result.observatory);
        };
        assert!(reason.starts_with("public suffix list unavailable"), "{reason}");
        assert!(result.ipv4_status.is_success());
    }

    /// A transport that never answers.
    struct Stalled;

    #[async_trait]
    impl Transport for Stalled {
        async fn send(&self, _request: OutgoingRequest) -> Result<IncomingResponse, TransportError> {
            std::future::pending().await
        }
    }

    /// The budget returns what finished: a stalled Observatory run costs only its own part.
    #[tokio::test]
    async fn a_stalled_grade_returns_the_target_observation_at_the_budget() {
        let (site, lists) = (page_server().await, Lists::new().await);
        let mut scanner =
            HttpScanner::with_observatory(Retriever::new(Arc::new(Stalled)), lists.preload(), lists.suffixes());
        scanner.budget = Duration::from_millis(600);

        let started = Instant::now();
        let result = http_result(Scanner::scan(&scanner, &site_target(site.port()), Protocol::Ipv4).await);

        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(result.ipv4_status.is_success(), "{:?}", result.ipv4_status);
        assert_eq!(result.observatory, ObservatoryOutcome::Failed("timed out".to_string()));
    }

    /// Stalled sessions hit their own 9s request cap, far inside the 35s budget and the runner's
    /// 40s: the budget is the backstop, not the usual limit.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_observatory_run_ends_at_the_session_cap_inside_the_budget() {
        // Warm caches serve both lists from disk, so no socket races the paused clock.
        let (preload_dir, psl_dir) = (temp_dir("http-warm-preload"), temp_dir("http-warm-psl"));
        std::fs::write(preload_dir.join(PRELOAD_CACHE_FILE), r#"{"entries": []}"#).unwrap();
        std::fs::write(psl_dir.join(PSL_CACHE_FILE), PSL_FIXTURE).unwrap();
        let preload = PreloadSource::from_url(Lists::client(), dead_http_url().await, Some(preload_dir));
        let suffixes = SuffixList {
            client: Lists::client(),
            url: dead_http_url().await,
            cache_dir: Some(psl_dir),
            fetch_timeout: FETCH_TIMEOUT,
        };
        let mut target = Target::parse("stalled.example.com").unwrap();
        target.update_resolved_ips(vec![]);
        let scanner = HttpScanner::with_observatory(Retriever::new(Arc::new(Stalled)), preload, suffixes);

        let started = tokio::time::Instant::now();
        let error = Scanner::scan(&scanner, &target, Protocol::Ipv4)
            .await
            .expect_err("no address and no grade");

        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(9), "{elapsed:?}");
        assert!(elapsed < scanner.budget, "{elapsed:?}");
        assert!(error.to_string().ends_with("grade: site down"), "{error}");
    }
}
