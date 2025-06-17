use crate::scanner::Scanner;
use crate::target::Target;
use crate::types::{AppState, ScanResult, ScanState, ScanStatus};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use url::Url;

#[derive(Debug, Clone)]
pub struct HttpScanner {
    client: Client,
    timeout: Duration,
}

impl Default for HttpScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpScanner {
    pub fn new() -> Self {
        log::debug!("[scan::http] new: timeout=10s");
        
        let timeout = Duration::from_secs(10);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent("scan/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            timeout,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn scan_http(&self, target: &Target) -> eyre::Result<HttpResult> {
        log::debug!("[scan::http] scan_http: target={}", target.display_name());
        
        let scan_start = Instant::now();
        
        // Determine URL to scan
        let url = match &target.target_type {
            crate::target::TargetType::Url(url) => url.to_string(),
            _ => {
                // For domains and IPs, try both HTTP and HTTPS
                let domain = target.display_name();
                let https_url = format!("https://{}", domain);
                let http_url = format!("http://{}", domain);
                
                log::debug!("[scan::http] trying_https_first: url={}", https_url);
                
                // Try HTTPS first
                match self.perform_scan(&https_url).await {
                    Ok(mut result) => {
                        result.scan_duration = scan_start.elapsed();
                        log::trace!("[scan::http] https_scan_successful: url={} status={} duration={}ms", 
                            https_url, result.status_code, result.scan_duration.as_millis());
                        return Ok(result);
                    }
                    Err(e) => {
                        log::debug!("[scan::http] https_failed_trying_http: https_error={} http_url={}", e, http_url);
                        // Fall back to HTTP
                        match self.perform_scan(&http_url).await {
                            Ok(mut result) => {
                                result.scan_duration = scan_start.elapsed();
                                log::trace!("[scan::http] http_scan_successful: url={} status={} duration={}ms", 
                                    http_url, result.status_code, result.scan_duration.as_millis());
                                return Ok(result);
                            }
                            Err(http_err) => {
                                log::error!("[scan::http] both_protocols_failed: https_error={} http_error={}", e, http_err);
                                return Err(http_err);
                            }
                        }
                    }
                }
            }
        };

        let mut result = self.perform_scan(&url).await?;
        result.scan_duration = scan_start.elapsed();
        
        log::debug!("[scan::http] scan_completed: url={} status={} duration={}ms grade={:?}", 
            url, result.status_code, result.scan_duration.as_millis(), result.security_grade);
        
        Ok(result)
    }

    async fn perform_scan(&self, url: &str) -> eyre::Result<HttpResult> {
        log::debug!("[scan::http] perform_scan: url={}", url);
        
        let start_time = Instant::now();
        let original_url = Url::parse(url)?;
        
        log::trace!("[scan::http] sending_request: url={}", url);
        let request_start = Instant::now();
        let response = self.client.get(url).send().await?;
        let request_duration = request_start.elapsed();
        
        let status_code = response.status().as_u16();
        let final_url = response.url().clone();
        let headers = response.headers().clone();
        
        log::trace!("[scan::http] response_received: url={} status={} request_duration={}ms final_url={}", 
            url, status_code, request_duration.as_millis(), final_url);

        // Analyze redirects
        let redirect_chain = self.analyze_redirects(&original_url, &final_url);
        log::trace!("[scan::http] redirect_analysis: url={} redirect_count={}", url, redirect_chain.len());

        // Get response body for content analysis
        let body_start = Instant::now();
        let body = response.bytes().await?;
        let body_duration = body_start.elapsed();
        let content_length = body.len();
        
        log::trace!("[scan::http] body_received: url={} content_length={} body_duration={}ms", 
            url, content_length, body_duration.as_millis());

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
        
        let vulnerabilities = self.assess_vulnerabilities(&security_headers, &csp, &cors);
        let security_grade = self.calculate_security_grade(&security_headers, &csp, &cors, &vulnerabilities);
        
        let security_duration = security_start.elapsed();
        log::trace!("[scan::http] security_analysis_completed: url={} duration={}μs grade={:?} vulnerabilities={}", 
            url, security_duration.as_micros(), security_grade, vulnerabilities.len());

        let result = HttpResult {
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
            security_grade,
            scan_duration: start_time.elapsed(),
        };

        log::debug!("[scan::http] scan_result: url={} status={} content_length={} security_grade={:?}", 
            result.url, result.status_code, result.content_length, result.security_grade);

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
            status_code: 301, // Assumption - would need to track actual codes
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
        let strength = self.calculate_csp_strength(&directives, &issues);

        Some(CspPolicy {
            header_value: csp_header.to_string(),
            directives,
            issues,
            strength,
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

    fn calculate_csp_strength(&self, directives: &HashMap<String, Vec<String>>, issues: &[CspIssue]) -> CspStrength {
        let directive_count = directives.len();
        let issue_count = issues.len();
        
        if directive_count == 0 {
            return CspStrength::None;
        }
        
        if issue_count == 0 && directive_count >= 5 {
            CspStrength::Strong
        } else if issue_count <= 2 && directive_count >= 3 {
            CspStrength::Moderate
        } else {
            CspStrength::Weak
        }
    }

    fn analyze_cors(&self, headers: &reqwest::header::HeaderMap) -> Option<CorsPolicy> {
        let access_control_allow_origin = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Check for any CORS-related headers, not just allow-origin
        let has_cors_headers = access_control_allow_origin.is_some() ||
            headers.contains_key("access-control-allow-methods") ||
            headers.contains_key("access-control-allow-headers") ||
            headers.contains_key("access-control-allow-credentials") ||
            headers.contains_key("access-control-expose-headers") ||
            headers.contains_key("access-control-max-age");

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

        let security_level = self.calculate_cors_security(&access_control_allow_origin, &issues);

        Some(CorsPolicy {
            access_control_allow_origin,
            access_control_allow_methods,
            access_control_allow_headers,
            access_control_allow_credentials,
            issues,
            security_level,
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

        if let Some(origin) = origin {
            if origin == "*" {
                if credentials {
                    issues.push(CorsIssue::WildcardWithCredentials);
                } else {
                    issues.push(CorsIssue::WildcardOrigin);
                }
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

    fn calculate_cors_security(&self, _origin: &Option<String>, issues: &[CorsIssue]) -> CorsSecurityLevel {
        if issues.iter().any(|i| matches!(i, CorsIssue::WildcardWithCredentials)) {
            return CorsSecurityLevel::Dangerous;
        }

        if issues.len() >= 2 {
            CorsSecurityLevel::Weak
        } else if issues.len() == 1 {
            CorsSecurityLevel::Moderate
        } else {
            CorsSecurityLevel::Secure
        }
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
            etag: headers
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            last_modified: headers
                .get("last-modified")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }

    fn assess_vulnerabilities(
        &self,
        security_headers: &SecurityHeaders,
        csp: &Option<CspPolicy>,
        cors: &Option<CorsPolicy>,
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

        // CSP issues
        if csp.is_none() {
            vulnerabilities.push(HttpVulnerability::MissingCsp);
        } else if let Some(csp_policy) = csp {
            if matches!(csp_policy.strength, CspStrength::Weak | CspStrength::None) {
                vulnerabilities.push(HttpVulnerability::WeakCsp);
            }
        }

        // CORS issues
        if let Some(cors_policy) = cors {
            if matches!(cors_policy.security_level, CorsSecurityLevel::Dangerous) {
                vulnerabilities.push(HttpVulnerability::InsecureCors);
            }
        }

        vulnerabilities
    }

    fn calculate_security_grade(
        &self,
        security_headers: &SecurityHeaders,
        csp: &Option<CspPolicy>,
        cors: &Option<CorsPolicy>,
        vulnerabilities: &[HttpVulnerability],
    ) -> SecurityGrade {
        let mut score = 100;

        // Deduct points for missing security headers
        if security_headers.strict_transport_security.is_none() {
            score -= 15;
        }
        if security_headers.x_frame_options.is_none() {
            score -= 10;
        }
        if security_headers.x_content_type_options.is_none() {
            score -= 5;
        }
        if security_headers.x_xss_protection.is_none() {
            score -= 5;
        }

        // CSP scoring
        match csp {
            None => score -= 20,
            Some(csp_policy) => match csp_policy.strength {
                CspStrength::None => score -= 20,
                CspStrength::Weak => score -= 15,
                CspStrength::Moderate => score -= 5,
                CspStrength::Strong => {} // No deduction
            },
        }

        // CORS scoring
        if let Some(cors_policy) = cors {
            match cors_policy.security_level {
                CorsSecurityLevel::Dangerous => score -= 25,
                CorsSecurityLevel::Weak => score -= 10,
                CorsSecurityLevel::Moderate => score -= 5,
                CorsSecurityLevel::Secure => {} // No deduction
            }
        }

        // Additional vulnerability penalties
        for vulnerability in vulnerabilities {
            match vulnerability {
                HttpVulnerability::InsecureCors => score -= 20,
                HttpVulnerability::WeakCsp => score -= 15,
                HttpVulnerability::MissingHsts => score -= 10,
                _ => score -= 5,
            }
        }

        match score {
            90..=100 => SecurityGrade::APlus,
            80..=89 => SecurityGrade::A,
            70..=79 => SecurityGrade::B,
            60..=69 => SecurityGrade::C,
            50..=59 => SecurityGrade::D,
            _ => SecurityGrade::F,
        }
    }
}

#[async_trait::async_trait]
impl Scanner for HttpScanner {
    fn name(&self) -> &'static str {
        "http"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(300) // 5 minutes
    }

    async fn scan(&self, target: &Target) -> eyre::Result<ScanResult> {
        log::debug!("[scan::http] scan: target={}", target.display_name());
        
        let scan_start = Instant::now();
        match self.scan_http(target).await {
            Ok(result) => {
                let scan_duration = scan_start.elapsed();
                log::trace!("[scan::http] http_scan_completed: target={} duration={}ms status={} grade={:?} vulnerabilities={}", 
                    target.display_name(), scan_duration.as_millis(), result.status_code, 
                    result.security_grade, result.vulnerabilities.len());
                Ok(ScanResult::Http(result))
            }
            Err(e) => {
                let scan_duration = scan_start.elapsed();
                log::error!("[scan::http] http_scan_failed: target={} duration={}ms error={}", 
                    target.display_name(), scan_duration.as_millis(), e);
                Err(e)
            }
        }
    }

    async fn run(&self, target: Target, state: Arc<AppState>) {
        loop {
            let scan_start = Instant::now();
            
            match self.scan_http(&target).await {
                Ok(result) => {
                    let scan_state = ScanState {
                        result: Some(ScanResult::Http(result.clone())),
                        error: None,
                        status: ScanStatus::Complete,
                        last_updated: scan_start,
                        history: {
                            let mut history = std::collections::VecDeque::new();
                            history.push_back(crate::types::TimestampedResult {
                                timestamp: scan_start,
                                result: ScanResult::Http(result),
                            });
                            history
                        },
                    };
                    state.scanners.insert(self.name().to_string(), scan_state);
                }
                Err(e) => {
                    let scan_state = ScanState {
                        result: None,
                        error: Some(e),
                        status: ScanStatus::Failed,
                        last_updated: scan_start,
                        history: std::collections::VecDeque::new(),
                    };
                    state.scanners.insert(self.name().to_string(), scan_state);
                }
            }

            sleep(self.interval()).await;
        }
    }
}

// Data structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
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
    pub security_grade: SecurityGrade,
    pub scan_duration: Duration,
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
    pub strength: CspStrength,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CspIssue {
    UnsafeInline(String),
    UnsafeEval(String),
    WildcardSource(String),
    MissingDirective(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CspStrength {
    None,
    Weak,
    Moderate,
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub access_control_allow_origin: Option<String>,
    pub access_control_allow_methods: Vec<String>,
    pub access_control_allow_headers: Vec<String>,
    pub access_control_allow_credentials: bool,
    pub issues: Vec<CorsIssue>,
    pub security_level: CorsSecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorsIssue {
    WildcardOrigin,
    WildcardMethods,
    WildcardHeaders,
    WildcardWithCredentials,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CorsSecurityLevel {
    Secure,
    Moderate,
    Weak,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachingPolicy {
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpVulnerability {
    MissingHsts,
    MissingXFrameOptions,
    MissingXContentTypeOptions,
    MissingCsp,
    WeakCsp,
    InsecureCors,
    InformationDisclosure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityGrade {
    APlus,
    A,
    B,
    C,
    D,
    F,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_directive_parsing() {
        let scanner = HttpScanner::new();
        let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'";
        let directives = scanner.parse_csp_directives(csp);
        
        assert_eq!(directives.get("default-src"), Some(&vec!["'self'".to_string()]));
        assert_eq!(directives.get("script-src"), Some(&vec!["'self'".to_string(), "'unsafe-inline'".to_string()]));
        assert_eq!(directives.get("object-src"), Some(&vec!["'none'".to_string()]));
    }

    #[test]
    fn test_csp_issue_detection() {
        let scanner = HttpScanner::new();
        let mut directives = HashMap::new();
        directives.insert("script-src".to_string(), vec!["'self'".to_string(), "'unsafe-inline'".to_string()]);
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
    fn test_security_grade_calculation() {
        let scanner = HttpScanner::new();
        
        // Perfect security headers
        let security_headers = SecurityHeaders {
            strict_transport_security: Some("max-age=31536000".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=()".to_string()),
        };
        
        let csp = Some(CspPolicy {
            header_value: "default-src 'self'".to_string(),
            directives: HashMap::new(),
            issues: vec![],
            strength: CspStrength::Strong,
        });
        
        let cors = None;
        let vulnerabilities = vec![];
        
        let grade = scanner.calculate_security_grade(&security_headers, &csp, &cors, &vulnerabilities);
        assert!(matches!(grade, SecurityGrade::APlus));
    }

    #[test]
    fn test_vulnerability_assessment() {
        let scanner = HttpScanner::new();
        
        let security_headers = SecurityHeaders {
            strict_transport_security: None,
            x_frame_options: None,
            x_content_type_options: None,
            x_xss_protection: None,
            referrer_policy: None,
            permissions_policy: None,
        };
        
        let csp = None;
        let cors = Some(CorsPolicy {
            access_control_allow_origin: Some("*".to_string()),
            access_control_allow_methods: vec![],
            access_control_allow_headers: vec![],
            access_control_allow_credentials: true,
            issues: vec![CorsIssue::WildcardWithCredentials],
            security_level: CorsSecurityLevel::Dangerous,
        });
        
        let vulnerabilities = scanner.assess_vulnerabilities(&security_headers, &csp, &cors);
        
        assert!(vulnerabilities.contains(&HttpVulnerability::MissingHsts));
        assert!(vulnerabilities.contains(&HttpVulnerability::MissingXFrameOptions));
        assert!(vulnerabilities.contains(&HttpVulnerability::MissingCsp));
        assert!(vulnerabilities.contains(&HttpVulnerability::InsecureCors));
    }
} 