use crate::tui::pane::{create_block, Pane};
use crate::types::AppState;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};
use std::any::Any;
use log;

/// SECURITY pane displays TLS/SSL certificate information and security analysis
pub struct SecurityPane {
    title: &'static str,
    id: &'static str,
    scroll_offset: u16,
}

impl SecurityPane {
    pub fn new() -> Self {
        log::debug!("[tui::security] new:");
        Self {
            title: "security",
            id: "security",
            scroll_offset: 0,
        }
    }
    
    pub fn scroll_up(&mut self) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
        log::debug!("[tui::security] scroll_up: old_offset={} new_offset={}", 
            old_offset, self.scroll_offset);
    }
    
    pub fn scroll_down_smart(&mut self, state: &AppState, visible_height: u16) {
        // Use the SINGLE SOURCE OF TRUTH for content calculation
        let lines = self.build_content_lines(state);
        let actual_lines = lines.len() as u16;
        
        let old_offset = self.scroll_offset;
        if actual_lines > visible_height {
            let max_scroll = actual_lines.saturating_sub(visible_height);
            if self.scroll_offset < max_scroll {
                self.scroll_offset += 1;
            }
        }
        
        log::debug!("[tui::security] scroll_down_smart: old_offset={} new_offset={} actual_lines={} visible_height={} max_scroll={}", 
            old_offset, self.scroll_offset, actual_lines, visible_height, 
            actual_lines.saturating_sub(visible_height));
    }
    
    pub fn reset_scroll(&mut self) {
        let old_offset = self.scroll_offset;
        self.scroll_offset = 0;
        log::debug!("[tui::security] reset_scroll: old_offset={}", old_offset);
    }
    
    /// Build the actual content lines - SINGLE SOURCE OF TRUTH
    /// This method is used by both scroll calculation and rendering
    fn build_content_lines(&self, state: &AppState) -> Vec<Line> {
        log::trace!("[tui::security] build_content_lines: building security analysis content");
        
        let mut lines = Vec::new();
        
        // Security status header
        lines.push(Line::from(vec![
            Span::styled("🔒 SECURITY: ", Style::default().fg(Color::Cyan)),
            Span::styled("analyzing...", Style::default().fg(Color::Yellow)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Extract TLS data upfront
        let tls_data = if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(crate::types::ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                Some((
                    tls_result.connection_successful,
                    tls_result.negotiated_version.as_ref().map(|v| v.as_str().to_string()),
                    tls_result.negotiated_cipher.as_ref().map(|c| c.name.clone()),
                    tls_result.perfect_forward_secrecy,
                    tls_result.ocsp_stapling,
                    tls_result.certificate_valid,
                    tls_result.days_until_expiry,
                    tls_result.security_grade.as_str().to_string(),
                    tls_result.vulnerabilities.len(),
                    tls_result.certificate_chain.first().map(|cert| (
                        cert.subject.clone(),
                        cert.issuer.clone(),
                        cert.public_key_algorithm.clone(),
                        cert.key_size,
                        cert.san_domains.len()
                    ))
                ))
            } else {
                None
            }
        } else {
            None
        };
        
        // Extract HTTP data upfront
        let http_data = if let Some(http_state) = state.scanners.get("http") {
            if let Some(crate::types::ScanResult::Http(http_result)) = http_state.result.as_ref() {
                Some((
                    http_result.security_headers.strict_transport_security.is_some(),
                    http_result.security_headers.x_frame_options.clone().unwrap_or_else(|| "missing".to_string()),
                    http_result.security_headers.x_content_type_options.clone().unwrap_or_else(|| "missing".to_string()),
                    http_result.security_headers.x_xss_protection.clone().unwrap_or_else(|| "missing".to_string()),
                    http_result.security_headers.referrer_policy.clone().unwrap_or_else(|| "missing".to_string()),
                    http_result.security_headers.permissions_policy.clone().unwrap_or_else(|| "missing".to_string()),
                    http_result.csp.as_ref().map(|csp| (
                        csp.strength.clone(),
                        csp.header_value.clone(),
                        csp.issues.iter().take(3).map(|issue| match issue {
                            crate::scan::http::CspIssue::UnsafeInline(directive) => format!("unsafe-inline in {}", directive),
                            crate::scan::http::CspIssue::UnsafeEval(directive) => format!("unsafe-eval in {}", directive),
                            crate::scan::http::CspIssue::WildcardSource(directive) => format!("wildcard in {}", directive),
                            crate::scan::http::CspIssue::MissingDirective(directive) => format!("missing {}", directive),
                        }).collect::<Vec<_>>()
                    )),
                    http_result.cors.as_ref().map(|cors| (
                        cors.security_level.clone(),
                        cors.access_control_allow_origin.clone(),
                        cors.access_control_allow_methods.clone(),
                        cors.access_control_allow_credentials,
                        cors.issues.iter().take(3).map(|issue| match issue {
                            crate::scan::http::CorsIssue::WildcardOrigin => "wildcard origin".to_string(),
                            crate::scan::http::CorsIssue::WildcardMethods => "wildcard methods".to_string(),
                            crate::scan::http::CorsIssue::WildcardHeaders => "wildcard headers".to_string(),
                            crate::scan::http::CorsIssue::WildcardWithCredentials => "wildcard + credentials".to_string(),
                        }).collect::<Vec<_>>()
                    )),
                    http_result.vulnerabilities.iter().take(5).map(|vuln| match vuln {
                        crate::scan::http::HttpVulnerability::MissingHsts => "Missing HSTS header".to_string(),
                        crate::scan::http::HttpVulnerability::MissingXFrameOptions => "Missing X-Frame-Options".to_string(),
                        crate::scan::http::HttpVulnerability::MissingXContentTypeOptions => "Missing X-Content-Type-Options".to_string(),
                        crate::scan::http::HttpVulnerability::MissingCsp => "Missing Content Security Policy".to_string(),
                        crate::scan::http::HttpVulnerability::WeakCsp => "Weak Content Security Policy".to_string(),
                        crate::scan::http::HttpVulnerability::InsecureCors => "Insecure CORS configuration".to_string(),
                        crate::scan::http::HttpVulnerability::InformationDisclosure => "Information disclosure risk".to_string(),
                    }).collect::<Vec<_>>(),
                    format!("{:?}", http_result.security_grade)
                ))
            } else {
                None
            }
        } else {
            None
        };
        
        // Extract DNS data upfront
        let dns_data = if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(crate::types::ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                dns_result.email_security.as_ref().map(|email_security| (
                    email_security.spf_record.clone(),
                    email_security.dmarc_record.clone(),
                    email_security.dkim_domains.clone(),
                    email_security.mx_count,
                    email_security.has_mx
                ))
            } else {
                None
            }
        } else {
            None
        };
        
        // Extract TLS vulnerability details
        let tls_vulnerabilities = if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(crate::types::ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                Some(tls_result.vulnerabilities.iter().take(5).map(|vuln| match vuln {
                    crate::scan::tls::TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
                    crate::scan::tls::TlsVulnerability::Poodle => "POODLE (CVE-2014-3566)".to_string(),
                    crate::scan::tls::TlsVulnerability::Beast => "BEAST (CVE-2011-3389)".to_string(),
                    crate::scan::tls::TlsVulnerability::Crime => "CRIME (CVE-2012-4929)".to_string(),
                    crate::scan::tls::TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
                    crate::scan::tls::TlsVulnerability::ExpiredCertificate => "Certificate expired".to_string(),
                    crate::scan::tls::TlsVulnerability::SelfSignedCertificate => "Self-signed certificate".to_string(),
                    crate::scan::tls::TlsVulnerability::WeakSignatureAlgorithm(alg) => format!("Weak signature: {}", alg),
                    crate::scan::tls::TlsVulnerability::InsecureRenegotiation => "Insecure renegotiation".to_string(),
                    crate::scan::tls::TlsVulnerability::WeakDhParams => "Weak DH parameters".to_string(),
                    crate::scan::tls::TlsVulnerability::SslV2Enabled => "SSLv2 enabled".to_string(),
                    crate::scan::tls::TlsVulnerability::SslV3Enabled => "SSLv3 enabled".to_string(),
                }).collect::<Vec<_>>())
            } else {
                None
            }
        } else {
            None
        };
        
        // Now build the UI with owned data
        if let Some((connection_successful, negotiated_version, negotiated_cipher, pfs, ocsp, cert_valid, days_until_expiry, security_grade, vuln_count, cert_info)) = tls_data {
            // Update header based on status
            lines[0] = Line::from(vec![
                Span::styled("🔒 SECURITY: ", Style::default().fg(Color::Cyan)),
                Span::styled("analyzed", Style::default().fg(Color::Green)),
            ]);
            
            // TLS Connection
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                Span::styled(
                    if connection_successful { "connected" } else { "failed" },
                    Style::default().fg(if connection_successful { Color::Green } else { Color::Red })
                ),
            ]));
            
            // TLS Version
            if let Some(version) = negotiated_version {
                lines.push(Line::from(vec![
                    Span::styled("🔐 Version: ", Style::default().fg(Color::White)),
                    Span::styled(
                        version,
                        Style::default().fg(Color::Green)
                    ),
                ]));
            }
            
            // Cipher Suite
            if let Some(cipher) = negotiated_cipher {
                lines.push(Line::from(vec![
                    Span::styled("🔑 Cipher: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if cipher.len() > 25 { format!("{}...", &cipher[..22]) } else { cipher },
                        Style::default().fg(Color::Yellow)
                    ),
                ]));
            }
            
            // Security Features
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("🛡️ Security Features", Style::default().fg(Color::Cyan)),
            ]));
            
            lines.push(Line::from(vec![
                Span::styled("  PFS: ", Style::default().fg(Color::White)),
                Span::styled(
                    if pfs { "yes" } else { "no" },
                    Style::default().fg(if pfs { Color::Green } else { Color::Red })
                ),
            ]));
            
            lines.push(Line::from(vec![
                Span::styled("  OCSP: ", Style::default().fg(Color::White)),
                Span::styled(
                    if ocsp { "yes" } else { "no" },
                    Style::default().fg(if ocsp { Color::Green } else { Color::Yellow })
                ),
            ]));
            
            // Certificate Details
            if let Some((subject, issuer, key_algo, key_size, san_count)) = cert_info {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("📜 Certificate Details", Style::default().fg(Color::Cyan)),
                ]));
                
                let cert_color = if cert_valid { Color::Green } else { Color::Red };
                
                lines.push(Line::from(vec![
                    Span::styled("  Valid: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if cert_valid { "yes" } else { "no" },
                        Style::default().fg(cert_color)
                    ),
                ]));
                
                // Subject (extract CN)
                let subject_display = if let Some(cn_start) = subject.find("CN=") {
                    let cn_part = &subject[cn_start + 3..];
                    if let Some(comma) = cn_part.find(',') {
                        &cn_part[..comma.min(25)]
                    } else {
                        &cn_part[..cn_part.len().min(25)]
                    }
                } else {
                    "unknown"
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  Subject: ", Style::default().fg(Color::White)),
                    Span::styled(subject_display.to_string(), Style::default().fg(Color::Yellow)),
                ]));
                
                // Issuer (extract CN)
                let issuer_display = if let Some(cn_start) = issuer.find("CN=") {
                    let cn_part = &issuer[cn_start + 3..];
                    if let Some(comma) = cn_part.find(',') {
                        &cn_part[..comma.min(25)]
                    } else {
                        &cn_part[..cn_part.len().min(25)]
                    }
                } else {
                    "unknown"
                };
                
                lines.push(Line::from(vec![
                    Span::styled("  Issuer: ", Style::default().fg(Color::White)),
                    Span::styled(issuer_display.to_string(), Style::default().fg(Color::Green)),
                ]));
                
                // Certificate expiry
                if let Some(days_until_expiry) = days_until_expiry {
                    let expiry_color = if days_until_expiry > 30 {
                        Color::Green
                    } else if days_until_expiry > 7 {
                        Color::Yellow
                    } else {
                        Color::Red
                    };
                    
                    lines.push(Line::from(vec![
                        Span::styled("  Expires: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{} days", days_until_expiry),
                            Style::default().fg(expiry_color)
                        ),
                    ]));
                }
                
                // Key algorithm and size
                lines.push(Line::from(vec![
                    Span::styled("  Key: ", Style::default().fg(Color::White)),
                    Span::styled(
                        key_algo,
                        Style::default().fg(Color::Yellow)
                    ),
                    Span::styled(
                        key_size.map_or(String::new(), |size| format!(" {}bit", size)),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
                
                // SAN domains count
                if san_count > 0 {
                    lines.push(Line::from(vec![
                        Span::styled("  SAN: ", Style::default().fg(Color::White)),
                        Span::styled(
                            format!("{} domains", san_count),
                            Style::default().fg(Color::Green)
                        ),
                    ]));
                }
            }
            
            // Grade and vulnerabilities
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📊 Grade: ", Style::default().fg(Color::White)),
                Span::styled(
                    security_grade.clone(),
                    Style::default().fg(match security_grade.as_str() {
                        "A+" | "A" => Color::Green,
                        "B" => Color::Yellow,
                        _ => Color::Red,
                    })
                ),
            ]));
            
            lines.push(Line::from(vec![
                Span::styled("⚠️ Issues: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}", vuln_count),
                    Style::default().fg(if vuln_count == 0 { Color::Green } else { Color::Red })
                ),
            ]));
            
        } else if state.scanners.contains_key("tls") {
            // TLS scanner exists but no result yet
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                Span::styled("checking...", Style::default().fg(Color::Gray)),
            ]));
            
            lines.push(Line::from(vec![
                Span::styled("🔐 Version: ", Style::default().fg(Color::White)),
                Span::styled("detecting...", Style::default().fg(Color::Gray)),
            ]));
            
            lines.push(Line::from(vec![
                Span::styled("📜 Cert: ", Style::default().fg(Color::White)),
                Span::styled("validating...", Style::default().fg(Color::Gray)),
            ]));
        } else {
            // No TLS scanner available
            lines[0] = Line::from(vec![
                Span::styled("🔒 SECURITY: ", Style::default().fg(Color::Cyan)),
                Span::styled("unavailable", Style::default().fg(Color::Red)),
            ]);
            
            lines.push(Line::from(vec![
                Span::styled("🔗 Status: ", Style::default().fg(Color::White)),
                Span::styled("TLS scanner not available", Style::default().fg(Color::Red)),
            ]));
        }
        
        // HTTP Security Headers
        if let Some((hsts_present, x_frame, x_content, xss_protect, referrer_policy, permissions_policy, csp_data, cors_data, http_vulnerabilities, http_grade)) = http_data {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("🌐 HTTP Security", Style::default().fg(Color::Cyan)),
            ]));
            
            // HSTS
            lines.push(Line::from(vec![
                Span::styled("  HSTS: ", Style::default().fg(Color::White)),
                Span::styled(
                    if hsts_present { "yes" } else { "no" },
                    Style::default().fg(if hsts_present { Color::Green } else { Color::Red })
                ),
            ]));
            
            // X-Frame-Options
            lines.push(Line::from(vec![
                Span::styled("  X-Frame: ", Style::default().fg(Color::White)),
                Span::styled(
                    x_frame.clone(),
                    Style::default().fg(if x_frame != "missing" { Color::Green } else { Color::Red })
                ),
            ]));
            
            // X-Content-Type-Options
            lines.push(Line::from(vec![
                Span::styled("  X-Content: ", Style::default().fg(Color::White)),
                Span::styled(
                    x_content.clone(),
                    Style::default().fg(if x_content != "missing" { Color::Green } else { Color::Red })
                ),
            ]));
            
            // X-XSS-Protection
            lines.push(Line::from(vec![
                Span::styled("  XSS-Protect: ", Style::default().fg(Color::White)),
                Span::styled(
                    xss_protect.clone(),
                    Style::default().fg(if xss_protect != "missing" { Color::Green } else { Color::Yellow })
                ),
            ]));
            
            // Referrer Policy
            lines.push(Line::from(vec![
                Span::styled("  Referrer: ", Style::default().fg(Color::White)),
                Span::styled(
                    referrer_policy.clone(),
                    Style::default().fg(if referrer_policy != "missing" { Color::Green } else { Color::Yellow })
                ),
            ]));
            
            // Permissions Policy
            lines.push(Line::from(vec![
                Span::styled("  Permissions: ", Style::default().fg(Color::White)),
                Span::styled(
                    permissions_policy.clone(),
                    Style::default().fg(if permissions_policy != "missing" { Color::Green } else { Color::Yellow })
                ),
            ]));
            
            // CSP
            if let Some((strength, header_value, issues)) = csp_data {
                lines.push(Line::from(vec![
                    Span::styled("  CSP: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", strength),
                        Style::default().fg(match strength {
                            crate::scan::http::CspStrength::Strong => Color::Green,
                            crate::scan::http::CspStrength::Moderate => Color::Yellow,
                            crate::scan::http::CspStrength::Weak => Color::Red,
                            crate::scan::http::CspStrength::None => Color::Red,
                        })
                    ),
                ]));
                
                // CSP Header Value (truncated for display)
                lines.push(Line::from(vec![
                    Span::styled("    Policy: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if header_value.len() > 40 { 
                            format!("{}...", &header_value[..37]) 
                        } else { 
                            header_value.clone() 
                        },
                        Style::default().fg(Color::Gray)
                    ),
                ]));
                
                // CSP Issues
                for issue in issues {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Red)),
                        Span::styled(
                            if issue.len() > 20 { format!("{}...", &issue[..17]) } else { issue },
                            Style::default().fg(Color::Red)
                        ),
                    ]));
                }
            } else {
                lines.push(Line::from(vec![
                    Span::styled("  CSP: ", Style::default().fg(Color::White)),
                    Span::styled("missing", Style::default().fg(Color::Red)),
                ]));
            }
            
            // CORS
            if let Some((security_level, access_control_allow_origin, access_control_allow_methods, access_control_allow_credentials, issues)) = cors_data {
                lines.push(Line::from(vec![
                    Span::styled("  CORS: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{:?}", security_level),
                        Style::default().fg(match security_level {
                            crate::scan::http::CorsSecurityLevel::Secure => Color::Green,
                            crate::scan::http::CorsSecurityLevel::Moderate => Color::Yellow,
                            crate::scan::http::CorsSecurityLevel::Weak => Color::Red,
                            crate::scan::http::CorsSecurityLevel::Dangerous => Color::Red,
                        })
                    ),
                ]));
                
                // CORS Details (compact)
                if let Some(origin) = &access_control_allow_origin {
                    lines.push(Line::from(vec![
                        Span::styled("    Origin: ", Style::default().fg(Color::White)),
                        Span::styled(
                            if origin.len() > 25 { format!("{}...", &origin[..22]) } else { origin.clone() },
                            Style::default().fg(Color::Gray)
                        ),
                    ]));
                }
                
                lines.push(Line::from(vec![
                    Span::styled("    Methods: ", Style::default().fg(Color::White)),
                    Span::styled(
                        format!("{}", access_control_allow_methods.len()),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
                
                lines.push(Line::from(vec![
                    Span::styled("    Credentials: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if access_control_allow_credentials { "yes" } else { "no" },
                        Style::default().fg(if access_control_allow_credentials { Color::Yellow } else { Color::Green })
                    ),
                ]));
                
                // CORS Issues
                for issue in issues {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(Color::Red)),
                        Span::styled(
                            if issue.len() > 20 { format!("{}...", &issue[..17]) } else { issue },
                            Style::default().fg(Color::Red)
                        ),
                    ]));
                }
            }
            
            // HTTP Vulnerabilities
            if !http_vulnerabilities.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("⚠️ HTTP Vulnerabilities", Style::default().fg(Color::Red)),
                ]));
                
                for vuln in http_vulnerabilities {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(Color::Red)),
                        Span::styled(vuln, Style::default().fg(Color::Red)),
                    ]));
                }
            }
            
            // HTTP Security Grade
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📊 HTTP Grade: ", Style::default().fg(Color::White)),
                Span::styled(
                    http_grade.clone(),
                    Style::default().fg(match http_grade.as_str() {
                        "APlus" => Color::Green,
                        "A" => Color::Green,
                        "B" => Color::Yellow,
                        _ => Color::Red,
                    })
                ),
            ]));
        }
        
        // DNS Security Records
        if let Some((spf_record, dmarc_record, dkim_domains, mx_count, has_mx)) = dns_data {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📧 Email Security", Style::default().fg(Color::Cyan)),
            ]));
            
            // SPF Record
            lines.push(Line::from(vec![
                Span::styled("  SPF: ", Style::default().fg(Color::White)),
                Span::styled(
                    if spf_record.is_some() { "configured" } else { "missing" },
                    Style::default().fg(if spf_record.is_some() { Color::Green } else { Color::Red })
                ),
            ]));
            
            // DMARC Record
            lines.push(Line::from(vec![
                Span::styled("  DMARC: ", Style::default().fg(Color::White)),
                Span::styled(
                    if dmarc_record.is_some() { "configured" } else { "missing" },
                    Style::default().fg(if dmarc_record.is_some() { Color::Green } else { Color::Red })
                ),
            ]));
            
            // DKIM
            lines.push(Line::from(vec![
                Span::styled("  DKIM: ", Style::default().fg(Color::White)),
                Span::styled(
                    if dkim_domains.is_empty() { 
                        "not found".to_string() 
                    } else { 
                        format!("{} domains", dkim_domains.len()) 
                    },
                    Style::default().fg(if !dkim_domains.is_empty() { Color::Green } else { Color::Yellow })
                ),
            ]));
            
            // MX Records
            lines.push(Line::from(vec![
                Span::styled("  MX: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{} records", mx_count),
                    Style::default().fg(if has_mx { Color::Green } else { Color::Gray })
                ),
            ]));
            
            // Show actual record contents (truncated)
            if let Some(spf) = &spf_record {
                lines.push(Line::from(vec![
                    Span::styled("    SPF: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if spf.len() > 50 { format!("{}...", &spf[..47]) } else { spf.clone() },
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
            
            if let Some(dmarc) = &dmarc_record {
                lines.push(Line::from(vec![
                    Span::styled("    DMARC: ", Style::default().fg(Color::White)),
                    Span::styled(
                        if dmarc.len() > 50 { format!("{}...", &dmarc[..47]) } else { dmarc.clone() },
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
            
            if !dkim_domains.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("    DKIM: ", Style::default().fg(Color::White)),
                    Span::styled(
                        dkim_domains.join(", "),
                        Style::default().fg(Color::Gray)
                    ),
                ]));
            }
        }
        
        // TLS Vulnerabilities section
        if let Some(vulnerabilities) = tls_vulnerabilities {
            if !vulnerabilities.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("⚠️ TLS Vulnerabilities", Style::default().fg(Color::Red)),
                ]));
                
                for vuln in vulnerabilities {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(Color::Red)),
                        Span::styled(vuln, Style::default().fg(Color::Red)),
                    ]));
                }
            }
        }
        
        lines
    }
    
    /// Get the actual number of lines that would be rendered for the current state
    pub fn get_actual_line_count(&self, state: &AppState) -> u16 {
        // Use the SINGLE SOURCE OF TRUTH
        self.build_content_lines(state).len() as u16
    }
}

impl Default for SecurityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for SecurityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::security] render: area={}x{} focused={} scroll_offset={}", 
            area.width, area.height, focused, self.scroll_offset);
        
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Use the SINGLE SOURCE OF TRUTH for content
        let lines = self.build_content_lines(state);
        
        // Apply scrolling
        let total_lines = lines.len() as u16;
        let visible_area_height = inner_area.height;
        let max_scroll_offset = if total_lines > visible_area_height {
            total_lines.saturating_sub(visible_area_height)
        } else {
            0
        };
        let safe_scroll_offset = self.scroll_offset.min(max_scroll_offset);
        
        log::trace!("[tui::security] scroll_calculation: total_lines={} visible_height={} max_scroll={} safe_scroll={}", 
            total_lines, visible_area_height, max_scroll_offset, safe_scroll_offset);
        
        // Apply scroll offset - skip lines from the beginning
        let visible_lines = if safe_scroll_offset < total_lines {
            lines.into_iter().skip(safe_scroll_offset as usize).collect()
        } else {
            lines
        };
        
        log::trace!("[tui::security] render_content: visible_lines={}", visible_lines.len());
        
        let paragraph = Paragraph::new(visible_lines)
            .alignment(Alignment::Left);
        paragraph.render(inner_area, frame.buffer_mut());
    }
    
    fn title(&self) -> &'static str {
        self.title
    }
    
    fn id(&self) -> &'static str {
        self.id
    }
    
    fn min_size(&self) -> (u16, u16) {
        (50, 35)
    }
    
    fn is_focusable(&self) -> bool {
        true
    }
    
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AppState, ScanState, ScanStatus, ScanResult};
    use crate::scan::tls::{TlsResult, TlsVersion, CertificateInfo, SecurityGrade, TlsVulnerability};
    use crate::scan::http::{HttpResult, SecurityHeaders, CspPolicy, CspStrength, CspIssue, CorsPolicy, CorsSecurityLevel, CorsIssue, HttpVulnerability, SecurityGrade as HttpSecurityGrade};
    use crate::scan::dns::{DnsResult, EmailSecurityAnalysis};
    use std::time::{Duration, Instant};
    use std::collections::HashMap;
    use chrono::Utc;

    #[test]
    fn test_security_pane_creation() {
        let pane = SecurityPane::new();
        assert_eq!(pane.title(), "security");
        assert_eq!(pane.id(), "security");
        assert_eq!(pane.min_size(), (50, 35));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn test_tls_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());
        
        // Create comprehensive TLS result with certificate details
        let cert = CertificateInfo {
            subject: "CN=example.com,O=Example Corp,C=US".to_string(),
            issuer: "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US".to_string(),
            serial_number: "123456789".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(90),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            san_domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        };
        
        let tls_result = TlsResult {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![cert],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: Some(Utc::now() + chrono::Duration::days(90)),
            days_until_expiry: Some(90),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![
                TlsVulnerability::Heartbleed,
                TlsVulnerability::WeakCipher("RC4-MD5".to_string()),
            ],
            security_grade: SecurityGrade::A,
            scan_time: Duration::from_millis(500),
            queried_at: Instant::now(),
        };
        
        state.scanners.insert("tls".to_string(), ScanState {
            result: Some(ScanResult::Tls(tls_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        // Test TLS data extraction
        if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                assert!(tls_result.connection_successful, "TLS connection should be successful");
                assert_eq!(tls_result.negotiated_version.as_ref().unwrap().as_str(), "TLSv1.3");
                assert!(tls_result.perfect_forward_secrecy, "PFS should be enabled");
                assert!(tls_result.ocsp_stapling, "OCSP should be enabled");
                assert!(tls_result.certificate_valid, "Certificate should be valid");
                assert_eq!(tls_result.days_until_expiry, Some(90));
                assert_eq!(tls_result.security_grade.as_str(), "A");
                assert_eq!(tls_result.vulnerabilities.len(), 2);
                
                // Test certificate details
                let cert = &tls_result.certificate_chain[0];
                assert!(cert.subject.contains("example.com"));
                assert!(cert.issuer.contains("Let's Encrypt"));
                assert_eq!(cert.public_key_algorithm, "RSA");
                assert_eq!(cert.key_size, Some(2048));
                assert_eq!(cert.san_domains.len(), 2);
                
                // Test vulnerability extraction
                let vuln_strings: Vec<String> = tls_result.vulnerabilities.iter().map(|vuln| match vuln {
                    TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
                    TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
                    _ => "Other vulnerability".to_string(),
                }).collect();
                
                assert!(vuln_strings.contains(&"Heartbleed (CVE-2014-0160)".to_string()));
                assert!(vuln_strings.contains(&"Weak cipher: RC4-MD5".to_string()));
            }
        }
    }

    #[test]
    fn test_http_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());
        
        let security_headers = SecurityHeaders {
            strict_transport_security: Some("max-age=31536000; includeSubDomains".to_string()),
            x_frame_options: Some("DENY".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            x_xss_protection: Some("1; mode=block".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some("geolocation=(), microphone=()".to_string()),
        };
        
        let mut csp_directives = HashMap::new();
        csp_directives.insert("default-src".to_string(), vec!["'self'".to_string()]);
        csp_directives.insert("script-src".to_string(), vec!["'self'".to_string(), "'unsafe-inline'".to_string()]);
        
        let csp_policy = CspPolicy {
            header_value: "default-src 'self'; script-src 'self' 'unsafe-inline'".to_string(),
            directives: csp_directives,
            issues: vec![CspIssue::UnsafeInline("script-src".to_string())],
            strength: CspStrength::Moderate,
        };
        
        let cors_policy = CorsPolicy {
            access_control_allow_origin: Some("*".to_string()),
            access_control_allow_methods: vec!["GET".to_string(), "POST".to_string()],
            access_control_allow_headers: vec!["Content-Type".to_string()],
            access_control_allow_credentials: true,
            issues: vec![CorsIssue::WildcardWithCredentials],
            security_level: CorsSecurityLevel::Dangerous,
        };
        
        let http_result = HttpResult {
            url: "https://example.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(200),
            content_length: 1024,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers,
            csp: Some(csp_policy),
            cors: Some(cors_policy),
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![
                HttpVulnerability::WeakCsp,
                HttpVulnerability::InsecureCors,
            ],
            security_grade: HttpSecurityGrade::C,
            scan_duration: Duration::from_millis(300),
        };
        
        state.scanners.insert("http".to_string(), ScanState {
            result: Some(ScanResult::Http(http_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        // Test HTTP data extraction
        if let Some(http_state) = state.scanners.get("http") {
            if let Some(ScanResult::Http(http_result)) = http_state.result.as_ref() {
                // Test security headers
                assert!(http_result.security_headers.strict_transport_security.is_some());
                assert_eq!(http_result.security_headers.x_frame_options.as_ref().unwrap(), "DENY");
                assert_eq!(http_result.security_headers.x_content_type_options.as_ref().unwrap(), "nosniff");
                assert_eq!(http_result.security_headers.x_xss_protection.as_ref().unwrap(), "1; mode=block");
                assert!(http_result.security_headers.referrer_policy.is_some());
                assert!(http_result.security_headers.permissions_policy.is_some());
                
                // Test CSP
                let csp = http_result.csp.as_ref().unwrap();
                assert_eq!(csp.strength, CspStrength::Moderate);
                assert!(csp.header_value.contains("default-src 'self'"));
                assert_eq!(csp.issues.len(), 1);
                
                // Test CORS
                let cors = http_result.cors.as_ref().unwrap();
                assert_eq!(cors.security_level, CorsSecurityLevel::Dangerous);
                assert_eq!(cors.access_control_allow_origin.as_ref().unwrap(), "*");
                assert_eq!(cors.access_control_allow_methods.len(), 2);
                assert!(cors.access_control_allow_credentials);
                assert_eq!(cors.issues.len(), 1);
                
                // Test vulnerabilities
                assert_eq!(http_result.vulnerabilities.len(), 2);
                assert!(http_result.vulnerabilities.contains(&HttpVulnerability::WeakCsp));
                assert!(http_result.vulnerabilities.contains(&HttpVulnerability::InsecureCors));
                
                // Test grade
                assert_eq!(http_result.security_grade, HttpSecurityGrade::C);
            }
        }
    }

    #[test]
    fn test_dns_data_extraction() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("example.com".to_string());
        
        let email_security = EmailSecurityAnalysis {
            spf_record: Some("v=spf1 include:_spf.google.com ~all".to_string()),
            dmarc_record: Some("v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com".to_string()),
            has_mx: true,
            mx_count: 2,
            dkim_domains: vec!["default._domainkey.example.com".to_string(), "selector1._domainkey.example.com".to_string()],
        };
        
        let dns_result = DnsResult {
            A: vec![],
            AAAA: vec![],
            CNAME: vec![],
            MX: vec![],
            TXT: vec![],
            NS: vec![],
            CAA: vec![],
            PTR: vec![],
            SOA: vec![],
            SRV: vec![],
            email_security: Some(email_security),
            response_time: Duration::from_millis(50),
            queried_at: Instant::now(),
        };
        
        state.scanners.insert("dns".to_string(), ScanState {
            result: Some(ScanResult::Dns(dns_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        // Test DNS data extraction
        if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                let email_security = dns_result.email_security.as_ref().unwrap();
                
                // Test SPF
                assert!(email_security.spf_record.is_some());
                assert!(email_security.spf_record.as_ref().unwrap().contains("v=spf1"));
                
                // Test DMARC
                assert!(email_security.dmarc_record.is_some());
                assert!(email_security.dmarc_record.as_ref().unwrap().contains("v=DMARC1"));
                
                // Test DKIM
                assert_eq!(email_security.dkim_domains.len(), 2);
                assert!(email_security.dkim_domains[0].contains("default._domainkey"));
                
                // Test MX
                assert!(email_security.has_mx);
                assert_eq!(email_security.mx_count, 2);
            }
        }
    }

    #[test]
    fn test_comprehensive_data_availability() {
        // False positive: mut is required for state.scanners.insert() calls
        #[allow(unused_mut)]
        let mut state = AppState::new("comprehensive.com".to_string());
        
        // Add all scanner types with data
        let cert = CertificateInfo {
            subject: "CN=comprehensive.com".to_string(),
            issuer: "CN=DigiCert".to_string(),
            serial_number: "123".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            signature_algorithm: "SHA256withRSA".to_string(),
            public_key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            san_domains: vec!["comprehensive.com".to_string()],
            is_self_signed: false,
            is_ca: false,
        };
        
        let tls_result = TlsResult {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![cert],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: Some(Utc::now() + chrono::Duration::days(365)),
            days_until_expiry: Some(365),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![],
            security_grade: SecurityGrade::APlus,
            scan_time: Duration::from_millis(500),
            queried_at: Instant::now(),
        };
        
        let http_result = HttpResult {
            url: "https://comprehensive.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(100),
            content_length: 2048,
            content_type: Some("text/html".to_string()),
            redirect_chain: vec![],
            security_headers: SecurityHeaders {
                strict_transport_security: Some("max-age=31536000".to_string()),
                x_frame_options: Some("SAMEORIGIN".to_string()),
                x_content_type_options: Some("nosniff".to_string()),
                x_xss_protection: Some("1; mode=block".to_string()),
                referrer_policy: Some("strict-origin".to_string()),
                permissions_policy: Some("geolocation=()".to_string()),
            },
            csp: None,
            cors: None,
            caching: crate::scan::http::CachingPolicy {
                cache_control: None,
                expires: None,
                etag: None,
                last_modified: None,
            },
            vulnerabilities: vec![HttpVulnerability::MissingCsp],
            security_grade: HttpSecurityGrade::B,
            scan_duration: Duration::from_millis(200),
        };
        
        let dns_result = DnsResult {
            A: vec![],
            AAAA: vec![],
            CNAME: vec![],
            MX: vec![],
            TXT: vec![],
            NS: vec![],
            CAA: vec![],
            PTR: vec![],
            SOA: vec![],
            SRV: vec![],
            email_security: Some(EmailSecurityAnalysis {
                spf_record: Some("v=spf1 -all".to_string()),
                dmarc_record: Some("v=DMARC1; p=reject".to_string()),
                has_mx: true,
                mx_count: 1,
                dkim_domains: vec!["default._domainkey.comprehensive.com".to_string()],
            }),
            response_time: Duration::from_millis(30),
            queried_at: Instant::now(),
        };
        
        state.scanners.insert("tls".to_string(), ScanState {
            result: Some(ScanResult::Tls(tls_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        state.scanners.insert("http".to_string(), ScanState {
            result: Some(ScanResult::Http(http_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        state.scanners.insert("dns".to_string(), ScanState {
            result: Some(ScanResult::Dns(dns_result)),
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: std::collections::VecDeque::new(),
        });
        
        // Verify all scanners have data
        assert!(state.scanners.contains_key("tls"));
        assert!(state.scanners.contains_key("http"));
        assert!(state.scanners.contains_key("dns"));
        
        // Verify TLS data is extractable
        if let Some(tls_state) = state.scanners.get("tls") {
            if let Some(ScanResult::Tls(tls_result)) = tls_state.result.as_ref() {
                assert!(tls_result.connection_successful);
                assert_eq!(tls_result.security_grade.as_str(), "A+");
                assert!(!tls_result.certificate_chain.is_empty());
            } else {
                panic!("TLS result should be extractable");
            }
        }
        
        // Verify HTTP data is extractable
        if let Some(http_state) = state.scanners.get("http") {
            if let Some(ScanResult::Http(http_result)) = http_state.result.as_ref() {
                assert!(http_result.security_headers.strict_transport_security.is_some());
                assert_eq!(http_result.security_grade, HttpSecurityGrade::B);
                assert!(!http_result.vulnerabilities.is_empty());
            } else {
                panic!("HTTP result should be extractable");
            }
        }
        
        // Verify DNS data is extractable
        if let Some(dns_state) = state.scanners.get("dns") {
            if let Some(ScanResult::Dns(dns_result)) = dns_state.result.as_ref() {
                assert!(dns_result.email_security.is_some());
                let email_security = dns_result.email_security.as_ref().unwrap();
                assert!(email_security.spf_record.is_some());
                assert!(email_security.dmarc_record.is_some());
            } else {
                panic!("DNS result should be extractable");
            }
        }
    }

    #[test]
    fn test_vulnerability_extraction_logic() {
        // Test TLS vulnerability extraction
        let tls_vulnerabilities = vec![
            TlsVulnerability::Heartbleed,
            TlsVulnerability::Poodle,
            TlsVulnerability::WeakCipher("RC4-MD5".to_string()),
            TlsVulnerability::ExpiredCertificate,
        ];
        
        let vuln_strings: Vec<String> = tls_vulnerabilities.iter().take(5).map(|vuln| match vuln {
            TlsVulnerability::Heartbleed => "Heartbleed (CVE-2014-0160)".to_string(),
            TlsVulnerability::Poodle => "POODLE (CVE-2014-3566)".to_string(),
            TlsVulnerability::Beast => "BEAST (CVE-2011-3389)".to_string(),
            TlsVulnerability::Crime => "CRIME (CVE-2012-4929)".to_string(),
            TlsVulnerability::WeakCipher(cipher) => format!("Weak cipher: {}", cipher),
            TlsVulnerability::ExpiredCertificate => "Certificate expired".to_string(),
            TlsVulnerability::SelfSignedCertificate => "Self-signed certificate".to_string(),
            TlsVulnerability::WeakSignatureAlgorithm(alg) => format!("Weak signature: {}", alg),
            TlsVulnerability::InsecureRenegotiation => "Insecure renegotiation".to_string(),
            TlsVulnerability::WeakDhParams => "Weak DH parameters".to_string(),
            TlsVulnerability::SslV2Enabled => "SSLv2 enabled".to_string(),
            TlsVulnerability::SslV3Enabled => "SSLv3 enabled".to_string(),
        }).collect();
        
        assert_eq!(vuln_strings.len(), 4);
        assert!(vuln_strings.contains(&"Heartbleed (CVE-2014-0160)".to_string()));
        assert!(vuln_strings.contains(&"POODLE (CVE-2014-3566)".to_string()));
        assert!(vuln_strings.contains(&"Weak cipher: RC4-MD5".to_string()));
        assert!(vuln_strings.contains(&"Certificate expired".to_string()));
        
        // Test HTTP vulnerability extraction
        let http_vulnerabilities = vec![
            HttpVulnerability::MissingHsts,
            HttpVulnerability::WeakCsp,
            HttpVulnerability::InsecureCors,
        ];
        
        let http_vuln_strings: Vec<String> = http_vulnerabilities.iter().take(5).map(|vuln| match vuln {
            HttpVulnerability::MissingHsts => "Missing HSTS header".to_string(),
            HttpVulnerability::MissingXFrameOptions => "Missing X-Frame-Options".to_string(),
            HttpVulnerability::MissingXContentTypeOptions => "Missing X-Content-Type-Options".to_string(),
            HttpVulnerability::MissingCsp => "Missing Content Security Policy".to_string(),
            HttpVulnerability::WeakCsp => "Weak Content Security Policy".to_string(),
            HttpVulnerability::InsecureCors => "Insecure CORS configuration".to_string(),
            HttpVulnerability::InformationDisclosure => "Information disclosure risk".to_string(),
        }).collect();
        
        assert_eq!(http_vuln_strings.len(), 3);
        assert!(http_vuln_strings.contains(&"Missing HSTS header".to_string()));
        assert!(http_vuln_strings.contains(&"Weak Content Security Policy".to_string()));
        assert!(http_vuln_strings.contains(&"Insecure CORS configuration".to_string()));
    }
} 