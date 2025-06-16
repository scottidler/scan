use crate::types::{ScanResult, ScanState, ScanStatus};
use std::time::Duration;

pub fn print_scan_state(scanner_name: &str, scan_state: &ScanState) {
    let status_icon = match scan_state.status {
        ScanStatus::Running => "🔄",
        ScanStatus::Complete => "✅",
        ScanStatus::Failed => "❌",
    };
    
    let elapsed = scan_state.last_updated.elapsed();
    let elapsed_str = format_duration(elapsed);
    
    print!("{} {}: ", status_icon, scanner_name.to_uppercase());
    
    if let Some(result) = &scan_state.result {
        print_scan_result(result);
    } else if let Some(error) = &scan_state.error {
        println!("Error - {}", error);
    } else {
        println!("Running...");
    }
    
    println!("  └─ Last updated: {} ago", elapsed_str);
}

fn print_scan_result(result: &ScanResult) {
    match result {
        ScanResult::Ping(ping) => {
            println!("{}ms latency (TTL: {}, Loss: {:.1}%)", 
                ping.latency.as_millis(),
                ping.ttl.map(|t| t.to_string()).unwrap_or_else(|| "?".to_string()),
                ping.packet_loss * 100.0
            );
        }
        
        ScanResult::Dns(dns) => {
            let a_count = dns.A.len();
            let aaaa_count = dns.AAAA.len();
            let mx_count = dns.MX.len();
            let txt_count = dns.TXT.len();
            
            print!("{} A records", a_count);
            if aaaa_count > 0 { print!(", {} AAAA", aaaa_count); }
            if mx_count > 0 { print!(", {} MX", mx_count); }
            if txt_count > 0 { print!(", {} TXT", txt_count); }
            
            if let Some(email_sec) = &dns.email_security {
                if email_sec.spf_record.is_some() { print!(", SPF✓"); }
                if email_sec.dmarc_record.is_some() { print!(", DMARC✓"); }
            }
            
            println!(" ({}ms)", dns.response_time.as_millis());
        }
        
        ScanResult::Tls(tls) => {
            if tls.connection_successful {
                let version = tls.negotiated_version
                    .as_ref()
                    .map(|v| format!("{:?}", v))
                    .unwrap_or_else(|| "Unknown".to_string());
                
                let cert_status = if tls.certificate_valid {
                    if let Some(days) = tls.days_until_expiry {
                        if days > 30 {
                            format!("cert valid ({}d)", days)
                        } else {
                            format!("cert expires soon ({}d)", days)
                        }
                    } else {
                        "cert valid".to_string()
                    }
                } else {
                    "cert invalid".to_string()
                };
                
                println!("{}, {}, grade {:?} ({}ms)", 
                    version, cert_status, tls.security_grade, tls.handshake_time.as_millis());
            } else {
                println!("Connection failed");
            }
        }
        
        ScanResult::Http(http) => {
            let security_features = count_security_features(http);
            let vuln_count = http.vulnerabilities.len();
            
            println!("{} {}, {} security features, {} vulnerabilities, grade {:?} ({}ms)",
                http.status_code,
                http.content_type.as_deref().unwrap_or("unknown"),
                security_features,
                vuln_count,
                http.security_grade,
                http.response_time.as_millis()
            );
        }
        
        ScanResult::Whois(whois) => {
            let age_str = whois.domain_age_days
                .map(|days| {
                    if days < 365 {
                        format!("{}d old", days)
                    } else {
                        format!("{}yr old", days / 365)
                    }
                })
                .unwrap_or_else(|| "unknown age".to_string());
            
            let expiry_str = whois.expires_in_days
                .map(|days| {
                    if days < 30 {
                        format!("expires in {}d", days)
                    } else if days < 365 {
                        format!("expires in {}d", days)
                    } else {
                        format!("expires in {}yr", days / 365)
                    }
                })
                .unwrap_or_else(|| "unknown expiry".to_string());
            
            let registrar = whois.registrar
                .as_ref()
                .map(|r| r.name.as_str())
                .unwrap_or("unknown registrar");
            
            let risk_count = whois.risk_indicators.len();
            let risk_str = if risk_count > 0 {
                format!(", {} risks", risk_count)
            } else {
                String::new()
            };
            
            println!("{}, {}, {:?} privacy, {} ({}ms{})",
                age_str, expiry_str, whois.privacy_score, registrar,
                whois.scan_duration.as_millis(), risk_str
            );
        }
    }
}

fn count_security_features(http: &crate::scan::http::HttpResult) -> usize {
    let mut count = 0;
    
    if http.security_headers.strict_transport_security.is_some() { count += 1; }
    if http.security_headers.x_frame_options.is_some() { count += 1; }
    if http.security_headers.x_content_type_options.is_some() { count += 1; }
    if http.security_headers.x_xss_protection.is_some() { count += 1; }
    if http.security_headers.referrer_policy.is_some() { count += 1; }
    if http.security_headers.permissions_policy.is_some() { count += 1; }
    if http.csp.is_some() { count += 1; }
    
    count
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    
    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        format!("{}m{}s", total_secs / 60, total_secs % 60)
    } else {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        format!("{}h{}m", hours, minutes)
    }
}

pub fn print_separator() {
    println!("{}", "─".repeat(80));
}

pub fn print_header(target: &str) {
    println!("🎯 Scanning: {}", target);
    print_separator();
} 