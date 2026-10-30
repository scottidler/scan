use crate::scan::whois::DataSource;
use crate::types::{ScanResult, ScanState, ScanStatus};
use std::time::Duration;

const PACKET_LOSS_PERCENTAGE_MULTIPLIER: f32 = 100.0;
const CERT_EXPIRY_WARNING_DAYS: i64 = 30;
const DAYS_PER_YEAR: i64 = 365;
const EXPIRY_WARNING_DAYS: i64 = 30;
const MAX_PORTS_DISPLAY: usize = 4;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SEPARATOR_WIDTH: usize = 80;

/// What a finished result says about its target, which picks the line's icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Failed,
    NotApplicable,
}

pub fn print_scan_state(scanner_name: &str, scan_state: &ScanState) {
    print!("{}", format_scan_state(scanner_name, scan_state));
}

/// The `--no-tui` lines for one scanner: icon, name, result or error, a retained result's newer
/// error, and the age of the state.
pub fn format_scan_state(scanner_name: &str, scan_state: &ScanState) -> String {
    let described = scan_state.result.as_ref().map(describe_result);
    // A failed or n/a result keeps its icon while the scanner refreshes: ping is nearly always
    // mid-scan when this prints, so `🔄` would hide a failure for good.
    let status_icon = match (&scan_state.status, described.as_ref().map(|(outcome, _)| *outcome)) {
        (ScanStatus::Failed, _) | (_, Some(Outcome::Failed)) => "❌",
        (_, Some(Outcome::NotApplicable)) => "⚫",
        (ScanStatus::Running, _) => "🔄",
        (ScanStatus::Complete, _) => "✅",
    };

    let mut out = format!("{} {}: ", status_icon, scanner_name.to_uppercase());
    match (described, &scan_state.error) {
        (Some((_, text)), error) => {
            out.push_str(&text);
            out.push('\n');
            // A failed refresh keeps the last good result on screen; its reason is printed under it.
            if let (ScanStatus::Failed, Some(error)) = (&scan_state.status, error) {
                out.push_str(&format!("  └─ Error: {error:#}\n"));
            }
        }
        (None, Some(error)) => out.push_str(&format!("Error - {error:#}\n")),
        (None, None) => out.push_str("Running...\n"),
    }

    let elapsed_str = format_duration(scan_state.last_updated.elapsed());
    out.push_str(&format!("  └─ Last updated: {} ago\n", elapsed_str));
    out
}

fn describe_result(result: &ScanResult) -> (Outcome, String) {
    match result {
        ScanResult::Ping(ping) => {
            let Some(best_latency) = ping.get_best_latency() else {
                let reason = ping.failure_reason().unwrap_or_else(|| "no response".to_string());
                return (Outcome::Failed, format!("Ping failed: {}", reason));
            };
            let primary_result = ping.get_primary_result();
            let ttl_str = primary_result
                .and_then(|r| r.ttl)
                .map(|t| t.to_string())
                .unwrap_or_else(|| "?".to_string());
            let loss = primary_result
                .map(|r| r.packet_loss * PACKET_LOSS_PERCENTAGE_MULTIPLIER)
                .unwrap_or(0.0);

            // Show protocol-specific results
            let mut protocol_results = Vec::new();
            if ping.ipv4_status.is_success()
                && let Some(latency) = ping.ipv4_status.latency()
            {
                protocol_results.push(format!("IPv4: {}ms", latency.as_millis()));
            }
            if ping.ipv6_status.is_success()
                && let Some(latency) = ping.ipv6_status.latency()
            {
                protocol_results.push(format!("IPv6: {}ms", latency.as_millis()));
            }

            let protocol_str = if protocol_results.is_empty() {
                "no response".to_string()
            } else {
                protocol_results.join(", ")
            };

            (
                Outcome::Ok,
                format!(
                    "{}ms best latency ({}, TTL: {}, Loss: {:.1}%)",
                    best_latency.as_millis(),
                    protocol_str,
                    ttl_str,
                    loss
                ),
            )
        }

        ScanResult::Dns(dns) => {
            let mut text = format!("{} A records", dns.A.len());
            if !dns.AAAA.is_empty() {
                text.push_str(&format!(", {} AAAA", dns.AAAA.len()));
            }
            if !dns.MX.is_empty() {
                text.push_str(&format!(", {} MX", dns.MX.len()));
            }
            if !dns.TXT.is_empty() {
                text.push_str(&format!(", {} TXT", dns.TXT.len()));
            }

            if let Some(email_sec) = &dns.email_security {
                if email_sec.spf_record.is_some() {
                    text.push_str(", SPF✓");
                }
                if email_sec.dmarc_record.is_some() {
                    text.push_str(", DMARC✓");
                }
            }

            text.push_str(&format!(" ({}ms)", dns.response_time.as_millis()));
            (Outcome::Ok, text)
        }

        ScanResult::Tls(tls) => {
            let Some(primary_data) = tls.get_primary_result().filter(|_| tls.has_any_success()) else {
                return (
                    Outcome::Failed,
                    format!("Connection failed: {}", tls_status_failure(tls)),
                );
            };
            if !primary_data.connection_successful {
                // A connect error sits in certificate_errors (`Connection failed: <cause>`); a handshake
                // rejected at certificate verification records its cause as a vulnerability instead.
                let reason = primary_data
                    .certificate_errors
                    .first()
                    .cloned()
                    .or_else(|| primary_data.vulnerabilities.first().map(|vuln| vuln.description()))
                    .unwrap_or_else(|| "Connection failed".to_string());
                return (
                    Outcome::Failed,
                    format!("{}, grade {}", reason, primary_data.security_grade.as_str()),
                );
            }
            let version = primary_data
                .negotiated_version
                .as_ref()
                .map(|v| v.as_str().to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            let cert_status = if primary_data.certificate_valid {
                if let Some(days) = primary_data.days_until_expiry {
                    if days > CERT_EXPIRY_WARNING_DAYS {
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

            // Same version and grade text as the Security pane.
            let best_grade = tls.get_best_security_grade().map(|g| g.as_str()).unwrap_or("F");

            (
                Outcome::Ok,
                format!(
                    "{}, {}, grade {} ({}ms)",
                    version,
                    cert_status,
                    best_grade,
                    primary_data.handshake_time.as_millis()
                ),
            )
        }

        ScanResult::Http(http) => {
            let Some(primary_data) = http.get_primary_result() else {
                return (Outcome::Failed, "HTTP scan failed for all protocols".to_string());
            };
            let security_features = count_security_features(primary_data);
            let vuln_count = http.total_vulnerabilities();

            // The grade is the primary result's, the same one whose HTTPS failure is printed.
            let mut text = format!(
                "{} {}, {} security features, {} vulnerabilities, grade {} ({}ms)",
                primary_data.status_code,
                primary_data.content_type.as_deref().unwrap_or("unknown"),
                security_features,
                vuln_count,
                primary_data.security_grade.as_str(),
                primary_data.response_time.as_millis()
            );
            if let Some(reason) = &primary_data.https_failure {
                text.push_str(&format!("\n  └─ plain HTTP (HTTPS failed: {})", reason));
            }
            (Outcome::Ok, text)
        }

        ScanResult::Whois(whois) => {
            match &whois.data_source {
                DataSource::NotApplicable(reason) => return (Outcome::NotApplicable, reason.to_string()),
                DataSource::Rdap | DataSource::Whois => {}
            }
            let age_str = whois
                .domain_age_days
                .map(|days| {
                    if days < DAYS_PER_YEAR {
                        format!("{}d old", days)
                    } else {
                        format!("{}yr old", days / DAYS_PER_YEAR)
                    }
                })
                .unwrap_or_else(|| "unknown age".to_string());

            // NOTE: the first two branches are identical; this looks like a latent
            // bug (the `< EXPIRY_WARNING_DAYS` branch was likely meant to format
            // differently). Preserving authored behavior; allow the lint rather than
            // silently collapse the branches.
            #[allow(clippy::if_same_then_else)]
            let expiry_str = whois
                .expires_in_days
                .map(|days| {
                    if days < EXPIRY_WARNING_DAYS {
                        format!("expires in {}d", days)
                    } else if days < DAYS_PER_YEAR {
                        format!("expires in {}d", days)
                    } else {
                        format!("expires in {}yr", days / DAYS_PER_YEAR)
                    }
                })
                .unwrap_or_else(|| "unknown expiry".to_string());

            let registrar = whois
                .registrar
                .as_ref()
                .map(|r| r.name.as_str())
                .unwrap_or("unknown registrar");

            let risk_count = whois.risk_indicators.len();
            let risk_str = if risk_count > 0 { format!(", {} risks", risk_count) } else { String::new() };

            (
                Outcome::Ok,
                format!(
                    "{} via {}: {}, {}, {:?} privacy, {} ({}ms{})",
                    whois.domain_label(),
                    whois.data_source,
                    age_str,
                    expiry_str,
                    whois.privacy_score,
                    registrar,
                    whois.scan_duration.as_millis(),
                    risk_str
                ),
            )
        }

        ScanResult::Traceroute(traceroute) => {
            let Some(primary_data) = traceroute.get_primary_result() else {
                return (
                    Outcome::Failed,
                    format!(
                        "Traceroute failed for all protocols ({}ms)",
                        traceroute.total_duration.as_millis()
                    ),
                );
            };
            let protocol = if primary_data.ipv6 { "IPv6" } else { "IPv4" };
            let reached = primary_data.reach_label();

            // Calculate average RTT from last hop
            let last_hop_rtt = primary_data
                .hops
                .last()
                .and_then(|hop| hop.avg_rtt)
                .map(|rtt| format!("{}ms", rtt.as_millis()))
                .unwrap_or_else(|| "timeout".to_string());

            // Count timeouts
            let timeout_hops = primary_data.silent_hops();

            let timeout_str = if timeout_hops > 0 {
                format!(", {} timeouts", timeout_hops)
            } else {
                String::new()
            };

            // Show protocol status if both were attempted
            let protocol_info = if traceroute.ipv4_result.is_some() && traceroute.ipv6_result.is_some() {
                format!("{} (dual)", protocol)
            } else {
                protocol.to_string()
            };

            (
                Outcome::Ok,
                format!(
                    "{} {} hops, {} ({}{}, {}ms)",
                    protocol_info,
                    traceroute.total_hops(),
                    reached,
                    last_hop_rtt,
                    timeout_str,
                    traceroute.total_duration.as_millis()
                ),
            )
        }

        ScanResult::GeoIp(geoip) => {
            let Some(primary_data) = geoip.get_primary_result() else {
                return (
                    Outcome::Failed,
                    format!(
                        "GeoIP lookup failed for all protocols ({}ms)",
                        geoip.total_duration.as_millis()
                    ),
                );
            };
            let location_str = if let Some(location) = &primary_data.location {
                if location.city.is_empty() {
                    format!("{}, {}", location.region, location.country)
                } else {
                    format!("{}, {}, {}", location.city, location.region, location.country)
                }
            } else {
                "Unknown location".to_string()
            };

            let network_str = if let Some(network) = &primary_data.network_info {
                if let Some(asn) = network.asn {
                    format!("AS{} {}", asn, network.organization)
                } else {
                    network.organization.clone()
                }
            } else {
                "Unknown network".to_string()
            };

            // Show protocol status if both were attempted
            let protocol = if primary_data.target_ip.is_ipv6() { "IPv6" } else { "IPv4" };
            let protocol_info = if geoip.ipv4_result.is_some() && geoip.ipv6_result.is_some() {
                format!("{} (dual)", protocol)
            } else {
                protocol.to_string()
            };

            (
                Outcome::Ok,
                format!(
                    "{} - {} ({}ms, {}, {})",
                    location_str,
                    network_str,
                    geoip.total_duration.as_millis(),
                    primary_data.data_source,
                    protocol_info
                ),
            )
        }

        ScanResult::Port(port) => {
            let open_count = port.total_open_ports();

            if open_count == 0 {
                return (
                    Outcome::Ok,
                    format!("No open ports found ({}ms)", port.total_duration.as_millis()),
                );
            }
            // Show first few ports with services
            let mut port_descriptions = Vec::new();
            for open_port in port.get_all_open_ports().iter().take(MAX_PORTS_DISPLAY) {
                let service_name = if let Some(service) = &open_port.service {
                    service.name.clone()
                } else {
                    "unknown".to_string()
                };

                port_descriptions.push(format!("{} {}", open_port.port, service_name.to_uppercase()));
            }

            let ports_str = if open_count > MAX_PORTS_DISPLAY {
                format!(
                    "{}, +{} more",
                    port_descriptions.join(", "),
                    open_count - MAX_PORTS_DISPLAY
                )
            } else {
                port_descriptions.join(", ")
            };

            let mode_str = if let Some(primary) = port.get_primary_result() {
                match primary.scan_mode {
                    crate::scan::port::ScanMode::Minimal => "minimal",
                    crate::scan::port::ScanMode::Quick => "quick",
                    crate::scan::port::ScanMode::Standard => "standard",
                    crate::scan::port::ScanMode::Custom(_) => "custom",
                }
            } else {
                "unknown"
            };

            (
                Outcome::Ok,
                format!(
                    "{} open ({}) ({}ms, {} scan)",
                    open_count,
                    ports_str,
                    port.total_duration.as_millis(),
                    mode_str
                ),
            )
        }
    }
}

/// The first per-family TLS failure message, for a result with no successful family.
fn tls_status_failure(tls: &crate::scan::tls::TlsResult) -> String {
    use crate::scan::tls::TlsStatus;
    [&tls.ipv4_status, &tls.ipv6_status]
        .into_iter()
        .find_map(|status| match status {
            TlsStatus::Failed(msg) => Some(msg.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "no address".to_string())
}

fn count_security_features(http_data: &crate::scan::http::HttpData) -> usize {
    let mut count = 0;

    if http_data.security_headers.strict_transport_security.is_some() {
        count += 1;
    }
    if http_data.security_headers.x_frame_options.is_some() {
        count += 1;
    }
    if http_data.security_headers.x_content_type_options.is_some() {
        count += 1;
    }
    if http_data.security_headers.x_xss_protection.is_some() {
        count += 1;
    }
    if http_data.security_headers.referrer_policy.is_some() {
        count += 1;
    }
    if http_data.security_headers.permissions_policy.is_some() {
        count += 1;
    }
    if http_data.csp.is_some() {
        count += 1;
    }

    count
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs < SECONDS_PER_MINUTE {
        format!("{}s", total_secs)
    } else if total_secs < SECONDS_PER_HOUR {
        format!(
            "{}m{}s",
            total_secs / SECONDS_PER_MINUTE,
            total_secs % SECONDS_PER_MINUTE
        )
    } else {
        let hours = total_secs / SECONDS_PER_HOUR;
        let minutes = (total_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
        format!("{}h{}m", hours, minutes)
    }
}

pub fn print_separator() {
    println!("{}", "─".repeat(SEPARATOR_WIDTH));
}

pub fn print_header(target: &str) {
    println!("🎯 Scanning: {}", target);
    print_separator();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::http::{
        CachingPolicy, HttpData, HttpResult, HttpStatus, SecurityGrade as HttpSecurityGrade, SecurityHeaders,
    };
    use crate::scan::ping::{PingFailure, PingResult, PingStatus};
    use crate::scan::whois::{NotApplicableReason, WhoisResult};
    use std::collections::VecDeque;
    use std::time::Instant;

    fn state(status: ScanStatus, result: Option<ScanResult>, error: Option<eyre::Error>) -> ScanState {
        ScanState {
            result,
            error,
            status,
            last_updated: Instant::now(),
            history: VecDeque::new(),
        }
    }

    fn all_failed_ping() -> ScanResult {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Failed(PingFailure::NoReply);
        ping.ipv6_status = PingStatus::NoAddress;
        ScanResult::Ping(ping)
    }

    fn http_data(grade: HttpSecurityGrade, https_failure: Option<&str>) -> HttpData {
        HttpData {
            url: "http://example.com".to_string(),
            status_code: 200,
            response_time: Duration::from_millis(120),
            content_length: 10,
            content_type: Some("text/html".to_string()),
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
            security_grade: grade,
            scan_duration: Duration::from_millis(120),
            target_ip: "192.0.2.1".to_string(),
            https_failure: https_failure.map(str::to_string),
        }
    }

    #[test]
    fn all_failed_ping_prints_failure_icon_and_reason() {
        let out = format_scan_state("ping", &state(ScanStatus::Complete, Some(all_failed_ping()), None));
        assert!(out.starts_with("❌ PING: "), "{out}");
        assert!(out.contains("Ping failed: no echo reply"), "reason missing: {out}");
        assert!(!out.contains('✅'), "success icon on a failed ping: {out}");
    }

    #[test]
    fn refreshing_all_failed_ping_keeps_failure_icon() {
        let out = format_scan_state("ping", &state(ScanStatus::Running, Some(all_failed_ping()), None));
        assert!(out.starts_with("❌ PING: "), "{out}");
    }

    #[test]
    fn refreshing_successful_ping_shows_refresh_icon() {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Success(Duration::from_millis(12));
        let out = format_scan_state("ping", &state(ScanStatus::Running, Some(ScanResult::Ping(ping)), None));
        assert!(out.starts_with("🔄 PING: "), "{out}");
    }

    #[test]
    fn successful_ping_keeps_success_icon() {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Success(Duration::from_millis(12));
        let out = format_scan_state("ping", &state(ScanStatus::Complete, Some(ScanResult::Ping(ping)), None));
        assert!(out.starts_with("✅ PING: 12ms best latency"), "{out}");
    }

    #[test]
    fn whois_prints_the_queried_domain_and_its_source() {
        use crate::scan::whois::DataSource;
        let mut whois = WhoisResult::not_applicable("www.tatari.tv".to_string(), NotApplicableReason::IpTarget);
        whois.queried_domain = "tatari.tv".to_string();
        whois.data_source = DataSource::Rdap;
        let out = format_scan_state(
            "whois",
            &state(ScanStatus::Complete, Some(ScanResult::Whois(whois)), None),
        );
        assert!(
            out.starts_with("✅ WHOIS: tatari.tv (from www.tatari.tv) via RDAP: "),
            "{out}"
        );
    }

    #[test]
    fn whois_no_registrable_domain_prints_the_reason() {
        let result = ScanResult::Whois(WhoisResult::not_applicable(
            "localhost".to_string(),
            NotApplicableReason::NoRegistrableDomain,
        ));
        let out = format_scan_state("whois", &state(ScanStatus::Complete, Some(result), None));
        assert!(out.contains("no registrable domain"), "{out}");
        assert!(!out.contains('✅'), "{out}");
    }

    #[test]
    fn whois_not_applicable_prints_neutral() {
        let result = ScanResult::Whois(WhoisResult::not_applicable(
            "192.0.2.1".to_string(),
            NotApplicableReason::IpTarget,
        ));
        let out = format_scan_state("whois", &state(ScanStatus::Complete, Some(result), None));
        assert!(out.contains("n/a"), "{out}");
        assert!(!out.contains('✅'), "n/a printed as a successful lookup: {out}");
        assert!(
            !out.contains("unknown registrar"),
            "n/a printed as an empty lookup: {out}"
        );
    }

    #[test]
    fn failed_refresh_prints_retained_result_and_its_error() {
        let out = format_scan_state(
            "ping",
            &state(
                ScanStatus::Failed,
                Some(all_failed_ping()),
                Some(eyre::eyre!("timed out after 30s")),
            ),
        );
        assert!(out.starts_with("❌ PING: "), "{out}");
        assert!(out.contains("Error: timed out after 30s"), "newer error hidden: {out}");
    }

    #[test]
    fn failed_first_scan_prints_error() {
        let out = format_scan_state(
            "tls",
            &state(ScanStatus::Failed, None, Some(eyre::eyre!("timed out after 30s"))),
        );
        assert!(out.starts_with("❌ TLS: Error - timed out after 30s"), "{out}");
    }

    #[test]
    fn http_prints_https_failure_and_primary_grade() {
        let result = ScanResult::Http(HttpResult {
            ipv4_status: HttpStatus::Success(HttpSecurityGrade::F),
            ipv4_result: Some(http_data(HttpSecurityGrade::F, Some("certificate expired"))),
            ipv6_status: HttpStatus::Success(HttpSecurityGrade::APlus),
            ipv6_result: Some(http_data(HttpSecurityGrade::APlus, None)),
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(240),
        });
        let out = format_scan_state("http", &state(ScanStatus::Complete, Some(result), None));
        assert!(out.contains("grade F "), "grade must be the primary result's: {out}");
        assert!(!out.contains("APlus"), "grade printed with Debug: {out}");
        assert!(
            out.contains("HTTPS failed: certificate expired"),
            "https_failure missing: {out}"
        );
    }

    #[test]
    fn tls_version_and_grade_use_display_form() {
        use crate::scan::tls::{SecurityGrade as TlsSecurityGrade, TlsResult, TlsStatus};
        let mut tls = TlsResult::new();
        let mut data = crate::scan::tls::fixtures::expired_handshake_result();
        data.connection_successful = true;
        data.negotiated_version = Some(crate::scan::tls::TlsVersion::V1_3);
        data.security_grade = TlsSecurityGrade::APlus;
        tls.ipv4_result = Some(data);
        tls.ipv4_status = TlsStatus::Success(TlsSecurityGrade::APlus);
        let out = format_scan_state("tls", &state(ScanStatus::Complete, Some(ScanResult::Tls(tls)), None));
        assert!(out.contains("TLSv1.3, "), "{out}");
        assert!(out.contains("grade A+ "), "{out}");
    }

    #[test]
    fn tls_connection_failure_prints_failure_icon_and_reason() {
        use crate::scan::tls::{SecurityGrade as TlsSecurityGrade, TlsData, TlsResult, TlsStatus};
        let mut tls = TlsResult::new();
        let mut data = TlsData::new("192.0.2.1".to_string());
        data.certificate_errors
            .push("Connection failed: connect timed out".to_string());
        tls.ipv4_result = Some(data);
        tls.ipv4_status = TlsStatus::Success(TlsSecurityGrade::F);
        let out = format_scan_state("tls", &state(ScanStatus::Complete, Some(ScanResult::Tls(tls)), None));
        assert!(
            out.starts_with("❌ TLS: Connection failed: connect timed out, grade F"),
            "{out}"
        );
        assert!(!out.contains('✅'), "{out}");
    }

    #[test]
    fn tls_rejected_handshake_prints_vulnerability_reason_and_grade() {
        use crate::scan::tls::{TlsResult, TlsStatus};
        let mut tls = TlsResult::new();
        let data = crate::scan::tls::fixtures::expired_handshake_result();
        tls.ipv4_status = TlsStatus::Success(data.security_grade.clone());
        tls.ipv4_result = Some(data);
        let out = format_scan_state("tls", &state(ScanStatus::Complete, Some(ScanResult::Tls(tls)), None));
        assert!(out.starts_with("❌ TLS: Certificate expired"), "{out}");
        assert!(out.contains("grade F"), "grade dropped: {out}");
    }

    #[test]
    fn tls_with_no_successful_family_prints_status_reason() {
        use crate::scan::tls::{TlsResult, TlsStatus};
        let mut tls = TlsResult::new();
        tls.ipv4_status = TlsStatus::Failed("handshake refused".to_string());
        let out = format_scan_state("tls", &state(ScanStatus::Complete, Some(ScanResult::Tls(tls)), None));
        assert!(out.starts_with("❌ TLS: Connection failed: handshake refused"), "{out}");
    }

    #[test]
    fn http_grade_uses_display_form() {
        let result = ScanResult::Http(HttpResult {
            ipv4_status: HttpStatus::Success(HttpSecurityGrade::APlus),
            ipv4_result: Some(http_data(HttpSecurityGrade::APlus, None)),
            ipv6_status: HttpStatus::NotQueried,
            ipv6_result: None,
            queried_at: Instant::now(),
            total_duration: Duration::from_millis(120),
        });
        let out = format_scan_state("http", &state(ScanStatus::Complete, Some(result), None));
        assert!(out.contains("grade A+ "), "{out}");
        assert!(!out.contains("HTTPS failed"), "{out}");
    }
}
