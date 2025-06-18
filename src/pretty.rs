use crate::types::{ScanResult, ScanState, ScanStatus};
use std::time::Duration;

const PACKET_LOSS_PERCENTAGE_MULTIPLIER: f32 = 100.0;
const CERT_EXPIRY_WARNING_DAYS: i64 = 30;
const DAYS_PER_YEAR: i64 = 365;
const EXPIRY_WARNING_DAYS: i64 = 30;
const PACKET_LOSS_TIMEOUT_THRESHOLD: f32 = 0.5;
const MAX_PORTS_DISPLAY: usize = 4;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3600;
const SEPARATOR_WIDTH: usize = 80;

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
            if let Some(best_latency) = ping.get_best_latency() {
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
                if ping.ipv4_status.is_success() {
                    if let Some(latency) = ping.ipv4_status.latency() {
                        protocol_results.push(format!("IPv4: {}ms", latency.as_millis()));
                    }
                }
                if ping.ipv6_status.is_success() {
                    if let Some(latency) = ping.ipv6_status.latency() {
                        protocol_results.push(format!("IPv6: {}ms", latency.as_millis()));
                    }
                }

                let protocol_str = if protocol_results.is_empty() {
                    "no response".to_string()
                } else {
                    protocol_results.join(", ")
                };

                println!("{}ms best latency ({}, TTL: {}, Loss: {:.1}%)",
                    best_latency.as_millis(),
                    protocol_str,
                    ttl_str,
                    loss
                );
            } else {
                // All pings failed
                println!("Ping failed (no response from any protocol)");
            }
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
            if tls.has_any_success() {
                if let Some(primary_data) = tls.get_primary_result() {
                    let version = primary_data.negotiated_version
                        .as_ref()
                        .map(|v| format!("{:?}", v))
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

                    let best_grade = tls.get_best_security_grade()
                        .map(|g| format!("{:?}", g))
                        .unwrap_or_else(|| "F".to_string());

                    println!("{}, {}, grade {} ({}ms)",
                        version, cert_status, best_grade, primary_data.handshake_time.as_millis());
                }
            } else {
                println!("Connection failed");
            }
        }

        ScanResult::Http(http) => {
            if let Some(primary_data) = http.get_primary_result() {
                let security_features = count_security_features(primary_data);
                let vuln_count = http.total_vulnerabilities();

                println!("{} {}, {} security features, {} vulnerabilities, grade {:?} ({}ms)",
                    primary_data.status_code,
                    primary_data.content_type.as_deref().unwrap_or("unknown"),
                    security_features,
                    vuln_count,
                    http.get_best_security_grade().map(|g| format!("{:?}", g)).unwrap_or_else(|| "N/A".to_string()),
                    primary_data.response_time.as_millis()
                );
            } else {
                println!("HTTP scan failed for all protocols");
            }
        }

        ScanResult::Whois(whois) => {
            let age_str = whois.domain_age_days
                .map(|days| {
                    if days < DAYS_PER_YEAR {
                        format!("{}d old", days)
                    } else {
                        format!("{}yr old", days / DAYS_PER_YEAR)
                    }
                })
                .unwrap_or_else(|| "unknown age".to_string());

            let expiry_str = whois.expires_in_days
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

        ScanResult::Traceroute(traceroute) => {
            if let Some(primary_data) = traceroute.get_primary_result() {
                let protocol = if primary_data.ipv6 { "IPv6" } else { "IPv4" };
                let reached = if primary_data.destination_reached { "reached" } else { "unreached" };

                // Calculate average RTT from last hop
                let last_hop_rtt = primary_data.hops.last()
                    .and_then(|hop| hop.avg_rtt)
                    .map(|rtt| format!("{}ms", rtt.as_millis()))
                    .unwrap_or_else(|| "timeout".to_string());

                // Count timeouts
                let timeout_hops = primary_data.hops.iter()
                    .filter(|hop| hop.packet_loss > PACKET_LOSS_TIMEOUT_THRESHOLD)
                    .count();

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

                println!("{} {} hops, {} ({}{}, {}ms)",
                    protocol_info,
                    traceroute.total_hops(),
                    reached,
                    last_hop_rtt,
                    timeout_str,
                    traceroute.total_duration.as_millis()
                );
            } else {
                println!("Traceroute failed for all protocols ({}ms)",
                    traceroute.total_duration.as_millis()
                );
            }
        }

        ScanResult::GeoIp(geoip) => {
            if let Some(primary_data) = geoip.get_primary_result() {
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
                let protocol_info = if geoip.ipv4_result.is_some() && geoip.ipv6_result.is_some() {
                    let protocol = if primary_data.target_ip.is_ipv6() { "IPv6" } else { "IPv4" };
                    format!("{} (dual)", protocol)
                } else {
                    let protocol = if primary_data.target_ip.is_ipv6() { "IPv6" } else { "IPv4" };
                    protocol.to_string()
                };

                println!("{} - {} ({}ms, {}, {})",
                    location_str,
                    network_str,
                    geoip.total_duration.as_millis(),
                    primary_data.data_source,
                    protocol_info
                );
            } else {
                println!("GeoIP lookup failed for all protocols ({}ms)",
                    geoip.total_duration.as_millis()
                );
            }
        }

        ScanResult::Port(port) => {
            let open_count = port.total_open_ports();

            if open_count == 0 {
                println!("No open ports found ({}ms)",
                    port.total_duration.as_millis()
                );
            } else {
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
                    format!("{}, +{} more", port_descriptions.join(", "), open_count - MAX_PORTS_DISPLAY)
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

                println!("{} open ({}) ({}ms, {} scan)",
                    open_count,
                    ports_str,
                    port.total_duration.as_millis(),
                    mode_str
                );
            }
        }
    }
}

fn count_security_features(http_data: &crate::scan::http::HttpData) -> usize {
    let mut count = 0;

    if http_data.security_headers.strict_transport_security.is_some() { count += 1; }
    if http_data.security_headers.x_frame_options.is_some() { count += 1; }
    if http_data.security_headers.x_content_type_options.is_some() { count += 1; }
    if http_data.security_headers.x_xss_protection.is_some() { count += 1; }
    if http_data.security_headers.referrer_policy.is_some() { count += 1; }
    if http_data.security_headers.permissions_policy.is_some() { count += 1; }
    if http_data.csp.is_some() { count += 1; }

    count
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs < SECONDS_PER_MINUTE {
        format!("{}s", total_secs)
    } else if total_secs < SECONDS_PER_HOUR {
        format!("{}m{}s", total_secs / SECONDS_PER_MINUTE, total_secs % SECONDS_PER_MINUTE)
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