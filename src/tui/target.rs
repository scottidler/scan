use crate::scan::dns::QueryStatus;
use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanState, ScanStatus};
use log;
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use std::any::Any;
use std::net::IpAddr;

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * 60; // 3600
const MIN_TARGET_PANE_WIDTH: u16 = 25;
const MIN_TARGET_PANE_HEIGHT: u16 = 12;
/// Display order of the scanner rows, matching `create_default_scanners`.
const SCANNER_DISPLAY_ORDER: [&str; 8] = ["ping", "dns", "tls", "http", "whois", "traceroute", "geoip", "port"];

/// Scanner counts for the Status row. A scanner whose last attempt found no target address in the
/// selected protocol counts as `no_address`, never as `failed`.
#[derive(Debug, Default, PartialEq, Eq)]
struct ScannerCounts {
    total: usize,
    running: usize,
    complete: usize,
    failed: usize,
    no_address: usize,
}

#[derive(Clone, Copy)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn label(self) -> &'static str {
        match self {
            AddressFamily::V4 => "IPv4",
            AddressFamily::V6 => "IPv6",
        }
    }

    fn matches(self, ip: &IpAddr) -> bool {
        match self {
            AddressFamily::V4 => ip.is_ipv4(),
            AddressFamily::V6 => ip.is_ipv6(),
        }
    }
}

/// TARGET pane displays basic target information and scanner status overview
pub struct TargetPane {
    title: &'static str,
    id: &'static str,
}

impl TargetPane {
    pub fn new() -> Self {
        log::debug!("[tui::target] new:");
        Self {
            title: "target",
            id: "target",
        }
    }

    /// Format elapsed time in a human-readable way
    fn format_elapsed(elapsed: std::time::Duration) -> String {
        let secs = elapsed.as_secs();
        if secs < SECONDS_PER_MINUTE {
            format!("{}s", secs)
        } else if secs < SECONDS_PER_HOUR {
            format!("{}m {}s", secs / SECONDS_PER_MINUTE, secs % SECONDS_PER_MINUTE)
        } else {
            format!(
                "{}h {}m",
                secs / SECONDS_PER_HOUR,
                (secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE
            )
        }
    }

    /// Status icon and color for a scanner row. A failed attempt with no target address in the
    /// selected protocol is not a fault: `⚫` in MUTED.
    fn status_icon_and_color(scan_state: &ScanState) -> (&'static str, Color) {
        match scan_state.status {
            ScanStatus::Running => ("🔄", theme::WARN),
            ScanStatus::Complete => ("✅", theme::GOOD),
            ScanStatus::Failed if crate::tui::no_address(scan_state).is_some() => ("⚫", theme::MUTED),
            ScanStatus::Failed => ("❌", theme::BAD),
        }
    }

    /// Scanner keys in the fixed display order; unknown keys follow, sorted.
    /// DashMap iteration order is arbitrary, so rows would reshuffle every redraw without this.
    fn ordered_scanner_keys(state: &AppState) -> Vec<String> {
        let mut keys: Vec<String> = SCANNER_DISPLAY_ORDER
            .iter()
            .filter(|name| state.scanners.contains_key(**name))
            .map(|name| name.to_string())
            .collect();
        let mut extra: Vec<String> = state
            .scanners
            .iter()
            .map(|entry| entry.key().clone())
            .filter(|key| !SCANNER_DISPLAY_ORDER.contains(&key.as_str()))
            .collect();
        extra.sort();
        keys.extend(extra);
        keys
    }

    fn summary_color(running: usize, failed: usize) -> Style {
        if failed > 0 {
            Style::default().fg(theme::BAD)
        } else if running > 0 {
            Style::default().fg(theme::WARN)
        } else {
            Style::default().fg(theme::GOOD)
        }
    }

    /// The scanner counts on the Status row, e.g. `5/8 ✅ 1 🔄 1 ❌ 1 ⚫`.
    fn collapsed_summary(counts: &ScannerCounts) -> String {
        let mut summary = format!("{}/{} ✅", counts.complete, counts.total);
        if counts.running > 0 {
            summary.push_str(&format!(" {} 🔄", counts.running));
        }
        if counts.failed > 0 {
            summary.push_str(&format!(" {} ❌", counts.failed));
        }
        if counts.no_address > 0 {
            summary.push_str(&format!(" {} ⚫", counts.no_address));
        }
        summary
    }

    /// One IPv4/IPv6 status row. `Target` resolution (`state.resolved_ips`) answers first, so an IP
    /// target needs no DNS scan; the DNS scanner's records and status are the fallback.
    fn address_line(state: &AppState, family: AddressFamily) -> Line<'static> {
        let label = family.label();
        let selected = match family {
            AddressFamily::V4 => state.protocol.includes_ipv4(),
            AddressFamily::V6 => state.protocol.includes_ipv6(),
        };
        if !selected {
            return Line::from(vec![
                Span::styled("  ", Style::default().fg(theme::MUTED)),
                Span::styled(format!("⚫ {}: ", label), Style::default().fg(theme::MUTED)),
                Span::styled("disabled", Style::default().fg(theme::MUTED)),
            ]);
        }

        let (icon, value, color) = match state.resolved_ips.iter().find(|ip| family.matches(ip)) {
            Some(ip) => {
                log::trace!("[tui::target] address_from_resolution: family={} ip={}", label, ip);
                ("✅", ip.to_string(), theme::GOOD)
            }
            None => Self::address_from_dns(state, family),
        };
        Line::from(vec![
            Span::styled("▶ ", Style::default().fg(theme::GOOD)),
            Span::styled(format!("{} {}: ", icon, label), Style::default().fg(color)),
            Span::styled(value, Style::default().fg(color)),
        ])
    }

    /// Fallback when `Target` resolution has no address of this family. A family that simply has
    /// no address is neutral gray; red is kept for a DNS query that errored.
    fn address_from_dns(state: &AppState, family: AddressFamily) -> (&'static str, String, Color) {
        if state.target.parse::<IpAddr>().is_ok() {
            return ("⚫", "n/a".to_string(), theme::MUTED);
        }
        let Some(dns_state) = state.scanners.get("dns") else {
            return ("⚫", "initializing...".to_string(), theme::MUTED);
        };
        match &dns_state.result {
            Some(crate::types::ScanResult::Dns(dns_result)) => {
                let (first, status) = match family {
                    AddressFamily::V4 => (dns_result.A.first().map(|r| r.value.to_string()), &dns_result.A_status),
                    AddressFamily::V6 => (
                        dns_result.AAAA.first().map(|r| r.value.to_string()),
                        &dns_result.AAAA_status,
                    ),
                };
                match (first, status) {
                    (Some(ip), _) => ("✅", ip, theme::GOOD),
                    (None, QueryStatus::Failed(_) | QueryStatus::Timeout) => ("❌", "no data".to_string(), theme::BAD),
                    (None, QueryStatus::NotQueried) => ("⚫", "not queried".to_string(), theme::MUTED),
                    (None, QueryStatus::NoRecords | QueryStatus::Success(_)) => {
                        ("⚫", "none".to_string(), theme::MUTED)
                    }
                }
            }
            Some(_) => {
                log::warn!("[tui::target] dns_unexpected_result_type:");
                ("❌", "error".to_string(), theme::BAD)
            }
            None => match dns_state.status {
                ScanStatus::Running => ("🔄", "resolving...".to_string(), theme::WARN),
                ScanStatus::Failed => ("❌", "resolution failed".to_string(), theme::BAD),
                ScanStatus::Complete => ("⚫", "waiting to resolve...".to_string(), theme::MUTED),
            },
        }
    }

    /// Count scanners by status.
    fn calculate_stats(state: &AppState) -> ScannerCounts {
        let mut counts = ScannerCounts {
            total: state.scanners.len(),
            ..ScannerCounts::default()
        };

        for scanner in state.scanners.iter() {
            match scanner.status {
                ScanStatus::Running => counts.running += 1,
                ScanStatus::Complete => counts.complete += 1,
                ScanStatus::Failed if crate::tui::no_address(&scanner).is_some() => counts.no_address += 1,
                ScanStatus::Failed => counts.failed += 1,
            }
        }

        log::trace!("[tui::target] calculate_stats: counts={:?}", counts);

        counts
    }
}

impl Default for TargetPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TargetPane {
    /// The target, both addresses and the scanner summary come first, so a short dashboard cell
    /// shows them; the protocol hint and one row per scanner follow, reached by scrolling.
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!(
            "[tui::target] content: width={} detail={:?} target={}",
            width,
            detail,
            state.target
        );

        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("🎯 ", Style::default().fg(theme::VALUE)),
            Span::styled(state.target.clone(), Style::default().fg(theme::LABEL)),
        ]));

        lines.push(Self::address_line(state, AddressFamily::V4));
        lines.push(Self::address_line(state, AddressFamily::V6));

        let counts = Self::calculate_stats(state);
        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(theme::LABEL)),
            Span::styled(
                Self::collapsed_summary(&counts),
                Self::summary_color(counts.running, counts.failed),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("🔗 ", Style::default().fg(theme::ACCENT)),
            Span::styled("Protocol: ", Style::default().fg(theme::LABEL)),
            Span::styled(
                format!("{} (Press 'p' to cycle)", state.protocol_display()),
                Style::default().fg(theme::VALUE),
            ),
        ]));

        for key in Self::ordered_scanner_keys(state) {
            if let Some(scanner) = state.scanners.get(&key) {
                let (icon, color) = Self::status_icon_and_color(&scanner);
                let elapsed = scanner.last_updated.elapsed();

                lines.push(Line::from(vec![
                    Span::styled(format!("{} ", icon), Style::default().fg(color)),
                    Span::styled(format!("{}: ", key.to_uppercase()), Style::default().fg(theme::LABEL)),
                    Span::styled(Self::format_elapsed(elapsed), Style::default().fg(theme::MUTED)),
                ]));
            }
        }

        log::trace!(
            "[tui::target] content_prepared: lines={} scanners={}",
            lines.len(),
            state.scanners.len()
        );

        // No line here carries a failure reason, so every one is fit to a single row.
        crate::tui::text::to_rows(lines, width, detail, &[])
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_TARGET_PANE_WIDTH, MIN_TARGET_PANE_HEIGHT) // Larger to show all scanners
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn is_focusable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Protocol;
    use crate::types::{ScanState, ScanStatus};
    use dashmap::DashMap;
    use std::time::Instant;

    #[test]
    fn test_target_pane_creation() {
        let pane = TargetPane::new();
        assert_eq!(pane.title(), "target");
        assert_eq!(pane.id(), "target");
        assert_eq!(pane.min_size(), (MIN_TARGET_PANE_WIDTH, MIN_TARGET_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn test_format_elapsed() {
        use std::time::Duration;

        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(30)), "30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(90)), "1m 30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(3661)), "1h 1m");
    }

    #[test]
    fn test_status_icon_and_color() {
        let scan_state = |status, error| ScanState {
            result: None,
            error,
            status,
            last_updated: Instant::now(),
            history: Default::default(),
        };
        let (icon, color) = TargetPane::status_icon_and_color(&scan_state(ScanStatus::Running, None));
        assert_eq!(icon, "🔄");
        assert_eq!(color, Color::Yellow);

        let (icon, color) = TargetPane::status_icon_and_color(&scan_state(ScanStatus::Complete, None));
        assert_eq!(icon, "✅");
        assert_eq!(color, Color::Green);

        let (icon, color) = TargetPane::status_icon_and_color(&scan_state(
            ScanStatus::Failed,
            Some(eyre::eyre!("IPv6: operation timed out")),
        ));
        assert_eq!(icon, "❌");
        assert_eq!(color, Color::LightRed);

        let (icon, color) = TargetPane::status_icon_and_color(&scan_state(
            ScanStatus::Failed,
            Some(eyre::Report::new(crate::scan::NoAddress(Protocol::Ipv6))),
        ));
        assert_eq!(icon, "⚫");
        assert_eq!(color, theme::MUTED);
    }

    #[test]
    fn test_calculate_stats() {
        let state = AppState {
            target: "example.com".to_string(),
            scanners: DashMap::new(),
            protocol: Protocol::Both,
            resolved_ips: Vec::new(),
        };

        // Add some test scanner states
        state.scanners.insert(
            "ping".to_string(),
            ScanState {
                result: None,
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );

        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );

        state.scanners.insert(
            "http".to_string(),
            ScanState {
                result: None,
                error: Some(eyre::eyre!("Connection failed")),
                status: ScanStatus::Failed,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );

        state.scanners.insert(
            "tls".to_string(),
            ScanState {
                result: None,
                error: Some(eyre::Report::new(crate::scan::NoAddress(Protocol::Ipv6))),
                status: ScanStatus::Failed,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );

        assert_eq!(
            TargetPane::calculate_stats(&state),
            ScannerCounts {
                total: 4,
                running: 1,
                complete: 1,
                failed: 1,
                no_address: 1,
            }
        );
    }

    fn state_with_scanners(names: &[&str], status: ScanStatus) -> AppState {
        let state = AppState::new("example.com".to_string());
        for name in names {
            state.scanners.insert(
                name.to_string(),
                ScanState {
                    result: None,
                    error: None,
                    status: status.clone(),
                    last_updated: Instant::now(),
                    history: Default::default(),
                },
            );
        }
        state
    }

    #[test]
    fn test_full_list_uses_constant_order() {
        use crate::tui::testing::render_pane;
        // Inserted in reverse so map order cannot match the constant by accident.
        let mut names = SCANNER_DISPLAY_ORDER.to_vec();
        names.reverse();
        let state = state_with_scanners(&names, ScanStatus::Complete);
        let out = render_pane(&TargetPane::new(), &state, 40, 20, false);
        let positions: Vec<usize> = SCANNER_DISPLAY_ORDER
            .iter()
            .map(|n| {
                out.find(&format!("{}:", n.to_uppercase()))
                    .unwrap_or_else(|| panic!("{} missing:\n{}", n, out))
            })
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "order wrong:\n{}", out);
    }

    /// Target, two addresses, Status, Protocol, then one row per scanner.
    const TARGET_ROWS_WITH_EVERY_SCANNER: u16 = 5 + SCANNER_DISPLAY_ORDER.len() as u16;

    #[test]
    fn short_pane_shows_the_summary_and_marks_the_hidden_scanners() {
        use crate::tui::testing::render_pane;
        let state = state_with_scanners(&SCANNER_DISPLAY_ORDER, ScanStatus::Complete);
        // 6 rows is the 25% top row of a 24-row terminal; inner height is 4.
        for height in [6u16, 8, 10, 12] {
            let out = render_pane(&TargetPane::new(), &state, 40, height, false);
            assert!(
                out.contains("Status: 8/8 ✅"),
                "no summary at height {}:\n{}",
                height,
                out
            );
            let hidden = TARGET_ROWS_WITH_EVERY_SCANNER - (height - 2);
            assert!(
                out.contains(&format!("↓ {hidden} more")),
                "hidden scanners not marked at height {}:\n{}",
                height,
                out
            );
        }
    }

    #[test]
    fn tall_pane_shows_every_scanner_the_summary_and_no_marker() {
        use crate::tui::testing::render_pane;
        let state = state_with_scanners(&SCANNER_DISPLAY_ORDER, ScanStatus::Complete);
        let out = render_pane(&TargetPane::new(), &state, 40, 20, false);
        for n in SCANNER_DISPLAY_ORDER {
            assert!(
                out.contains(&format!("{}:", n.to_uppercase())),
                "{} missing:\n{}",
                n,
                out
            );
        }
        assert!(out.contains("Status: 8/8 ✅"), "{out}");
        assert!(!out.contains('↓'), "{out}");
    }

    #[test]
    fn test_collapsed_summary_counts() {
        let counts = |total, running, complete, failed, no_address| ScannerCounts {
            total,
            running,
            complete,
            failed,
            no_address,
        };
        assert_eq!(TargetPane::collapsed_summary(&counts(8, 0, 8, 0, 0)), "8/8 ✅");
        assert_eq!(
            TargetPane::collapsed_summary(&counts(8, 1, 6, 1, 0)),
            "6/8 ✅ 1 🔄 1 ❌"
        );
        assert_eq!(TargetPane::collapsed_summary(&counts(8, 0, 3, 0, 5)), "3/8 ✅ 5 ⚫");
    }

    fn ip_target_state(target: &str) -> AppState {
        let mut state = AppState::new(target.to_string());
        state.resolved_ips = vec![target.parse().unwrap()];
        state
    }

    #[test]
    fn bare_ipv4_target_renders_its_address_without_dns() {
        use crate::tui::testing::render_pane;
        let state = ip_target_state("1.1.1.1");
        let out = render_pane(&TargetPane::new(), &state, 40, 20, false);
        assert!(out.contains("✅ IPv4: 1.1.1.1"), "{}", out);
        assert!(!out.contains("IPv4: no data"), "{}", out);
    }

    #[test]
    fn bare_ipv6_target_renders_its_address() {
        use crate::tui::testing::render_pane;
        let state = ip_target_state("2606:4700:4700::1111");
        let out = render_pane(&TargetPane::new(), &state, 50, 20, false);
        assert!(out.contains("✅ IPv6: 2606:4700:4700::1111"), "{}", out);
    }

    #[test]
    fn resolved_address_respects_disabled_protocol() {
        use crate::tui::testing::render_pane;
        let mut state = ip_target_state("1.1.1.1");
        state.protocol = Protocol::Ipv6;
        let out = render_pane(&TargetPane::new(), &state, 40, 20, false);
        assert!(out.contains("IPv4: disabled"), "{}", out);
        assert!(!out.contains("IPv4: 1.1.1.1"), "{}", out);
    }

    #[test]
    fn dns_records_fill_in_when_resolution_has_no_address() {
        use crate::scan::dns::{DnsRecord, DnsResult};
        use crate::tui::testing::render_pane;
        use crate::types::ScanResult;
        let state = AppState::new("example.com".to_string());
        let mut dns = DnsResult::new();
        dns.A.push(DnsRecord::new("93.184.216.34".parse().unwrap(), 60));
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(ScanResult::Dns(dns)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        let out = render_pane(&TargetPane::new(), &state, 40, 20, false);
        assert!(out.contains("✅ IPv4: 93.184.216.34"), "{}", out);
        // AAAA left at its default `NotQueried`: never asked, so neutral rather than red.
        assert!(out.contains("IPv6: not queried"), "{}", out);
        assert!(!out.contains("❌"), "{}", out);
    }

    fn state_with_dns(target: &str, dns: crate::scan::dns::DnsResult) -> AppState {
        let state = AppState::new(target.to_string());
        state.scanners.insert(
            "dns".to_string(),
            ScanState {
                result: Some(crate::types::ScanResult::Dns(dns)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        state
    }

    #[test]
    fn bare_ip_target_shows_other_family_as_neutral_na() {
        use crate::tui::testing::render_pane;
        let out = render_pane(&TargetPane::new(), &ip_target_state("1.1.1.1"), 40, 20, false);
        assert!(out.contains("✅ IPv4: 1.1.1.1"), "{}", out);
        assert!(out.contains("IPv6: n/a"), "{}", out);
        assert!(!out.contains("❌"), "{}", out);

        let out = render_pane(
            &TargetPane::new(),
            &ip_target_state("2606:4700:4700::1111"),
            50,
            20,
            false,
        );
        assert!(out.contains("IPv4: n/a"), "{}", out);
        assert!(!out.contains("❌"), "{}", out);
    }

    #[test]
    fn domain_with_empty_aaaa_shows_neutral_none() {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
        use crate::tui::testing::render_pane;
        let mut dns = DnsResult::new();
        dns.A.push(DnsRecord::new("140.82.112.3".parse().unwrap(), 60));
        dns.A_status = QueryStatus::Success(1);
        dns.AAAA_status = QueryStatus::NoRecords;
        let out = render_pane(&TargetPane::new(), &state_with_dns("github.com", dns), 40, 20, false);
        assert!(out.contains("✅ IPv4: 140.82.112.3"), "{}", out);
        assert!(out.contains("IPv6: none"), "{}", out);
        assert!(!out.contains("❌"), "{}", out);
    }

    #[test]
    fn queried_family_that_errored_stays_red() {
        use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
        use crate::tui::testing::render_pane;
        let mut dns = DnsResult::new();
        dns.A.push(DnsRecord::new("93.184.216.34".parse().unwrap(), 60));
        dns.A_status = QueryStatus::Success(1);
        for status in [QueryStatus::Failed("SERVFAIL".to_string()), QueryStatus::Timeout] {
            dns.AAAA_status = status;
            let out = render_pane(
                &TargetPane::new(),
                &state_with_dns("example.com", dns.clone()),
                40,
                20,
                false,
            );
            assert!(out.contains("❌ IPv6: no data"), "{}", out);
        }
    }

    const LONG_TARGET: &str = "a-very-long-subdomain-label.of-a-long-registrable-domain.example.com";

    #[test]
    fn long_target_is_fit_with_ellipsis_in_narrow_terminals() {
        let state = AppState::new(LONG_TARGET.to_string());
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &TargetPane::new(),
            &state,
            0,
            0,
            &format!("🎯 {LONG_TARGET}"),
        );
    }

    fn protocol_source(state: &AppState) -> String {
        format!("🔗 Protocol: {} (Press 'p' to cycle)", state.protocol_display())
    }

    #[test]
    fn protocol_line_is_fit_with_ellipsis_at_108_columns() {
        // Scott's ~108-column screenshot cut this to `Protocol: IPv4+IPv6 (Pre`.
        let state = AppState::new("www.tatari.tv".to_string());
        let (width, height) = crate::tui::testing::dashboard_pane_size(0, 0, 108, 40);
        let expected = crate::tui::testing::expected_clip(&protocol_source(&state), width - 2);
        let out = crate::tui::testing::render_pane(&TargetPane::new(), &state, width, height, false);
        assert!(out.contains(&format!("│{expected}│")), "`{expected}` missing:\n{out}");
    }

    #[test]
    fn protocol_line_that_fits_is_unchanged() {
        let state = AppState::new("www.tatari.tv".to_string());
        let (width, height) = crate::tui::testing::dashboard_pane_size(0, 0, 200, 55);
        let out = crate::tui::testing::render_pane(&TargetPane::new(), &state, width, height, false);
        assert!(out.contains(&protocol_source(&state)), "protocol line changed:\n{out}");
        assert!(!out.contains('…'), "nothing here is too long:\n{out}");
    }
}
