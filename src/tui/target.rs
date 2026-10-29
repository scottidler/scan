use crate::scan::dns::QueryStatus;
use crate::tui::pane::{Pane, create_block};
use crate::types::{AppState, ScanStatus};
use log;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
};
use std::any::Any;
use std::net::IpAddr;

const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 60 * 60; // 3600
const MIN_TARGET_PANE_WIDTH: u16 = 25;
const MIN_TARGET_PANE_HEIGHT: u16 = 12;
/// Display order of the scanner rows, matching `create_default_scanners`.
const SCANNER_DISPLAY_ORDER: [&str; 8] = ["ping", "dns", "tls", "http", "whois", "traceroute", "geoip", "port"];

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

    /// Get status icon and color for a scanner status
    fn status_icon_and_color(status: &ScanStatus) -> (&'static str, Color) {
        match status {
            ScanStatus::Running => ("🔄", Color::Yellow),
            ScanStatus::Complete => ("✅", Color::Green),
            ScanStatus::Failed => ("❌", Color::Red),
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
            Style::default().fg(Color::Red)
        } else if running > 0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Green)
        }
    }

    /// One-line stand-in for the scanner list, e.g. `6/8 ✅ 1 🔄 1 ❌`.
    fn collapsed_summary(total: usize, running: usize, complete: usize, failed: usize) -> String {
        let mut summary = format!("{}/{} ✅", complete, total);
        if running > 0 {
            summary.push_str(&format!(" {} 🔄", running));
        }
        if failed > 0 {
            summary.push_str(&format!(" {} ❌", failed));
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
                Span::styled("  ", Style::default().fg(Color::Gray)),
                Span::styled(format!("⚫ {}: ", label), Style::default().fg(Color::Gray)),
                Span::styled("disabled", Style::default().fg(Color::Gray)),
            ]);
        }

        let (icon, value, color) = match state.resolved_ips.iter().find(|ip| family.matches(ip)) {
            Some(ip) => {
                log::trace!("[tui::target] address_from_resolution: family={} ip={}", label, ip);
                ("✅", ip.to_string(), Color::Green)
            }
            None => Self::address_from_dns(state, family),
        };
        Line::from(vec![
            Span::styled("▶ ", Style::default().fg(Color::Green)),
            Span::styled(format!("{} {}: ", icon, label), Style::default().fg(color)),
            Span::styled(value, Style::default().fg(color)),
        ])
    }

    /// Fallback when `Target` resolution has no address of this family. A family that simply has
    /// no address is neutral gray; red is kept for a DNS query that errored.
    fn address_from_dns(state: &AppState, family: AddressFamily) -> (&'static str, String, Color) {
        if state.target.parse::<IpAddr>().is_ok() {
            return ("⚫", "n/a".to_string(), Color::Gray);
        }
        let Some(dns_state) = state.scanners.get("dns") else {
            return ("⚫", "initializing...".to_string(), Color::Gray);
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
                    (Some(ip), _) => ("✅", ip, Color::Green),
                    (None, QueryStatus::Failed(_) | QueryStatus::Timeout) => ("❌", "no data".to_string(), Color::Red),
                    (None, QueryStatus::NotQueried) => ("⚫", "not queried".to_string(), Color::Gray),
                    (None, QueryStatus::NoRecords | QueryStatus::Success(_)) => ("⚫", "none".to_string(), Color::Gray),
                }
            }
            Some(_) => {
                log::warn!("[tui::target] dns_unexpected_result_type:");
                ("❌", "error".to_string(), Color::Red)
            }
            None => match dns_state.status {
                ScanStatus::Running => ("🔄", "resolving...".to_string(), Color::Yellow),
                ScanStatus::Failed => ("❌", "resolution failed".to_string(), Color::Red),
                ScanStatus::Complete => ("⚫", "waiting to resolve...".to_string(), Color::Gray),
            },
        }
    }

    /// Calculate scanner statistics
    fn calculate_stats(state: &AppState) -> (usize, usize, usize, usize) {
        let total = state.scanners.len();
        let mut running = 0;
        let mut complete = 0;
        let mut failed = 0;

        for scanner in state.scanners.iter() {
            match scanner.status {
                ScanStatus::Running => running += 1,
                ScanStatus::Complete => complete += 1,
                ScanStatus::Failed => failed += 1,
            }
        }

        log::trace!(
            "[tui::target] calculate_stats: total={} running={} complete={} failed={}",
            total,
            running,
            complete,
            failed
        );

        (total, running, complete, failed)
    }
}

impl Default for TargetPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TargetPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!(
            "[tui::target] render: area={}x{} focused={} target={}",
            area.width,
            area.height,
            focused,
            state.target
        );

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Target information
        lines.push(Line::from(vec![
            Span::styled("🎯 ", Style::default().fg(Color::Cyan)),
            Span::styled(&state.target, Style::default().fg(Color::White)),
        ]));

        // Protocol information
        lines.push(Line::from(vec![
            Span::styled("🔗 ", Style::default().fg(Color::Magenta)),
            Span::styled("Protocol: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{} (Press 'p' to cycle)", state.protocol_display()),
                Style::default().fg(Color::Cyan),
            ),
        ]));

        lines.push(Self::address_line(state, AddressFamily::V4));
        lines.push(Self::address_line(state, AddressFamily::V6));

        let (total, running, complete, failed) = Self::calculate_stats(state);
        let rows = inner_area.height as usize;
        let ordered = Self::ordered_scanner_keys(state);

        // Spacer + Status line + one row per scanner must all fit, otherwise show the
        // one-line summary: a clipped list would silently hide scanners.
        let full_list_rows = lines.len() + 2 + ordered.len();
        if full_list_rows <= rows {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::White)),
                Span::styled(
                    format!("{}/{} scanners", complete, total),
                    Self::summary_color(running, failed),
                ),
            ]));

            for key in &ordered {
                if let Some(scanner) = state.scanners.get(key) {
                    let (icon, color) = Self::status_icon_and_color(&scanner.status);
                    let elapsed = scanner.last_updated.elapsed();

                    lines.push(Line::from(vec![
                        Span::styled(format!("{} ", icon), Style::default().fg(color)),
                        Span::styled(format!("{}: ", key.to_uppercase()), Style::default().fg(Color::White)),
                        Span::styled(Self::format_elapsed(elapsed), Style::default().fg(Color::Gray)),
                    ]));
                }
            }
        } else {
            // The summary outranks the protocol hint when rows are scarce.
            if lines.len() + 1 > rows && lines.len() > 2 {
                lines.remove(1);
            }
            lines.push(Line::from(Span::styled(
                Self::collapsed_summary(total, running, complete, failed),
                Self::summary_color(running, failed),
            )));
        }

        log::trace!(
            "[tui::target] content_prepared: lines={} scanners={}",
            lines.len(),
            state.scanners.len()
        );

        // No line here carries a failure reason, so every one is fit to a single row.
        let lines: Vec<Line<'_>> = lines
            .into_iter()
            .map(|line| crate::tui::text::fit_line(line, inner_area.width))
            .collect();
        let paragraph = Paragraph::new(lines).alignment(Alignment::Left);

        paragraph.render(inner_area, frame.buffer_mut());
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
        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Running);
        assert_eq!(icon, "🔄");
        assert_eq!(color, Color::Yellow);

        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Complete);
        assert_eq!(icon, "✅");
        assert_eq!(color, Color::Green);

        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Failed);
        assert_eq!(icon, "❌");
        assert_eq!(color, Color::Red);
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

        let (total, running, complete, failed) = TargetPane::calculate_stats(&state);
        assert_eq!(total, 3);
        assert_eq!(running, 1);
        assert_eq!(complete, 1);
        assert_eq!(failed, 1);
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

    #[test]
    fn test_short_pane_collapses_never_clips_subset() {
        use crate::tui::testing::render_pane;
        let state = state_with_scanners(&SCANNER_DISPLAY_ORDER, ScanStatus::Complete);
        // 6 rows is the 25% top row of a 24-row terminal; inner height is 4.
        for height in [6u16, 8, 10, 12] {
            let out = render_pane(&TargetPane::new(), &state, 40, height, false);
            assert!(out.contains("8/8 ✅"), "no summary at height {}:\n{}", height, out);
            assert!(
                !SCANNER_DISPLAY_ORDER
                    .iter()
                    .any(|n| out.contains(&format!("{}:", n.to_uppercase()))),
                "partial scanner list at height {}:\n{}",
                height,
                out
            );
        }
    }

    #[test]
    fn test_tall_pane_shows_every_scanner_and_no_summary() {
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
        assert!(!out.contains("8/8 ✅"));
    }

    #[test]
    fn test_collapsed_summary_counts() {
        assert_eq!(TargetPane::collapsed_summary(8, 0, 8, 0), "8/8 ✅");
        assert_eq!(TargetPane::collapsed_summary(8, 1, 6, 1), "6/8 ✅ 1 🔄 1 ❌");
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
