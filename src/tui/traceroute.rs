use crate::scan::traceroute::{TracerouteData, TracerouteHop, TracerouteResult, TracerouteStatus};
use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::any::Any;

const MIN_TRACEROUTE_PANE_WIDTH: u16 = 35;
const MIN_TRACEROUTE_PANE_HEIGHT: u16 = 20;

/// Traceroute pane displays network path tracing information
pub struct TraceroutePane {
    title: &'static str,
    id: &'static str,
}

impl TraceroutePane {
    pub fn new() -> Self {
        log::debug!("[tui::traceroute] new:");
        Self {
            title: "traceroute",
            id: "traceroute",
        }
    }
}

impl Default for TraceroutePane {
    fn default() -> Self {
        Self::new()
    }
}

/// The hop's first answer as `(ip, rtt)` text, `*` for what the answer did not carry.
fn first_answer(hop: &TracerouteHop) -> Option<(String, String)> {
    let response = hop.responses.iter().find(|r| !r.timeout)?;
    let ip = response.ip_address.map_or_else(|| "*".to_string(), |ip| ip.to_string());
    let rtt = response
        .rtt
        .map_or_else(|| "*".to_string(), |rtt| format!("{}ms", rtt.as_millis()));
    Some((ip, rtt))
}

/// The RTT of the hop's first probe answered by `target_ip`, as text, `*` if it carried none.
/// A probe answered by another router at the same TTL is not the target's round trip.
fn target_rtt(hop: &TracerouteHop, target_ip: std::net::IpAddr) -> Option<String> {
    let response = hop
        .responses
        .iter()
        .find(|r| !r.timeout && r.ip_address == Some(target_ip))?;
    Some(
        response
            .rtt
            .map_or_else(|| "*".to_string(), |rtt| format!("{}ms", rtt.as_millis())),
    )
}

/// `→ <target ip> (<rtt>)`, or `(no reply)` when the target never answered.
fn destination_line(data: &TracerouteData, destination_hop: Option<&TracerouteHop>) -> Line<'static> {
    let note = match destination_hop.and_then(|hop| target_rtt(hop, data.target_ip)) {
        Some(rtt) => format!(" ({rtt})"),
        None if data.destination_reached => String::new(),
        None => " (no reply)".to_string(),
    };
    Line::from(vec![
        Span::styled("→ ", Style::default().fg(theme::MUTED)),
        Span::styled(data.target_ip.to_string(), Style::default().fg(theme::VALUE)),
        Span::styled(note, Style::default().fg(theme::MUTED)),
    ])
}

/// One row per answering hop, and one per run of silent hops: `3-9: no reply (7 hops)`, or
/// `3: no reply` for a run of one. The destination hop is left out; it has its own row.
fn hop_lines(data: &TracerouteData, destination_hop: Option<&TracerouteHop>) -> Vec<Line<'static>> {
    let route: Vec<&TracerouteHop> = data
        .hops
        .iter()
        .filter(|hop| destination_hop.is_none_or(|dest| dest.hop_number != hop.hop_number))
        .collect();
    let mut lines = Vec::new();
    let mut index = 0;
    while index < route.len() {
        let hop = route[index];
        if hop.is_silent() {
            let run = route[index..].iter().take_while(|h| h.is_silent()).count();
            let last = route[index + run - 1].hop_number;
            let text = match run {
                1 => format!("{}: no reply", hop.hop_number),
                _ => format!("{}-{}: no reply ({} hops)", hop.hop_number, last, run),
            };
            lines.push(Line::from(Span::styled(
                format!("  {text}"),
                Style::default().fg(theme::MUTED),
            )));
            index += run;
            continue;
        }
        let (ip, rtt) = first_answer(hop).unwrap_or_else(|| ("*".to_string(), "*".to_string()));
        lines.push(Line::from(vec![
            Span::styled(format!("  {:2}: ", hop.hop_number), Style::default().fg(theme::LABEL)),
            Span::styled(ip, Style::default().fg(theme::VALUE)),
            Span::styled(format!(" ({rtt})"), Style::default().fg(theme::MUTED)),
        ]));
        index += 1;
    }
    lines
}

/// `IPv4 ✓ reached` / `IPv4 ✗ target silent (...)`, the family's route header.
fn reach_line(data: &TracerouteData) -> Line<'static> {
    let protocol = if data.ipv6 { "IPv6" } else { "IPv4" };
    Line::from(vec![
        Span::styled(format!("📍 {}", protocol), Style::default().fg(theme::LABEL)),
        if data.destination_reached {
            Span::styled(" ✓ reached", Style::default().fg(theme::GOOD))
        } else {
            Span::styled(format!(" ✗ {}", data.reach_label()), Style::default().fg(theme::BAD))
        },
    ])
}

/// Zoomed, every hop has a row, the destination included and silent hops uncollapsed: each
/// probe's IP and RTT (`*` for a probe with no answer) and the hop's loss.
fn every_hop_lines(data: &TracerouteData) -> Vec<Line<'static>> {
    data.hops
        .iter()
        .map(|hop| {
            let probes: Vec<String> = hop
                .responses
                .iter()
                .map(|response| match (response.timeout, response.ip_address, response.rtt) {
                    (true, _, _) => "*".to_string(),
                    (false, ip, rtt) => format!(
                        "{} {}",
                        ip.map_or_else(|| "*".to_string(), |ip| ip.to_string()),
                        rtt.map_or_else(|| "*".to_string(), |rtt| format!("{}ms", rtt.as_millis()))
                    ),
                })
                .collect();
            let lost = hop.responses.iter().filter(|response| response.timeout).count();
            let probes_sent = hop.responses.len();
            // Rounded, as Connectivity's loss is: one answer in three reads 67%.
            let loss = (lost * 100 + probes_sent / 2)
                .checked_div(probes_sent)
                .map_or_else(|| "---".to_string(), |percent| format!("{percent}%"));
            let probe_color = if hop.is_silent() { theme::MUTED } else { theme::VALUE };
            Line::from(vec![
                Span::styled(format!("  {:2}: ", hop.hop_number), Style::default().fg(theme::LABEL)),
                Span::styled(probes.join(" · "), Style::default().fg(probe_color)),
                Span::styled(format!("  loss {loss}"), Style::default().fg(theme::MUTED)),
            ])
        })
        .collect()
}

/// Zoomed: each family's route in full, or why the family has none.
fn zoomed_route_lines(result: &TracerouteResult) -> Vec<Line<'static>> {
    let families = [
        ("IPv4", &result.ipv4_result, &result.ipv4_status),
        ("IPv6", &result.ipv6_result, &result.ipv6_status),
    ];
    let mut lines = Vec::new();
    for (name, data, status) in families {
        match data {
            Some(data) => {
                lines.push(reach_line(data));
                lines.push(destination_line(data, data.destination_hop()));
                lines.extend(every_hop_lines(data));
            }
            None => {
                let color = match status {
                    TracerouteStatus::Failed(_) => theme::BAD,
                    _ => theme::MUTED,
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("📍 {name}: "), Style::default().fg(theme::LABEL)),
                    Span::styled(status.to_string(), Style::default().fg(color)),
                ]));
            }
        }
    }
    lines
}

impl Pane for TraceroutePane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::traceroute] content: width={} detail={:?}", width, detail);

        // Prepare content lines
        let mut lines = Vec::new();

        // Traceroute status header
        lines.push(Line::from(vec![
            Span::styled("🧭 Status: ", Style::default().fg(theme::VALUE)),
            Span::styled("tracing...", Style::default().fg(theme::MUTED)),
        ]));

        // Get traceroute results and render them
        if let Some(traceroute_state) = state.scanners.get("traceroute") {
            // Update header with current status
            let (label, label_color) = crate::tui::status_label(&traceroute_state, "tracing...", "traced");
            lines[0] = Line::from(vec![
                Span::styled("🧭 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled(label, Style::default().fg(label_color)),
            ]);

            if let Some(ScanResult::Traceroute(traceroute_result)) = &traceroute_state.result {
                if detail == Detail::Zoomed {
                    lines.extend(zoomed_route_lines(traceroute_result));
                } else if let Some(primary_data) = traceroute_result.get_primary_result() {
                    // The primary family only; the destination has its own row, the route above
                    // it is the other hops.
                    lines.push(reach_line(primary_data));
                    let destination_hop = primary_data.destination_hop();
                    lines.push(destination_line(primary_data, destination_hop));
                    lines.extend(hop_lines(primary_data, destination_hop));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                        Span::styled("All protocols failed", Style::default().fg(theme::BAD)),
                    ]));
                }

                // Total scan time
                let scan_time_ms = traceroute_result.total_duration.as_millis();
                lines.push(Line::from(vec![
                    Span::styled("⏳ Duration: ", Style::default().fg(theme::LABEL)),
                    Span::styled(format!("{}ms", scan_time_ms), Style::default().fg(theme::WARN)),
                ]));
            } else {
                // No traceroute data available yet - check scanner status
                match traceroute_state.status {
                    crate::types::ScanStatus::Running => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled("tracing route...", Style::default().fg(theme::WARN)),
                        ]));
                    }
                    // The header carries the failure reason.
                    crate::types::ScanStatus::Failed => {}
                    _ => {
                        lines.push(Line::from(vec![
                            Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                            Span::styled("waiting to trace...", Style::default().fg(theme::MUTED)),
                        ]));
                    }
                }
            }
        } else {
            // No traceroute scanner available
            lines[0] = Line::from(vec![
                Span::styled("🧭 Status: ", Style::default().fg(theme::VALUE)),
                Span::styled("unavailable", Style::default().fg(theme::BAD)),
            ]);

            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("Traceroute scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        crate::tui::text::to_rows(lines, width, detail, &[])
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_TRACEROUTE_PANE_WIDTH, MIN_TRACEROUTE_PANE_HEIGHT) // Much larger to show all hops (up to ~30 hops)
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
    use ratatui::style::Color;

    #[test]
    fn test_traceroute_pane_creation() {
        let pane = TraceroutePane::new();
        assert_eq!(pane.title(), "traceroute");
        assert_eq!(pane.id(), "traceroute");
        assert_eq!(pane.min_size(), (MIN_TRACEROUTE_PANE_WIDTH, MIN_TRACEROUTE_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    fn traced_state(data: crate::scan::traceroute::TracerouteData) -> AppState {
        let mut result = crate::scan::traceroute::TracerouteResult::new();
        result.ipv6_status = crate::scan::traceroute::TracerouteStatus::Success(data.total_hops);
        result.ipv6_result = Some(data);
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            "traceroute".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Traceroute(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        state
    }

    fn ipv6_route(hop_ip: &str, reached: bool) -> crate::scan::traceroute::TracerouteData {
        use crate::scan::traceroute::{HopResponse, TracerouteData, TracerouteHop};
        use std::time::Duration;
        let ip: std::net::IpAddr = hop_ip.parse().expect("ip");
        TracerouteData {
            hops: vec![TracerouteHop {
                hop_number: 1,
                responses: vec![HopResponse {
                    ip_address: Some(ip),
                    rtt: Some(Duration::from_millis(5)),
                    timeout: false,
                }],
                best_rtt: Some(Duration::from_millis(5)),
                avg_rtt: Some(Duration::from_millis(5)),
                worst_rtt: Some(Duration::from_millis(5)),
                packet_loss: 0.0,
            }],
            destination_reached: reached,
            total_hops: 1,
            max_hops: 30,
            target_ip: ip,
            scan_duration: Duration::from_millis(100),
            ipv6: true,
        }
    }

    #[test]
    fn long_ipv6_hop_is_fit_with_ellipsis_in_narrow_terminals() {
        let hop = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff";
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &TraceroutePane::new(),
            &traced_state(ipv6_route(hop, true)),
            2,
            1,
            &format!("→ {hop} (5ms)"),
        );
    }

    #[test]
    fn reached_and_silent_labels_are_intact_at_200x55() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 200, 55);
        let render = |reached| {
            let state = traced_state(ipv6_route("2001:db8::1", reached));
            crate::tui::testing::render_pane(&TraceroutePane::new(), &state, width, height, false)
        };
        let reached = render(true);
        assert!(reached.contains("✓ reached"), "{reached}");
        let silent = render(false);
        assert!(silent.contains("✗ target silent (last reply: hop 1)"), "{silent}");
        assert!(!silent.contains('…'), "{silent}");
    }

    fn hop(number: u8, replies: &[bool], packet_loss: f32) -> crate::scan::traceroute::TracerouteHop {
        use crate::scan::traceroute::{HopResponse, TracerouteHop};
        use std::time::Duration;
        TracerouteHop {
            hop_number: number,
            responses: replies
                .iter()
                .map(|answered| HopResponse {
                    ip_address: answered.then(|| "192.0.2.1".parse().expect("ip")),
                    rtt: answered.then(|| Duration::from_millis(5)),
                    timeout: !answered,
                })
                .collect(),
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            packet_loss,
        }
    }

    /// Hop 2 is silent, hop 3 answered one probe in three (loss 0.67), hop 4 is silent.
    fn route_with_silent_hops() -> crate::scan::traceroute::TracerouteData {
        let mut data = ipv6_route("2001:db8::1", true);
        data.hops = vec![
            hop(1, &[true, true, true], 0.0),
            hop(2, &[false, false, false], 1.0),
            hop(3, &[true, false, false], 0.67),
            hop(4, &[false, false, false], 1.0),
        ];
        data
    }

    #[test]
    fn tui_and_no_tui_report_the_same_silent_hop_count() {
        let data = route_with_silent_hops();
        assert_eq!(data.silent_hops(), 2, "a hop that answered one probe is not silent");

        let state = traced_state(data);
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, 60, 20, false);
        assert!(out.contains("2: no reply"), "{out}");
        assert!(out.contains("4: no reply"), "{out}");
        assert!(!out.contains("3: no reply"), "{out}");

        let scan_state = state.scanners.get("traceroute").expect("traceroute state");
        let summary = crate::pretty::format_scan_state("traceroute", &scan_state);
        assert!(summary.contains("2 timeouts"), "{summary}");
    }

    /// www.tatari.tv from the shakedown: hops 1-2 answer, 3-9 are silent, 10 answers, 11 is the target.
    fn tatari_route() -> crate::scan::traceroute::TracerouteData {
        use crate::scan::traceroute::{HopResponse, TracerouteHop};
        use std::time::Duration;
        let answer = |number: u8, ip: &str, ms: u64| TracerouteHop {
            hop_number: number,
            responses: vec![HopResponse {
                ip_address: Some(ip.parse().expect("ip")),
                rtt: Some(Duration::from_millis(ms)),
                timeout: false,
            }],
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            packet_loss: 0.0,
        };
        let mut hops = vec![answer(1, "192.168.1.1", 1), answer(2, "10.0.0.1", 2)];
        hops.extend((3..=9).map(|n| hop(n, &[false, false, false], 1.0)));
        hops.push(answer(10, "63.140.62.5", 3));
        hops.push(answer(11, "216.150.16.193", 3));
        let mut data = ipv6_route("2001:db8::1", true);
        data.target_ip = "216.150.16.193".parse().expect("ip");
        data.ipv6 = false;
        data.total_hops = 11;
        data.hops = hops;
        data
    }

    fn tatari_pane(width: u16, height: u16) -> String {
        let mut result = crate::scan::traceroute::TracerouteResult::new();
        result.ipv4_result = Some(tatari_route());
        result.total_duration = std::time::Duration::from_millis(3200);
        let state = AppState::new("www.tatari.tv".to_string());
        state.scanners.insert(
            "traceroute".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Traceroute(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        crate::tui::testing::render_pane(&TraceroutePane::new(), &state, width, height, false)
    }

    #[test]
    fn tatari_route_fits_the_80x24_dashboard_with_destination_and_duration() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let out = tatari_pane(width, height);
        assert!(out.contains("📍 IPv4 ✓ reached"), "{out}");
        assert!(out.contains("→ 216.150.16.193 (3ms)"), "{out}");
        assert!(out.contains("3-9: no reply (7 hops)"), "{out}");
        assert!(out.contains("Duration: 3200ms"), "{out}");
        assert!(!out.contains("more"), "nothing is hidden at 80x24:\n{out}");
        let last_row = out.lines().rev().nth(1).expect("row above the border");
        assert!(last_row.contains("Duration"), "Duration is the last row:\n{out}");
    }

    #[test]
    fn destination_row_shows_the_rtt_of_the_target_answer_not_another_router() {
        use crate::scan::traceroute::HopResponse;
        use std::time::Duration;
        let mut data = tatari_route();
        let last = data.hops.last_mut().expect("destination hop");
        last.responses = vec![
            HopResponse {
                ip_address: Some("63.140.62.9".parse().expect("ip")),
                rtt: Some(Duration::from_millis(41)),
                timeout: false,
            },
            HopResponse {
                ip_address: Some("216.150.16.193".parse().expect("ip")),
                rtt: Some(Duration::from_millis(7)),
                timeout: false,
            },
        ];
        let row = destination_line(&data, data.destination_hop());
        let text: String = row.spans.iter().map(|span| span.content.as_ref()).collect();
        assert_eq!(text, "→ 216.150.16.193 (7ms)");
    }

    #[test]
    fn rendered_traceroute_pane_has_no_variation_selector() {
        let out = tatari_pane(80, 24);
        assert!(out.contains('🧭') && out.contains('⏳'), "{out}");
        assert!(!out.contains('\u{FE0F}'), "{out}");
    }

    #[test]
    fn no_hop_row_says_timeout() {
        let out = tatari_pane(60, 30);
        assert!(!out.contains("timeout"), "{out}");
        let single = traced_state(route_with_silent_hops());
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &single, 60, 20, false);
        assert!(!out.contains("timeout"), "{out}");
    }

    #[test]
    fn a_single_silent_hop_reads_without_a_count() {
        let out = crate::tui::testing::render_pane(
            &TraceroutePane::new(),
            &traced_state(route_with_silent_hops()),
            60,
            20,
            false,
        );
        assert!(out.contains("2: no reply\n") || out.contains("2: no reply "), "{out}");
        assert!(!out.contains("(1 hops)"), "{out}");
    }

    #[test]
    fn a_silent_target_keeps_its_label_and_a_no_reply_destination_row() {
        let mut data = tatari_route();
        data.destination_reached = false;
        data.hops.truncate(10);
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &traced_state(data), 60, 20, false);
        assert!(out.contains("✗ target silent (last reply: hop 10)"), "{out}");
        assert!(out.contains("→ 216.150.16.193 (no reply)"), "{out}");
    }

    #[test]
    fn hop_numbers_use_the_label_color_never_the_bad_color() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(60, 30)).expect("terminal");
        let mut result = crate::scan::traceroute::TracerouteResult::new();
        let mut data = tatari_route();
        data.hops.truncate(2);
        for n in 11..=14 {
            data.hops.push(hop(n, &[true], 0.0));
        }
        result.ipv4_result = Some(data);
        let state = AppState::new("www.tatari.tv".to_string());
        state.scanners.insert(
            "traceroute".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Traceroute(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        let pane = TraceroutePane::new();
        terminal
            .draw(|frame| pane.render(frame, frame.area(), &state, false))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        for number in ["12:", "14:", "1:"] {
            let color = crate::tui::testing::fg_of(&buffer, number);
            assert_eq!(color, Color::White, "hop {number}");
            assert_ne!(color, Color::LightRed, "hop {number}");
        }
    }

    #[test]
    fn zoomed_content_shows_every_probe_rtt_for_a_hop() {
        use crate::scan::traceroute::{HopResponse, TracerouteResult, TracerouteStatus};
        use std::time::Duration;
        let probe = |ms: u64| HopResponse {
            ip_address: Some("192.0.2.1".parse().expect("ip")),
            rtt: Some(Duration::from_millis(ms)),
            timeout: false,
        };
        let mut data = tatari_route();
        data.hops[0].responses = vec![probe(5), probe(7), probe(9)];
        let mut result = TracerouteResult::new();
        result.ipv4_status = TracerouteStatus::Success(11);
        result.ipv4_result = Some(data);
        result.ipv6_status = TracerouteStatus::NoAddress;
        let state = AppState::new("www.tatari.tv".to_string());
        state.scanners.insert(
            "traceroute".to_string(),
            crate::types::ScanState {
                result: Some(ScanResult::Traceroute(result)),
                error: None,
                status: crate::types::ScanStatus::Complete,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        let pane = TraceroutePane::new();
        let rows = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Zoomed);
        let text = rows.join("\n");
        assert!(
            text.contains(" 1: 192.0.2.1 5ms · 192.0.2.1 7ms · 192.0.2.1 9ms  loss 0%"),
            "{text}"
        );
        // Silent hops are not collapsed, and the destination hop is listed too.
        for number in 3..=9 {
            assert!(
                text.contains(&format!("{number:2}: * · * · *  loss 100%")),
                "hop {number}: {text}"
            );
        }
        assert!(text.contains("11: 216.150.16.193 3ms"), "{text}");
        assert!(text.contains(" 2: 10.0.0.1 2ms  loss 0%"), "{text}");
        assert!(text.contains("📍 IPv6: no address"), "{text}");
        assert!(text.contains("Duration:"), "{text}");

        let normal = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Normal).join("\n");
        assert!(
            !normal.contains("7ms"),
            "the grid shows only the first answer:\n{normal}"
        );
    }

    #[test]
    fn zoomed_hop_loss_is_rounded_like_connectivity() {
        let state = traced_state(route_with_silent_hops());
        let text = crate::tui::testing::content_rows(&TraceroutePane::new(), &state, 120, Detail::Zoomed).join("\n");
        assert!(text.contains(" 3: 192.0.2.1 5ms · * · *  loss 67%"), "{text}");
    }
}
