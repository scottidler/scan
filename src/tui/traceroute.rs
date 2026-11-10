use crate::scan::traceroute::{
    FallbackFailure, TraceEngine, TracerouteData, TracerouteHop, TracerouteResult, TracerouteStatus,
};
use crate::tui::pane::{Detail, Pane};
use crate::tui::theme;
use crate::types::{AppState, ScanResult};
use log;
use ratatui::style::Color;
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::any::Any;
use std::net::IpAddr;
use std::time::Duration;

/// A hop at or above this loss reads BAD; any loss below it reads WARN, none reads GOOD.
const BAD_LOSS_PERCENT: u64 = 10;
const NO_ADDRESS_HOST: &str = "???";
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

fn loss_color(percent: Option<u64>) -> Color {
    match percent {
        None => theme::MUTED,
        Some(0) => theme::GOOD,
        Some(percent) if percent < BAD_LOSS_PERCENT => theme::WARN,
        Some(_) => theme::BAD,
    }
}

fn loss_text(hop: &TracerouteHop) -> String {
    hop.loss_percent()
        .map_or_else(|| "---".to_string(), |percent| format!("{percent}%"))
}

/// Whole milliseconds, `-` for a column with no reply behind it.
fn whole_ms(rtt: Option<Duration>) -> String {
    rtt.map_or_else(|| "-".to_string(), |rtt| format!("{}ms", rtt.as_millis()))
}

/// One decimal, so a sub-millisecond hop does not read `0ms`.
fn tenth_ms(rtt: Option<Duration>) -> String {
    rtt.map_or_else(|| "-".to_string(), |rtt| format!("{:.1}ms", rtt.as_secs_f64() * 1000.0))
}

fn is_mtr(data: &TracerouteData) -> bool {
    matches!(data.engine, TraceEngine::Mtr { .. })
}

/// Which prober produced the route, and the reason when it is the fallback.
fn engine_status(engine: &TraceEngine) -> (String, Color) {
    match engine {
        TraceEngine::Mtr { cycles } => (
            format!("mtr · {}", crate::tui::text::plural(*cycles, "cycle")),
            theme::GOOD,
        ),
        TraceEngine::Traceroute { reason } => (format!("traceroute ({reason})"), theme::WARN),
    }
}

fn tracing_line() -> Line<'static> {
    Line::from(vec![
        Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
        Span::styled("tracing route...", Style::default().fg(theme::WARN)),
    ])
}

/// `→ <target ip> (<rtt>)`, or `(no reply)` when the target never answered. Under mtr the row
/// reads like a hop row: `+N` for the other addresses the hop answered from, then the average and
/// the loss, colored by the same thresholds.
fn destination_line(data: &TracerouteData, destination_hop: Option<&TracerouteHop>) -> Line<'static> {
    let target = vec![
        Span::styled("→ ", Style::default().fg(theme::MUTED)),
        Span::styled(data.target_ip.to_string(), Style::default().fg(theme::VALUE)),
    ];
    if let Some(hop) = destination_hop.filter(|_| is_mtr(data)) {
        let others = hop.addresses.len().saturating_sub(1);
        let mut spans = target;
        if others > 0 {
            spans.push(Span::styled(format!(" +{others}"), Style::default().fg(theme::VALUE)));
        }
        spans.extend([
            Span::styled(
                format!(" ({} ", whole_ms(hop.avg_rtt)),
                Style::default().fg(theme::MUTED),
            ),
            Span::styled(loss_text(hop), Style::default().fg(loss_color(hop.loss_percent()))),
            Span::styled(")", Style::default().fg(theme::MUTED)),
        ]);
        return Line::from(spans);
    }
    let note = match destination_hop.and_then(|hop| target_rtt(hop, data.target_ip)) {
        Some(rtt) => format!(" ({rtt})"),
        None if data.destination_reached => String::new(),
        None => " (no reply)".to_string(),
    };
    let mut spans = target;
    spans.push(Span::styled(note, Style::default().fg(theme::MUTED)));
    Line::from(spans)
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
        if is_mtr(data) {
            lines.push(mtr_hop_row(hop));
            index += 1;
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

/// `  4: 10.0.0.1 +2 3% 6ms`: the hop's latest address, how many others it has answered from,
/// then its loss and average.
fn mtr_hop_row(hop: &TracerouteHop) -> Line<'static> {
    let host = hop
        .current_address
        .map_or_else(|| NO_ADDRESS_HOST.to_string(), |ip| ip.to_string());
    let others = hop.addresses.len().saturating_sub(1);
    let host = if others > 0 { format!("{host} +{others}") } else { host };
    Line::from(vec![
        Span::styled(format!("  {:2}: ", hop.hop_number), Style::default().fg(theme::LABEL)),
        Span::styled(host, Style::default().fg(theme::VALUE)),
        Span::styled(
            format!(" {}", loss_text(hop)),
            Style::default().fg(loss_color(hop.loss_percent())),
        ),
        Span::styled(format!(" {}", whole_ms(hop.avg_rtt)), Style::default().fg(theme::MUTED)),
    ])
}

/// The route under the reach line: the destination row, then the hops above it.
fn route_lines(data: &TracerouteData) -> Vec<Line<'static>> {
    if is_mtr(data) && data.hops.is_empty() {
        return vec![tracing_line()];
    }
    let destination_hop = data.destination_hop();
    let mut lines = vec![reach_line(data), destination_line(data, destination_hop)];
    lines.extend(hop_lines(data, destination_hop));
    lines
}

/// Zoomed mtr table: a row per hop with every column, an indented row per extra ECMP address.
fn mtr_table_lines(data: &TracerouteData) -> Vec<Line<'static>> {
    let host_of = |hop: &TracerouteHop| {
        hop.current_address
            .map_or_else(|| NO_ADDRESS_HOST.to_string(), |ip| ip.to_string())
    };
    let host_width = data
        .hops
        .iter()
        .map(|hop| host_of(hop).chars().count())
        .max()
        .unwrap_or(0)
        .max("Host".len());
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "  {:>3}  {:<host_width$}  {:>6}  {:>4}  {:>7}  {:>7}  {:>7}  {:>7}  {:>7}",
            "Hop", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"
        ),
        Style::default().fg(theme::LABEL),
    ))];
    for hop in &data.hops {
        let host_color = if hop.is_silent() { theme::MUTED } else { theme::VALUE };
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>3}  ", hop.hop_number), Style::default().fg(theme::LABEL)),
            Span::styled(
                format!("{:<host_width$}", host_of(hop)),
                Style::default().fg(host_color),
            ),
            Span::styled(
                format!("  {:>6}", loss_text(hop)),
                Style::default().fg(loss_color(hop.loss_percent())),
            ),
            Span::styled(format!("  {:>4}", hop.sent), Style::default().fg(theme::VALUE)),
            Span::styled(
                format!(
                    "  {:>7}  {:>7}  {:>7}  {:>7}  {:>7}",
                    tenth_ms(hop.last_rtt),
                    tenth_ms(hop.avg_rtt),
                    tenth_ms(hop.best_rtt),
                    tenth_ms(hop.worst_rtt),
                    tenth_ms(hop.stddev_rtt)
                ),
                Style::default().fg(theme::VALUE),
            ),
        ]));
        let others: Vec<&IpAddr> = hop
            .addresses
            .iter()
            .filter(|ip| Some(**ip) != hop.current_address)
            .collect();
        for ip in others {
            lines.push(Line::from(Span::styled(
                format!("  {:>3}  {ip}", ""),
                Style::default().fg(theme::MUTED),
            )));
        }
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
            Some(data) if is_mtr(data) && data.hops.is_empty() => lines.push(tracing_line()),
            Some(data) if is_mtr(data) => {
                lines.push(reach_line(data));
                lines.push(destination_line(data, data.destination_hop()));
                lines.extend(mtr_table_lines(data));
            }
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

/// `🧭 Status: <label>`: the scanner's status, and once a scan is Complete, the prober that
/// produced it where "traced" would be.
fn header_line(state: &AppState) -> Line<'static> {
    let (label, label_color) = match state.scanners.get("traceroute") {
        Some(traceroute_state) => {
            let status = crate::tui::status_label(&traceroute_state, "tracing...", "traced");
            let engine = match (&traceroute_state.status, &traceroute_state.result) {
                (crate::types::ScanStatus::Complete, Some(ScanResult::Traceroute(result))) => {
                    result.get_primary_result().map(|data| engine_status(&data.engine))
                }
                _ => None,
            };
            engine.unwrap_or(status)
        }
        None => ("unavailable".to_string(), theme::BAD),
    };
    Line::from(vec![
        Span::styled("🧭 Status: ", Style::default().fg(theme::VALUE)),
        Span::styled(label, Style::default().fg(label_color)),
    ])
}

/// Why `traceroute` is in use: from a fallback failure when every family failed, else from the
/// shown route's engine. `None` under mtr.
fn fallback_reason(state: &AppState) -> Option<String> {
    let traceroute_state = state.scanners.get("traceroute")?;
    if let Some(failure) = traceroute_state
        .error
        .as_ref()
        .and_then(|error| error.downcast_ref::<FallbackFailure>())
    {
        return Some(failure.reason.clone());
    }
    match &traceroute_state.result {
        Some(ScanResult::Traceroute(result)) => match &result.get_primary_result()?.engine {
            TraceEngine::Traceroute { reason } => Some(reason.clone()),
            TraceEngine::Mtr { .. } => None,
        },
        _ => None,
    }
}

impl Pane for TraceroutePane {
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::traceroute] content: width={} detail={:?}", width, detail);

        let mut lines = vec![header_line(state)];

        // Get traceroute results and render them
        if let Some(traceroute_state) = state.scanners.get("traceroute") {
            if let Some(ScanResult::Traceroute(traceroute_result)) = &traceroute_state.result {
                if detail == Detail::Zoomed {
                    lines.extend(zoomed_route_lines(traceroute_result));
                } else if let Some(primary_data) = traceroute_result.get_primary_result() {
                    // The primary family only; the destination has its own row, the route above
                    // it is the other hops.
                    lines.extend(route_lines(primary_data));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                        Span::styled("All protocols failed", Style::default().fg(theme::BAD)),
                    ]));
                }

                // A continuous trace's snapshot is instant: its duration says nothing.
                let continuous = traceroute_result.get_primary_result().is_some_and(is_mtr);
                if !continuous {
                    let scan_time_ms = traceroute_result.total_duration.as_millis();
                    lines.push(Line::from(vec![
                        Span::styled("⏳ Duration: ", Style::default().fg(theme::LABEL)),
                        Span::styled(format!("{}ms", scan_time_ms), Style::default().fg(theme::WARN)),
                    ]));
                }
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
            lines.push(Line::from(vec![
                Span::styled("📍 Status: ", Style::default().fg(theme::LABEL)),
                Span::styled("Traceroute scanner not available", Style::default().fg(theme::BAD)),
            ]));
        }

        crate::tui::text::to_rows(lines, width, detail, &[])
    }

    /// The fallback reason, when the Status header is too wide for the pane to show it.
    fn border_note(&self, state: &AppState, width: u16) -> Option<String> {
        let reason = fallback_reason(state)?;
        (header_line(state).width() > usize::from(width)).then_some(reason)
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
        use crate::scan::traceroute::{HopResponse, TraceEngine, TracerouteData, TracerouteHop};
        use std::time::Duration;
        let ip: std::net::IpAddr = hop_ip.parse().expect("ip");
        TracerouteData {
            hops: vec![TracerouteHop::from_probes(
                1,
                vec![HopResponse {
                    ip_address: Some(ip),
                    rtt: Some(Duration::from_millis(5)),
                    timeout: false,
                }],
            )],
            destination_reached: reached,
            total_hops: 1,
            max_hops: 30,
            target_ip: ip,
            scan_duration: Duration::from_millis(100),
            ipv6: true,
            engine: TraceEngine::Traceroute {
                reason: "mtr not installed".to_string(),
            },
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
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            packet_loss,
            ..TracerouteHop::from_probes(
                number,
                replies
                    .iter()
                    .map(|answered| HopResponse {
                        ip_address: answered.then(|| "192.0.2.1".parse().expect("ip")),
                        rtt: answered.then(|| Duration::from_millis(5)),
                        timeout: !answered,
                    })
                    .collect(),
            )
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
        assert!(summary.contains("2 no reply"), "{summary}");
    }

    /// www.tatari.tv from the shakedown, as the `traceroute` fallback reports it: hops 1-2 answer,
    /// 3-9 are silent, 10 answers, 11 is the target.
    fn tatari_fallback_route() -> crate::scan::traceroute::TracerouteData {
        use crate::scan::traceroute::{HopResponse, TracerouteHop};
        use std::time::Duration;
        let answer = |number: u8, ip: &str, ms: u64| TracerouteHop {
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            ..TracerouteHop::from_probes(
                number,
                vec![HopResponse {
                    ip_address: Some(ip.parse().expect("ip")),
                    rtt: Some(Duration::from_millis(ms)),
                    timeout: false,
                }],
            )
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

    /// A hop as mtr accumulates it: no per-probe responses, `rtts_us` is last, avg, best, worst, stddev.
    fn mtr_hop(number: u8, ips: &[&str], sent: u32, replied: u32, rtts_us: [u64; 5]) -> TracerouteHop {
        use std::time::Duration;
        let addresses: Vec<std::net::IpAddr> = ips.iter().map(|ip| ip.parse().expect("ip")).collect();
        let rtt = |us: u64| (replied > 0).then(|| Duration::from_micros(us));
        TracerouteHop {
            hop_number: number,
            responses: vec![],
            best_rtt: rtt(rtts_us[2]),
            avg_rtt: rtt(rtts_us[1]),
            worst_rtt: rtt(rtts_us[3]),
            packet_loss: (sent - replied) as f32 / sent as f32,
            sent,
            replied,
            last_rtt: rtt(rtts_us[0]),
            stddev_rtt: rtt(rtts_us[4]),
            current_address: addresses.last().copied(),
            addresses,
        }
    }

    /// `tatari_fallback_route` as mtr reports it after 42 cycles.
    fn tatari_route() -> crate::scan::traceroute::TracerouteData {
        use crate::scan::traceroute::TraceEngine;
        let answered =
            |number: u8, ip: &str, us: u64| mtr_hop(number, &[ip], 42, 42, [us, us, us - 200, us + 400, 150]);
        let mut hops = vec![answered(1, "192.168.1.1", 1000), answered(2, "10.0.0.1", 2000)];
        hops.extend((3..=9).map(|n| mtr_hop(n, &[], 42, 0, [0; 5])));
        hops.push(answered(10, "63.140.62.5", 3000));
        hops.push(answered(11, "216.150.16.193", 3000));
        let mut data = tatari_fallback_route();
        data.hops = hops;
        data.engine = TraceEngine::Mtr { cycles: 42 };
        data
    }

    fn state_of(data: crate::scan::traceroute::TracerouteData, total: std::time::Duration) -> AppState {
        let mut result = crate::scan::traceroute::TracerouteResult::new();
        result.ipv4_result = Some(data);
        result.total_duration = total;
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
        state
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
    fn tatari_route_fits_the_80x24_dashboard_with_engine_and_destination() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let out = tatari_pane(width, height);
        assert!(out.contains("🧭 Status: mtr · 42"), "{out}");
        assert!(out.contains("📍 IPv4 ✓ reached"), "{out}");
        assert!(out.contains("→ 216.150.16.193 (3ms 0%)"), "{out}");
        assert!(out.contains("3-9: no reply (7 hops)"), "{out}");
        assert!(out.contains("10: 63.140.62.5 0% 3ms"), "{out}");
        assert!(!out.contains("Duration"), "an instant snapshot has no duration:\n{out}");
        assert!(!out.contains("more"), "nothing is hidden at 80x24:\n{out}");
    }

    #[test]
    fn fallback_route_fits_the_80x24_dashboard_with_destination_and_duration() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let state = state_of(tatari_fallback_route(), std::time::Duration::from_millis(3200));
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, width, height, false);
        assert!(out.contains("🧭 Status: traceroute"), "{out}");
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
        let mut data = tatari_fallback_route();
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
        let state = state_of(tatari_fallback_route(), std::time::Duration::from_millis(3200));
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, 80, 24, false);
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
            assert_eq!(color, crate::tui::theme::LABEL, "hop {number}");
            assert_ne!(color, crate::tui::theme::BAD, "hop {number}");
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
        let mut data = tatari_fallback_route();
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

    #[test]
    fn mtr_pane_says_tracing_route_before_any_hop_settles() {
        let mut data = tatari_route();
        data.hops.clear();
        data.total_hops = 0;
        data.destination_reached = false;
        let state = state_of(data, std::time::Duration::ZERO);
        let pane = TraceroutePane::new();
        for detail in [Detail::Normal, Detail::Zoomed] {
            let text = crate::tui::testing::content_rows(&pane, &state, 80, detail).join("\n");
            assert!(text.contains("tracing route..."), "{detail:?}: {text}");
            assert!(text.contains("mtr · 42 cycles"), "{detail:?}: {text}");
            assert!(!text.contains("target silent"), "{detail:?}: {text}");
        }
    }

    /// Hop 2 answered from three addresses; 2 of its 40 probes were lost.
    fn ecmp_route() -> crate::scan::traceroute::TracerouteData {
        let mut data = tatari_route();
        data.hops[1] = mtr_hop(
            2,
            &["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            40,
            38,
            [5200, 6000, 4500, 12300, 1800],
        );
        data
    }

    #[test]
    fn mtr_grid_row_shows_address_extras_loss_and_average() {
        let state = state_of(ecmp_route(), std::time::Duration::ZERO);
        let text = crate::tui::testing::content_rows(&TraceroutePane::new(), &state, 80, Detail::Normal).join("\n");
        assert!(text.contains(" 2: 10.0.0.3 +2 5% 6ms"), "{text}");
        assert!(text.contains(" 1: 192.168.1.1 0% 1ms"), "{text}");
    }

    #[test]
    fn zoomed_mtr_table_has_every_column_and_ecmp_rows() {
        let state = state_of(ecmp_route(), std::time::Duration::ZERO);
        let text = crate::tui::testing::content_rows(&TraceroutePane::new(), &state, 120, Detail::Zoomed).join("\n");
        let cells = |starts_with: &str| -> Vec<String> {
            let line = text
                .lines()
                .find(|line| line.split_whitespace().next() == Some(starts_with))
                .unwrap_or_else(|| panic!("no row {starts_with}: {text}"));
            line.split_whitespace().map(str::to_string).collect()
        };
        assert_eq!(
            cells("Hop"),
            ["Hop", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"]
        );
        assert_eq!(
            cells("2"),
            [
                "2", "10.0.0.3", "5%", "40", "5.2ms", "6.0ms", "4.5ms", "12.3ms", "1.8ms"
            ]
        );
        assert_eq!(cells("3"), ["3", "???", "100%", "42", "-", "-", "-", "-", "-"]);
        for extra in ["10.0.0.1", "10.0.0.2"] {
            let row = text.lines().find(|line| line.trim() == extra).expect(extra);
            assert!(row.starts_with("       "), "extra address is indented: {row:?}");
        }
        assert!(text.contains("mtr · 42 cycles"), "{text}");
        assert!(!text.contains("Duration"), "{text}");
    }

    #[test]
    fn mtr_loss_is_colored_good_warn_bad_by_threshold() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut data = tatari_route();
        data.hops = vec![
            mtr_hop(1, &["192.168.1.1"], 100, 100, [1000; 5]),
            mtr_hop(2, &["10.0.0.1"], 100, 97, [1000; 5]),
            mtr_hop(3, &["10.0.0.2"], 100, 80, [1000; 5]),
            mtr_hop(4, &["216.150.16.193"], 100, 50, [1000; 5]),
        ];
        let state = state_of(data, std::time::Duration::ZERO);
        let mut terminal = Terminal::new(TestBackend::new(60, 30)).expect("terminal");
        let pane = TraceroutePane::new();
        terminal
            .draw(|frame| pane.render(frame, frame.area(), &state, false))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        assert_eq!(crate::tui::testing::fg_of(&buffer, " 0%"), crate::tui::theme::GOOD);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "3%"), crate::tui::theme::WARN);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "20%"), crate::tui::theme::BAD);
    }

    #[test]
    fn tui_and_no_tui_report_the_same_silent_hop_count_under_mtr() {
        let data = tatari_route();
        assert_eq!(data.silent_hops(), 7);
        let state = state_of(data, std::time::Duration::ZERO);
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, 60, 24, false);
        assert!(out.contains("3-9: no reply (7 hops)"), "{out}");
        let scan_state = state.scanners.get("traceroute").expect("traceroute state");
        let summary = crate::pretty::format_scan_state("traceroute", &scan_state);
        assert!(summary.contains("7 no reply"), "{summary}");
    }

    #[test]
    fn mtr_destination_row_colors_its_loss_and_counts_extra_addresses() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut data = tatari_route();
        data.hops[10] = mtr_hop(
            11,
            &["216.150.16.9", "216.150.16.10", "216.150.16.193"],
            100,
            50,
            [3000; 5],
        );
        let state = state_of(data, std::time::Duration::ZERO);
        let mut terminal = Terminal::new(TestBackend::new(60, 30)).expect("terminal");
        let pane = TraceroutePane::new();
        terminal
            .draw(|frame| pane.render(frame, frame.area(), &state, false))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let text = crate::tui::testing::content_rows(&pane, &state, 60, Detail::Normal).join("\n");
        assert!(text.contains("→ 216.150.16.193 +2 (3ms 50%)"), "{text}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "50%"), crate::tui::theme::BAD);
        assert_eq!(crate::tui::testing::fg_of(&buffer, "+2"), crate::tui::theme::VALUE);
    }

    #[test]
    fn mtr_destination_row_with_no_loss_reads_good_and_has_no_extras() {
        use ratatui::{Terminal, backend::TestBackend};
        let state = state_of(tatari_route(), std::time::Duration::ZERO);
        let mut terminal = Terminal::new(TestBackend::new(60, 30)).expect("terminal");
        let pane = TraceroutePane::new();
        terminal
            .draw(|frame| pane.render(frame, frame.area(), &state, false))
            .expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let text = crate::tui::testing::content_rows(&pane, &state, 60, Detail::Normal).join("\n");
        assert!(text.contains("→ 216.150.16.193 (3ms 0%)"), "{text}");
        assert_eq!(crate::tui::testing::fg_of(&buffer, "0%)"), crate::tui::theme::GOOD);
    }

    /// The bottom border row of a rendered pane.
    fn bottom_border(out: &str) -> &str {
        out.lines().last().expect("bottom border")
    }

    #[test]
    fn fallback_reason_is_on_the_border_when_the_80x24_header_clips_it() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let state = state_of(tatari_fallback_route(), std::time::Duration::from_millis(3200));
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, width, height, false);
        assert!(
            out.lines().next().is_some_and(|row| !row.contains("mtr not installed")),
            "the header row clips the reason:\n{out}"
        );
        assert!(bottom_border(&out).contains("┘mtr not installed└"), "{out}");
        assert!(out.contains("Duration: 3200ms"), "{out}");
        assert!(!out.contains("more"), "{out}");

        let wide = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, 80, 24, false);
        assert!(wide.contains("🧭 Status: traceroute (mtr not installed)"), "{wide}");
        assert!(
            !bottom_border(&wide).contains("mtr not installed"),
            "no note when the header shows the reason:\n{wide}"
        );
    }

    #[test]
    fn mtr_pane_has_no_border_note_at_80x24() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let out = tatari_pane(width, height);
        assert!(!bottom_border(&out).contains('┘'), "{out}");
    }

    #[test]
    fn a_long_fallback_reason_is_clipped_on_the_border() {
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let mut data = tatari_fallback_route();
        data.engine = TraceEngine::Traceroute {
            reason: "mtr: Failure to open IPv4 sockets: Permission denied".to_string(),
        };
        let state = state_of(data, std::time::Duration::from_millis(3200));
        let out = crate::tui::testing::render_pane(&TraceroutePane::new(), &state, width, height, false);
        let border = bottom_border(&out);
        assert!(border.contains("┘mtr: Failure"), "{out}");
        assert!(border.contains("…└"), "{out}");
    }

    /// Every family failed under the fallback: no route, only the error.
    fn fallback_failed_state() -> AppState {
        let state = AppState::new("www.tatari.tv".to_string());
        state.scanners.insert(
            "traceroute".to_string(),
            crate::types::ScanState {
                result: None,
                error: Some(eyre::Report::new(FallbackFailure {
                    failure: "IPv4: no IPv4 route on this host".to_string(),
                    reason: "mtr not installed".to_string(),
                })),
                status: crate::types::ScanStatus::Failed,
                last_updated: std::time::Instant::now(),
                history: Default::default(),
            },
        );
        state
    }

    #[test]
    fn every_fallback_family_failing_still_says_why_traceroute_is_in_use() {
        let state = fallback_failed_state();
        let pane = TraceroutePane::new();
        let wide = crate::tui::testing::content_rows(&pane, &state, 120, Detail::Normal).join("\n");
        assert!(
            wide.contains("failed: IPv4: no IPv4 route on this host (traceroute: mtr not installed)"),
            "{wide}"
        );
        let (width, height) = crate::tui::testing::dashboard_pane_size(2, 1, 80, 24);
        let narrow = crate::tui::testing::render_pane(&pane, &state, width, height, false);
        assert!(bottom_border(&narrow).contains("┘mtr not installed└"), "{narrow}");

        let scan_state = state.scanners.get("traceroute").expect("traceroute state");
        let line = crate::pretty::format_scan_state("traceroute", &scan_state);
        assert!(line.contains("(traceroute: mtr not installed)"), "{line}");
    }

    #[test]
    fn zoomed_fallback_names_the_engine_reason() {
        let state = state_of(tatari_fallback_route(), std::time::Duration::from_millis(10));
        let text = crate::tui::testing::content_rows(&TraceroutePane::new(), &state, 120, Detail::Zoomed).join("\n");
        assert!(text.contains("🧭 Status: traceroute (mtr not installed)"), "{text}");
    }
}
