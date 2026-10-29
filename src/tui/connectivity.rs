use crate::scan::Family;
use crate::scan::ping::PingStatus;
use crate::tui::pane::{Pane, create_block};
use crate::tui::sparkline::{Sample, SparklineData, average_us, bars_newest_first, scale_max_us, span};
use crate::types::{AppState, ScanResult};
use log;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, RenderDirection, Sparkline, Widget},
};
use std::any::Any;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

const MIN_CONNECTIVITY_PANE_WIDTH: u16 = 25;
const NO_REPLY_LABEL: &str = "no echo reply";
/// Ping cycles kept per family, enough for the widest pane.
const SPARKLINE_CAPACITY: usize = 200;
const MIN_CONNECTIVITY_PANE_HEIGHT: u16 = 12; // Double-height sparklines like btop

/// The label for a family's latest ping failure, or `no ping reply` when none is on record.
fn family_failure_label(state: &AppState, family: Family) -> String {
    let status = state
        .scanners
        .get("ping")
        .and_then(|ping_state| match &ping_state.result {
            Some(ScanResult::Ping(ping)) => Some(match family {
                Family::Ipv4 => ping.ipv4_status.clone(),
                Family::Ipv6 => ping.ipv6_status.clone(),
            }),
            _ => None,
        });
    match status {
        Some(PingStatus::Failed(failure)) => failure.label(family),
        _ => "no ping reply".to_string(),
    }
}

/// Drawn, in red, for a ping cycle that got no reply.
const FAILED_SAMPLE_SYMBOL: &str = "░";
/// Average latency, in µs, above which a family's graph turns yellow, then red.
const SLOW_LATENCY_US: u64 = 50_000;
const VERY_SLOW_LATENCY_US: u64 = 150_000;
const FAMILY_COUNT: u16 = 2;

/// Where the status line and each family's rows sit inside the pane border.
#[derive(Debug, Clone, PartialEq)]
enum ConnectivityRows {
    /// Per family, a title row over a graph at least one row tall.
    Full { status: Rect, families: [(Rect, Rect); 2] },
    /// Per family, one row: short label, then graph. A family with no row left is not drawn.
    Compact { status: Rect, families: [Option<Rect>; 2] },
}

impl ConnectivityRows {
    fn status(&self) -> Rect {
        match self {
            ConnectivityRows::Full { status, .. } | ConnectivityRows::Compact { status, .. } => *status,
        }
    }
}

/// Full mode when `inner` has the status row plus a title and a graph row per family, extra rows
/// going to the graphs (IPv4 takes the odd one); compact mode otherwise.
fn connectivity_rows(inner: Rect) -> ConnectivityRows {
    let row = |offset: u16, height: u16| Rect {
        y: inner.y + offset,
        height,
        ..inner
    };
    let status = row(0, inner.height.min(1));
    if inner.height > 2 * FAMILY_COUNT {
        let graph_rows = inner.height - 1 - FAMILY_COUNT;
        let ipv4_graph = graph_rows.div_ceil(2);
        let ipv6_graph = graph_rows - ipv4_graph;
        ConnectivityRows::Full {
            status,
            families: [
                (row(1, 1), row(2, ipv4_graph)),
                (row(2 + ipv4_graph, 1), row(3 + ipv4_graph, ipv6_graph)),
            ],
        }
    } else {
        let family_row = |index: u16| (inner.height > 1 + index).then(|| row(1 + index, 1));
        ConnectivityRows::Compact {
            status,
            families: [family_row(0), family_row(1)],
        }
    }
}

/// A latency in µs as ms: one decimal below 1ms, whole ms above.
fn format_latency(micros: u64) -> String {
    if micros < 1000 {
        format!("{:.1}ms", micros as f64 / 1000.0)
    } else {
        format!("{}ms", (micros + 500) / 1000)
    }
}

/// The latest sample: its latency, `✗` when it failed, `---` with no samples.
fn latest_text(latest: Option<Option<u64>>) -> String {
    match latest {
        Some(Some(micros)) => format_latency(micros),
        Some(None) => "✗".to_string(),
        None => "---".to_string(),
    }
}

/// One family's state and history, snapshotted for a render.
struct FamilyView {
    family: Family,
    short: &'static str,
    state: ConnectivityState,
    connected: bool,
    data: SparklineData,
}

impl FamilyView {
    /// `12ms avg 11ms`, prefixed `intermittent` when the family is.
    fn latency_text(&self, visible: &[Sample]) -> String {
        let average = average_us(visible)
            .map(format_latency)
            .unwrap_or_else(|| "---".to_string());
        let text = format!("{} avg {}", latest_text(self.data.latest()), average);
        if self.state == ConnectivityState::Intermittent {
            format!("intermittent {text}")
        } else {
            text
        }
    }

    fn title_color(&self) -> Color {
        if self.connected { Color::Green } else { Color::Red }
    }

    fn graph_color(&self, visible: &[Sample]) -> Color {
        if !self.connected {
            return Color::Red;
        }
        match average_us(visible) {
            Some(average) if average > VERY_SLOW_LATENCY_US => Color::Red,
            Some(average) if average > SLOW_LATENCY_US => Color::Yellow,
            _ => Color::Green,
        }
    }
}

/// Draw `visible` newest at the right edge, against a 0..`max_us` scale, failures in red.
fn render_graph(frame: &mut Frame, area: Rect, visible: &[Sample], max_us: u64, color: Color) {
    Sparkline::default()
        .data(bars_newest_first(visible, area.height, max_us))
        .max(max_us)
        .direction(RenderDirection::RightToLeft)
        .style(Style::default().fg(color))
        .absent_value_symbol(FAILED_SAMPLE_SYMBOL)
        .absent_value_style(Style::default().fg(Color::Red))
        .render(area, frame.buffer_mut());
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectivityState {
    Checking,
    Connected,
    Disconnected,
    Intermittent,
}

#[derive(Debug, Clone)]
struct ConnectivityHistory {
    ipv4_results: VecDeque<(Instant, bool)>, // (timestamp, success)
    ipv6_results: VecDeque<(Instant, bool)>,
    ipv4_state: ConnectivityState,
    ipv6_state: ConnectivityState,
    last_state_change: Instant,
}

impl ConnectivityHistory {
    fn new() -> Self {
        Self {
            ipv4_results: VecDeque::new(),
            ipv6_results: VecDeque::new(),
            ipv4_state: ConnectivityState::Checking,
            ipv6_state: ConnectivityState::Checking,
            last_state_change: Instant::now(),
        }
    }

    fn add_result(&mut self, ipv4_success: Option<bool>, ipv6_success: Option<bool>) {
        let now = Instant::now();

        // Keep last 10 results for each protocol
        const MAX_HISTORY: usize = 10;

        if let Some(success) = ipv4_success {
            self.ipv4_results.push_back((now, success));
            while self.ipv4_results.len() > MAX_HISTORY {
                self.ipv4_results.pop_front();
            }
            self.update_ipv4_state();
        }

        if let Some(success) = ipv6_success {
            self.ipv6_results.push_back((now, success));
            while self.ipv6_results.len() > MAX_HISTORY {
                self.ipv6_results.pop_front();
            }
            self.update_ipv6_state();
        }
    }

    fn update_ipv4_state(&mut self) {
        let new_state = self.calculate_state(&self.ipv4_results);
        if new_state != self.ipv4_state {
            self.ipv4_state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    fn update_ipv6_state(&mut self) {
        let new_state = self.calculate_state(&self.ipv6_results);
        if new_state != self.ipv6_state {
            self.ipv6_state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    fn calculate_state(&self, results: &VecDeque<(Instant, bool)>) -> ConnectivityState {
        if results.is_empty() {
            return ConnectivityState::Checking;
        }

        let recent_count = results.len().min(5); // Look at last 5 results
        let recent_results: Vec<bool> = results
            .iter()
            .rev()
            .take(recent_count)
            .map(|(_, success)| *success)
            .collect();

        let success_count = recent_results.iter().filter(|&&s| s).count();
        let failure_count = recent_results.len() - success_count;

        match (success_count, failure_count) {
            (s, 0) if s >= 2 => ConnectivityState::Connected, // All recent pings successful
            (0, f) if f >= 3 => ConnectivityState::Disconnected, // Multiple recent failures
            (s, f) if s > 0 && f > 0 => ConnectivityState::Intermittent, // Mixed results
            _ => ConnectivityState::Checking,                 // Not enough data
        }
    }
}

/// CONNECTIVITY pane displays real-time ping latency and network connectivity metrics
pub struct ConnectivityPane {
    title: &'static str,
    id: &'static str,
    ipv4_sparkline: Mutex<SparklineData>,
    ipv6_sparkline: Mutex<SparklineData>,
    last_ping_timestamp: Mutex<Option<std::time::Instant>>,
    connectivity_history: Mutex<ConnectivityHistory>,
}

impl ConnectivityPane {
    pub fn new() -> Self {
        log::debug!("[tui::connectivity] new:");

        Self {
            title: "connectivity",
            id: "connectivity",
            ipv4_sparkline: Mutex::new(SparklineData::new(SPARKLINE_CAPACITY)),
            ipv6_sparkline: Mutex::new(SparklineData::new(SPARKLINE_CAPACITY)),
            last_ping_timestamp: Mutex::new(None),
            connectivity_history: Mutex::new(ConnectivityHistory::new()),
        }
    }

    fn update_sparklines(&self, ping_result: &crate::scan::ping::PingResult) {
        // Check if this is new data
        let is_new_data = if let Ok(mut last_timestamp) = self.last_ping_timestamp.lock() {
            let current_timestamp = ping_result.queried_at;
            match *last_timestamp {
                Some(last) if last >= current_timestamp => {
                    // This is old data, don't update sparklines
                    log::trace!(
                        "[tui::connectivity] skipping_old_data: last={:?} current={:?}",
                        last,
                        current_timestamp
                    );
                    return;
                }
                _ => {
                    // This is new data, update timestamp and continue
                    log::debug!("[tui::connectivity] new_ping_data: timestamp={:?}", current_timestamp);
                    *last_timestamp = Some(current_timestamp);
                    true
                }
            }
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_timestamp");
            false
        };

        if !is_new_data {
            return;
        }

        let ipv4_success = ping_result.ipv4_status.is_success();
        let ipv6_success = ping_result.ipv6_status.is_success();
        let ipv4_attempted = ping_result.ipv4_status.was_attempted();
        let ipv6_attempted = ping_result.ipv6_status.was_attempted();

        log::debug!(
            "[tui::connectivity] updating_sparklines: ipv4_success={} ipv6_success={}",
            ipv4_success,
            ipv6_success
        );

        // Update connectivity history - treat any attempt as a result to track
        if let Ok(mut history) = self.connectivity_history.lock() {
            let ipv4_result = if ipv4_attempted { Some(ipv4_success) } else { None };
            let ipv6_result = if ipv6_attempted { Some(ipv6_success) } else { None };

            history.add_result(ipv4_result, ipv6_result);
            log::debug!(
                "[tui::connectivity] connectivity_history_updated: ipv4_attempted={} ipv4_success={} ipv4_state={:?} ipv6_attempted={} ipv6_success={} ipv6_state={:?}",
                ipv4_attempted,
                ipv4_success,
                history.ipv4_state,
                ipv6_attempted,
                ipv6_success,
                history.ipv6_state
            );
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_connectivity_history");
        }

        let at = ping_result.queried_at;
        for (family, status, sparkline) in [
            (Family::Ipv4, &ping_result.ipv4_status, &self.ipv4_sparkline),
            (Family::Ipv6, &ping_result.ipv6_status, &self.ipv6_sparkline),
        ] {
            let sample = match status {
                PingStatus::Success(latency) => Some(Some(*latency)),
                PingStatus::Failed(_) | PingStatus::ToolMissing(_) => Some(None),
                PingStatus::NoAddress | PingStatus::NotQueried => None,
            };
            let Some(latency) = sample else {
                log::debug!("[tui::connectivity] no_sample: family={:?} status={:?}", family, status);
                continue;
            };
            if let Ok(mut sparkline) = sparkline.lock() {
                sparkline.add_sample(at, latency);
                log::debug!(
                    "[tui::connectivity] sparkline_updated: family={:?} latency={:?} points={}",
                    family,
                    latency,
                    sparkline.len()
                );
            } else {
                log::warn!("[tui::connectivity] failed_to_lock_sparkline: family={:?}", family);
            }
        }
    }
}

impl Default for ConnectivityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for ConnectivityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!(
            "[tui::connectivity] render: area={}x{} focused={}",
            area.width,
            area.height,
            focused
        );

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Get stable connectivity states to prevent flashing
        let (has_ipv4, has_ipv6, status_text, status_color) = if let Ok(history) = self.connectivity_history.lock() {
            let ipv4_connected = matches!(history.ipv4_state, ConnectivityState::Connected);
            let ipv6_connected = matches!(history.ipv6_state, ConnectivityState::Connected);

            let (text, color) = match (&history.ipv4_state, &history.ipv6_state) {
                (ConnectivityState::Connected, ConnectivityState::Connected) => ("dual-stack", Color::Green),
                (ConnectivityState::Connected, ConnectivityState::Disconnected) => ("ipv4 only", Color::Yellow),
                (ConnectivityState::Disconnected, ConnectivityState::Connected) => ("ipv6 only", Color::Yellow),
                (ConnectivityState::Connected, ConnectivityState::Intermittent) => {
                    ("ipv4 stable, ipv6 intermittent", Color::Yellow)
                }
                (ConnectivityState::Intermittent, ConnectivityState::Connected) => {
                    ("ipv4 intermittent, ipv6 stable", Color::Yellow)
                }
                (ConnectivityState::Intermittent, ConnectivityState::Intermittent) => {
                    ("intermittent connectivity", Color::Yellow)
                }
                (ConnectivityState::Intermittent, ConnectivityState::Disconnected) => {
                    ("ipv4 intermittent", Color::Yellow)
                }
                (ConnectivityState::Disconnected, ConnectivityState::Intermittent) => {
                    ("ipv6 intermittent", Color::Yellow)
                }
                (ConnectivityState::Disconnected, ConnectivityState::Disconnected)
                | (ConnectivityState::Disconnected, ConnectivityState::Checking)
                | (ConnectivityState::Checking, ConnectivityState::Disconnected) => ("no ping reply", Color::Red),
                (ConnectivityState::Checking, _) | (_, ConnectivityState::Checking) => {
                    ("checking connectivity", Color::Gray)
                }
            };

            log::trace!(
                "[tui::connectivity] stable_states: ipv4={:?} ipv6={:?} text={}",
                history.ipv4_state,
                history.ipv6_state,
                text
            );

            (ipv4_connected, ipv6_connected, text, color)
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_connectivity_history");
            (false, false, "checking", Color::Gray)
        };
        let mut status_text = status_text.to_string();
        let mut status_color = status_color;
        // The latest ping scan's error (deadline hit). The smoothed label stays, since it reflects
        // the last samples; the error rides next to it. With no samples yet it replaces
        // `checking connectivity`, which would otherwise never change.
        let mut scan_failure = state
            .scanners
            .get("ping")
            .and_then(|ping_state| crate::tui::failure_text(&ping_state));
        if status_text == "checking connectivity"
            && let Some(failure) = scan_failure.take()
        {
            status_text = failure;
            status_color = Color::Red;
        } else if status_text == "no ping reply"
            && let Some(ping_state) = state.scanners.get("ping")
            && let Some(ScanResult::Ping(ping)) = &ping_state.result
            && let Some(reason) = ping.failure_reason()
            && reason != NO_REPLY_LABEL
        {
            status_text = format!("no ping reply: {reason}");
        }

        // Update sparklines if we have ping results
        if let Some(ping_state) = state.scanners.get("ping")
            && let Some(ScanResult::Ping(ping)) = &ping_state.result
        {
            log::trace!("[tui::connectivity] updating_sparklines_from_render");
            self.update_sparklines(ping);
        }

        // Status line
        let mut status_spans = vec![
            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled(status_text, Style::default().fg(status_color)),
        ];
        if let Some(failure) = scan_failure {
            status_spans.push(Span::styled(format!(", {failure}"), Style::default().fg(Color::Red)));
        }
        lines.push(Line::from(status_spans));

        let rows = connectivity_rows(inner_area);
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .render(rows.status(), frame.buffer_mut());

        // A failed ping scan with no samples has nothing pending: the families have no data.
        let checking_text = if state
            .scanners
            .get("ping")
            .is_some_and(|ping_state| crate::tui::failure_text(&ping_state).is_some())
        {
            "no data"
        } else {
            "checking"
        };

        let (ipv4_state, ipv6_state) = match self.connectivity_history.lock() {
            Ok(history) => (history.ipv4_state.clone(), history.ipv6_state.clone()),
            Err(_) => (ConnectivityState::Checking, ConnectivityState::Checking),
        };
        let snapshot = |sparkline: &Mutex<SparklineData>| match sparkline.lock() {
            Ok(data) => data.clone(),
            Err(_) => {
                log::warn!("[tui::connectivity] sparkline_lock_failed");
                SparklineData::new(0)
            }
        };
        let families = [
            FamilyView {
                family: Family::Ipv4,
                short: "v4",
                state: ipv4_state,
                connected: has_ipv4,
                data: snapshot(&self.ipv4_sparkline),
            },
            FamilyView {
                family: Family::Ipv6,
                short: "v6",
                state: ipv6_state,
                connected: has_ipv6,
                data: snapshot(&self.ipv6_sparkline),
            },
        ];

        match rows {
            ConnectivityRows::Full {
                families: family_rows, ..
            } => {
                for (view, (title_area, graph_area)) in families.iter().zip(family_rows) {
                    let visible = view.data.visible(usize::from(graph_area.width));
                    let max_us = scale_max_us(&visible);
                    let state_text = match view.state {
                        ConnectivityState::Disconnected => family_failure_label(state, view.family),
                        ConnectivityState::Checking => checking_text.to_string(),
                        _ => view.latency_text(&visible),
                    };
                    let mut spans = vec![
                        Span::styled(format!("{} ", view.family), Style::default().fg(Color::White)),
                        Span::styled(state_text, Style::default().fg(view.title_color())),
                    ];
                    if !visible.is_empty() {
                        spans.push(Span::styled(
                            format!(
                                " │ scale 0-{}ms │ ← {}s",
                                max_us / 1000,
                                span(&visible).as_secs_f64().round() as u64
                            ),
                            Style::default().fg(Color::Gray),
                        ));
                    }
                    Paragraph::new(Line::from(spans)).render(title_area, frame.buffer_mut());
                    render_graph(frame, graph_area, &visible, max_us, view.graph_color(&visible));
                }
            }
            ConnectivityRows::Compact {
                families: family_rows, ..
            } => {
                let labels: Vec<String> = families
                    .iter()
                    .map(|view| format!("{} {}", view.short, latest_text(view.data.latest())))
                    .collect();
                let label_width = labels
                    .iter()
                    .map(|label| Span::raw(label.as_str()).width())
                    .max()
                    .unwrap_or(0) as u16
                    + 1;
                for ((view, label), row) in families.iter().zip(labels).zip(family_rows) {
                    let Some(row) = row else { continue };
                    let label_area = Rect {
                        width: label_width.min(row.width),
                        ..row
                    };
                    let graph_area = Rect {
                        x: row.x + label_area.width,
                        width: row.width - label_area.width,
                        ..row
                    };
                    Paragraph::new(Span::styled(label, Style::default().fg(view.title_color())))
                        .render(label_area, frame.buffer_mut());
                    let visible = view.data.visible(usize::from(graph_area.width));
                    let max_us = scale_max_us(&visible);
                    render_graph(frame, graph_area, &visible, max_us, view.graph_color(&visible));
                }
            }
        }
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT)
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
    use crate::scan::ping::{PingFailure, PingResult};
    use crate::tui::testing::render_pane;
    use crate::types::{ScanState, ScanStatus};
    use std::time::Duration;

    #[test]
    fn test_connectivity_pane_creation() {
        let pane = ConnectivityPane::new();
        assert_eq!(pane.title(), "connectivity");
        assert_eq!(pane.id(), "connectivity");
        assert_eq!(
            pane.min_size(),
            (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT)
        );
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn failed_pings_are_recorded_as_absent_samples() {
        let pane = ConnectivityPane::new();
        let start = Instant::now();
        let mut ok = PingResult::new();
        ok.ipv4_status = PingStatus::Success(Duration::from_micros(500));
        ok.ipv6_status = PingStatus::NoAddress;
        ok.queried_at = start;
        pane.update_sparklines(&ok);
        let mut failed = failed_ping_with(PingFailure::NoReply);
        failed.queried_at = start + Duration::from_secs(1);
        pane.update_sparklines(&failed);

        let ipv4 = pane.ipv4_sparkline.lock().expect("ipv4 sparkline");
        let values: Vec<Option<u64>> = ipv4.visible(10).iter().map(|(_, micros)| *micros).collect();
        assert_eq!(values, vec![Some(500), None]);
        let ipv6 = pane.ipv6_sparkline.lock().expect("ipv6 sparkline");
        assert_eq!(ipv6.len(), 1, "NoAddress is not a ping cycle; the failure is");
    }

    /// Render `pane` once per ping from `pings`, each 1s after the last; returns the final render.
    fn render_cycles(pane: &ConnectivityPane, pings: &[PingResult], width: u16, height: u16) -> String {
        let start = Instant::now();
        let mut out = String::new();
        for (cycle, ping) in pings.iter().enumerate() {
            let mut ping = ping.clone();
            ping.queried_at = start + Duration::from_secs(cycle as u64);
            out = render_pane(pane, &state_with_ping(ping), width, height, false);
        }
        out
    }

    fn ok_ping(ipv4_ms: u64, ipv6_ms: u64) -> PingResult {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Success(Duration::from_millis(ipv4_ms));
        ping.ipv6_status = PingStatus::Success(Duration::from_millis(ipv6_ms));
        ping
    }

    fn has_bar_glyph(row: &str) -> bool {
        row.chars().any(|glyph| ('▁'..='█').contains(&glyph))
    }

    fn row_containing<'a>(out: &'a str, needle: &str) -> &'a str {
        out.lines()
            .find(|row| row.contains(needle))
            .unwrap_or_else(|| panic!("no row contains {needle:?}:\n{out}"))
    }

    /// The glyph in the last column inside the right border.
    fn last_inner_glyph(row: &str) -> char {
        let glyphs: Vec<char> = row.chars().collect();
        glyphs[glyphs.len() - 2]
    }

    #[test]
    fn compact_mode_at_80x24_draws_both_families() {
        let pane = ConnectivityPane::new();
        let pings: Vec<PingResult> = (0..5).map(|_| ok_ping(12, 14)).collect();
        let out = render_cycles(&pane, &pings, 56, 6);
        let ipv4_row = row_containing(&out, "v4 12ms");
        let ipv6_row = row_containing(&out, "v6 14ms");
        assert!(has_bar_glyph(ipv4_row), "no IPv4 sparkline:\n{out}");
        assert!(has_bar_glyph(ipv6_row), "no IPv6 sparkline:\n{out}");
    }

    #[test]
    fn newest_sample_is_in_the_rightmost_column() {
        let pane = ConnectivityPane::new();
        let mut pings: Vec<PingResult> = (0..4).map(|_| ok_ping(12, 14)).collect();
        let mut failed_v4 = ok_ping(12, 14);
        failed_v4.ipv4_status = PingStatus::Failed(PingFailure::NoReply);
        pings.push(failed_v4);
        let out = render_cycles(&pane, &pings, 56, 6);
        let ipv4_row = row_containing(&out, "v4 ✗");
        assert_eq!(
            last_inner_glyph(ipv4_row),
            '░',
            "newest (failed) sample not at the right:\n{out}"
        );
        let ipv6_row = row_containing(&out, "v6 14ms");
        assert!(('▁'..='█').contains(&last_inner_glyph(ipv6_row)), "{out}");
    }

    #[test]
    fn failed_sample_renders_the_absent_symbol_under_a_scaled_title() {
        let out = render_failures(|| failed_ping_with(PingFailure::NoReply));
        assert!(out.contains('░'), "failed samples not drawn:\n{out}");
        assert!(out.contains("scale 0-"), "no scale in the title:\n{out}");
    }

    #[test]
    fn full_mode_title_names_latency_scale_and_span() {
        let pane = ConnectivityPane::new();
        let pings: Vec<PingResult> = [10, 11, 12, 11, 12].iter().map(|ms| ok_ping(*ms, 30)).collect();
        let out = render_cycles(&pane, &pings, 100, 20);
        assert!(
            out.contains("IPv4 12ms avg 11ms │ scale 0-20ms │ ← 4s"),
            "IPv4 title:\n{out}"
        );
        assert!(
            out.contains("IPv6 30ms avg 30ms │ scale 0-50ms │ ← 4s"),
            "IPv6 title:\n{out}"
        );
    }

    #[test]
    fn rows_are_compact_below_the_full_mode_height() {
        let inner = Rect::new(1, 1, 54, 4);
        let row = |y| Rect::new(1, y, 54, 1);
        assert_eq!(
            connectivity_rows(inner),
            ConnectivityRows::Compact {
                status: row(1),
                families: [Some(row(2)), Some(row(3))],
            }
        );
        assert_eq!(
            connectivity_rows(Rect::new(1, 1, 54, 2)),
            ConnectivityRows::Compact {
                status: row(1),
                families: [Some(row(2)), None],
            }
        );
    }

    #[test]
    fn rows_give_extra_height_to_the_graphs_in_full_mode() {
        let rect = |y, height| Rect::new(0, y, 40, height);
        assert_eq!(
            connectivity_rows(rect(0, 5)),
            ConnectivityRows::Full {
                status: rect(0, 1),
                families: [(rect(1, 1), rect(2, 1)), (rect(3, 1), rect(4, 1))],
            }
        );
        assert_eq!(
            connectivity_rows(rect(0, 8)),
            ConnectivityRows::Full {
                status: rect(0, 1),
                families: [(rect(1, 1), rect(2, 3)), (rect(5, 1), rect(6, 2))],
            }
        );
    }

    #[test]
    fn latency_formats_sub_millisecond_with_a_decimal() {
        assert_eq!(format_latency(500), "0.5ms");
        assert_eq!(format_latency(12_400), "12ms");
        assert_eq!(latest_text(Some(None)), "✗");
        assert_eq!(latest_text(None), "---");
    }

    fn failed_ping(reason: &str) -> PingResult {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Failed(PingFailure::Other(reason.to_string()));
        ping.ipv6_status = PingStatus::Failed(PingFailure::Other(reason.to_string()));
        ping
    }

    fn failed_ping_with(failure: PingFailure) -> PingResult {
        let mut ping = PingResult::new();
        ping.ipv4_status = PingStatus::Failed(failure.clone());
        ping.ipv6_status = PingStatus::Failed(failure);
        ping
    }

    fn render_failures(ping: impl Fn() -> PingResult) -> String {
        let pane = ConnectivityPane::new();
        let mut out = String::new();
        for _ in 0..5 {
            out = render_pane(&pane, &state_with_ping(ping()), 100, 20, false);
        }
        out
    }

    #[test]
    fn no_reply_renders_no_echo_reply_never_disconnected_or_unreachable() {
        let out = render_failures(|| failed_ping_with(PingFailure::NoReply));
        assert!(out.contains("no echo reply"), "{out}");
        assert!(out.contains("no ping reply"), "{out}");
        assert!(!out.contains("disconnected"), "{out}");
        assert!(!out.contains("network unreachable"), "{out}");
    }

    #[test]
    fn no_route_renders_the_missing_route_on_this_host() {
        let out = render_failures(|| {
            let mut ping = failed_ping_with(PingFailure::NoReply);
            ping.ipv6_status = PingStatus::Failed(PingFailure::NoRoute);
            ping
        });
        assert!(out.contains("no IPv6 route on this host"), "{out}");
        assert!(out.contains("no echo reply"), "{out}");
        assert!(!out.contains("network unreachable"), "{out}");
    }

    #[test]
    fn other_failure_keeps_its_reason_under_the_overall_label() {
        let out = render_failures(|| failed_ping("ping binary missing"));
        assert!(out.contains("no ping reply: ping binary missing"), "{out}");
    }

    fn state_with_ping(ping: PingResult) -> AppState {
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            "ping".to_string(),
            ScanState {
                result: Some(ScanResult::Ping(ping)),
                error: None,
                status: ScanStatus::Complete,
                last_updated: Instant::now(),
                history: VecDeque::new(),
            },
        );
        state
    }

    #[test]
    fn five_failed_samples_render_no_ping_reply_with_reason() {
        let pane = ConnectivityPane::new();
        let mut out = String::new();
        for _ in 0..5 {
            let state = state_with_ping(failed_ping("ping binary missing"));
            out = render_pane(&pane, &state, 100, 20, false);
        }
        assert!(out.contains("no ping reply"), "{out}");
        assert!(out.contains("ping binary missing"), "{out}");
        assert!(!out.contains("checking"), "{out}");
    }

    #[test]
    fn fewer_than_three_failures_still_checking() {
        let pane = ConnectivityPane::new();
        let mut out = String::new();
        for _ in 0..2 {
            out = render_pane(&pane, &state_with_ping(failed_ping("x")), 100, 20, false);
        }
        assert!(out.contains("checking"), "{out}");
    }

    #[test]
    fn failed_refresh_after_history_shows_error_next_to_smoothed_label() {
        let pane = ConnectivityPane::new();
        let start = Instant::now();
        let ok = |sample: u64| {
            let mut ping = PingResult::new();
            ping.ipv4_status = PingStatus::Success(Duration::from_millis(12));
            ping.ipv6_status = PingStatus::Success(Duration::from_millis(14));
            // Distinct timestamps: the pane skips a sample it has already counted.
            ping.queried_at = start + Duration::from_millis(sample);
            ping
        };
        for sample in 1..=5 {
            render_pane(&pane, &state_with_ping(ok(sample)), 100, 20, false);
        }
        let state = state_with_ping(ok(5));
        if let Some(mut ping_state) = state.scanners.get_mut("ping") {
            ping_state.status = ScanStatus::Failed;
            ping_state.error = Some(eyre::eyre!("timed out after 30s"));
        }
        let out = render_pane(&pane, &state, 100, 20, false);
        assert!(out.contains("dual-stack"), "smoothed label dropped:\n{out}");
        assert!(
            out.contains("failed: timed out after 30s"),
            "failed refresh hidden:\n{out}"
        );
    }
}
