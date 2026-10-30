use crate::scan::Family;
use crate::scan::ping::{PingResult, PingStatus};
use crate::target::Protocol;
use crate::tui::pane::{Detail, Pane, create_block};
use crate::tui::sparkline::{
    Sample, SparklineData, average_us, bars_newest_first, jitter_us, loss_percent, scale_max_us, span,
};
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

/// How much of a family's state a row has room for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StateForm {
    /// Title row: latency, average, state.
    Full,
    /// One-row layout: the latest sample only, but a failure keeps its full label.
    Compact,
}

/// The one text for a family's state, shared by the full and compact layouts so a failed family
/// reads the same in both.
fn family_state_text(
    state: &AppState,
    view: &FamilyView,
    visible: &[Sample],
    form: StateForm,
    checking_text: &str,
) -> String {
    match (&view.state, form) {
        (ConnectivityState::NoAddress, _) => format!("no {} address", view.family.as_str()),
        (ConnectivityState::Disabled, _) => DISABLED_LABEL.to_string(),
        (ConnectivityState::Disconnected, _) => family_failure_label(state, view.family),
        (ConnectivityState::Checking, StateForm::Full) => checking_text.to_string(),
        (_, StateForm::Full) => view.latency_text(visible),
        (_, StateForm::Compact) => latest_text(view.data.latest()),
    }
}

/// Shown for a family the protocol selection turned off; `p` turns it back on.
const DISABLED_LABEL: &str = "disabled (p)";
/// Ping results kept per family to judge its state.
const STATE_WINDOW: usize = 10;
/// How many of the newest results decide the state.
const STATE_RECENT: usize = 5;

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

/// `loss N% · jitter Xms` over `samples`, `---` for what they cannot tell.
fn loss_and_jitter(samples: &[Sample]) -> String {
    let loss = loss_percent(samples).map_or_else(|| "---".to_string(), |percent| format!("{percent}%"));
    let jitter = jitter_us(samples).map_or_else(|| "---".to_string(), format_latency);
    format!("loss {loss} · jitter {jitter}")
}

/// One family's state and history, snapshotted for a render.
struct FamilyView {
    family: Family,
    short: &'static str,
    state: ConnectivityState,
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
        match self.state {
            ConnectivityState::Connected => Color::Green,
            // MUTED: neither is a fault. Phase 2 moves this to the theme.
            ConnectivityState::NoAddress | ConnectivityState::Disabled => Color::Gray,
            _ => Color::Red,
        }
    }

    fn graph_color(&self, visible: &[Sample]) -> Color {
        if self.state != ConnectivityState::Connected {
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
    /// The target has no address in this family: nothing to ping, not a failure.
    NoAddress,
    /// The protocol selection leaves this family out.
    Disabled,
}

/// The overall status line for the two families' states. A family with no address, or left out by
/// the protocol selection, never makes the status a warning.
fn overall_status(ipv4: &ConnectivityState, ipv6: &ConnectivityState) -> (&'static str, Color) {
    use ConnectivityState::*;
    match (ipv4, ipv6) {
        (NoAddress | Disabled, NoAddress | Disabled) => ("no address", Color::Gray),
        (live, NoAddress | Disabled) => single_family_status(live, "ipv4", "ipv4 intermittent"),
        (NoAddress | Disabled, live) => single_family_status(live, "ipv6", "ipv6 intermittent"),
        (Connected, Connected) => ("dual-stack", Color::Green),
        (Connected, Disconnected) => ("ipv4 only", Color::Yellow),
        (Disconnected, Connected) => ("ipv6 only", Color::Yellow),
        (Connected, Intermittent) => ("ipv4 stable, ipv6 intermittent", Color::Yellow),
        (Intermittent, Connected) => ("ipv4 intermittent, ipv6 stable", Color::Yellow),
        (Intermittent, Intermittent) => ("intermittent connectivity", Color::Yellow),
        (Intermittent, Disconnected) => ("ipv4 intermittent", Color::Yellow),
        (Disconnected, Intermittent) => ("ipv6 intermittent", Color::Yellow),
        (Disconnected, Disconnected) | (Disconnected, Checking) | (Checking, Disconnected) => {
            ("no ping reply", Color::Red)
        }
        (Checking, _) | (_, Checking) => ("checking connectivity", Color::Gray),
    }
}

/// The status when only one family can be pinged.
fn single_family_status(
    state: &ConnectivityState,
    connected_text: &'static str,
    intermittent_text: &'static str,
) -> (&'static str, Color) {
    match state {
        ConnectivityState::Connected => (connected_text, Color::Green),
        ConnectivityState::Intermittent => (intermittent_text, Color::Yellow),
        ConnectivityState::Disconnected => ("no ping reply", Color::Red),
        _ => ("checking connectivity", Color::Gray),
    }
}

/// One family's recent ping results, the state they add up to, and its sparkline samples.
#[derive(Debug, Clone)]
struct FamilyHistory {
    results: VecDeque<bool>,
    state: ConnectivityState,
    samples: SparklineData,
}

impl FamilyHistory {
    fn new() -> Self {
        Self {
            results: VecDeque::new(),
            state: ConnectivityState::Checking,
            samples: SparklineData::new(SPARKLINE_CAPACITY),
        }
    }

    /// Record one ping cycle's `status` for this family. `NoAddress` sets the state directly: it is
    /// not a ping attempt, so it never counts as a failure. A disabled family records nothing.
    fn observe(&mut self, at: Instant, status: &PingStatus) {
        if self.state == ConnectivityState::Disabled {
            return;
        }
        match status {
            PingStatus::Success(latency) => {
                self.push_result(true);
                self.samples.add_sample(at, Some(*latency));
            }
            PingStatus::Failed(_) | PingStatus::ToolMissing(_) => {
                self.push_result(false);
                self.samples.add_sample(at, None);
            }
            PingStatus::NoAddress => {
                self.results.clear();
                self.state = ConnectivityState::NoAddress;
            }
            PingStatus::NotQueried => {}
        }
    }

    fn push_result(&mut self, success: bool) {
        self.results.push_back(success);
        while self.results.len() > STATE_WINDOW {
            self.results.pop_front();
        }
        self.state = state_of(&self.results);
    }

    /// Drop everything recorded: the family is off until the protocol selection includes it again.
    fn disable(&mut self) {
        *self = Self::new();
        self.state = ConnectivityState::Disabled;
    }

    /// Start a disabled family over at `Checking`; an enabled family is left as it is.
    fn enable(&mut self) {
        if self.state == ConnectivityState::Disabled {
            *self = Self::new();
        }
    }
}

/// The state the newest results add up to.
fn state_of(results: &VecDeque<bool>) -> ConnectivityState {
    let recent: Vec<bool> = results.iter().rev().take(STATE_RECENT).copied().collect();
    let success_count = recent.iter().filter(|&&success| success).count();
    let failure_count = recent.len() - success_count;
    match (success_count, failure_count) {
        (s, 0) if s >= 2 => ConnectivityState::Connected,
        (0, f) if f >= 3 => ConnectivityState::Disconnected,
        (s, f) if s > 0 && f > 0 => ConnectivityState::Intermittent,
        _ => ConnectivityState::Checking,
    }
}

/// Everything Connectivity has taken in from the ping scanner, updated by `ingest` once per TUI
/// tick whether or not the pane is drawn.
#[derive(Debug, Clone)]
struct Ingested {
    /// IPv4, then IPv6.
    families: [FamilyHistory; 2],
    /// `queried_at` of the newest ping result taken in, so none is counted twice.
    last_ping_at: Option<Instant>,
    /// The protocol selection last seen, so a change disables the family it leaves out.
    protocol: Option<Protocol>,
}

impl Ingested {
    fn new() -> Self {
        Self {
            families: [FamilyHistory::new(), FamilyHistory::new()],
            last_ping_at: None,
            protocol: None,
        }
    }

    fn family(&self, family: Family) -> &FamilyHistory {
        &self.families[family_index(family)]
    }

    /// On a protocol change, clear and disable each family the selection leaves out, and restart
    /// each one it brings back.
    fn follow_protocol(&mut self, protocol: Protocol) {
        if self.protocol == Some(protocol) {
            return;
        }
        for family in [Family::Ipv4, Family::Ipv6] {
            let history = &mut self.families[family_index(family)];
            if protocol_includes(protocol, family) {
                history.enable();
            } else {
                history.disable();
            }
        }
        log::debug!(
            "[tui::connectivity] protocol_followed: old={:?} new={} ipv4={:?} ipv6={:?}",
            self.protocol.map(|p| p.as_str()),
            protocol.as_str(),
            self.families[0].state,
            self.families[1].state
        );
        self.protocol = Some(protocol);
    }

    /// Take in one ping result, unless it is not newer than the last one taken in.
    fn take_ping(&mut self, ping: &PingResult) {
        if self.last_ping_at.is_some_and(|last| last >= ping.queried_at) {
            log::trace!(
                "[tui::connectivity] skipping_old_data: last={:?} current={:?}",
                self.last_ping_at,
                ping.queried_at
            );
            return;
        }
        self.last_ping_at = Some(ping.queried_at);
        self.families[0].observe(ping.queried_at, &ping.ipv4_status);
        self.families[1].observe(ping.queried_at, &ping.ipv6_status);
        log::debug!(
            "[tui::connectivity] ping_taken: ipv4={:?} ipv4_state={:?} ipv4_samples={} ipv6={:?} ipv6_state={:?} ipv6_samples={}",
            ping.ipv4_status,
            self.families[0].state,
            self.families[0].samples.len(),
            ping.ipv6_status,
            self.families[1].state,
            self.families[1].samples.len()
        );
    }
}

fn family_index(family: Family) -> usize {
    match family {
        Family::Ipv4 => 0,
        Family::Ipv6 => 1,
    }
}

fn protocol_includes(protocol: Protocol, family: Family) -> bool {
    match family {
        Family::Ipv4 => protocol.includes_ipv4(),
        Family::Ipv6 => protocol.includes_ipv6(),
    }
}

/// CONNECTIVITY pane displays real-time ping latency and network connectivity metrics
pub struct ConnectivityPane {
    title: &'static str,
    id: &'static str,
    ingested: Mutex<Ingested>,
}

impl ConnectivityPane {
    pub fn new() -> Self {
        log::debug!("[tui::connectivity] new:");

        Self {
            title: "connectivity",
            id: "connectivity",
            ingested: Mutex::new(Ingested::new()),
        }
    }

    /// A copy of what has been taken in, for one render.
    fn snapshot(&self) -> Ingested {
        match self.ingested.lock() {
            Ok(ingested) => ingested.clone(),
            Err(_) => {
                log::warn!("[tui::connectivity] ingested_lock_failed");
                Ingested::new()
            }
        }
    }

    /// IPv4 and IPv6 sparkline sample counts.
    #[cfg(test)]
    pub(crate) fn sample_counts(&self) -> (usize, usize) {
        let ingested = self.snapshot();
        (ingested.families[0].samples.len(), ingested.families[1].samples.len())
    }
}

impl Default for ConnectivityPane {
    fn default() -> Self {
        Self::new()
    }
}

/// The overall status row: the smoothed connectivity verdict, with the latest ping scan's failure
/// beside it or in its place.
fn status_line(state: &AppState, ipv4_state: &ConnectivityState, ipv6_state: &ConnectivityState) -> Line<'static> {
    let (status_text, status_color) = overall_status(ipv4_state, ipv6_state);
    log::trace!(
        "[tui::connectivity] stable_states: ipv4={:?} ipv6={:?} text={}",
        ipv4_state,
        ipv6_state,
        status_text
    );
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

    // Status line
    let mut status_spans = vec![
        Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
        Span::styled(status_text, Style::default().fg(status_color)),
    ];
    if let Some(failure) = scan_failure {
        status_spans.push(Span::styled(format!(", {failure}"), Style::default().fg(Color::Red)));
    }
    Line::from(status_spans)
}

impl Pane for ConnectivityPane {
    /// Take in the protocol selection and every ping result not yet seen: the scanner's history
    /// first, then its current result, so results published between two ticks are all counted.
    fn ingest(&self, state: &AppState) {
        let Ok(mut ingested) = self.ingested.lock() else {
            log::warn!("[tui::connectivity] ingested_lock_failed");
            return;
        };
        ingested.follow_protocol(state.protocol);
        let Some(ping_state) = state.scanners.get("ping") else {
            return;
        };
        let results = ping_state
            .history
            .iter()
            .map(|entry| &entry.result)
            .chain(ping_state.result.as_ref());
        for result in results {
            if let ScanResult::Ping(ping) = result {
                ingested.take_ping(ping);
            }
        }
    }

    /// The status row. The family rows are sparklines, drawn only by `render`.
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>> {
        log::trace!("[tui::connectivity] content: width={} detail={:?}", width, detail);
        let ingested = self.snapshot();
        let line = status_line(
            state,
            &ingested.family(Family::Ipv4).state,
            &ingested.family(Family::Ipv6).state,
        );
        vec![crate::tui::text::owned(crate::tui::text::fit_line(line, width))]
    }

    /// Draws sparklines, not rows, so the layout never scrolls it.
    fn scrolls(&self) -> bool {
        false
    }

    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        self.render_detail(frame, area, state, focused, Detail::Normal);
    }

    /// Zoomed, the graphs take the full frame and each family's title adds loss and jitter over
    /// every kept sample, not just the visible ones.
    fn render_detail(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool, detail: Detail) {
        log::trace!(
            "[tui::connectivity] render_detail: area={}x{} focused={} detail={:?}",
            area.width,
            area.height,
            focused,
            detail
        );

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        let ingested = self.snapshot();
        let ipv4_state = ingested.family(Family::Ipv4).state.clone();
        let ipv6_state = ingested.family(Family::Ipv6).state.clone();

        let rows = connectivity_rows(inner_area);
        // The status gets one row, so a long failure reason is fit to it rather than wrapped.
        let status_width = rows.status().width;
        let status = crate::tui::text::fit_line(status_line(state, &ipv4_state, &ipv6_state), status_width);
        Paragraph::new(status)
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

        let families = [
            FamilyView {
                family: Family::Ipv4,
                short: "v4",
                state: ipv4_state,
                data: ingested.family(Family::Ipv4).samples.clone(),
            },
            FamilyView {
                family: Family::Ipv6,
                short: "v6",
                state: ipv6_state,
                data: ingested.family(Family::Ipv6).samples.clone(),
            },
        ];

        match rows {
            ConnectivityRows::Full {
                families: family_rows, ..
            } => {
                for (view, (title_area, graph_area)) in families.iter().zip(family_rows) {
                    let visible = view.data.visible(usize::from(graph_area.width));
                    let max_us = scale_max_us(&visible);
                    let state_text = family_state_text(state, view, &visible, StateForm::Full, checking_text);
                    let mut spans = vec![
                        Span::styled(format!("{} ", view.family), Style::default().fg(Color::White)),
                        Span::styled(state_text, Style::default().fg(view.title_color())),
                    ];
                    if detail == Detail::Zoomed {
                        spans.push(Span::styled(
                            format!(" │ {}", loss_and_jitter(&view.data.all())),
                            Style::default().fg(Color::Gray),
                        ));
                    }
                    if !visible.is_empty() {
                        let has_reply = visible.iter().any(|(_, micros)| micros.is_some());
                        let scale = if has_reply {
                            format!("scale 0-{}ms │ ", max_us / 1000)
                        } else {
                            String::new()
                        };
                        spans.push(Span::styled(
                            format!(" │ {scale}← {}s", span(&visible).as_secs_f64().round() as u64),
                            Style::default().fg(Color::Gray),
                        ));
                    }
                    Paragraph::new(crate::tui::text::fit_line(Line::from(spans), title_area.width))
                        .render(title_area, frame.buffer_mut());
                    render_graph(frame, graph_area, &visible, max_us, view.graph_color(&visible));
                }
            }
            ConnectivityRows::Compact {
                families: family_rows, ..
            } => {
                let labels: Vec<String> = families
                    .iter()
                    .map(|view| {
                        let text = family_state_text(state, view, &[], StateForm::Compact, checking_text);
                        format!("{} {}", view.short, text)
                    })
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
                    let label = Line::from(Span::styled(label, Style::default().fg(view.title_color())));
                    Paragraph::new(crate::tui::text::fit_line(label, label_area.width))
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
        pane.ingest(&state_with_ping(ok));
        let mut failed = failed_ping_with(PingFailure::NoReply);
        failed.queried_at = start + Duration::from_secs(1);
        pane.ingest(&state_with_ping(failed));

        let ingested = pane.snapshot();
        let ipv4 = &ingested.family(Family::Ipv4).samples;
        let values: Vec<Option<u64>> = ipv4.visible(10).iter().map(|(_, micros)| *micros).collect();
        assert_eq!(values, vec![Some(500), None]);
        let ipv6 = &ingested.family(Family::Ipv6).samples;
        assert_eq!(ipv6.len(), 1, "NoAddress is not a ping cycle; the failure is");
    }

    /// One TUI tick: ingest `state`, then draw the pane.
    fn tick(pane: &ConnectivityPane, state: &AppState, width: u16, height: u16) -> String {
        pane.ingest(state);
        render_pane(pane, state, width, height, false)
    }

    /// One tick per ping from `pings`, each 1s after the last, under `protocol`.
    fn states_for(pings: &[PingResult], protocol: Protocol) -> Vec<AppState> {
        let start = Instant::now();
        pings
            .iter()
            .enumerate()
            .map(|(cycle, ping)| {
                let mut ping = ping.clone();
                ping.queried_at = start + Duration::from_secs(cycle as u64);
                let mut state = state_with_ping(ping);
                state.protocol = protocol;
                state
            })
            .collect()
    }

    /// Tick `pane` once per ping from `pings`, each 1s after the last; returns the final render.
    fn render_cycles(pane: &ConnectivityPane, pings: &[PingResult], width: u16, height: u16) -> String {
        let mut out = String::new();
        for state in states_for(pings, Protocol::Both) {
            out = tick(pane, &state, width, height);
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
    fn failed_sample_renders_the_absent_symbol_with_no_scale() {
        let out = render_failures(|| failed_ping_with(PingFailure::NoReply));
        assert!(out.contains('░'), "failed samples not drawn:\n{out}");
        assert!(!out.contains("scale 0-"), "scale printed with no reply sampled:\n{out}");
        assert!(out.contains("← "), "span dropped:\n{out}");
    }

    #[test]
    fn full_and_compact_modes_render_the_same_no_route_text() {
        let no_route = || {
            let mut ping = failed_ping_with(PingFailure::NoReply);
            ping.ipv6_status = PingStatus::Failed(PingFailure::NoRoute);
            ping
        };
        let full = render_cycles(&ConnectivityPane::new(), &vec![no_route(); 5], 100, 20);
        let compact = render_cycles(&ConnectivityPane::new(), &vec![no_route(); 5], 100, 6);
        for (mode, out) in [("full", &full), ("compact", &compact)] {
            assert!(out.contains("no IPv6 route on this host"), "{mode}:\n{out}");
            assert!(!out.contains("v6 ---"), "{mode}:\n{out}");
        }
    }

    #[test]
    fn mixed_samples_keep_the_scale() {
        let pane = ConnectivityPane::new();
        let mut failed = failed_ping_with(PingFailure::NoReply);
        failed.ipv4_status = PingStatus::Failed(PingFailure::NoReply);
        let pings = vec![ok_ping(10, 10), failed, ok_ping(10, 10)];
        let out = render_cycles(&pane, &pings, 100, 20);
        assert!(out.contains("scale 0-"), "{out}");
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
            out = tick(&pane, &state_with_ping(ping()), 100, 20);
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
            out = tick(&pane, &state, 100, 20);
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
            out = tick(&pane, &state_with_ping(failed_ping("x")), 100, 20);
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
            tick(&pane, &state_with_ping(ok(sample)), 100, 20);
        }
        let state = state_with_ping(ok(5));
        if let Some(mut ping_state) = state.scanners.get_mut("ping") {
            ping_state.status = ScanStatus::Failed;
            ping_state.error = Some(eyre::eyre!("timed out after 30s"));
        }
        let out = tick(&pane, &state, 100, 20);
        assert!(out.contains("dual-stack"), "smoothed label dropped:\n{out}");
        assert!(
            out.contains("failed: timed out after 30s"),
            "failed refresh hidden:\n{out}"
        );
    }

    #[test]
    fn long_failure_reason_is_fit_to_the_status_row_in_narrow_terminals() {
        let reason = "timed out after 30s waiting for an echo reply from a-very-long-host-name.example.com over IPv4";
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            "ping".to_string(),
            ScanState {
                result: None,
                error: Some(eyre::eyre!(reason)),
                status: ScanStatus::Failed,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        crate::tui::testing::assert_clipped_in_narrow_terminals(
            &ConnectivityPane::new(),
            &state,
            0,
            1,
            &format!("🌐 Status: failed: {reason}"),
        );
    }

    fn no_address_ping(family: Family) -> PingResult {
        let mut ping = ok_ping(12, 14);
        match family {
            Family::Ipv4 => ping.ipv4_status = PingStatus::NoAddress,
            Family::Ipv6 => ping.ipv6_status = PingStatus::NoAddress,
        }
        ping
    }

    /// Five cycles in `pane`, then the final frame as a styled buffer.
    fn five_cycles_buffer(pings: &[PingResult], width: u16, height: u16) -> ratatui::buffer::Buffer {
        let pane = ConnectivityPane::new();
        let states = states_for(pings, Protocol::Both);
        for state in &states {
            pane.ingest(state);
        }
        crate::tui::testing::render_buffer(&pane, states.last().unwrap(), width, height, false)
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn five_no_aaaa_cycles_read_no_ipv6_address_muted_and_status_ipv4() {
        use crate::tui::testing::fg_of;
        let pings = vec![no_address_ping(Family::Ipv6); 5];
        for (mode, height) in [("full", 20), ("compact", 6)] {
            let buffer = five_cycles_buffer(&pings, 100, height);
            let out = buffer_text(&buffer);
            assert!(out.contains("no IPv6 address"), "{mode}:\n{out}");
            assert_eq!(fg_of(&buffer, "no IPv6 address"), Color::Gray, "{mode}: not MUTED");
            assert!(out.contains("Status: ipv4 "), "{mode}:\n{out}");
            assert_eq!(fg_of(&buffer, "ipv4 "), Color::Green, "{mode}: status not GOOD");
            for wrong in ["no ping reply", "ipv4 only", "no echo reply"] {
                assert!(!out.contains(wrong), "{mode}: shows `{wrong}`:\n{out}");
            }
        }
    }

    #[test]
    fn five_no_a_cycles_read_no_ipv4_address_and_status_ipv6() {
        let buffer = five_cycles_buffer(&vec![no_address_ping(Family::Ipv4); 5], 100, 20);
        let out = buffer_text(&buffer);
        assert!(out.contains("no IPv4 address"), "{out}");
        assert!(out.contains("Status: ipv6 "), "{out}");
        assert!(!out.contains("ipv6 only"), "{out}");
    }

    #[test]
    fn no_address_never_makes_the_status_a_warning() {
        use ConnectivityState::*;
        assert_eq!(overall_status(&Connected, &NoAddress), ("ipv4", Color::Green));
        assert_eq!(overall_status(&NoAddress, &Connected), ("ipv6", Color::Green));
        assert_eq!(overall_status(&Connected, &Disabled), ("ipv4", Color::Green));
        assert_eq!(overall_status(&Disconnected, &NoAddress), ("no ping reply", Color::Red));
        assert_eq!(overall_status(&Checking, &NoAddress).1, Color::Gray);
        assert_eq!(overall_status(&Connected, &Disconnected), ("ipv4 only", Color::Yellow));
    }

    /// Rows of the IPv6 graph in a full-mode render: those after the `IPv6` title row.
    fn rows_after<'a>(out: &'a str, title: &str) -> Vec<&'a str> {
        out.lines().skip_while(|row| !row.contains(title)).skip(1).collect()
    }

    #[test]
    fn disabling_a_family_clears_its_samples_and_draws_no_bars() {
        use crate::tui::testing::{fg_of, render_buffer};
        let pane = ConnectivityPane::new();
        let states = states_for(&vec![ok_ping(12, 14); 5], Protocol::Both);
        for state in &states {
            pane.ingest(state);
        }
        assert_eq!(pane.sample_counts(), (5, 5));

        // `p`: IPv4 only. The next ping result has no IPv6 status.
        let mut v4_only = ok_ping(12, 14);
        v4_only.ipv6_status = PingStatus::NotQueried;
        let mut next = states_for(&vec![v4_only; 6], Protocol::Ipv4);
        let state = next.pop().unwrap();
        pane.ingest(&state);
        assert_eq!(pane.sample_counts(), (6, 0), "IPv6 samples kept after disabling it");

        let buffer = render_buffer(&pane, &state, 100, 20, false);
        let out = buffer_text(&buffer);
        assert!(out.contains("IPv6 disabled (p)"), "{out}");
        assert_eq!(fg_of(&buffer, "disabled (p)"), Color::Gray, "not MUTED");
        assert!(
            rows_after(&out, "IPv6 disabled").iter().all(|row| !has_bar_glyph(row)),
            "disabled family drew bars:\n{out}"
        );
        assert!(has_bar_glyph(&out), "IPv4 lost its bars:\n{out}");
        assert!(out.contains("Status: ipv4 "), "{out}");

        let compact = render_pane(&pane, &state, 56, 6, false);
        assert!(compact.contains("v6 disabled (p)"), "{compact}");
        assert!(!has_bar_glyph(row_containing(&compact, "v6 disabled")), "{compact}");

        // `p` twice more: back to both families, IPv6 starts over.
        let mut both = state_with_ping(ok_ping(12, 14));
        both.protocol = Protocol::Both;
        pane.ingest(&both);
        let out = render_pane(&pane, &both, 100, 20, false);
        assert!(!out.contains("disabled"), "{out}");
    }

    #[test]
    fn full_mode_title_is_intact_at_200x55() {
        let pane = ConnectivityPane::new();
        let pings: Vec<PingResult> = (0..5).map(|_| ok_ping(12, 15)).collect();
        let (width, height) = crate::tui::testing::dashboard_pane_size(0, 1, 200, 55);
        let out = render_cycles(&pane, &pings, width, height);
        assert!(out.contains("scale 0-"), "title lost its scale:\n{out}");
        assert!(!out.contains('…'), "title clipped at 200 columns:\n{out}");
    }

    #[test]
    fn zoomed_render_adds_loss_and_jitter_over_every_sample() {
        let pane = ConnectivityPane::new();
        let start = Instant::now();
        // Four cycles: 10ms, 14ms, a failure, 12ms. Loss 25%; jitter |14-10| = 4ms.
        let statuses = [
            PingStatus::Success(Duration::from_millis(10)),
            PingStatus::Success(Duration::from_millis(14)),
            PingStatus::Failed(PingFailure::NoReply),
            PingStatus::Success(Duration::from_millis(12)),
        ];
        let mut state = AppState::new("example.com".to_string());
        for (n, status) in statuses.into_iter().enumerate() {
            let mut ping = PingResult::new();
            ping.ipv4_status = status;
            ping.ipv6_status = PingStatus::NoAddress;
            ping.queried_at = start + Duration::from_secs(n as u64);
            state = state_with_ping(ping);
            pane.ingest(&state);
        }
        let draw = |detail: Detail| {
            let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 30)).expect("terminal");
            terminal
                .draw(|frame| pane.render_detail(frame, frame.area(), &state, true, detail))
                .expect("draw");
            let buffer = terminal.backend().buffer().clone();
            (0..30)
                .map(|y| {
                    (0..120)
                        .map(|x| buffer[(x, y)].symbol().to_string())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let zoomed = draw(Detail::Zoomed);
        assert!(zoomed.contains("loss 25% · jitter 4ms"), "{zoomed}");
        // IPv6 has no address, so no samples: nothing to measure.
        assert!(zoomed.contains("loss --- · jitter ---"), "{zoomed}");
        let normal = draw(Detail::Normal);
        assert!(!normal.contains("loss"), "{normal}");
    }
}
