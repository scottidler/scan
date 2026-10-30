use crate::tui::pane::{Detail, Pane, PaneConfig, create_block, draw_rows};
use crate::tui::theme;
use crate::types::AppState;
use crossterm::event::{KeyCode, KeyEvent};
use log;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::Line,
    widgets::{Paragraph, Widget},
};
use std::collections::HashMap;

const DEFAULT_GRID_ROWS: usize = 3;
const DEFAULT_GRID_COLS: usize = 4;
const TOP_ROW_HEIGHT_PERCENT: u16 = 25;
const MIDDLE_ROW_HEIGHT_PERCENT: u16 = 35;
const BOTTOM_ROW_HEIGHT_PERCENT: u16 = 40;
const SCROLL_STEP: u16 = 1;
/// Rows under the zoomed pane for the key footer.
const ZOOM_FOOTER_ROWS: u16 = 1;
/// The keys that act while a pane is zoomed.
pub const ZOOM_FOOTER: &str = "Esc back · ←/→ pane · ↑/↓ scroll";
// Row 0 widths (2 columns)
const TARGET_PANE_WIDTH_PERCENT: u16 = 30;
const CONNECTIVITY_PANE_WIDTH_PERCENT: u16 = 70;

// Row 1 widths (4 columns - 25% each)
const WHOIS_PANE_WIDTH_PERCENT: u16 = 25;
const HTTP_PANE_WIDTH_PERCENT: u16 = 25;
const PORTS_PANE_WIDTH_PERCENT: u16 = 25;
const GEOIP_PANE_WIDTH_PERCENT: u16 = 25;

// Row 2 widths (3 columns)
const DNS_PANE_WIDTH_PERCENT: u16 = 33;
const TRACEROUTE_PANE_WIDTH_PERCENT: u16 = 33;
const SECURITY_PANE_WIDTH_PERCENT: u16 = 34;

// Fallback equal widths
const EQUAL_COLUMN_WIDTH_PERCENT_FIRST: u16 = 33;
const EQUAL_COLUMN_WIDTH_PERCENT_SECOND: u16 = 33;
const EQUAL_COLUMN_WIDTH_PERCENT_THIRD: u16 = 34;

/// Manages the layout and rendering of TUI panes in a grid
pub struct PaneLayout {
    panes: Vec<Box<dyn Pane>>,
    config: HashMap<String, PaneConfig>,
    focused_pane: Option<String>,
    grid_rows: usize,
    grid_cols: usize,
    /// First row shown per pane and detail, clamped against the pane's rows on every render.
    scroll: HashMap<(&'static str, Detail), u16>,
    /// The frame area last rendered, so key handling sizes panes exactly as they were drawn.
    area: Rect,
    /// The focused pane fills the frame at `Detail::Zoomed` instead of the grid being drawn.
    zoomed: bool,
}

impl PaneLayout {
    /// Create a new pane layout with the specified grid dimensions
    pub fn new(grid_rows: usize, grid_cols: usize) -> Self {
        log::debug!("[tui::layout] new: grid_rows={} grid_cols={}", grid_rows, grid_cols);
        Self {
            panes: Vec::new(),
            config: HashMap::new(),
            focused_pane: None,
            grid_rows,
            grid_cols,
            scroll: HashMap::new(),
            area: Rect::default(),
            zoomed: false,
        }
    }

    /// Create the default 3x3 layout for our dashboard
    pub fn default_dashboard() -> Self {
        log::debug!("[tui::layout] default_dashboard: creating 3x3 layout");
        Self::new(DEFAULT_GRID_ROWS, DEFAULT_GRID_COLS)
    }

    /// Add a pane to the layout with its configuration
    pub fn add_pane(&mut self, pane: Box<dyn Pane>, config: PaneConfig) {
        let pane_id = pane.id().to_string();
        log::debug!(
            "[tui::layout] add_pane: pane_id={} position=({},{}) visible={}",
            pane_id,
            config.position.row,
            config.position.col,
            config.visible
        );

        self.config.insert(pane_id, config);
        self.panes.push(pane);

        log::trace!("[tui::layout] pane_added: total_panes={}", self.panes.len());
    }

    /// Set the focused pane by ID. While zoomed, the zoom moves to that pane, starting at its
    /// first row.
    pub fn set_focus(&mut self, pane_id: Option<String>) {
        log::debug!(
            "[tui::layout] set_focus: old_focus={:?} new_focus={:?} zoomed={}",
            self.focused_pane,
            pane_id,
            self.zoomed
        );
        self.focused_pane = pane_id;
        if self.zoomed {
            self.reset_zoom_offset();
        }
    }

    /// Whether the focused pane is drawn zoomed to the full frame.
    pub fn is_zoomed(&self) -> bool {
        self.zoomed
    }

    /// Zoom the focused pane to the full frame, from its first row. Returns false, and stays in
    /// the grid, when no pane has focus.
    pub fn zoom(&mut self) -> bool {
        if self.focused_pane.is_none() {
            log::debug!("[tui::layout] zoom_ignored: no focused pane");
            return false;
        }
        self.zoomed = true;
        self.reset_zoom_offset();
        log::debug!("[tui::layout] zoomed: pane={:?}", self.focused_pane);
        true
    }

    /// Return to the grid. Grid scroll offsets are untouched by zoom.
    pub fn unzoom(&mut self) {
        log::debug!("[tui::layout] unzoomed: pane={:?}", self.focused_pane);
        self.zoomed = false;
    }

    /// Forget the focused pane's zoomed offset, so its zoom starts at row 0.
    fn reset_zoom_offset(&mut self) {
        if let Some(focused) = self.focused_pane.as_deref() {
            self.scroll
                .retain(|(id, detail), _| !(*id == focused && *detail == Detail::Zoomed));
        }
    }

    /// Get the currently focused pane ID
    pub fn focused_pane(&self) -> Option<&String> {
        self.focused_pane.as_ref()
    }

    /// Let every pane take in new scanner data, whether or not it is drawn this frame.
    pub fn ingest(&self, state: &AppState) {
        log::trace!("[tui::layout] ingest: panes={}", self.panes.len());
        for pane in &self.panes {
            pane.ingest(state);
        }
    }

    /// The pane with `id`, for tests that inspect a pane's own state.
    #[cfg(test)]
    pub(crate) fn pane_mut(&mut self, id: &str) -> Option<&mut dyn Pane> {
        match self.panes.iter_mut().find(|pane| pane.id() == id) {
            Some(pane) => Some(pane.as_mut()),
            None => None,
        }
    }

    /// The detail panes are drawn at: Zoomed while a pane fills the frame, Normal in the grid.
    fn detail(&self) -> Detail {
        if self.zoomed { Detail::Zoomed } else { Detail::Normal }
    }

    /// The first row shown for `pane_id` at `detail`.
    pub fn scroll_offset(&self, pane_id: &str, detail: Detail) -> u16 {
        self.scroll
            .iter()
            .find(|((id, d), _)| *id == pane_id && *d == detail)
            .map(|(_, offset)| *offset)
            .unwrap_or(0)
    }

    /// Render all panes in the layout. Each scrolling pane is drawn at its kept offset, and the
    /// offset clamped against its rows this frame is kept, so a resize or shorter content
    /// re-clamps.
    pub fn render(&mut self, frame: &mut Frame, area: Rect, state: &AppState) {
        log::trace!(
            "[tui::layout] render: area={}x{} panes={} focused={:?}",
            area.width,
            area.height,
            self.panes.len(),
            self.focused_pane
        );
        self.area = area;
        if self.zoomed {
            if self.render_zoomed(frame, area, state) {
                return;
            }
            log::warn!(
                "[tui::layout] zoom_dropped: focused pane {:?} cannot be drawn",
                self.focused_pane
            );
            self.zoomed = false;
        }
        let detail = self.detail();

        let mut rendered_count = 0;
        let mut skipped_count = 0;

        for pane in &self.panes {
            let pane_id = pane.id();
            let Some(config) = self.config.get(pane_id) else {
                skipped_count += 1;
                log::warn!("[tui::layout] pane_config_not_found: pane_id={}", pane_id);
                continue;
            };
            if !config.visible || !pane.is_visible() {
                skipped_count += 1;
                log::trace!(
                    "[tui::layout] pane_skipped: pane_id={} config_visible={} pane_visible={}",
                    pane_id,
                    config.visible,
                    pane.is_visible()
                );
                continue;
            }
            let Some(pane_area) = pane_rect(self.grid_rows, self.grid_cols, config, area) else {
                skipped_count += 1;
                log::warn!(
                    "[tui::layout] pane_area_not_found: pane_id={} position=({},{})",
                    pane_id,
                    config.position.row,
                    config.position.col
                );
                continue;
            };
            let is_focused = self.focused_pane.as_deref() == Some(pane_id);
            log::trace!(
                "[tui::layout] rendering_pane: pane_id={} area={}x{} focused={}",
                pane_id,
                pane_area.width,
                pane_area.height,
                is_focused
            );
            draw_pane(
                pane.as_ref(),
                &mut self.scroll,
                frame,
                pane_area,
                state,
                is_focused,
                detail,
            );
            rendered_count += 1;
        }

        log::trace!(
            "[tui::layout] render_completed: rendered={} skipped={}",
            rendered_count,
            skipped_count
        );
    }

    /// Draw only the focused pane, zoomed over the frame above the key footer. Returns false when
    /// there is no focused pane to draw.
    fn render_zoomed(&mut self, frame: &mut Frame, area: Rect, state: &AppState) -> bool {
        let Some(focused) = self.focused_pane.as_deref() else {
            return false;
        };
        let Some(pane) = self.panes.iter().find(|pane| pane.id() == focused) else {
            return false;
        };
        let pane_area = zoom_rect(area);
        log::trace!(
            "[tui::layout] rendering_zoomed: pane_id={} area={}x{}",
            focused,
            pane_area.width,
            pane_area.height
        );
        draw_pane(
            pane.as_ref(),
            &mut self.scroll,
            frame,
            pane_area,
            state,
            true,
            Detail::Zoomed,
        );
        if let Some(footer) = footer_rect(area) {
            Paragraph::new(crate::tui::text::fit_line(
                // MUTED: Gray until the theme lands (Phase 2).
                Line::styled(ZOOM_FOOTER, Style::default().fg(theme::MUTED)),
                footer.width,
            ))
            .render(footer, frame.buffer_mut());
        }
        true
    }

    /// The rect of `pane_id` when the frame is `area`, as `render` places it: the zoom rect for the
    /// zoomed pane, nothing for the others while zoomed, its grid cell otherwise.
    fn rect_of(&self, pane_id: &str, area: Rect) -> Option<Rect> {
        if self.zoomed {
            return (self.focused_pane.as_deref() == Some(pane_id)).then(|| zoom_rect(area));
        }
        let config = self.config.get(pane_id)?;
        pane_rect(self.grid_rows, self.grid_cols, config, area)
    }

    /// The rect of `pane_id` when the frame is `area`, as `render` places it.
    pub fn pane_area(&self, pane_id: &str, area: Rect) -> Option<Rect> {
        self.rect_of(pane_id, area)
    }

    /// Get all pane IDs in the layout
    pub fn pane_ids(&self) -> Vec<String> {
        self.panes.iter().map(|p| p.id().to_string()).collect()
    }

    /// Get pane configuration by ID
    pub fn get_config(&self, pane_id: &str) -> Option<&PaneConfig> {
        self.config.get(pane_id)
    }

    /// Update pane configuration
    pub fn update_config(&mut self, pane_id: String, config: PaneConfig) {
        self.config.insert(pane_id, config);
    }

    /// Toggle pane visibility
    pub fn toggle_pane_visibility(&mut self, pane_id: &str) {
        if let Some(config) = self.config.get_mut(pane_id) {
            let old_visible = config.visible;
            config.visible = !config.visible;
            log::debug!(
                "[tui::layout] toggle_pane_visibility: pane_id={} old={} new={}",
                pane_id,
                old_visible,
                config.visible
            );
        } else {
            log::warn!("[tui::layout] toggle_visibility_failed: pane_id={} not_found", pane_id);
        }
    }

    /// Get the next focusable pane ID
    pub fn next_focusable_pane(&self, current: Option<&str>) -> Option<String> {
        let focusable_panes: Vec<_> = self
            .panes
            .iter()
            .filter(|p| p.is_focusable())
            .map(|p| p.id().to_string())
            .collect();

        log::trace!(
            "[tui::layout] next_focusable_pane: current={:?} focusable_count={}",
            current,
            focusable_panes.len()
        );

        if focusable_panes.is_empty() {
            log::debug!("[tui::layout] no_focusable_panes:");
            return None;
        }

        let next_pane = match current {
            None => Some(focusable_panes[0].clone()),
            Some(current_id) => {
                if let Some(current_index) = focusable_panes.iter().position(|id| id == current_id) {
                    let next_index = (current_index + 1) % focusable_panes.len();
                    Some(focusable_panes[next_index].clone())
                } else {
                    Some(focusable_panes[0].clone())
                }
            }
        };

        log::debug!(
            "[tui::layout] next_focusable_result: current={:?} next={:?}",
            current,
            next_pane
        );
        next_pane
    }

    /// Get the previous focusable pane ID
    pub fn prev_focusable_pane(&self, current: Option<&str>) -> Option<String> {
        let focusable_panes: Vec<_> = self
            .panes
            .iter()
            .filter(|p| p.is_focusable())
            .map(|p| p.id().to_string())
            .collect();

        if focusable_panes.is_empty() {
            return None;
        }

        match current {
            None => Some(focusable_panes[focusable_panes.len() - 1].clone()),
            Some(current_id) => {
                if let Some(current_index) = focusable_panes.iter().position(|id| id == current_id) {
                    let prev_index = if current_index == 0 { focusable_panes.len() - 1 } else { current_index - 1 };
                    Some(focusable_panes[prev_index].clone())
                } else {
                    Some(focusable_panes[focusable_panes.len() - 1].clone())
                }
            }
        }
    }

    /// Scroll the focused pane on Up/k, Down/j or Home. The pane is sized by the same rect
    /// function `render` uses, against the last rendered frame area, and the new offset is clamped
    /// against its rows. Returns whether the key was handled.
    pub fn handle_key_event(&mut self, key: KeyEvent, state: &AppState) -> bool {
        log::debug!(
            "[tui::layout] handle_key_event: focused_pane={:?} key={:?}",
            self.focused_pane,
            key.code
        );
        let Some(focused_id) = self.focused_pane.as_deref() else {
            log::trace!("[tui::layout] key_event_no_focused_pane: key={:?}", key.code);
            return false;
        };
        let Some(pane) = self.panes.iter().find(|pane| pane.id() == focused_id) else {
            log::warn!("[tui::layout] focused_pane_not_found: pane_id={}", focused_id);
            return false;
        };
        if !pane.scrolls() {
            log::trace!("[tui::layout] pane_does_not_scroll: pane={}", focused_id);
            return false;
        }
        let Some(rect) = self.rect_of(focused_id, self.area) else {
            log::warn!("[tui::layout] focused_pane_has_no_rect: pane_id={}", focused_id);
            return false;
        };
        let detail = self.detail();
        let pane_id = pane.id();
        let inner = create_block(pane.title(), false).inner(rect);
        let total = pane.content(state, inner.width, detail).len();
        let current = self.scroll_offset(pane_id, detail);
        let at = |offset: u16| crate::tui::pane::RowView::new(total, inner.height, offset).offset;
        let new_offset = match key.code {
            KeyCode::Up | KeyCode::Char('k') => at(current).saturating_sub(SCROLL_STEP),
            KeyCode::Down | KeyCode::Char('j') => at(at(current).saturating_add(SCROLL_STEP)),
            KeyCode::Home => 0,
            _ => {
                log::trace!(
                    "[tui::layout] unhandled_key_in_pane: pane={} key={:?}",
                    focused_id,
                    key.code
                );
                return false;
            }
        };
        log::debug!(
            "[tui::layout] pane_scroll: pane={} key={:?} rows={} visible={} old_offset={} new_offset={}",
            pane_id,
            key.code,
            total,
            inner.height,
            current,
            new_offset
        );
        self.scroll.insert((pane_id, detail), new_offset);
        true
    }
}

/// Draw `pane` at `rect` for `detail`. A scrolling pane is drawn at its kept offset and the offset
/// clamped against its rows this frame is kept, so a resize or shorter content re-clamps.
fn draw_pane(
    pane: &dyn Pane,
    scroll: &mut HashMap<(&'static str, Detail), u16>,
    frame: &mut Frame,
    rect: Rect,
    state: &AppState,
    focused: bool,
    detail: Detail,
) {
    if !pane.scrolls() {
        pane.render_detail(frame, rect, state, focused, detail);
        return;
    }
    let key = (pane.id(), detail);
    let offset = scroll.get(&key).copied().unwrap_or(0);
    let clamped = draw_rows(pane, frame, rect, state, focused, detail, offset);
    if clamped != offset {
        log::debug!(
            "[tui::layout] scroll_clamped: pane={} detail={:?} offset={} clamped={}",
            key.0,
            detail,
            offset,
            clamped
        );
    }
    scroll.insert(key, clamped);
}

/// The zoomed pane's rect: the whole frame but the key footer.
fn zoom_rect(area: Rect) -> Rect {
    Rect {
        height: area.height.saturating_sub(ZOOM_FOOTER_ROWS),
        ..area
    }
}

/// The key footer's row under the zoomed pane, or `None` when the frame has no room for it.
fn footer_rect(area: Rect) -> Option<Rect> {
    (area.height > ZOOM_FOOTER_ROWS).then(|| Rect {
        y: area.y + area.height - ZOOM_FOOTER_ROWS,
        height: ZOOM_FOOTER_ROWS,
        ..area
    })
}

/// The dashboard grid over `area`: one rect per cell, row by row, with custom proportions.
pub(crate) fn grid_layout(area: Rect) -> Vec<Vec<Rect>> {
    // Create custom row constraints for better space allocation
    // Row 0: Smaller for summary info (target, connectivity)
    // Row 1: Medium for WHOIS, HTTP, Ports, GeoIP
    // Row 2: Larger for detailed info (DNS, traceroute, security)
    let row_constraints = vec![
        Constraint::Percentage(TOP_ROW_HEIGHT_PERCENT),
        Constraint::Percentage(MIDDLE_ROW_HEIGHT_PERCENT),
        Constraint::Percentage(BOTTOM_ROW_HEIGHT_PERCENT),
    ];

    // Split into rows
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(area);

    // Split each row into columns with custom proportions
    let mut grid_areas = Vec::new();

    for (row_idx, row_area) in rows.iter().enumerate() {
        let col_constraints = match row_idx {
            0 => vec![
                Constraint::Percentage(TARGET_PANE_WIDTH_PERCENT),
                Constraint::Percentage(CONNECTIVITY_PANE_WIDTH_PERCENT),
            ],
            1 => vec![
                Constraint::Percentage(WHOIS_PANE_WIDTH_PERCENT),
                Constraint::Percentage(HTTP_PANE_WIDTH_PERCENT),
                Constraint::Percentage(PORTS_PANE_WIDTH_PERCENT),
                Constraint::Percentage(GEOIP_PANE_WIDTH_PERCENT),
            ],
            2 => vec![
                Constraint::Percentage(DNS_PANE_WIDTH_PERCENT),
                Constraint::Percentage(TRACEROUTE_PANE_WIDTH_PERCENT),
                Constraint::Percentage(SECURITY_PANE_WIDTH_PERCENT),
            ],
            _ => vec![
                Constraint::Percentage(EQUAL_COLUMN_WIDTH_PERCENT_FIRST),
                Constraint::Percentage(EQUAL_COLUMN_WIDTH_PERCENT_SECOND),
                Constraint::Percentage(EQUAL_COLUMN_WIDTH_PERCENT_THIRD),
            ],
        };

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(*row_area);

        grid_areas.push(cols.iter().copied().collect());
    }

    grid_areas
}

/// The rect of the pane placed by `config` in a `grid_rows` x `grid_cols` dashboard over `area`,
/// or `None` when its position is outside the grid. The one rect function for render and keys.
fn pane_rect(grid_rows: usize, grid_cols: usize, config: &PaneConfig, area: Rect) -> Option<Rect> {
    let row = config.position.row;
    let col = config.position.col;
    if row >= grid_rows || col >= grid_cols {
        return None;
    }
    grid_layout(area).get(row)?.get(col).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::target::TargetPane;

    #[test]
    fn test_layout_creation() {
        let layout = PaneLayout::default_dashboard();
        assert_eq!(layout.grid_rows, DEFAULT_GRID_ROWS);
        assert_eq!(layout.grid_cols, DEFAULT_GRID_COLS);
        assert!(layout.panes.is_empty());
        assert!(layout.focused_pane.is_none());
    }

    #[test]
    fn test_add_pane() {
        let mut layout = PaneLayout::default_dashboard();
        let pane = Box::new(TargetPane::new());
        let config = PaneConfig::new(0, 0);

        layout.add_pane(pane, config);
        assert_eq!(layout.panes.len(), 1);
        assert!(layout.config.contains_key("target"));
    }

    #[test]
    fn test_focus_management() {
        let mut layout = PaneLayout::default_dashboard();

        // Initially no focus
        assert!(layout.focused_pane().is_none());

        // Set focus
        layout.set_focus(Some("target".to_string()));
        assert_eq!(layout.focused_pane(), Some(&"target".to_string()));

        // Clear focus
        layout.set_focus(None);
        assert!(layout.focused_pane().is_none());
    }

    #[test]
    fn test_pane_visibility_toggle() {
        let mut layout = PaneLayout::default_dashboard();
        let pane = Box::new(TargetPane::new());
        let config = PaneConfig::new(0, 0);

        layout.add_pane(pane, config);

        // Initially visible
        assert!(layout.get_config("target").unwrap().visible);

        // Toggle visibility
        layout.toggle_pane_visibility("target");
        assert!(!layout.get_config("target").unwrap().visible);

        // Toggle back
        layout.toggle_pane_visibility("target");
        assert!(layout.get_config("target").unwrap().visible);
    }

    use crate::scan::dns::{DnsRecord, DnsResult, QueryStatus};
    use crate::scan::tls::{SecurityGrade, TlsData, TlsResult, TlsStatus, TlsVersion};
    use crate::scan::traceroute::{HopResponse, TracerouteData, TracerouteHop, TracerouteResult, TracerouteStatus};
    use crate::scan::whois::{DataSource, NotApplicableReason, WhoisResult};
    use crate::types::{ScanResult, ScanState, ScanStatus};
    use crossterm::event::KeyModifiers;
    use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
    use std::time::{Duration, Instant};

    /// Every pane the layout scrolls: all but Connectivity, which draws sparklines.
    const SCROLLING_PANES: [&str; 8] = [
        "target",
        "whois",
        "http",
        "ports",
        "geoip",
        "dns",
        "traceroute",
        "security",
    ];
    const LONG_FAILURE: &str = "connect to 2606:4700:4700::1111 failed: network is unreachable (os error 101)";

    fn scan_state(result: Option<ScanResult>, error: Option<&str>, status: ScanStatus) -> ScanState {
        ScanState {
            result,
            error: error.map(|e| eyre::eyre!(e.to_string())),
            status,
            last_updated: Instant::now(),
            history: Default::default(),
        }
    }

    /// WHOIS shaped like web.dev, with a suffix-list failure on the Domain row, which wraps.
    fn whois_fixture() -> WhoisResult {
        let mut result = WhoisResult::not_applicable("web.dev".to_string(), NotApplicableReason::IpTarget);
        result.data_source = DataSource::Rdap;
        result.suffix_list_error = Some("public suffix list fetch failed: connection refused by peer".to_string());
        result.nameservers = (1..=4).map(|n| format!("ns{n}.zdns.google")).collect();
        result.status = vec![
            "client transfer prohibited".to_string(),
            "server delete prohibited".to_string(),
        ];
        result
    }

    fn dns_fixture(records: u8) -> DnsResult {
        let mut dns = DnsResult::new();
        for n in 0..records {
            dns.A
                .push(DnsRecord::new(format!("192.0.2.{n}").parse().expect("ip"), 300));
        }
        dns.A_status = QueryStatus::Success(usize::from(records));
        dns
    }

    fn traceroute_fixture(hops: u8) -> TracerouteResult {
        let ip: std::net::IpAddr = "192.0.2.1".parse().expect("ip");
        let data = TracerouteData {
            hops: (1..=hops)
                .map(|hop_number| TracerouteHop {
                    hop_number,
                    responses: vec![HopResponse {
                        ip_address: Some(ip),
                        rtt: Some(Duration::from_millis(5)),
                        timeout: false,
                    }],
                    best_rtt: None,
                    avg_rtt: None,
                    worst_rtt: None,
                    packet_loss: 0.0,
                })
                .collect(),
            destination_reached: true,
            total_hops: hops,
            max_hops: 30,
            target_ip: ip,
            scan_duration: Duration::from_millis(100),
            ipv6: false,
        };
        let mut result = TracerouteResult::new();
        result.ipv4_status = TracerouteStatus::Success(hops);
        result.ipv4_result = Some(data);
        result
    }

    fn tls_fixture() -> TlsResult {
        let mut result = TlsResult::new();
        result.ipv4_result = Some(TlsData {
            connection_successful: true,
            handshake_time: Duration::from_millis(100),
            supported_versions: vec![TlsVersion::V1_3],
            negotiated_version: Some(TlsVersion::V1_3),
            certificate_chain: vec![],
            certificate_valid: true,
            certificate_errors: vec![],
            expiry_date: None,
            days_until_expiry: Some(90),
            supported_ciphers: vec![],
            negotiated_cipher: None,
            perfect_forward_secrecy: true,
            ocsp_stapling: true,
            vulnerabilities: vec![],
            security_grade: SecurityGrade::A,
            scan_time: Duration::from_millis(500),
            target_ip: "192.0.2.1".to_string(),
            queried_at: Instant::now(),
        });
        result.ipv4_status = TlsStatus::Success(SecurityGrade::A);
        result
    }

    /// A state in which every scrolling pane has more rows than its dashboard cell at 80x24.
    fn overflowing_state() -> AppState {
        let state = AppState::new("web.dev".to_string());
        let insert = |key: &str, scan: ScanState| {
            state.scanners.insert(key.to_string(), scan);
        };
        insert("ping", scan_state(None, None, ScanStatus::Running));
        insert(
            "dns",
            scan_state(Some(ScanResult::Dns(dns_fixture(12))), None, ScanStatus::Complete),
        );
        insert(
            "tls",
            scan_state(Some(ScanResult::Tls(tls_fixture())), None, ScanStatus::Complete),
        );
        insert(
            "whois",
            scan_state(Some(ScanResult::Whois(whois_fixture())), None, ScanStatus::Complete),
        );
        insert(
            "traceroute",
            scan_state(
                Some(ScanResult::Traceroute(traceroute_fixture(12))),
                None,
                ScanStatus::Complete,
            ),
        );
        for key in ["http", "geoip", "port"] {
            insert(key, scan_state(None, Some(LONG_FAILURE), ScanStatus::Failed));
        }
        state
    }

    fn draw(layout: &mut PaneLayout, state: &AppState, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| layout.render(frame, frame.area(), state))
            .expect("draw");
        terminal.backend().buffer().clone()
    }

    fn row_text(buffer: &Buffer, y: u16, x: u16, width: u16) -> String {
        let mut text = String::new();
        let mut col = x;
        while col < x + width {
            let symbol = buffer[(col, y)].symbol();
            text.push_str(symbol);
            col += ratatui::text::Span::raw(symbol).width().max(1) as u16;
        }
        text
    }

    fn bottom_border(buffer: &Buffer, rect: Rect) -> String {
        row_text(buffer, rect.y + rect.height - 1, rect.x, rect.width)
    }

    /// The text of the rows drawn inside `rect`'s border.
    fn shown_rows(buffer: &Buffer, rect: Rect) -> Vec<String> {
        (rect.y + 1..rect.y + rect.height - 1)
            .map(|y| row_text(buffer, y, rect.x + 1, rect.width - 2))
            .collect()
    }

    fn pane<'a>(layout: &'a PaneLayout, id: &str) -> &'a dyn Pane {
        layout.panes.iter().find(|p| p.id() == id).expect("pane").as_ref()
    }

    /// The pane's rows laid out for its cell when the frame is `area`.
    fn built_rows(layout: &PaneLayout, id: &str, state: &AppState, area: Rect) -> Vec<String> {
        let rect = layout.pane_area(id, area).expect("rect");
        pane(layout, id)
            .content(state, rect.width - 2, Detail::Normal)
            .iter()
            .map(|line| line.spans.iter().map(|span| span.content.as_ref()).collect())
            .collect()
    }

    fn press(layout: &mut PaneLayout, state: &AppState, code: KeyCode) -> bool {
        layout.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE), state)
    }

    fn focused_layout(id: &str) -> PaneLayout {
        let mut layout = crate::tui::create_default_layout();
        layout.set_focus(Some(id.to_string()));
        layout
    }

    #[test]
    fn every_scrolling_pane_marks_the_rows_it_does_not_show() {
        let state = overflowing_state();
        let area = Rect::new(0, 0, 80, 24);
        for id in SCROLLING_PANES {
            let mut layout = focused_layout(id);
            let rect = layout.pane_area(id, area).expect("rect");
            let rows = built_rows(&layout, id, &state, area).len();
            let visible = usize::from(rect.height - 2);
            assert!(rows > visible, "{id}: fixture fits its cell ({rows} rows in {visible})");
            let hidden = rows - visible;

            let buffer = draw(&mut layout, &state, 80, 24);
            let border = bottom_border(&buffer, rect);
            assert!(border.contains(&format!("↓ {hidden} more")), "{id}: `{border}`");

            // N is what is really hidden: N presses of Down each move the view, and then the
            // marker shows nothing below.
            for step in 1..=hidden {
                let before = shown_rows(&buffer, rect);
                press(&mut layout, &state, KeyCode::Down);
                let buffer = draw(&mut layout, &state, 80, 24);
                assert_ne!(shown_rows(&buffer, rect), before, "{id}: Down {step} did not move");
                let border = bottom_border(&buffer, rect);
                assert!(border.contains(&format!("↑ {step}")), "{id}: `{border}`");
            }
            let buffer = draw(&mut layout, &state, 80, 24);
            assert!(!bottom_border(&buffer, rect).contains('↓'), "{id}: rows still below");
        }
    }

    #[test]
    fn scroll_tests_cover_every_pane_but_connectivity() {
        let layout = crate::tui::create_default_layout();
        let mut ids: Vec<String> = layout.pane_ids();
        ids.retain(|id| id != "connectivity");
        ids.sort();
        let mut covered: Vec<String> = SCROLLING_PANES.iter().map(|id| id.to_string()).collect();
        covered.sort();
        assert_eq!(ids, covered);
        for pane in &layout.panes {
            assert_eq!(pane.scrolls(), pane.id() != "connectivity", "{}", pane.id());
        }
    }

    #[test]
    fn whois_wrapped_domain_row_counts_every_row_it_takes() {
        let state = overflowing_state();
        let area = Rect::new(0, 0, 80, 24);
        let layout = focused_layout("whois");
        let rows = built_rows(&layout, "whois", &state, area);
        let domain = rows.iter().position(|r| r.contains("Domain:")).expect("domain row");
        let source = rows.iter().position(|r| r.contains("Source:")).expect("source row");
        assert!(
            source - domain >= 3,
            "domain row did not wrap over several rows: {rows:#?}"
        );
    }

    #[test]
    fn scrolling_to_the_end_reveals_the_last_built_row_in_every_scrolling_pane() {
        let state = overflowing_state();
        let area = Rect::new(0, 0, 80, 24);
        for id in SCROLLING_PANES {
            let mut layout = focused_layout(id);
            let rect = layout.pane_area(id, area).expect("rect");
            let rows = built_rows(&layout, id, &state, area);
            let last = rows.last().expect("rows").trim_end().to_string();
            draw(&mut layout, &state, 80, 24);
            for _ in 0..rows.len() {
                press(&mut layout, &state, KeyCode::Down);
            }
            let buffer = draw(&mut layout, &state, 80, 24);
            let shown = shown_rows(&buffer, rect);
            assert_eq!(
                shown.last().map(|r| r.trim_end().to_string()),
                Some(last),
                "{id}: last row not shown: {shown:#?}"
            );
        }
    }

    #[test]
    fn a_resize_or_shorter_content_reclamps_the_offset() {
        let state = overflowing_state();
        let mut layout = focused_layout("dns");
        let small = Rect::new(0, 0, 80, 24);
        let rows = built_rows(&layout, "dns", &state, small).len() as u16;
        draw(&mut layout, &state, 80, 24);
        for _ in 0..rows {
            press(&mut layout, &state, KeyCode::Down);
        }
        draw(&mut layout, &state, 80, 24);
        let small_visible = layout.pane_area("dns", small).expect("rect").height - 2;
        assert_eq!(layout.scroll_offset("dns", Detail::Normal), rows - small_visible);

        // Taller frame: fewer rows hidden, so the offset drops to the new end.
        let tall = Rect::new(0, 0, 80, 40);
        let tall_visible = layout.pane_area("dns", tall).expect("rect").height - 2;
        assert!(
            tall_visible > small_visible && tall_visible < rows,
            "fixture must still overflow"
        );
        draw(&mut layout, &state, 80, 40);
        assert_eq!(layout.scroll_offset("dns", Detail::Normal), rows - tall_visible);

        // Content shrinks to fit: the offset returns to 0.
        state.scanners.insert(
            "dns".to_string(),
            scan_state(Some(ScanResult::Dns(dns_fixture(1))), None, ScanStatus::Complete),
        );
        draw(&mut layout, &state, 80, 40);
        assert_eq!(layout.scroll_offset("dns", Detail::Normal), 0);
    }

    #[test]
    fn up_after_scrolling_to_the_end_changes_the_view_on_the_first_press() {
        let state = overflowing_state();
        let area = Rect::new(0, 0, 80, 24);
        for id in SCROLLING_PANES {
            let mut layout = focused_layout(id);
            let rect = layout.pane_area(id, area).expect("rect");
            let rows = built_rows(&layout, id, &state, area).len();
            draw(&mut layout, &state, 80, 24);
            // Overshoot: more Downs than there are rows, with no frame drawn in between.
            for _ in 0..rows + 5 {
                press(&mut layout, &state, KeyCode::Down);
            }
            let at_end = shown_rows(&draw(&mut layout, &state, 80, 24), rect);
            assert!(press(&mut layout, &state, KeyCode::Up), "{id}: Up not handled");
            let after_up = shown_rows(&draw(&mut layout, &state, 80, 24), rect);
            assert_ne!(after_up, at_end, "{id}: first Up after the end did not move the view");
        }
    }

    #[test]
    fn home_returns_to_the_first_row_and_connectivity_takes_no_scroll_keys() {
        let state = overflowing_state();
        let mut layout = focused_layout("security");
        draw(&mut layout, &state, 80, 24);
        press(&mut layout, &state, KeyCode::Down);
        press(&mut layout, &state, KeyCode::Down);
        assert_eq!(layout.scroll_offset("security", Detail::Normal), 2);
        assert!(press(&mut layout, &state, KeyCode::Home));
        assert_eq!(layout.scroll_offset("security", Detail::Normal), 0);

        let mut layout = focused_layout("connectivity");
        draw(&mut layout, &state, 80, 24);
        assert!(!press(&mut layout, &state, KeyCode::Down));
    }

    use crate::target::Protocol;
    use crate::tui::TuiApp;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;

    const PANE_TITLES: [&str; 9] = [
        "TARGET",
        "CONNECTIVITY",
        "WHOIS",
        "HTTP",
        "PORTS",
        "GEOIP",
        "DNS",
        "TRACEROUTE",
        "SECURITY",
    ];

    /// The app with `focus`, over `state`, with a protocol channel nobody listens on.
    fn app_on(focus: &str) -> (TuiApp, watch::Sender<Protocol>) {
        let mut app = TuiApp::new().expect("app");
        app.layout.set_focus(Some(focus.to_string()));
        (app, watch::channel(Protocol::Both).0)
    }

    fn key(app: &mut TuiApp, state: &Arc<Mutex<AppState>>, tx: &watch::Sender<Protocol>, code: KeyCode) {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE), state, tx);
    }

    /// Draw the whole app as the event loop does; the frame as text rows.
    fn frame_text(app: &mut TuiApp, state: &Arc<Mutex<AppState>>, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| app.ui(frame, state)).expect("draw");
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| row_text(&buffer, y, 0, width))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The pane titles drawn on a top border in `text`.
    fn titles(text: &str) -> Vec<&'static str> {
        PANE_TITLES
            .into_iter()
            .filter(|title| text.contains(&format!("┌{title}")))
            .collect()
    }

    fn shared(state: AppState) -> Arc<Mutex<AppState>> {
        Arc::new(Mutex::new(state))
    }

    fn zoomed_rows(id: &str, state: &AppState, width: u16) -> usize {
        let layout = crate::tui::create_default_layout();
        pane(&layout, id).content(state, width - 2, Detail::Zoomed).len()
    }

    #[test]
    fn zoom_draws_exactly_one_pane_title_and_the_key_footer() {
        let state = shared(overflowing_state());
        let (mut app, tx) = app_on("security");
        let grid = frame_text(&mut app, &state, 80, 24);
        assert_eq!(titles(&grid).len(), 9, "the grid draws every pane:\n{grid}");

        key(&mut app, &state, &tx, KeyCode::Enter);
        let zoomed = frame_text(&mut app, &state, 80, 24);
        assert_eq!(titles(&zoomed), vec!["SECURITY"], "{zoomed}");
        let footer = zoomed.lines().last().expect("footer row");
        assert!(footer.starts_with(ZOOM_FOOTER), "footer: `{footer}`");
    }

    #[test]
    fn right_while_zoomed_shows_the_next_pane_from_its_first_row() {
        let state = overflowing_state();
        state.scanners.insert(
            "traceroute".to_string(),
            scan_state(
                Some(ScanResult::Traceroute(traceroute_fixture(30))),
                None,
                ScanStatus::Complete,
            ),
        );
        assert!(
            zoomed_rows("traceroute", &state, 80) > 22,
            "fixture must overflow the zoom"
        );
        let state = shared(state);
        let (mut app, tx) = app_on("traceroute");
        key(&mut app, &state, &tx, KeyCode::Enter);
        frame_text(&mut app, &state, 80, 24);
        for _ in 0..3 {
            key(&mut app, &state, &tx, KeyCode::Down);
        }
        assert_eq!(app.layout.scroll_offset("traceroute", Detail::Zoomed), 3);

        // Away and back: the traceroute zoom starts over at its first row.
        key(&mut app, &state, &tx, KeyCode::Left);
        assert_eq!(app.layout.focused_pane().map(String::as_str), Some("dns"));
        key(&mut app, &state, &tx, KeyCode::Right);
        let text = frame_text(&mut app, &state, 80, 24);
        assert!(app.layout.is_zoomed());
        assert_eq!(titles(&text), vec!["TRACEROUTE"], "{text}");
        assert_eq!(app.layout.scroll_offset("traceroute", Detail::Zoomed), 0);
        let first_row = text.lines().nth(1).expect("first content row");
        assert!(first_row.contains("Status:"), "not at row 0: `{first_row}`");
    }

    #[test]
    fn a_resize_while_zoomed_stays_zoomed_and_reclamps() {
        let state = overflowing_state();
        state.scanners.insert(
            "dns".to_string(),
            scan_state(Some(ScanResult::Dns(dns_fixture(40))), None, ScanStatus::Complete),
        );
        let rows = zoomed_rows("dns", &state, 80) as u16;
        let state = shared(state);
        let (mut app, tx) = app_on("dns");
        key(&mut app, &state, &tx, KeyCode::Enter);
        frame_text(&mut app, &state, 80, 24);
        for _ in 0..rows {
            key(&mut app, &state, &tx, KeyCode::Down);
        }
        frame_text(&mut app, &state, 80, 24);
        // 24 rows: one footer row and two border rows leave 21.
        assert_eq!(app.layout.scroll_offset("dns", Detail::Zoomed), rows - 21);

        let text = frame_text(&mut app, &state, 80, 40);
        assert!(app.layout.is_zoomed(), "a resize left zoom");
        assert_eq!(titles(&text), vec!["DNS"], "{text}");
        assert!(rows > 37, "fixture must still overflow at 80x40");
        assert_eq!(app.layout.scroll_offset("dns", Detail::Zoomed), rows - 37);
    }

    #[test]
    fn esc_while_zoomed_leaves_zoom_and_does_not_quit() {
        let state = shared(overflowing_state());
        let (mut app, tx) = app_on("security");
        key(&mut app, &state, &tx, KeyCode::Enter);
        assert!(app.layout.is_zoomed());
        key(&mut app, &state, &tx, KeyCode::Esc);
        assert!(!app.layout.is_zoomed(), "Esc did not leave zoom");
        assert!(!app.should_quit(), "Esc quit from zoom");
        assert_eq!(titles(&frame_text(&mut app, &state, 80, 24)).len(), 9);
    }

    #[test]
    fn esc_while_not_zoomed_quits_and_q_quits_from_zoom() {
        let state = shared(overflowing_state());
        let (mut app, tx) = app_on("security");
        key(&mut app, &state, &tx, KeyCode::Esc);
        assert!(app.should_quit(), "Esc in the grid did not quit");

        let (mut app, tx) = app_on("security");
        key(&mut app, &state, &tx, KeyCode::Enter);
        key(&mut app, &state, &tx, KeyCode::Char('q'));
        assert!(app.should_quit(), "q in zoom did not quit");
    }

    #[test]
    fn grid_and_zoomed_offsets_of_one_pane_are_independent() {
        let state = overflowing_state();
        state.scanners.insert(
            "dns".to_string(),
            scan_state(Some(ScanResult::Dns(dns_fixture(40))), None, ScanStatus::Complete),
        );
        let state = shared(state);
        let (mut app, tx) = app_on("dns");
        frame_text(&mut app, &state, 80, 24);
        key(&mut app, &state, &tx, KeyCode::Down);
        assert_eq!(app.layout.scroll_offset("dns", Detail::Normal), 1);

        key(&mut app, &state, &tx, KeyCode::Enter);
        frame_text(&mut app, &state, 80, 24);
        assert_eq!(
            app.layout.scroll_offset("dns", Detail::Zoomed),
            0,
            "zoom starts at row 0"
        );
        for _ in 0..3 {
            key(&mut app, &state, &tx, KeyCode::Down);
        }
        frame_text(&mut app, &state, 80, 24);
        assert_eq!(app.layout.scroll_offset("dns", Detail::Zoomed), 3);
        assert_eq!(
            app.layout.scroll_offset("dns", Detail::Normal),
            1,
            "zoom moved the grid offset"
        );

        key(&mut app, &state, &tx, KeyCode::Esc);
        frame_text(&mut app, &state, 80, 24);
        assert_eq!(app.layout.scroll_offset("dns", Detail::Normal), 1);
        key(&mut app, &state, &tx, KeyCode::Enter);
        assert_eq!(
            app.layout.scroll_offset("dns", Detail::Zoomed),
            0,
            "re-entering zoom resets it"
        );
    }

    #[test]
    fn enter_with_no_focused_pane_stays_in_the_grid() {
        let mut layout = crate::tui::create_default_layout();
        assert!(!layout.zoom());
        assert!(!layout.is_zoomed());
    }

    #[test]
    fn zoomed_connectivity_takes_no_scroll_keys() {
        let state = shared(overflowing_state());
        let (mut app, tx) = app_on("connectivity");
        key(&mut app, &state, &tx, KeyCode::Enter);
        let text = frame_text(&mut app, &state, 80, 24);
        assert_eq!(titles(&text), vec!["CONNECTIVITY"], "{text}");
        let guard = state.lock().unwrap();
        assert!(
            !app.layout
                .handle_key_event(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &guard)
        );
    }
}
