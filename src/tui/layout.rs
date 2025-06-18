use crate::tui::pane::{Pane, PaneConfig};
use crate::tui::scrollable::ScrollablePane;
use crate::types::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
};
use std::collections::HashMap;
use log;

const DEFAULT_GRID_ROWS: usize = 3;
const DEFAULT_GRID_COLS: usize = 3;
const TOP_ROW_HEIGHT_PERCENT: u16 = 25;
const MIDDLE_ROW_HEIGHT_PERCENT: u16 = 35;
const BOTTOM_ROW_HEIGHT_PERCENT: u16 = 40;
const BORDER_HEIGHT_OFFSET: u16 = 2;
const FALLBACK_VISIBLE_LINES: u16 = 20;
const TARGET_PANE_WIDTH_PERCENT: u16 = 30;
const CONNECTIVITY_PANE_WIDTH_PERCENT: u16 = 35;
const SECURITY_PANE_WIDTH_PERCENT: u16 = 35;
const DNS_PANE_WIDTH_PERCENT: u16 = 35;
const HTTP_PANE_WIDTH_PERCENT: u16 = 30;
const PORTS_PANE_WIDTH_PERCENT: u16 = 35;
const WHOIS_PANE_WIDTH_PERCENT: u16 = 40;
const TRACEROUTE_PANE_WIDTH_PERCENT: u16 = 35;
const GEOIP_PANE_WIDTH_PERCENT: u16 = 25;
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
        log::debug!("[tui::layout] add_pane: pane_id={} position=({},{}) visible={}",
            pane_id, config.position.row, config.position.col, config.visible);

        self.config.insert(pane_id, config);
        self.panes.push(pane);

        log::trace!("[tui::layout] pane_added: total_panes={}", self.panes.len());
    }

    /// Set the focused pane by ID
    pub fn set_focus(&mut self, pane_id: Option<String>) {
        log::debug!("[tui::layout] set_focus: old_focus={:?} new_focus={:?}",
            self.focused_pane, pane_id);
        self.focused_pane = pane_id;
    }

    /// Get the currently focused pane ID
    pub fn focused_pane(&self) -> Option<&String> {
        self.focused_pane.as_ref()
    }

    /// Render all panes in the layout
    pub fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        log::trace!("[tui::layout] render: area={}x{} panes={} focused={:?}",
            area.width, area.height, self.panes.len(), self.focused_pane);

        // Create the grid layout
        let grid_areas = self.create_grid_layout(area);
        log::trace!("[tui::layout] grid_created: rows={} cols={}",
            grid_areas.len(), grid_areas.first().map(|r| r.len()).unwrap_or(0));

        let mut rendered_count = 0;
        let mut skipped_count = 0;

        // Render each pane in its designated area
        for pane in &self.panes {
            let pane_id = pane.id();

            if let Some(config) = self.config.get(pane_id) {
                if !config.visible || !pane.is_visible() {
                    skipped_count += 1;
                    log::trace!("[tui::layout] pane_skipped: pane_id={} config_visible={} pane_visible={}",
                        pane_id, config.visible, pane.is_visible());
                    continue;
                }

                if let Some(pane_area) = self.get_pane_area(&grid_areas, config) {
                    // Check if this pane is focused
                    let is_focused = self.focused_pane.as_ref()
                        .map(|focused_id| focused_id == pane_id)
                        .unwrap_or(false);

                    log::trace!("[tui::layout] rendering_pane: pane_id={} area={}x{} focused={}",
                        pane_id, pane_area.width, pane_area.height, is_focused);

                    pane.render(frame, pane_area, state, is_focused);
                    rendered_count += 1;
                } else {
                    skipped_count += 1;
                    log::warn!("[tui::layout] pane_area_not_found: pane_id={} position=({},{})",
                        pane_id, config.position.row, config.position.col);
                }
            } else {
                skipped_count += 1;
                log::warn!("[tui::layout] pane_config_not_found: pane_id={}", pane_id);
            }
        }

        log::trace!("[tui::layout] render_completed: rendered={} skipped={}",
            rendered_count, skipped_count);
    }

    /// Create the grid layout areas with custom proportions (public version)
    pub fn create_grid_layout_public(&self, area: ratatui::layout::Rect) -> Vec<Vec<ratatui::layout::Rect>> {
        self.create_grid_layout(area)
    }

    /// Create the grid layout areas with custom proportions
    fn create_grid_layout(&self, area: Rect) -> Vec<Vec<Rect>> {
        // Create custom row constraints for better space allocation
        // Row 0: Smaller for summary info (target, connectivity, security)
        // Row 1: Medium for DNS, HTTP, Ports
        // Row 2: Larger for detailed info (whois, traceroute, geoip)
        let row_constraints = vec![
            Constraint::Percentage(TOP_ROW_HEIGHT_PERCENT), // Top row - 25%
            Constraint::Percentage(MIDDLE_ROW_HEIGHT_PERCENT), // Middle row - 35%
            Constraint::Percentage(BOTTOM_ROW_HEIGHT_PERCENT), // Bottom row - 40%
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
                    Constraint::Percentage(TARGET_PANE_WIDTH_PERCENT), // target - compact
                    Constraint::Percentage(CONNECTIVITY_PANE_WIDTH_PERCENT), // connectivity - medium
                    Constraint::Percentage(SECURITY_PANE_WIDTH_PERCENT), // security - medium
                ],
                1 => vec![
                    Constraint::Percentage(DNS_PANE_WIDTH_PERCENT), // dns - needs more space
                    Constraint::Percentage(HTTP_PANE_WIDTH_PERCENT), // http - medium
                    Constraint::Percentage(PORTS_PANE_WIDTH_PERCENT), // ports - needs more space
                ],
                2 => vec![
                    Constraint::Percentage(WHOIS_PANE_WIDTH_PERCENT), // whois - needs more space
                    Constraint::Percentage(TRACEROUTE_PANE_WIDTH_PERCENT), // traceroute - needs lots of space
                    Constraint::Percentage(GEOIP_PANE_WIDTH_PERCENT), // geoip - compact
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

    /// Get the area for a specific pane based on its configuration
    fn get_pane_area(&self, grid_areas: &[Vec<Rect>], config: &PaneConfig) -> Option<Rect> {
        let row = config.position.row;
        let col = config.position.col;

        // Check bounds
        if row >= self.grid_rows || col >= self.grid_cols {
            return None;
        }

        // For now, just return the single cell area
        // TODO: Handle spanning multiple cells
        Some(grid_areas[row][col])
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
            log::debug!("[tui::layout] toggle_pane_visibility: pane_id={} old={} new={}",
                pane_id, old_visible, config.visible);
        } else {
            log::warn!("[tui::layout] toggle_visibility_failed: pane_id={} not_found", pane_id);
        }
    }

    /// Get the next focusable pane ID
    pub fn next_focusable_pane(&self, current: Option<&str>) -> Option<String> {
        let focusable_panes: Vec<_> = self.panes
            .iter()
            .filter(|p| p.is_focusable())
            .map(|p| p.id().to_string())
            .collect();

        log::trace!("[tui::layout] next_focusable_pane: current={:?} focusable_count={}",
            current, focusable_panes.len());

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

        log::debug!("[tui::layout] next_focusable_result: current={:?} next={:?}",
            current, next_pane);
        next_pane
    }

    /// Get the previous focusable pane ID
    pub fn prev_focusable_pane(&self, current: Option<&str>) -> Option<String> {
        let focusable_panes: Vec<_> = self.panes
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
                    let prev_index = if current_index == 0 {
                        focusable_panes.len() - 1
                    } else {
                        current_index - 1
                    };
                    Some(focusable_panes[prev_index].clone())
                } else {
                    Some(focusable_panes[focusable_panes.len() - 1].clone())
                }
            }
        }
    }

    /// Handle keyboard events for the focused pane
    pub fn handle_key_event(&mut self, key: crossterm::event::KeyEvent, state: &AppState, pane_areas: &[Vec<ratatui::layout::Rect>]) -> bool {
        log::debug!("[tui::layout] handle_key_event: focused_pane={:?} key={:?}",
            self.focused_pane, key.code);

        if let Some(focused_id) = &self.focused_pane {
            match key.code {
                crossterm::event::KeyCode::Up | crossterm::event::KeyCode::Char('k') => {
                    log::debug!("[tui::layout] pane_scroll_up: pane={}", focused_id);
                    for pane in &mut self.panes {
                        if pane.id() == focused_id {
                            if focused_id == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    security_pane.scroll_up();
                                    return true;
                                }
                            } else if focused_id == "dns" {
                                if let Some(dns_pane) = pane.as_any_mut().downcast_mut::<crate::tui::dns::DnsPane>() {
                                    dns_pane.scroll_up();
                                    return true;
                                }
                            } else if focused_id == "traceroute" {
                                if let Some(traceroute_pane) = pane.as_any_mut().downcast_mut::<crate::tui::traceroute::TraceroutePane>() {
                                    traceroute_pane.scroll_up();
                                    return true;
                                }
                            }
                        }
                    }
                }
                crossterm::event::KeyCode::Down | crossterm::event::KeyCode::Char('j') => {
                    log::debug!("[tui::layout] pane_scroll_down: pane={}", focused_id);
                    for pane in &mut self.panes {
                        if pane.id() == focused_id {
                            if focused_id == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    // Get the security pane area (bottom-right: row 2, col 2)
                                    let visible_lines = if pane_areas.len() > 2 && pane_areas[2].len() > 2 {
                                        // Subtract 2 for borders
                                        pane_areas[2][2].height.saturating_sub(BORDER_HEIGHT_OFFSET)
                                    } else {
                                        FALLBACK_VISIBLE_LINES // Fallback
                                    };

                                    security_pane.scroll_down_smart(state, visible_lines);
                                    return true;
                                }
                            } else if focused_id == "dns" {
                                if let Some(dns_pane) = pane.as_any_mut().downcast_mut::<crate::tui::dns::DnsPane>() {
                                    // Get the DNS pane area - need to find which position dns pane is in
                                    let mut visible_lines = FALLBACK_VISIBLE_LINES;
                                    if let Some(config) = self.config.get("dns") {
                                        let row = config.position.row;
                                        let col = config.position.col;
                                        if pane_areas.len() > row && pane_areas[row].len() > col {
                                            visible_lines = pane_areas[row][col].height.saturating_sub(BORDER_HEIGHT_OFFSET);
                                        }
                                    }

                                    dns_pane.scroll_down_smart(state, visible_lines);
                                    return true;
                                }
                            } else if focused_id == "traceroute" {
                                if let Some(traceroute_pane) = pane.as_any_mut().downcast_mut::<crate::tui::traceroute::TraceroutePane>() {
                                    // Get the TraceroutePane area
                                    let mut visible_lines = FALLBACK_VISIBLE_LINES;
                                    if let Some(config) = self.config.get("traceroute") {
                                        let row = config.position.row;
                                        let col = config.position.col;
                                        if pane_areas.len() > row && pane_areas[row].len() > col {
                                            visible_lines = pane_areas[row][col].height.saturating_sub(BORDER_HEIGHT_OFFSET);
                                        }
                                    }

                                    traceroute_pane.scroll_down_smart(state, visible_lines);
                                    return true;
                                }
                            }
                        }
                    }
                }
                crossterm::event::KeyCode::Home => {
                    log::debug!("[tui::layout] pane_scroll_home: pane={}", focused_id);
                    for pane in &mut self.panes {
                        if pane.id() == focused_id {
                            if focused_id == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    security_pane.reset_scroll();
                                    return true;
                                }
                            } else if focused_id == "dns" {
                                if let Some(dns_pane) = pane.as_any_mut().downcast_mut::<crate::tui::dns::DnsPane>() {
                                    dns_pane.reset_scroll();
                                    return true;
                                }
                            } else if focused_id == "traceroute" {
                                if let Some(traceroute_pane) = pane.as_any_mut().downcast_mut::<crate::tui::traceroute::TraceroutePane>() {
                                    traceroute_pane.reset_scroll();
                                    return true;
                                }
                            }
                        }
                    }
                }
                _ => {
                    log::trace!("[tui::layout] unhandled_key_in_pane: pane={} key={:?}", focused_id, key.code);
                }
            }
        } else {
            log::trace!("[tui::layout] key_event_no_focused_pane: key={:?}", key.code);
        }
        false
    }
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
}
