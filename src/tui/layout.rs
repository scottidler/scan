use crate::tui::pane::{Pane, PaneConfig};
use crate::types::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
};
use std::collections::HashMap;

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
        Self::new(3, 3)
    }
    
    /// Add a pane to the layout with its configuration
    pub fn add_pane(&mut self, pane: Box<dyn Pane>, config: PaneConfig) {
        let pane_id = pane.id().to_string();
        self.config.insert(pane_id, config);
        self.panes.push(pane);
    }
    
    /// Set the focused pane by ID
    pub fn set_focus(&mut self, pane_id: Option<String>) {
        self.focused_pane = pane_id;
    }
    
    /// Get the currently focused pane ID
    pub fn focused_pane(&self) -> Option<&String> {
        self.focused_pane.as_ref()
    }
    
    /// Render all panes in the layout
    pub fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        // Create the grid layout
        let grid_areas = self.create_grid_layout(area);
        
        // Render each pane in its designated area
        for pane in &self.panes {
            let pane_id = pane.id();
            
            if let Some(config) = self.config.get(pane_id) {
                if !config.visible || !pane.is_visible() {
                    continue;
                }
                
                if let Some(pane_area) = self.get_pane_area(&grid_areas, config) {
                    // Check if this pane is focused
                    let is_focused = self.focused_pane.as_ref()
                        .map(|focused_id| focused_id == pane_id)
                        .unwrap_or(false);
                    
                    pane.render(frame, pane_area, state, is_focused);
                }
            }
        }
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
            Constraint::Percentage(25), // Top row - 25%
            Constraint::Percentage(35), // Middle row - 35%
            Constraint::Percentage(40), // Bottom row - 40%
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
                    Constraint::Percentage(30), // target - compact
                    Constraint::Percentage(35), // connectivity - medium
                    Constraint::Percentage(35), // security - medium
                ],
                1 => vec![
                    Constraint::Percentage(35), // dns - needs more space
                    Constraint::Percentage(30), // http - medium
                    Constraint::Percentage(35), // ports - needs more space
                ],
                2 => vec![
                    Constraint::Percentage(40), // whois - needs more space
                    Constraint::Percentage(35), // traceroute - needs lots of space
                    Constraint::Percentage(25), // geoip - compact
                ],
                _ => vec![
                    Constraint::Percentage(33),
                    Constraint::Percentage(33),
                    Constraint::Percentage(34),
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
            config.visible = !config.visible;
        }
    }
    
    /// Get the next focusable pane ID
    pub fn next_focusable_pane(&self, current: Option<&str>) -> Option<String> {
        let focusable_panes: Vec<_> = self.panes
            .iter()
            .filter(|p| p.is_focusable())
            .map(|p| p.id().to_string())
            .collect();
        
        if focusable_panes.is_empty() {
            return None;
        }
        
        match current {
            None => Some(focusable_panes[0].clone()),
            Some(current_id) => {
                if let Some(current_index) = focusable_panes.iter().position(|id| id == current_id) {
                    let next_index = (current_index + 1) % focusable_panes.len();
                    Some(focusable_panes[next_index].clone())
                } else {
                    Some(focusable_panes[0].clone())
                }
            }
        }
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
        if let Some(focused_id) = &self.focused_pane {
            // Handle scrolling for security pane specifically
            if focused_id == "security" {
                match key.code {
                    crossterm::event::KeyCode::Up | crossterm::event::KeyCode::Char('k') => {
                        // Find the security pane and scroll up
                        for pane in &mut self.panes {
                            if pane.id() == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    security_pane.scroll_up();
                                    return true;
                                }
                            }
                        }
                    }
                    crossterm::event::KeyCode::Down | crossterm::event::KeyCode::Char('j') => {
                        // Find the security pane and scroll down
                        for pane in &mut self.panes {
                            if pane.id() == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    // Calculate actual content and visible lines
                                    let content_lines = security_pane.get_actual_line_count(state);
                                    
                                    // Get the security pane area (bottom-right: row 2, col 2)
                                    let visible_lines = if pane_areas.len() > 2 && pane_areas[2].len() > 2 {
                                        // Subtract 2 for borders
                                        pane_areas[2][2].height.saturating_sub(2)
                                    } else {
                                        20 // Fallback
                                    };
                                    
                                    security_pane.scroll_down(content_lines, visible_lines);
                                    return true;
                                }
                            }
                        }
                    }
                    crossterm::event::KeyCode::Home => {
                        // Reset scroll to top
                        for pane in &mut self.panes {
                            if pane.id() == "security" {
                                if let Some(security_pane) = pane.as_any_mut().downcast_mut::<crate::tui::security::SecurityPane>() {
                                    security_pane.reset_scroll();
                                    return true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
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
        assert_eq!(layout.grid_rows, 3);
        assert_eq!(layout.grid_cols, 3);
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
