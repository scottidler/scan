use crate::types::AppState;
use log;

const SCROLL_STEP: u16 = 1;

/// Trait for panes that support scrolling content
pub trait ScrollablePane {
    /// Get the current scroll offset
    fn scroll_offset(&self) -> u16;
    
    /// Set the scroll offset
    fn set_scroll_offset(&mut self, offset: u16);
    
    /// Calculate the total number of content lines for this pane
    fn calculate_content_lines(&self, state: &AppState) -> u16;
    
    /// Scroll up by one step
    fn scroll_up(&mut self) {
        let old_offset = self.scroll_offset();
        let new_offset = old_offset.saturating_sub(SCROLL_STEP);
        self.set_scroll_offset(new_offset);
        log::debug!("[tui::scrollable] scroll_up: old_offset={} new_offset={}", old_offset, new_offset);
    }
    
    /// Scroll down intelligently based on content size and visible area
    fn scroll_down_smart(&mut self, state: &AppState, visible_height: u16) {
        let actual_lines = self.calculate_content_lines(state);
        let old_offset = self.scroll_offset();
        
        // Calculate maximum scroll offset (ensure we don't scroll past content)
        let max_scroll = actual_lines.saturating_sub(visible_height);
        if self.scroll_offset() < max_scroll {
            let new_offset = self.scroll_offset() + SCROLL_STEP;
            self.set_scroll_offset(new_offset);
        }
        
        log::debug!("[tui::scrollable] scroll_down_smart: old_offset={} new_offset={} actual_lines={} visible_height={} max_scroll={}",
            old_offset, self.scroll_offset(), actual_lines, visible_height, max_scroll);
    }
    
    /// Reset scroll to top
    fn reset_scroll(&mut self) {
        let old_offset = self.scroll_offset();
        self.set_scroll_offset(0);
        log::debug!("[tui::scrollable] reset_scroll: old_offset={}", old_offset);
    }
    
    /// Apply scroll offset to a vector of lines, returning only visible lines
    fn apply_scroll_to_lines<T>(&self, lines: Vec<T>, visible_height: u16) -> Vec<T> {
        let total_lines = lines.len() as u16;
        
        // Calculate safe scroll offset
        let max_scroll_offset = if total_lines > visible_height {
            total_lines - visible_height
        } else {
            0
        };
        
        let safe_scroll_offset = self.scroll_offset().min(max_scroll_offset);
        
        log::trace!("[tui::scrollable] apply_scroll: total_lines={} visible_height={} max_scroll={} safe_scroll={}",
            total_lines, visible_height, max_scroll_offset, safe_scroll_offset);
        
        // Apply scroll offset - skip lines from the beginning
        if safe_scroll_offset < total_lines {
            lines.into_iter().skip(safe_scroll_offset as usize).collect()
        } else {
            lines
        }
    }
} 