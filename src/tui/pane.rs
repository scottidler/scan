use crate::types::AppState;
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders},
    Frame,
};
use std::any::Any;
use log;

const DEFAULT_MIN_PANE_WIDTH: u16 = 20;
const DEFAULT_MIN_PANE_HEIGHT: u16 = 6;
const DEFAULT_SPAN_ROWS: usize = 1;
const DEFAULT_SPAN_COLS: usize = 1;

/// Trait for TUI panes that display scanner data
pub trait Pane {
    /// Render the pane content to the given area
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool);
    
    /// Get the pane's title for display
    fn title(&self) -> &'static str;
    
    /// Get the pane's identifier for positioning
    fn id(&self) -> &'static str;
    
    /// Whether this pane should be visible
    fn is_visible(&self) -> bool {
        true
    }
    
    /// Get the pane's preferred minimum size (width, height)
    fn min_size(&self) -> (u16, u16) {
        (DEFAULT_MIN_PANE_WIDTH, DEFAULT_MIN_PANE_HEIGHT)
    }
    
    /// Whether this pane can be focused/selected
    fn is_focusable(&self) -> bool {
        false
    }
    
    /// Enable downcasting to concrete types
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Helper function to create a standard bordered block for panes
pub fn create_block(title: &str, focused: bool) -> Block {
    log::trace!("[tui::pane] create_block: title={} focused={}", title, focused);
    
    Block::default()
        .title(title.to_uppercase())
        .borders(Borders::ALL)
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Gray)
        })
}

/// Pane position in the grid layout
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PanePosition {
    pub row: usize,
    pub col: usize,
}

impl PanePosition {
    pub fn new(row: usize, col: usize) -> Self {
        Self { row, col }
    }
}

/// Configuration for pane layout
#[derive(Debug, Clone)]
pub struct PaneConfig {
    pub position: PanePosition,
    pub span_rows: usize,
    pub span_cols: usize,
    pub visible: bool,
}

impl PaneConfig {
    pub fn new(row: usize, col: usize) -> Self {
        log::trace!("[tui::pane] PaneConfig::new: row={} col={}", row, col);
        Self {
            position: PanePosition::new(row, col),
            span_rows: DEFAULT_SPAN_ROWS,
            span_cols: DEFAULT_SPAN_COLS,
            visible: true,
        }
    }
    
    pub fn with_span(mut self, rows: usize, cols: usize) -> Self {
        self.span_rows = rows;
        self.span_cols = cols;
        self
    }
    
    pub fn with_visibility(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }
} 