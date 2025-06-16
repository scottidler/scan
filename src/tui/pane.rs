use crate::types::AppState;
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders},
    Frame,
};
use std::any::Any;

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
        (20, 6)
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
    let (border_style, border_type) = if focused {
        (
            ratatui::style::Style::default().fg(ratatui::style::Color::Cyan),
            ratatui::widgets::BorderType::Double
        )
    } else {
        (
            ratatui::style::Style::default().fg(ratatui::style::Color::Gray),
            ratatui::widgets::BorderType::Plain
        )
    };
    
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .border_type(border_type)
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
        Self {
            position: PanePosition::new(row, col),
            span_rows: 1,
            span_cols: 1,
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