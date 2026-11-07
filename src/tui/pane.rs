use crate::tui::theme;
use crate::types::AppState;
use log;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};
use std::any::Any;

const DEFAULT_MIN_PANE_WIDTH: u16 = 20;
const DEFAULT_MIN_PANE_HEIGHT: u16 = 6;
const DEFAULT_SPAN_ROWS: usize = 1;
const DEFAULT_SPAN_COLS: usize = 1;
/// The key legend on the target pane's top border, longest first. Each shorter form drops one
/// part (` help`, then ` hjkl`, then the arrows); `?` is in every form.
const KEY_LEGENDS: [&str; 4] = ["←↓↑→ hjkl ? help", "←↓↑→ hjkl ?", "←↓↑→ ?", "?"];

/// How much of a pane's data its content shows: the dashboard cell, or the pane zoomed to the
/// full frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detail {
    Normal,
    Zoomed,
}

/// Trait for TUI panes that display scanner data
pub trait Pane {
    /// The pane's rows for `detail`, already laid out to `width` cells: one `Line` per screen row.
    /// The renderer never wraps, so the length is the row count that scrolling and the overflow
    /// marker use. A pane that shows the same data at every detail ignores `detail`.
    fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>>;

    /// Render the pane at `area` from its first row, with the overflow marker.
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        draw_rows(self, frame, area, state, focused, Detail::Normal, 0);
    }

    /// Render the pane at `detail`. Only a pane that does not scroll (`scrolls() == false`) is
    /// drawn through this; the layout draws every other pane with `draw_rows` at its offset.
    fn render_detail(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool, _detail: Detail) {
        self.render(frame, area, state, focused);
    }

    /// Whether the layout scrolls this pane's `content` rows. A pane that draws more than rows
    /// (Connectivity's sparklines) returns false and is drawn by `render_detail`.
    fn scrolls(&self) -> bool {
        true
    }

    /// Take in new scanner data. Called once per TUI tick for every pane, drawn or not, so a pane
    /// that keeps its own history across scans records it here, never in `render`.
    fn ingest(&self, _state: &AppState) {}

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

    /// Whether the key legend is drawn right-aligned on this pane's top border.
    fn shows_key_legend(&self) -> bool {
        false
    }

    /// Whether this pane can be focused/selected
    fn is_focusable(&self) -> bool {
        false
    }

    /// Enable downcasting to concrete types
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A btop-style box: rounded border in the pane's own color, and the title set into the top
/// border between `┐` and `┌`. Focus brightens the border and turns the title red.
pub fn create_block(title: &str, focused: bool) -> Block<'_> {
    log::trace!("[tui::pane] create_block: title={} focused={}", title, focused);
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border_color(title, focused)))
        .title(title_line(title, focused))
}

fn border_color(title: &str, focused: bool) -> ratatui::style::Color {
    if focused { theme::BORDER_FOCUSED } else { theme::pane_border(title) }
}

/// The left top-border title, `─┐title┌`.
fn title_line(title: &str, focused: bool) -> Line<'static> {
    let border = border_color(title, focused);
    let title_style = if focused {
        Style::default().fg(theme::TITLE_FOCUSED).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TITLE).add_modifier(Modifier::BOLD)
    };
    Line::from(vec![
        Span::styled("─┐", Style::default().fg(border)),
        Span::styled(title.to_string(), title_style),
        Span::styled("┌", Style::default().fg(border)),
    ])
}

/// A bottom-border label set between `┘` and `└` in the border's color, as btop draws its key
/// hints.
pub(crate) fn bottom_label(text: String, focused: bool, title: &str) -> Line<'static> {
    let border = border_color(title, focused);
    Line::from(vec![
        Span::styled("┘", Style::default().fg(border)),
        Span::styled(text, Style::default().fg(theme::LABEL)),
        Span::styled("└─", Style::default().fg(border)),
    ])
    .right_aligned()
}

/// A right-aligned top-border label set between `┐` and `┌`, styled as `bottom_label`.
fn top_label(text: &str, focused: bool, title: &str) -> Line<'static> {
    let border = border_color(title, focused);
    Line::from(vec![
        Span::styled("┐", Style::default().fg(border)),
        Span::styled(text.to_string(), Style::default().fg(theme::LABEL)),
        Span::styled("┌─", Style::default().fg(border)),
    ])
    .right_aligned()
}

/// The longest key legend that fits on the top border of a `width`-cell box beside its title,
/// with one cell between them, or `None` when not even `?` fits.
pub(crate) fn key_legend(width: u16, title: &str, focused: bool) -> Option<Line<'static>> {
    let room = usize::from(width.saturating_sub(2));
    let taken = title_line(title, focused).width() + 1;
    let legend = KEY_LEGENDS
        .iter()
        .map(|text| top_label(text, focused, title))
        .find(|line| taken + line.width() <= room);
    log::trace!(
        "[tui::pane] key_legend: width={} title={} fits={}",
        width,
        title,
        legend.is_some()
    );
    legend
}

/// Where a pane's rows stand in its rect: the clamped first row shown, and how many rows sit
/// above and below the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowView {
    pub offset: u16,
    pub above: usize,
    pub below: usize,
}

impl RowView {
    /// `total` rows in `visible` rows of space, asked to start at `offset`. The offset is clamped
    /// so the last row never rises above the bottom of the view.
    pub fn new(total: usize, visible: u16, offset: u16) -> Self {
        let max_offset = total.saturating_sub(usize::from(visible));
        let start = usize::from(offset).min(max_offset);
        let below = total.saturating_sub(start + usize::from(visible));
        Self {
            offset: u16::try_from(start).unwrap_or(u16::MAX),
            above: start,
            below,
        }
    }

    /// The bottom-border marker: `↓ N more` while rows sit below the view, `↑ N` while rows sit
    /// above it, both when scrolled into the middle, or `None` when every row is shown.
    pub fn marker(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.above > 0 {
            parts.push(format!("↑ {}", self.above));
        }
        if self.below > 0 {
            parts.push(format!("↓ {} more", self.below));
        }
        if parts.is_empty() { None } else { Some(parts.join(" ")) }
    }
}

/// Draw `pane`'s `content` rows for `detail` in a bordered block at `area`, starting at row
/// `offset`, with the overflow marker on the bottom border. Returns the offset clamped against the
/// rows and the rect, for the caller to keep.
pub fn draw_rows<P: Pane + ?Sized>(
    pane: &P,
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    focused: bool,
    detail: Detail,
    offset: u16,
) -> u16 {
    let block = create_block(pane.title(), focused);
    let inner = block.inner(area);
    let rows = pane.content(state, inner.width, detail);
    let view = RowView::new(rows.len(), inner.height, offset);
    log::trace!(
        "[tui::pane] draw_rows: pane={} detail={:?} rows={} visible={} offset={} clamped={} below={}",
        pane.id(),
        detail,
        rows.len(),
        inner.height,
        offset,
        view.offset,
        view.below
    );
    let block = match view.marker() {
        Some(marker) => block.title_bottom(bottom_label(marker, focused, pane.title())),
        None => block,
    };
    let legend = pane
        .shows_key_legend()
        .then(|| key_legend(area.width, pane.title(), focused))
        .flatten();
    let block = match legend {
        Some(legend) => block.title_top(legend),
        None => block,
    };
    block.render(area, frame.buffer_mut());
    let shown: Vec<Line<'static>> = rows
        .into_iter()
        .skip(view.above)
        .take(usize::from(inner.height))
        .collect();
    Paragraph::new(shown).render(inner, frame.buffer_mut());
    view.offset
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_view_that_fits_has_no_marker() {
        let view = RowView::new(4, 6, 0);
        assert_eq!(
            view,
            RowView {
                offset: 0,
                above: 0,
                below: 0
            }
        );
        assert_eq!(view.marker(), None);
    }

    #[test]
    fn row_view_marks_rows_below_and_above() {
        assert_eq!(RowView::new(10, 4, 0).marker().as_deref(), Some("↓ 6 more"));
        assert_eq!(RowView::new(10, 4, 2).marker().as_deref(), Some("↑ 2 ↓ 4 more"));
        assert_eq!(RowView::new(10, 4, 6).marker().as_deref(), Some("↑ 6"));
    }

    fn legend_text(width: u16) -> Option<String> {
        key_legend(width, "target", false).map(|line| line.spans[1].content.to_string())
    }

    #[test]
    fn key_legend_drops_help_then_hjkl_then_the_arrows_and_keeps_the_question_mark() {
        // `─┐target┌` is 9 cells, plus one gap and the two corners: 12 cells before the legend.
        assert_eq!(legend_text(60).as_deref(), Some("←↓↑→ hjkl ? help"));
        assert_eq!(legend_text(12 + 19).as_deref(), Some("←↓↑→ hjkl ? help"));
        assert_eq!(legend_text(12 + 18).as_deref(), Some("←↓↑→ hjkl ?"));
        assert_eq!(legend_text(12 + 14).as_deref(), Some("←↓↑→ hjkl ?"));
        assert_eq!(legend_text(12 + 13).as_deref(), Some("←↓↑→ ?"));
        assert_eq!(legend_text(12 + 9).as_deref(), Some("←↓↑→ ?"));
        assert_eq!(legend_text(12 + 8).as_deref(), Some("?"));
        assert_eq!(legend_text(12 + 4).as_deref(), Some("?"));
        assert_eq!(legend_text(12 + 3), None);
    }

    #[test]
    fn every_key_legend_form_carries_the_question_mark() {
        assert!(KEY_LEGENDS.iter().all(|text| text.contains('?')));
        let widths: Vec<usize> = KEY_LEGENDS.iter().map(|text| Span::raw(*text).width()).collect();
        assert!(widths.windows(2).all(|pair| pair[0] > pair[1]), "{widths:?}");
    }

    #[test]
    fn row_view_clamps_an_offset_past_the_end() {
        let view = RowView::new(10, 4, 40);
        assert_eq!(view.offset, 6);
        assert_eq!(view.below, 0);
        assert_eq!(RowView::new(3, 4, 5).offset, 0);
        assert_eq!(RowView::new(10, 0, 40).offset, 10);
    }
}
