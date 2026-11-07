//! The Esc menu and the `?` help: centered boxes drawn over the dimmed dashboard, as btop draws
//! its menu. Each box is sized from the frame area on every draw, so a resize recenters it.

use crate::tui::pane::{RowView, bottom_label, create_block};
use crate::tui::text::fit_line;
use crate::tui::theme;
use log;
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Padding, Paragraph, Widget},
};

/// Every key the dashboard takes, as help lists it: (keys, what they do).
pub const KEY_HELP: &[(&str, &str)] = &[
    ("← / h, Shift-Tab", "previous pane"),
    ("→ / l, Tab", "next pane"),
    ("↑ / k, ↓ / j", "scroll; in the menu, move"),
    ("Home", "back to the first row"),
    ("Enter", "zoom the pane; in the menu, choose"),
    ("p", "switch protocol: both, IPv4, IPv6"),
    ("Esc", "menu; leave zoom; close this box"),
    ("?", "this help; again to close"),
    ("q, Ctrl-C", "quit"),
];

/// Cells between the key column and the description in help.
const KEY_GAP: usize = 2;
/// Cells of the menu box, border included.
const MENU_WIDTH: u16 = 16;
/// Border plus one cell of padding on each side of a box's rows.
const BOX_FRAME_WIDTH: u16 = 4;
/// Top and bottom border rows of a box.
const BOX_FRAME_HEIGHT: u16 = 2;

/// What is drawn over the dashboard. Neither box changes focus, zoom or any pane's scroll, so
/// closing one returns to the view it was opened from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    None,
    Menu { selected: usize },
    Help { scroll: u16 },
}

/// An entry of the Esc menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Help,
    Quit,
}

impl MenuItem {
    pub fn label(self) -> &'static str {
        match self {
            MenuItem::Help => "Help",
            MenuItem::Quit => "Quit",
        }
    }
}

/// The Esc menu's entries, top to bottom.
pub const MENU_ITEMS: [MenuItem; 2] = [MenuItem::Help, MenuItem::Quit];

/// A `width` x `height` rect centered in `area`, shrunk to fit it.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn boxed(title: &str) -> Block<'_> {
    create_block(title, true).padding(Padding::horizontal(1))
}

/// Help's rows: the keys in a column as wide as the widest, then what they do.
fn help_rows() -> Vec<Line<'static>> {
    let key_width = KEY_HELP
        .iter()
        .map(|(keys, _)| Span::raw(*keys).width())
        .max()
        .unwrap_or(0);
    KEY_HELP
        .iter()
        .map(|(keys, action)| {
            let pad = key_width - Span::raw(*keys).width() + KEY_GAP;
            Line::from(vec![
                Span::styled(keys.to_string(), Style::default().fg(theme::ACCENT)),
                Span::raw(" ".repeat(pad)),
                Span::styled(action.to_string(), Style::default().fg(theme::VALUE)),
            ])
        })
        .collect()
}

/// The help box over a frame of `area`, and the rect its rows are drawn in.
fn help_rects(area: Rect) -> (Rect, Rect) {
    let rows = help_rows();
    let width = rows.iter().map(Line::width).max().unwrap_or(0) as u16 + BOX_FRAME_WIDTH;
    let height = rows.len() as u16 + BOX_FRAME_HEIGHT;
    let rect = centered(area, width, height);
    (rect, boxed("help").inner(rect))
}

/// The last first-row help can scroll to in a frame of `area`.
pub fn help_max_scroll(area: Rect) -> u16 {
    let (_, inner) = help_rects(area);
    RowView::new(KEY_HELP.len(), inner.height, u16::MAX).offset
}

/// Dim every cell of `area`, so the box drawn over it stands out.
fn dim(buffer: &mut Buffer, area: Rect) {
    for position in area.positions() {
        let cell = &mut buffer[position];
        cell.fg = theme::dimmed(cell.fg);
    }
}

/// Clear `rect` to the theme background for a box to be drawn in.
fn clear(buffer: &mut Buffer, rect: Rect) {
    Clear.render(rect, buffer);
    buffer.set_style(rect, Style::default().bg(theme::BACKGROUND));
}

fn render_menu(buffer: &mut Buffer, area: Rect, selected: usize) {
    let rect = centered(area, MENU_WIDTH, MENU_ITEMS.len() as u16 + BOX_FRAME_HEIGHT);
    let block = boxed("menu");
    let inner = block.inner(rect);
    clear(buffer, rect);
    block.render(rect, buffer);
    let width = usize::from(inner.width);
    let rows: Vec<Line<'static>> = MENU_ITEMS
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let style = if index == selected {
                Style::default()
                    .fg(theme::BACKGROUND)
                    .bg(theme::TITLE_FOCUSED)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::VALUE)
            };
            Line::styled(format!("{:<width$}", item.label()), style)
        })
        .collect();
    Paragraph::new(rows).render(inner, buffer);
}

/// Draw help at `scroll`; returns the scroll clamped against this frame.
fn render_help(buffer: &mut Buffer, area: Rect, scroll: u16) -> u16 {
    let (rect, inner) = help_rects(area);
    let rows = help_rows();
    let view = RowView::new(rows.len(), inner.height, scroll);
    let block = match view.marker() {
        Some(marker) => boxed("help").title_bottom(bottom_label(marker, true, "help")),
        None => boxed("help"),
    };
    clear(buffer, rect);
    block.render(rect, buffer);
    let shown: Vec<Line<'static>> = rows
        .into_iter()
        .skip(view.above)
        .take(usize::from(inner.height))
        .map(|line| fit_line(line, inner.width))
        .collect();
    Paragraph::new(shown).render(inner, buffer);
    view.offset
}

/// Draw `overlay` over the dashboard already drawn in `area`, dimming the dashboard first. A help
/// scroll past the end of this frame's rows is clamped in place.
pub fn render(frame: &mut Frame, area: Rect, overlay: &mut Overlay) {
    log::trace!(
        "[tui::overlay] render: overlay={:?} area={}x{}",
        overlay,
        area.width,
        area.height
    );
    let buffer = frame.buffer_mut();
    match *overlay {
        Overlay::None => {}
        Overlay::Menu { selected } => {
            dim(buffer, area);
            render_menu(buffer, area, selected);
        }
        Overlay::Help { scroll } => {
            dim(buffer, area);
            let clamped = render_help(buffer, area, scroll);
            if clamped != scroll {
                log::debug!(
                    "[tui::overlay] help_scroll_clamped: scroll={} clamped={}",
                    scroll,
                    clamped
                );
            }
            *overlay = Overlay::Help { scroll: clamped };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys a help entry names, split on its separators.
    fn named_keys() -> Vec<&'static str> {
        KEY_HELP
            .iter()
            .flat_map(|(keys, _)| keys.split([' ', ',', '/']))
            .filter(|key| !key.is_empty())
            .collect()
    }

    #[test]
    fn key_help_names_every_key_the_dashboard_takes() {
        let named = named_keys();
        for key in [
            "h", "l", "j", "k", "?", "p", "Esc", "Enter", "q", "Ctrl-C", "Tab", "Home",
        ] {
            assert!(named.contains(&key), "KEY_HELP does not name `{key}`: {named:?}");
        }
    }

    #[test]
    fn centered_box_shrinks_to_a_small_frame() {
        assert_eq!(centered(Rect::new(0, 0, 80, 24), 20, 10), Rect::new(30, 7, 20, 10));
        assert_eq!(centered(Rect::new(0, 0, 10, 4), 20, 10), Rect::new(0, 0, 10, 4));
    }

    #[test]
    fn help_scrolls_only_when_the_frame_is_shorter_than_its_rows() {
        assert_eq!(help_max_scroll(Rect::new(0, 0, 80, 24)), 0);
        // 8 rows: two border rows leave 6 of the 9 entries.
        assert_eq!(help_max_scroll(Rect::new(0, 0, 80, 8)), (KEY_HELP.len() - 6) as u16);
    }

    #[test]
    fn help_fits_an_80_column_frame_unclipped() {
        let (rect, inner) = help_rects(Rect::new(0, 0, 80, 24));
        assert!(rect.width < 80, "help box is {} wide", rect.width);
        let widest = help_rows().iter().map(Line::width).max().unwrap_or(0);
        assert!(widest <= usize::from(inner.width));
    }
}
