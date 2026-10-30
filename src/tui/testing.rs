//! Test-only helper that renders a pane into a `TestBackend` buffer.

use crate::tui::pane::Pane;
use crate::types::AppState;
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer, layout::Rect, style::Color, text::Span};

/// Render `pane` at `width` x `height` into a buffer that keeps each cell's style.
pub fn render_buffer(pane: &dyn Pane, state: &AppState, width: u16, height: u16, focused: bool) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("TestBackend terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            pane.render(frame, area, state, focused);
        })
        .expect("draw pane");
    terminal.backend().buffer().clone()
}

/// Row `y` of `buffer` as text, with the x of the cell each byte offset starts at. The
/// continuation cell after a double-width glyph is dropped, as a terminal shows it.
fn buffer_row(buffer: &Buffer, y: u16) -> (String, Vec<(usize, u16)>) {
    let mut row = String::new();
    let mut starts = Vec::new();
    let mut x = 0;
    while x < buffer.area.width {
        let symbol = buffer[(x, y)].symbol();
        starts.push((row.len(), x));
        row.push_str(symbol);
        x += Span::raw(symbol).width().max(1) as u16;
    }
    (row, starts)
}

/// Render `pane` at `width` x `height` and return the buffer as newline-joined text rows.
pub fn render_pane(pane: &dyn Pane, state: &AppState, width: u16, height: u16, focused: bool) -> String {
    let buffer = render_buffer(pane, state, width, height, focused);
    (0..height)
        .map(|y| buffer_row(&buffer, y).0)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The foreground color of the first cell of the first occurrence of `needle` in `buffer`.
pub fn fg_of(buffer: &Buffer, needle: &str) -> Color {
    for y in 0..buffer.area.height {
        let (row, starts) = buffer_row(buffer, y);
        if let Some(offset) = row.find(needle) {
            let x = starts
                .iter()
                .find(|(start, _)| *start == offset)
                .map(|(_, x)| *x)
                .expect("needle starts on a cell boundary");
            return buffer[(x, y)].fg;
        }
    }
    panic!("{needle:?} not rendered");
}

/// The narrow terminals the clipping fixtures render at: Scott's 80x24 and his ~108-column
/// screenshot.
pub const NARROW_TERMINALS: [(u16, u16); 2] = [(80, 24), (108, 40)];

/// Width and height of the dashboard cell at `row`, `col` in a `cols` x `rows` terminal, as
/// `PaneLayout` splits it.
pub fn dashboard_pane_size(row: usize, col: usize, cols: u16, rows: u16) -> (u16, u16) {
    let grid = crate::tui::layout::grid_layout(Rect::new(0, 0, cols, rows));
    let cell = grid[row][col];
    (cell.width, cell.height)
}

/// What a line of `source` text must show in `width` cells: the longest char prefix that leaves
/// one cell for `…`, then `…`. Built from the source text, independently of `fit_line`.
pub fn expected_clip(source: &str, width: u16) -> String {
    let budget = usize::from(width) - 1;
    let mut used = 0;
    let mut prefix = String::new();
    for c in source.chars() {
        let c_width = Span::raw(c.to_string()).width();
        if used + c_width > budget {
            break;
        }
        prefix.push(c);
        used += c_width;
    }
    format!("{prefix}…")
}

/// Render `pane` in its dashboard cell (`row`, `col`) of each narrow terminal and assert one row
/// shows exactly `expected_clip(source)` between the borders.
pub fn assert_clipped_in_narrow_terminals(pane: &dyn Pane, state: &AppState, row: usize, col: usize, source: &str) {
    for (cols, rows) in NARROW_TERMINALS {
        let (width, height) = dashboard_pane_size(row, col, cols, rows);
        let inner_width = width - 2;
        assert!(
            Span::raw(source).width() > usize::from(inner_width),
            "{cols}x{rows}: fixture `{source}` fits {inner_width} cells, so it cannot test clipping"
        );
        let expected = expected_clip(source, inner_width);
        let out = render_pane(pane, state, width, height, false);
        let found = out.lines().any(|line| {
            line.strip_prefix('│')
                .and_then(|inner| inner.strip_prefix(expected.as_str()))
                .is_some_and(|rest| rest.trim_end_matches('│').trim().is_empty())
        });
        assert!(
            found,
            "{} at {cols}x{rows} ({width}x{height}): no row reads `{expected}`:\n{out}",
            pane.title()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    #[test]
    fn dashboard_pane_sizes_follow_the_layout_percentages() {
        // 80 cols: target 30% = 24, connectivity 70% = 56; the four middle panes 20 each.
        assert_eq!(dashboard_pane_size(0, 0, 80, 24).0, 24);
        assert_eq!(dashboard_pane_size(0, 1, 80, 24), (56, 6));
        assert_eq!(dashboard_pane_size(1, 0, 80, 24).0, 20);
    }

    #[test]
    fn expected_clip_keeps_a_prefix_one_cell_short_of_the_width() {
        assert_eq!(expected_clip("abcdef", 4), "abc…");
        assert_eq!(expected_clip("🎯 abc", 4), "🎯 …");
        assert_eq!(expected_clip("a🦀b", 3), "a…");
    }

    fn assert_renders_title(pane: &dyn Pane) {
        let state = AppState::new("example.com".to_string());
        let out = render_pane(pane, &state, 80, 24, false);
        assert!(
            out.contains(&pane.title().to_uppercase()),
            "{} pane render missing title:\n{}",
            pane.title(),
            out
        );
    }

    #[test]
    fn render_target_title() {
        assert_renders_title(&TargetPane::new());
    }

    #[test]
    fn render_connectivity_title() {
        assert_renders_title(&ConnectivityPane::new());
    }

    #[test]
    fn render_whois_title() {
        assert_renders_title(&WhoisPane::new());
    }

    #[test]
    fn render_http_title() {
        assert_renders_title(&HttpPane::new());
    }

    #[test]
    fn render_ports_title() {
        assert_renders_title(&PortsPane::new());
    }

    #[test]
    fn render_geoip_title() {
        assert_renders_title(&GeoIpPane::new());
    }

    #[test]
    fn render_dns_title() {
        assert_renders_title(&DnsPane::new());
    }

    #[test]
    fn render_traceroute_title() {
        assert_renders_title(&TraceroutePane::new());
    }

    #[test]
    fn render_security_title() {
        assert_renders_title(&SecurityPane::new());
    }

    #[test]
    fn render_helper_distinguishes_wrong_title() {
        let state = AppState::new("example.com".to_string());
        let out = render_pane(&DnsPane::new(), &state, 80, 24, false);
        assert!(!out.contains("SECURITY"));
    }

    fn failed_first_scan(scanner: &str) -> AppState {
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            scanner.to_string(),
            crate::types::ScanState {
                result: None,
                error: Some(eyre::eyre!("timed out after 30s")),
                status: crate::types::ScanStatus::Failed,
                last_updated: std::time::Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    #[test]
    fn every_status_pane_names_a_failed_first_scan() {
        let panes: Vec<(&str, Box<dyn Pane>)> = vec![
            ("ping", Box::new(ConnectivityPane::new())),
            ("dns", Box::new(DnsPane::new())),
            ("tls", Box::new(SecurityPane::new())),
            ("http", Box::new(HttpPane::new())),
            ("whois", Box::new(WhoisPane::new())),
            ("traceroute", Box::new(TraceroutePane::new())),
            ("geoip", Box::new(GeoIpPane::new())),
            ("port", Box::new(PortsPane::new())),
        ];
        for (scanner, pane) in panes {
            let out = render_pane(pane.as_ref(), &failed_first_scan(scanner), 100, 30, false);
            assert!(
                out.contains("failed: timed out after 30s"),
                "{scanner}: failure reason missing:\n{out}"
            );
            for pending in [
                "checking",
                "analyzing",
                "resolving",
                "scanning...",
                "querying",
                "locating",
                "tracing",
            ] {
                assert!(!out.contains(pending), "{scanner}: still shows `{pending}`:\n{out}");
            }
        }
    }

    #[test]
    fn failed_http_traceroute_and_ports_panes_show_status_once() {
        let panes: Vec<(&str, Box<dyn Pane>)> = vec![
            ("http", Box::new(HttpPane::new())),
            ("traceroute", Box::new(TraceroutePane::new())),
            ("port", Box::new(PortsPane::new())),
        ];
        for (scanner, pane) in panes {
            let out = render_pane(pane.as_ref(), &failed_first_scan(scanner), 100, 30, false);
            assert_eq!(out.matches("Status:").count(), 1, "{scanner}:\n{out}");
        }
    }
}
