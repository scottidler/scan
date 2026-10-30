//! Fitting pane lines to the width they are drawn in.

use crate::tui::pane::Detail;
use ratatui::{
    style::Style,
    text::{Line, Span},
};

/// Marks a line cut short by `fit_line`.
pub const ELLIPSIS: &str = "…";

/// `line` cut to `width` display cells, ending in `…`, or unchanged when it already fits.
///
/// Width is measured as ratatui lays text out (unicode-width per grapheme), across spans: every
/// span keeps its style up to the cut, and the `…` takes the style of the span it cuts. A wide
/// glyph that would straddle the cut is dropped whole, never split. Width 0 yields an empty line,
/// width 1 just `…`.
pub fn fit_line(line: Line<'_>, width: u16) -> Line<'_> {
    let width = usize::from(width);
    if line.width() <= width {
        return line;
    }
    let Line {
        style,
        alignment,
        spans,
    } = line;
    let mut fitted: Vec<Span<'_>> = Vec::new();
    if width == 0 {
        return Line {
            style,
            alignment,
            spans: fitted,
        };
    }
    let budget = width - Span::raw(ELLIPSIS).width();
    let mut used = 0;
    let mut ellipsis_style = Style::default();
    for span in &spans {
        ellipsis_style = span.style;
        let mut kept = String::new();
        let mut cut = false;
        for grapheme in span.styled_graphemes(Style::default()) {
            let grapheme_width = Span::raw(grapheme.symbol).width();
            if used + grapheme_width > budget {
                cut = true;
                break;
            }
            kept.push_str(grapheme.symbol);
            used += grapheme_width;
        }
        if !kept.is_empty() {
            fitted.push(Span::styled(kept, span.style));
        }
        if cut {
            break;
        }
    }
    fitted.push(Span::styled(ELLIPSIS, ellipsis_style));
    Line {
        style,
        alignment,
        spans: fitted,
    }
}

/// `line` broken into rows of at most `width` display cells, one `Line` per screen row.
///
/// Rows break after the last space that fits; a word longer than a row is broken between
/// graphemes, and a wide glyph that would straddle the edge starts the next row. Every span keeps
/// its style and every row keeps the line's style and alignment. An empty line is one empty row;
/// width 0 yields one empty row, since nothing can be drawn.
pub fn wrap_line(line: Line<'_>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width);
    let Line {
        style,
        alignment,
        spans,
    } = line;
    let row = |cells: &[(String, Style)]| Line {
        style,
        alignment,
        spans: merge_cells(cells),
    };
    if width == 0 {
        return vec![row(&[])];
    }
    let cells: Vec<(String, Style)> = spans
        .iter()
        .flat_map(|span| {
            span.styled_graphemes(Style::default())
                .map(|grapheme| (grapheme.symbol.to_string(), grapheme.style))
                .collect::<Vec<_>>()
        })
        .collect();

    let mut rows = Vec::new();
    let mut current: Vec<(String, Style)> = Vec::new();
    let mut used = 0;
    // Index in `current` just past the last space, where the row may break.
    let mut break_at: Option<usize> = None;
    for cell in cells {
        let cell_width = Span::raw(cell.0.as_str()).width();
        if used + cell_width > width && !current.is_empty() {
            let carried = match break_at {
                Some(at) if at < current.len() => current.split_off(at),
                _ => Vec::new(),
            };
            rows.push(row(&current));
            used = carried
                .iter()
                .map(|(symbol, _)| Span::raw(symbol.as_str()).width())
                .sum();
            current = carried;
            break_at = None;
        }
        let is_space = cell.0 == " ";
        current.push(cell);
        used += cell_width;
        if is_space {
            break_at = Some(current.len());
        }
    }
    rows.push(row(&current));
    rows
}

/// Adjacent graphemes of one style joined back into a single span.
fn merge_cells(cells: &[(String, Style)]) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    for (symbol, style) in cells {
        match spans.last_mut() {
            Some(last) if last.style == *style => last.content.to_mut().push_str(symbol),
            _ => spans.push(Span::styled(symbol.clone(), *style)),
        }
    }
    spans
}

/// `line` with its text owned, so it outlives the state it was built from.
pub fn owned(line: Line<'_>) -> Line<'static> {
    Line {
        style: line.style,
        alignment: line.alignment,
        spans: line
            .spans
            .into_iter()
            .map(|span| Span::styled(span.content.into_owned(), span.style))
            .collect(),
    }
}

/// `lines` laid out as screen rows of `width` for `detail`: one `Line` per row.
///
/// Normal detail fits every line to one row with `fit_line`, except those at the indices in
/// `wrapped` (failure and status-reason lines), which wrap so their cause stays readable. Zoomed
/// detail wraps every line, so a long TXT record, URL or certificate name is shown whole.
pub fn to_rows(lines: Vec<Line<'_>>, width: u16, detail: Detail, wrapped: &[usize]) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .enumerate()
        .flat_map(|(index, line)| {
            if detail == Detail::Zoomed || wrapped.contains(&index) {
                wrap_line(line, width)
            } else {
                vec![owned(fit_line(line, width))]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn text(line: &Line<'_>) -> String {
        line.spans.iter().map(|span| span.content.as_ref()).collect()
    }

    fn two_spans() -> Line<'static> {
        Line::from(vec![
            Span::styled("Domain: ", Style::default().fg(Color::White)),
            Span::styled("example.com", Style::default().fg(Color::Cyan)),
        ])
    }

    #[test]
    fn line_that_fits_is_unchanged() {
        let line = two_spans();
        assert_eq!(fit_line(line.clone(), 19), line);
        assert_eq!(fit_line(line.clone(), 80), line);
    }

    #[test]
    fn truncates_across_spans_keeping_each_style() {
        let fitted = fit_line(two_spans(), 12);
        assert_eq!(text(&fitted), "Domain: exa…");
        assert_eq!(fitted.width(), 12);
        assert_eq!(
            fitted.spans[0],
            Span::styled("Domain: ", Style::default().fg(Color::White))
        );
        assert_eq!(fitted.spans[1], Span::styled("exa", Style::default().fg(Color::Cyan)));
        assert_eq!(fitted.spans[2], Span::styled("…", Style::default().fg(Color::Cyan)));
    }

    #[test]
    fn cut_inside_the_first_span_drops_the_later_spans() {
        let fitted = fit_line(two_spans(), 5);
        assert_eq!(text(&fitted), "Doma…");
        assert_eq!(fitted.spans.len(), 2);
        assert_eq!(fitted.spans[1].style, Style::default().fg(Color::White));
    }

    #[test]
    fn width_zero_renders_nothing() {
        let fitted = fit_line(two_spans(), 0);
        assert!(fitted.spans.is_empty(), "{fitted:?}");
        assert_eq!(fitted.width(), 0);
    }

    #[test]
    fn width_one_renders_only_the_ellipsis() {
        let fitted = fit_line(two_spans(), 1);
        assert_eq!(text(&fitted), "…");
    }

    #[test]
    fn wide_glyph_straddling_the_cut_is_dropped_not_split() {
        // `ab` then a 2-cell crab: at width 4 the budget before `…` is 3, so the crab would need
        // cells 3-4 and is dropped whole.
        let fitted = fit_line(Line::from("ab🦀🦀"), 4);
        assert_eq!(text(&fitted), "ab…");
        assert_eq!(fitted.width(), 3);
        // At width 5 the crab fits before the `…`.
        assert_eq!(text(&fit_line(Line::from("ab🦀🦀"), 5)), "ab🦀…");
    }

    #[test]
    fn multibyte_text_is_cut_on_char_boundaries() {
        let fitted = fit_line(Line::from("é".repeat(10)), 4);
        assert_eq!(text(&fitted), "ééé…");
    }

    #[test]
    fn line_style_and_alignment_survive_the_cut() {
        let line = two_spans().style(Style::default().fg(Color::Red)).centered();
        let fitted = fit_line(line, 6);
        assert_eq!(fitted.style, Style::default().fg(Color::Red));
        assert_eq!(fitted.alignment, Some(ratatui::layout::Alignment::Center));
    }

    #[test]
    fn to_rows_fits_normal_lines_and_wraps_the_listed_ones() {
        let lines = vec![two_spans(), two_spans()];
        let rows = to_rows(lines, 10, Detail::Normal, &[1]);
        let texts: Vec<String> = rows.iter().map(text).collect();
        assert_eq!(texts, ["Domain: e…", "Domain: ", "example.co", "m"]);
    }

    #[test]
    fn to_rows_wraps_every_line_when_zoomed() {
        let rows = to_rows(vec![two_spans()], 10, Detail::Zoomed, &[]);
        let texts: Vec<String> = rows.iter().map(text).collect();
        assert_eq!(texts, ["Domain: ", "example.co", "m"]);
    }

    #[test]
    fn wrap_line_breaks_after_the_last_space_that_fits() {
        let rows = wrap_line(Line::from("failed: connection refused by peer"), 12);
        let texts: Vec<String> = rows.iter().map(text).collect();
        assert_eq!(texts, ["failed: ", "connection ", "refused by ", "peer"]);
        assert!(rows.iter().all(|row| row.width() <= 12), "{rows:?}");
    }

    #[test]
    fn wrap_line_keeps_each_span_style_across_rows() {
        let rows = wrap_line(two_spans(), 10);
        assert_eq!(
            rows[0].spans,
            [Span::styled("Domain: ", Style::default().fg(Color::White))]
        );
        assert_eq!(
            rows[1].spans,
            [Span::styled("example.co", Style::default().fg(Color::Cyan))]
        );
        assert_eq!(rows[2].spans, [Span::styled("m", Style::default().fg(Color::Cyan))]);
    }

    #[test]
    fn wrap_line_that_fits_is_one_row() {
        let rows = wrap_line(two_spans(), 80);
        assert_eq!(rows, vec![two_spans()]);
    }

    #[test]
    fn wrap_line_moves_a_straddling_wide_glyph_to_the_next_row() {
        let rows = wrap_line(Line::from("ab🦀cd"), 3);
        let texts: Vec<String> = rows.iter().map(text).collect();
        assert_eq!(texts, ["ab", "🦀c", "d"]);
    }

    #[test]
    fn wrap_line_of_empty_line_or_zero_width_is_one_empty_row() {
        assert_eq!(wrap_line(Line::from(""), 10).len(), 1);
        let rows = wrap_line(two_spans(), 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].width(), 0);
    }

    #[test]
    fn wrap_line_keeps_line_style_and_alignment_on_every_row() {
        let line = two_spans().style(Style::default().fg(Color::Red)).centered();
        for row in wrap_line(line, 10) {
            assert_eq!(row.style, Style::default().fg(Color::Red));
            assert_eq!(row.alignment, Some(ratatui::layout::Alignment::Center));
        }
    }
}
