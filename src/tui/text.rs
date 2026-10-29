//! Fitting pane lines to the width they are drawn in.

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

/// `lines` for a wrapping `Paragraph` of `width`: every line is fit to `width` except those at the
/// indices in `wrapped`, the failure and status-reason lines, which are left whole to wrap.
pub fn fit_lines_except<'a>(lines: Vec<Line<'a>>, width: u16, wrapped: &[usize]) -> Vec<Line<'a>> {
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| if wrapped.contains(&index) { line } else { fit_line(line, width) })
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
    fn fit_lines_except_leaves_wrapped_rows_whole() {
        let lines = vec![two_spans(), two_spans()];
        let fitted = fit_lines_except(lines, 5, &[1]);
        assert_eq!(text(&fitted[0]), "Doma…");
        assert_eq!(text(&fitted[1]), "Domain: example.com");
    }
}
