//! Semantic palette for every pane. Panes name a meaning (`BAD`, `MUTED`), never a raw
//! `Color::`; a unit test fails on any `Color::` outside this file and `#[cfg(test)]` modules.

use ratatui::style::Color;

// A btop-style palette: gray labels, bright values, status hues from btop's cpu gradient
// (green -> yellow -> red), and graphs shaded deep-to-bright. Truecolor throughout.

/// Painted under every cell, as btop does, so the terminal's own background never shows through.
pub const BACKGROUND: Color = Color::Rgb(0x00, 0x00, 0x00);
/// A fault: failure, error, 5xx, expired, closed-by-error.
pub const BAD: Color = Color::Rgb(0xdc, 0x4c, 0x4c);
/// Degraded but not failed: slow, short TTL, many open ports, missing header.
pub const WARN: Color = Color::Rgb(0xcb, 0xc0, 0x6c);
/// Healthy or hardened: success, locks, passing checks.
pub const GOOD: Color = Color::Rgb(0x77, 0xca, 0x9b);
/// A data value shown to the user: addresses, names, records.
pub const VALUE: Color = Color::Rgb(0xe6, 0xe6, 0xe6);
/// A field label or neutral text.
pub const LABEL: Color = Color::Rgb(0x9a, 0x9a, 0x9a);
/// De-emphasised text: pending, not applicable, hints.
pub const MUTED: Color = Color::Rgb(0x5c, 0x5c, 0x5c);
/// Decorative emphasis for body text that is neither a value nor a status.
pub const ACCENT: Color = Color::Rgb(0xb0, 0xa9, 0xde);
/// A pane title on its top border.
pub const TITLE: Color = Color::Rgb(0xee, 0xee, 0xee);
/// The focused pane's title, btop's hotkey red.
pub const TITLE_FOCUSED: Color = Color::Rgb(0xff, 0x6a, 0x6a);
/// Border of the focused pane.
pub const BORDER_FOCUSED: Color = Color::Rgb(0xee, 0xee, 0xee);
/// Border of a pane with no box color of its own.
pub const BORDER_UNFOCUSED: Color = Color::Rgb(0x50, 0x50, 0x50);

/// Fraction of `base` a graph's bottom row keeps: deep, nearly the background.
const GRAPH_FLOOR: f32 = 0.3;
/// How far a graph's top row is washed from `base` toward white.
const GRAPH_CREST: f32 = 0.45;

/// The color of a graph row `t` of the way up (0 bottom, 1 top) in `base`'s hue: deep at the
/// floor, `base` at mid-height, washed toward white at the top, as btop shades its net graph.
pub fn graph_shade(base: Color, t: f32) -> Color {
    let Color::Rgb(r, g, b) = base else {
        return base;
    };
    let t = t.clamp(0.0, 1.0);
    let channel = |c: u8| {
        let c = f32::from(c);
        let shaded = if t < 0.5 {
            c * (GRAPH_FLOOR + (1.0 - GRAPH_FLOOR) * t * 2.0)
        } else {
            c + (255.0 - c) * GRAPH_CREST * (t - 0.5) * 2.0
        };
        shaded.round().clamp(0.0, 255.0) as u8
    };
    Color::Rgb(channel(r), channel(g), channel(b))
}

/// Each pane's box color, so neighbouring panes read as separate boxes the way btop's cpu, mem,
/// net and proc boxes do.
pub fn pane_border(id: &str) -> Color {
    match id {
        "target" => Color::Rgb(0x3d, 0x7b, 0x46),
        "connectivity" => Color::Rgb(0x42, 0x3b, 0xa5),
        "whois" => Color::Rgb(0x8a, 0x88, 0x2e),
        "http" => Color::Rgb(0x2e, 0x6f, 0x8a),
        "ports" => Color::Rgb(0x92, 0x35, 0x35),
        "geoip" => Color::Rgb(0x7d, 0x41, 0x80),
        "dns" => Color::Rgb(0x2e, 0x7a, 0x6a),
        "traceroute" => Color::Rgb(0x8a, 0x5a, 0x2e),
        "security" => Color::Rgb(0x3b, 0x5b, 0xa5),
        _ => BORDER_UNFOCUSED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn graph_shade_runs_deep_to_base_to_washed() {
        let base = Color::Rgb(100, 200, 50);
        assert_eq!(graph_shade(base, 0.0), Color::Rgb(30, 60, 15));
        assert_eq!(graph_shade(base, 0.5), base);
        assert_eq!(graph_shade(base, 1.0), Color::Rgb(170, 225, 142));
        assert_eq!(graph_shade(Color::Reset, 0.7), Color::Reset);
    }

    /// `mod <name> {` or `pub mod <name> {`: an inline module body opens on this line.
    fn opens_inline_module(line: &str) -> bool {
        let trimmed = line.trim();
        let declaration = trimmed.strip_prefix("pub ").unwrap_or(trimmed);
        declaration.starts_with("mod ") && declaration.contains('{')
    }

    /// Non-comment lines of `source` that mention `needle`, outside the body of any inline
    /// `#[cfg(test)]` module. Only a module body is skipped: a `#[cfg(test)]` on a function, an
    /// import or a `mod name;` declaration leaves the lines after it scanned.
    fn production_lines_with(source: &str, needle: &str) -> Vec<(usize, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            if line.trim() == "#[cfg(test)]"
                && let Some(next) = lines.get(index + 1)
                && opens_inline_module(next)
            {
                let opened_and_closed = next.matches('{').count() == next.matches('}').count();
                let indent = &next[..next.len() - next.trim_start().len()];
                let close = format!("{indent}}}");
                index += 2;
                if !opened_and_closed {
                    while index < lines.len() && lines[index] != close {
                        index += 1;
                    }
                    index += 1;
                }
                continue;
            }
            if !line.trim_start().starts_with("//") && line.contains(needle) {
                found.push((index + 1, line.trim().to_string()));
            }
            index += 1;
        }
        found
    }

    fn tui_sources() -> Vec<(String, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
        let mut sources: Vec<_> = std::fs::read_dir(&dir)
            .expect("read src/tui")
            .map(|entry| entry.expect("dir entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .map(|path| {
                let name = path.file_name().expect("file name").to_string_lossy().into_owned();
                (name, std::fs::read_to_string(&path).expect("read source"))
            })
            .collect();
        sources.sort();
        assert!(sources.len() > 10, "found only {} tui sources", sources.len());
        sources
    }

    #[test]
    fn no_color_literal_outside_theme_and_test_modules() {
        let offenders: Vec<String> = tui_sources()
            .iter()
            .filter(|(name, _)| name != "theme.rs")
            .flat_map(|(name, source)| {
                production_lines_with(source, "Color::")
                    .into_iter()
                    .map(move |(line, text)| format!("src/tui/{name}:{line}: {text}"))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "use a theme constant, not Color::\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn the_color_lint_catches_a_color_added_to_a_pane() {
        let pane = "fn render() {\n    Style::default().fg(Color::Red)\n}\n#[cfg(test)]\nmod tests { Color::Red }\n";
        assert_eq!(
            production_lines_with(pane, "Color::"),
            vec![(2, "Style::default().fg(Color::Red)".to_string())]
        );
        assert!(production_lines_with("// Color::Red in a comment\n", "Color::").is_empty());
    }

    #[test]
    fn the_color_lint_scans_past_a_test_only_item_and_skips_only_the_test_module_body() {
        let pane = "\
#[cfg(test)]
pub mod testing;
impl Pane {
    #[cfg(test)]
    fn sample_counts() -> usize { 0 }

    fn render() {
        Style::default().fg(Color::Red)
    }
}

#[cfg(test)]
mod tests {
    fn helper() {
        Color::Blue
    }
}
fn after_tests() { Color::Green }
";
        assert_eq!(
            production_lines_with(pane, "Color::"),
            vec![
                (8, "Style::default().fg(Color::Red)".to_string()),
                (18, "fn after_tests() { Color::Green }".to_string()),
            ]
        );
    }

    /// Lines where a non-ASCII glyph is followed by two spaces. The second space made up for a
    /// glyph drawn 1 cell wide; with 2-cell glyphs it pushes the label a column right of its
    /// neighbours.
    fn glyph_double_space_lines(source: &str) -> Vec<usize> {
        source
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .filter(|(_, line)| {
                line.char_indices()
                    .any(|(at, ch)| !ch.is_ascii() && line[at + ch.len_utf8()..].starts_with("  "))
            })
            .map(|(index, _)| index + 1)
            .collect()
    }

    #[test]
    fn no_pane_label_pads_a_glyph_with_two_spaces() {
        let offenders: Vec<String> = tui_sources()
            .iter()
            .flat_map(|(name, source)| {
                glyph_double_space_lines(source)
                    .into_iter()
                    .map(move |line| format!("src/tui/{name}:{line}"))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "one space after a glyph, like the neighbouring labels:\n{}",
            offenders.join("\n")
        );
        assert_eq!(
            glyph_double_space_lines("\"\u{23F3}  Time: \"\n\"\u{1F4CA} Status: \"\n"),
            vec![1]
        );
    }

    #[test]
    fn no_pane_source_contains_a_variation_selector() {
        let offenders: Vec<String> = tui_sources()
            .iter()
            .flat_map(|(name, source)| {
                source
                    .lines()
                    .enumerate()
                    .filter(|(_, line)| line.contains('\u{FE0F}'))
                    .map(move |(index, _)| format!("src/tui/{name}:{}", index + 1))
            })
            .collect();
        assert!(
            offenders.is_empty(),
            "U+FE0F glyphs render 1 cell in some terminals:\n{}",
            offenders.join("\n")
        );
    }
}
