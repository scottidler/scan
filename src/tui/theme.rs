//! Semantic palette for every pane. Panes name a meaning (`BAD`, `MUTED`), never a raw
//! `Color::`; a unit test fails on any `Color::` outside this file and `#[cfg(test)]` modules.

use ratatui::style::Color;

/// A fault: failure, error, 5xx, expired, closed-by-error. ANSI 9 so it reads as red on any palette.
pub const BAD: Color = Color::LightRed;
/// Degraded but not failed: slow, short TTL, many open ports, missing header.
pub const WARN: Color = Color::Yellow;
/// Healthy or hardened: success, locks, passing checks.
pub const GOOD: Color = Color::Green;
/// A data value shown to the user: addresses, names, records.
pub const VALUE: Color = Color::Cyan;
/// A field label or neutral text.
pub const LABEL: Color = Color::White;
/// De-emphasised text: pending, not applicable, hints.
pub const MUTED: Color = Color::Gray;
/// Decorative emphasis for body text that is neither a value nor a status.
pub const ACCENT: Color = Color::Magenta;
/// Border of the focused pane.
pub const BORDER_FOCUSED: Color = Color::Yellow;
/// Border of an unfocused pane.
pub const BORDER_UNFOCUSED: Color = Color::Gray;

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Non-comment lines of `source` before its `#[cfg(test)]` module that mention `needle`.
    fn production_lines_with(source: &str, needle: &str) -> Vec<(usize, String)> {
        source
            .lines()
            .take_while(|line| line.trim() != "#[cfg(test)]")
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//") && line.contains(needle))
            .map(|(index, line)| (index + 1, line.trim().to_string()))
            .collect()
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
