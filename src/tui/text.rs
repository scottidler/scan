//! Char-safe text shortening for pane lines.

/// `text` unchanged when it has at most `max_chars` chars, else its first `keep_chars` chars
/// plus `...`. Counted in chars, not bytes: a byte cut inside a multibyte char panics the draw loop.
pub fn ellipsize(text: &str, max_chars: usize, keep_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        format!("{}...", text.chars().take(keep_chars).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_unchanged() {
        assert_eq!(ellipsize("abc", 3, 1), "abc");
        assert_eq!(ellipsize("ééé", 3, 1), "ééé");
    }

    #[test]
    fn long_text_keeps_chars_and_appends_ellipsis() {
        assert_eq!(ellipsize("abcdef", 5, 2), "ab...");
        assert_eq!(ellipsize(&"é".repeat(10), 5, 2), "éé...");
        assert_eq!(ellipsize("a🦀🦀🦀", 2, 2), "a🦀...");
    }
}
