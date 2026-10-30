// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Part of scan's port of mdn/mdn-http-observatory at commit 2776308.

//! The JavaScript string semantics the ported analyzers lean on: what `trim`, `slice`,
//! `split(/\s+/)` and `Number.parseInt` do. Upstream truncates headers with `slice(0, 1024)` in
//! UTF-16 code units and trims with JS's whitespace set, so the port does the same.

/// JS `WhiteSpace` + `LineTerminator`: what `String.prototype.trim` and `\s` match.
pub fn is_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

/// `String.prototype.trim`.
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_whitespace)
}

/// `s.length`: UTF-16 code units.
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.slice(start, end)` in UTF-16 code units. A cut through a surrogate pair yields U+FFFD where
/// JS would keep a lone surrogate, which no analyzer compares against.
pub fn slice(s: &str, start: usize, end: usize) -> String {
    if s.len() <= end && start == 0 && s.is_ascii() {
        return s.to_string();
    }
    let units: Vec<u16> = s.encode_utf16().collect();
    let end = end.min(units.len());
    let start = start.min(end);
    String::from_utf16_lossy(&units[start..end])
}

/// `s.split(/\s+/)`: a leading or trailing run of whitespace yields an empty first or last
/// element, and the empty string splits into `[""]`.
pub fn split_whitespace(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_run = false;
    for (i, c) in s.char_indices() {
        if is_whitespace(c) {
            if !in_run {
                parts.push(&s[start..i]);
                in_run = true;
            }
        } else if in_run {
            start = i;
            in_run = false;
        }
    }
    parts.push(if in_run { "" } else { &s[start..] });
    parts
}

/// `Number.parseInt(s, 10)`: leading whitespace, an optional sign, then the longest run of digits.
/// `NaN` when there are no digits, which compares false against every number, as in JS.
pub fn parse_int(s: &str) -> f64 {
    let s = s.trim_start_matches(is_whitespace);
    let (sign, rest) = match s.strip_prefix('-') {
        Some(rest) => (-1.0, rest),
        None => (1.0, s.strip_prefix('+').unwrap_or(s)),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return f64::NAN;
    }
    sign * digits.parse::<f64>().unwrap_or(f64::NAN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_strips_js_whitespace_including_bom_but_not_nel() {
        assert_eq!(trim("\u{FEFF} a \u{3000}"), "a");
        assert_eq!(trim("\u{85}a"), "\u{85}a");
    }

    #[test]
    fn slice_counts_utf16_units() {
        assert_eq!(slice("abcdef", 0, 3), "abc");
        assert_eq!(slice("é😀x", 0, 3), "é😀");
        assert_eq!(slice("ab", 0, 1024), "ab");
        assert_eq!(slice("😀", 0, 1), "\u{FFFD}");
    }

    #[test]
    fn split_whitespace_matches_js_regex_split() {
        assert_eq!(split_whitespace(""), vec![""]);
        assert_eq!(split_whitespace("a  b"), vec!["a", "b"]);
        assert_eq!(split_whitespace(" a"), vec!["", "a"]);
        assert_eq!(split_whitespace("a "), vec!["a", ""]);
    }

    #[test]
    fn parse_int_reads_a_leading_integer_or_nan() {
        assert_eq!(parse_int(" 15552000abc"), 15_552_000.0);
        assert_eq!(parse_int("-5"), -5.0);
        assert!(parse_int("abc").is_nan());
        assert!(parse_int("").is_nan());
    }
}
