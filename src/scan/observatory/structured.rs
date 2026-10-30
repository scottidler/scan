// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (parseStructuredFieldToken in
// src/analyzer/utils.js). The item parser mirrors `parseItem` of structured-headers 2.1.1 (MIT,
// © 2018-2026 Evert Pot), the RFC 8941/9651 parser upstream calls.

//! `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` are RFC 8941 items: the policy
//! is the item's token, and a value that does not parse as an item is no policy at all.
//! Positions count UTF-16 code units, as the JavaScript parser does.

/// The bare item's token when `value` parses as a structured field item whose bare item is a
/// token; `None` for a parse failure or any other bare item type (a string, a number, ...).
pub fn parse_token_item(value: &str) -> Option<String> {
    let mut parser = Parser {
        input: value.encode_utf16().collect(),
        pos: 0,
    };
    match parser.parse_item() {
        Ok(BareItem::Token(token)) => Some(token),
        Ok(BareItem::Other) => None,
        Err(()) => {
            log::trace!(
                "[observatory::structured] parse_token_item: not an item: value={:?}",
                value
            );
            None
        }
    }
}

enum BareItem {
    Token(String),
    Other,
}

type Parse<T> = Result<T, ()>;

struct Parser {
    input: Vec<u16>,
    pos: usize,
}

fn is_digit(c: Option<u16>) -> bool {
    c.is_some_and(|c| (u16::from(b'0')..=u16::from(b'9')).contains(&c))
}

fn is_lc_alpha(c: u16) -> bool {
    (u16::from(b'a')..=u16::from(b'z')).contains(&c)
}

fn is_alpha(c: u16) -> bool {
    is_lc_alpha(c) || (u16::from(b'A')..=u16::from(b'Z')).contains(&c)
}

fn is_token_char(c: u16) -> bool {
    is_alpha(c) || is_digit(Some(c)) || b":/!#$%&'*+-.^_`|~".iter().any(|&b| u16::from(b) == c)
}

fn is_key_char(c: u16) -> bool {
    is_lc_alpha(c) || is_digit(Some(c)) || b"_-.*".iter().any(|&b| u16::from(b) == c)
}

/// WHATWG forgiving-base64 decode (`atob`), on input already limited to `[A-Za-z0-9+/=]`.
fn is_forgiving_base64(content: &[u16]) -> bool {
    let mut data = content;
    if data.len().is_multiple_of(4) {
        for _ in 0..2 {
            if data.last() == Some(&u16::from(b'=')) {
                data = &data[..data.len() - 1];
            }
        }
    }
    data.len() % 4 != 1 && !data.contains(&u16::from(b'='))
}

impl Parser {
    fn look(&self) -> Option<u16> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u16> {
        let c = self.look();
        self.pos += 1;
        c
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn skip_ws(&mut self) {
        while self.look() == Some(u16::from(b' ')) {
            self.pos += 1;
        }
    }

    fn expect(&self, c: u8) -> Parse<()> {
        if self.look() == Some(u16::from(c)) { Ok(()) } else { Err(()) }
    }

    fn parse_item(&mut self) -> Parse<BareItem> {
        self.skip_ws();
        let item = self.parse_bare_item()?;
        self.parse_parameters()?;
        self.skip_ws();
        if !self.eof() {
            return Err(());
        }
        Ok(item)
    }

    fn parse_bare_item(&mut self) -> Parse<BareItem> {
        let c = self.look().ok_or(())?;
        if c == u16::from(b'-') || is_digit(Some(c)) {
            self.parse_integer_or_decimal()?;
        } else if c == u16::from(b'"') {
            self.parse_string()?;
        } else if is_alpha(c) || c == u16::from(b'*') {
            return Ok(BareItem::Token(self.parse_token()));
        } else if c == u16::from(b':') {
            self.parse_byte_sequence()?;
        } else if c == u16::from(b'?') {
            self.parse_boolean()?;
        } else if c == u16::from(b'@') {
            self.parse_date()?;
        } else if c == u16::from(b'%') {
            self.parse_display_string()?;
        } else {
            return Err(());
        }
        Ok(BareItem::Other)
    }

    fn parse_parameters(&mut self) -> Parse<()> {
        while !self.eof() {
            if self.look() != Some(u16::from(b';')) {
                break;
            }
            self.pos += 1;
            self.skip_ws();
            self.parse_key()?;
            if self.look() == Some(u16::from(b'=')) {
                self.pos += 1;
                self.parse_bare_item()?;
            }
        }
        Ok(())
    }

    fn parse_integer_or_decimal(&mut self) -> Parse<()> {
        let mut decimal = false;
        let mut digits: Vec<u16> = Vec::new();
        if self.look() == Some(u16::from(b'-')) {
            self.pos += 1;
        }
        if !is_digit(self.look()) {
            return Err(());
        }
        while !self.eof() {
            let c = self.next().ok_or(())?;
            if is_digit(Some(c)) {
                digits.push(c);
            } else if !decimal && c == u16::from(b'.') {
                if digits.len() > 12 {
                    return Err(());
                }
                digits.push(c);
                decimal = true;
            } else {
                self.pos -= 1;
                break;
            }
            if (!decimal && digits.len() > 15) || (decimal && digits.len() > 16) {
                return Err(());
            }
        }
        if decimal {
            let dot = digits.iter().position(|&c| c == u16::from(b'.')).ok_or(())?;
            let fraction = digits.len() - dot - 1;
            if fraction == 0 || fraction > 3 {
                return Err(());
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> Parse<()> {
        self.expect(b'"')?;
        self.pos += 1;
        while !self.eof() {
            let c = self.next().ok_or(())?;
            if c == u16::from(b'\\') {
                let escaped = self.next().ok_or(())?;
                if escaped != u16::from(b'\\') && escaped != u16::from(b'"') {
                    return Err(());
                }
            } else if c == u16::from(b'"') {
                return Ok(());
            } else if !(0x20..=0x7E).contains(&c) {
                return Err(());
            }
        }
        Err(())
    }

    fn parse_display_string(&mut self) -> Parse<()> {
        if self.input.get(self.pos..self.pos + 2) != Some(&[u16::from(b'%'), u16::from(b'"')][..]) {
            return Err(());
        }
        self.pos += 2;
        let mut bytes: Vec<u8> = Vec::new();
        while !self.eof() {
            let c = self.next().ok_or(())?;
            if c <= 0x1F || (0x7F..=0xFF).contains(&c) {
                return Err(());
            }
            if c == u16::from(b'%') {
                let hex = self.input.get(self.pos..self.pos + 2).ok_or(())?;
                self.pos += 2;
                let hex = String::from_utf16(hex).map_err(|_| ())?;
                if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return Err(());
                }
                bytes.push(u8::from_str_radix(&hex, 16).map_err(|_| ())?);
                continue;
            }
            if c == u16::from(b'"') {
                return String::from_utf8(bytes).map(|_| ()).map_err(|_| ());
            }
            bytes.push(c as u8);
        }
        Err(())
    }

    fn parse_token(&mut self) -> String {
        let start = self.pos;
        while self.look().is_some_and(is_token_char) {
            self.pos += 1;
        }
        String::from_utf16_lossy(&self.input[start..self.pos])
    }

    fn parse_byte_sequence(&mut self) -> Parse<()> {
        self.expect(b':')?;
        self.pos += 1;
        let end = self.input[self.pos..]
            .iter()
            .position(|&c| c == u16::from(b':'))
            .map(|i| self.pos + i)
            .ok_or(())?;
        let content = &self.input[self.pos..end];
        self.pos = end + 1;
        let alphabet = |c: &u16| is_alpha(*c) || is_digit(Some(*c)) || b"+/=".iter().any(|&b| u16::from(b) == *c);
        if !content.iter().all(alphabet) || !is_forgiving_base64(content) {
            return Err(());
        }
        Ok(())
    }

    fn parse_boolean(&mut self) -> Parse<()> {
        self.expect(b'?')?;
        self.pos += 1;
        match self.next() {
            Some(c) if c == u16::from(b'1') || c == u16::from(b'0') => Ok(()),
            _ => Err(()),
        }
    }

    /// structured-headers reads a date to the end of the input: anything after the digits fails.
    fn parse_date(&mut self) -> Parse<()> {
        self.expect(b'@')?;
        self.pos += 1;
        if self.look() == Some(u16::from(b'-')) {
            self.pos += 1;
        }
        if !is_digit(self.look()) {
            return Err(());
        }
        let mut digits = 0;
        while !self.eof() {
            if !is_digit(self.next()) {
                return Err(());
            }
            digits += 1;
        }
        if digits > 15 { Err(()) } else { Ok(()) }
    }

    fn parse_key(&mut self) -> Parse<()> {
        if !self.look().is_some_and(|c| is_lc_alpha(c) || c == u16::from(b'*')) {
            return Err(());
        }
        while self.look().is_some_and(is_key_char) {
            self.pos += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values from structured-headers 2.1.1 `parseItem`, run under node on the same
    /// inputs: `Some` when the bare item is a token, `None` for another type or a parse error.
    #[test]
    fn token_items_match_structured_headers() {
        let cases: [(&str, Option<&str>); 18] = [
            ("same-origin", Some("same-origin")),
            ("  same-origin  ", Some("same-origin")),
            ("same-origin; report-to=\"coop\"", Some("same-origin")),
            ("same-origin;report-to", Some("same-origin")),
            ("same-origin; report-to=coop endpoint", None),
            ("same-origin, same-origin", None),
            ("\"same-origin\"", None),
            ("Same-Origin", Some("Same-Origin")),
            ("*foo", Some("*foo")),
            ("same-origin; Report-To=x", None),
            ("same-origin; a=1.5; b=?0; c=:AQID:; d=%\"x%20y\"", Some("same-origin")),
            ("same-origin; a=1.2345", None),
            ("same-origin; c=:AQI=:", Some("same-origin")),
            ("same-origin; c=:A:", None),
            ("same-origin; d=@12345", Some("same-origin")),
            ("same-origin; d=@12345; e", None),
            ("same-origin\t", None),
            ("", None),
        ];
        for (value, expected) in cases {
            assert_eq!(parse_token_item(value).as_deref(), expected, "{value:?}");
        }
    }
}
