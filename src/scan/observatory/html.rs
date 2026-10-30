// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from mdn/mdn-http-observatory at commit 2776308 (src/utils/html-parser.js,
// parseHttpEquivHeaders in src/retriever/utils.js). The tokenizer and tree-builder mirror the
// state machine of htmlparser2 12.0.0 (MIT, © 2010, 2011 Chris Winberry) and the attribute-value
// character reference rules of entities 8.1.0 (BSD-2-Clause, © Felix Böhm), the parsers upstream
// runs with `lowerCaseTags`, `lowerCaseAttributeNames` and `decodeEntities`.

//! The HTML the analyzers read: the attributes of every `<meta>` and `<script>` open tag, found the
//! way htmlparser2's `onopentag` finds them (raw-text elements, comments, foreign content, the
//! first of duplicate attributes, entities decoded in attribute values).

mod entities;

use super::headers::CONTENT_SECURITY_POLICY;
use super::js;

/// One open tag's attributes, names lowercased, the first of duplicates kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes(Vec<(String, String)>);

impl Attributes {
    /// `getAttribute`: the value, `Some("")` for an attribute with no value.
    pub fn get(&self, name: &str) -> Option<&str> {
        let name = name.to_lowercase();
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }

    /// `hasAttribute`.
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

/// The meta tags the analyzers treat as headers (`httpEquiv`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetaTags {
    /// Every `<meta http-equiv="content-security-policy">` content, in document order.
    pub content_security_policy: Vec<String>,
    /// The last `<meta name="referrer">` content, as a one-element list; empty without one.
    pub referrer_policy: Vec<String>,
}

/// `parseHttpEquivHeaders`.
pub fn parse_http_equiv(html: &str) -> MetaTags {
    let mut meta = MetaTags::default();
    for tag in collect_elements(html, "meta") {
        if tag.has("http-equiv") && tag.has("content") {
            let http_equiv = tag.get("http-equiv").map(|v| js::trim(&v.to_lowercase()).to_string());
            let content = tag.get("content").unwrap_or_default();
            if !content.is_empty() && http_equiv.as_deref() == Some(CONTENT_SECURITY_POLICY) {
                meta.content_security_policy.push(content.to_string());
            }
        } else if tag
            .get("name")
            .map(|v| js::trim(&v.to_lowercase()).to_string())
            .as_deref()
            == Some("referrer")
            && let Some(content) = tag.get("content").filter(|c| !c.is_empty())
        {
            meta.referrer_policy = vec![content.to_string()];
        }
    }
    log::debug!(
        "[observatory::html] parse_http_equiv: csp={} referrer={:?}",
        meta.content_security_policy.len(),
        meta.referrer_policy
    );
    meta
}

/// `collectElements`: the attributes of every open tag named `tag_name`, in document order.
pub fn collect_elements(html: &str, tag_name: &str) -> Vec<Attributes> {
    let mut tokenizer = Tokenizer::new(html, &tag_name.to_lowercase());
    tokenizer.parse();
    log::trace!(
        "[observatory::html] collect_elements: tag={} bytes={} found={}",
        tag_name,
        html.len(),
        tokenizer.found.len()
    );
    tokenizer.found
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Text,
    BeforeTagName,
    InTagName,
    InSelfClosingTag,
    BeforeClosingTagName,
    InClosingTagName,
    AfterClosingTagName,
    BeforeAttributeName,
    InAttributeName,
    AfterAttributeName,
    BeforeAttributeValue,
    InAttributeValueDq,
    InAttributeValueSq,
    InAttributeValueNq,
    BeforeDeclaration,
    InDeclaration,
    BeforeComment,
    CdataSequence,
    DeclarationSequence,
    InSpecialComment,
    InCommentLike,
    SpecialStartSequence,
    InSpecialTag,
    InPlainText,
    InEntity,
}

/// htmlparser2's `Sequences`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seq {
    Empty,
    Cdata,
    CdataEnd,
    CommentEnd,
    Doctype,
    Iframe,
    Noembed,
    Noframes,
    Plaintext,
    Script,
    Style,
    Title,
    Textarea,
    Xmp,
}

impl Seq {
    fn bytes(self) -> &'static [u8] {
        match self {
            Seq::Empty => b"",
            Seq::Cdata => b"CDATA[",
            Seq::CdataEnd => b"]]>",
            Seq::CommentEnd => b"--!>",
            Seq::Doctype => b"doctype",
            Seq::Iframe => b"</iframe",
            Seq::Noembed => b"</noembed",
            Seq::Noframes => b"</noframes",
            Seq::Plaintext => b"</plaintext",
            Seq::Script => b"</script",
            Seq::Style => b"</style",
            Seq::Title => b"</title",
            Seq::Textarea => b"</textarea",
            Seq::Xmp => b"</xmp",
        }
    }

    /// `specialStartSequences`, keyed by the tag name's first letter.
    fn special_start(lower: u32) -> Option<Seq> {
        match char::from_u32(lower)? {
            'i' => Some(Seq::Iframe),
            'n' => Some(Seq::Noembed),
            'p' => Some(Seq::Plaintext),
            's' => Some(Seq::Script),
            't' => Some(Seq::Title),
            'x' => Some(Seq::Xmp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Foreign {
    None,
    Svg,
    MathMl,
}

const VOID_ELEMENTS: [&str; 19] = [
    "area", "base", "basefont", "br", "col", "command", "embed", "frame", "hr", "img", "input", "isindex", "keygen",
    "link", "meta", "param", "source", "track", "wbr",
];
const FOREIGN_CONTEXT_ELEMENTS: [&str; 2] = ["math", "svg"];
const HTML_INTEGRATION_ELEMENTS: [&str; 9] = [
    "mi",
    "mo",
    "mn",
    "ms",
    "mtext",
    "annotation-xml",
    "foreignObject",
    "desc",
    "title",
];
const SVG_TAG_NAME_ADJUSTMENTS: [(&str, &str); 37] = [
    ("altglyph", "altGlyph"),
    ("altglyphdef", "altGlyphDef"),
    ("altglyphitem", "altGlyphItem"),
    ("animatecolor", "animateColor"),
    ("animatemotion", "animateMotion"),
    ("animatetransform", "animateTransform"),
    ("clippath", "clipPath"),
    ("feblend", "feBlend"),
    ("fecolormatrix", "feColorMatrix"),
    ("fecomponenttransfer", "feComponentTransfer"),
    ("fecomposite", "feComposite"),
    ("feconvolvematrix", "feConvolveMatrix"),
    ("fediffuselighting", "feDiffuseLighting"),
    ("fedisplacementmap", "feDisplacementMap"),
    ("fedistantlight", "feDistantLight"),
    ("fedropshadow", "feDropShadow"),
    ("feflood", "feFlood"),
    ("fefunca", "feFuncA"),
    ("fefuncb", "feFuncB"),
    ("fefuncg", "feFuncG"),
    ("fefuncr", "feFuncR"),
    ("fegaussianblur", "feGaussianBlur"),
    ("feimage", "feImage"),
    ("femerge", "feMerge"),
    ("femergenode", "feMergeNode"),
    ("femorphology", "feMorphology"),
    ("feoffset", "feOffset"),
    ("fepointlight", "fePointLight"),
    ("fespecularlighting", "feSpecularLighting"),
    ("fespotlight", "feSpotLight"),
    ("fetile", "feTile"),
    ("feturbulence", "feTurbulence"),
    ("foreignobject", "foreignObject"),
    ("glyphref", "glyphRef"),
    ("lineargradient", "linearGradient"),
    ("radialgradient", "radialGradient"),
    ("textpath", "textPath"),
];

/// `openImpliesClose`: the open elements a new tag closes.
fn open_implies_close(name: &str) -> Option<&'static [&'static str]> {
    const P: &[&str] = &["p"];
    const HEADING: &[&str] = &["h1", "h2", "h3", "h4", "h5", "h6", "p"];
    const FORM: &[&str] = &[
        "input", "option", "optgroup", "select", "button", "datalist", "textarea",
    ];
    const TABLE_SECTION: &[&str] = &["thead", "tbody"];
    const DDT: &[&str] = &["dd", "dt"];
    const RTP: &[&str] = &["rt", "rp"];
    Some(match name {
        "tr" => &["tr", "th", "td"],
        "th" => &["th"],
        "td" => &["thead", "th", "td"],
        "body" => &["head", "link", "script"],
        "a" => &["a"],
        "li" => &["li"],
        "p" => P,
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => HEADING,
        "select" | "input" | "output" | "button" | "datalist" | "textarea" => FORM,
        "option" => &["option"],
        "optgroup" => &["optgroup", "option"],
        "dd" | "dt" => DDT,
        "address" | "article" | "aside" | "blockquote" | "details" | "div" | "dl" | "fieldset" | "figcaption"
        | "figure" | "footer" | "form" | "header" | "hr" | "main" | "nav" | "ol" | "pre" | "section" | "table"
        | "ul" => P,
        "rt" | "rp" => RTP,
        "tbody" | "tfoot" => TABLE_SECTION,
        _ => return None,
    })
}

const LT: u32 = '<' as u32;
const GT: u32 = '>' as u32;
const SLASH: u32 = '/' as u32;
const AMP: u32 = '&' as u32;

fn is_whitespace(c: u32) -> bool {
    matches!(c, 32 | 10 | 9 | 12 | 13)
}

fn is_end_of_tag_section(c: u32) -> bool {
    c == SLASH || c == GT || is_whitespace(c)
}

fn is_ascii_alpha(c: u32) -> bool {
    (u32::from(b'a')..=u32::from(b'z')).contains(&c) || (u32::from(b'A')..=u32::from(b'Z')).contains(&c)
}

/// A character reference in an attribute value, after the `&`.
enum Entity {
    /// Decoded; `consumed` counts from the `&`.
    Decoded { consumed: usize, value: String },
    /// Not a reference: the `&` stays literal.
    Rejected,
    /// The input ended inside the reference.
    Incomplete,
}

/// entities' `replaceCodePoint` for numeric references.
fn replace_code_point(code_point: u64) -> char {
    const C1: [u32; 32] = [
        8364, 0, 8218, 402, 8222, 8230, 8224, 8225, 710, 8240, 352, 8249, 338, 0, 381, 0, 0, 8216, 8217, 8220, 8221,
        8226, 8211, 8212, 732, 8482, 353, 8250, 339, 0, 382, 376,
    ];
    if code_point == 0 || (0xD800..=0xDFFF).contains(&code_point) || code_point > 0x10FFFF {
        return '\u{FFFD}';
    }
    let mut cp = code_point as u32;
    if (128..=159).contains(&cp) && C1[(cp - 128) as usize] != 0 {
        cp = C1[(cp - 128) as usize];
    }
    char::from_u32(cp).unwrap_or('\u{FFFD}')
}

/// entities' `EntityDecoder` in `DecodingMode.Attribute`, from `p` (the character after `&`).
fn decode_attribute_entity(buf: &[char], p: usize) -> Entity {
    let Some(&first) = buf.get(p) else {
        return Entity::Incomplete;
    };
    if first == '#' {
        let Some(&marker) = buf.get(p + 1) else {
            return Entity::Incomplete;
        };
        let hex = (u32::from(marker) | 0x20) == u32::from(b'x');
        let start = if hex { p + 2 } else { p + 1 };
        let radix = if hex { 16 } else { 10 };
        let mut value: u64 = 0;
        let mut end = start;
        loop {
            let Some(&c) = buf.get(end) else {
                return Entity::Incomplete;
            };
            match c.to_digit(radix).filter(|_| c.is_ascii()) {
                Some(digit) => value = value.saturating_mul(u64::from(radix)).saturating_add(u64::from(digit)),
                None => break,
            }
            end += 1;
        }
        if end == start {
            return Entity::Rejected;
        }
        let terminated = buf[end] == ';';
        return Entity::Decoded {
            consumed: end - p + 1 + usize::from(terminated),
            value: replace_code_point(value).to_string(),
        };
    }
    let longest = entities::LONGEST_NAME.min(buf.len() - p);
    for len in (1..=longest).rev() {
        let candidate: String = buf[p..p + len].iter().collect();
        let Ok(found) = entities::NAMED.binary_search_by(|(name, _)| (*name).cmp(candidate.as_str())) else {
            continue;
        };
        let (name, value) = entities::NAMED[found];
        if !name.ends_with(';') {
            match buf.get(p + len) {
                None => return Entity::Incomplete,
                Some(&next) if next == '=' || next.is_ascii_alphanumeric() => return Entity::Rejected,
                Some(_) => {}
            }
        }
        return Entity::Decoded {
            consumed: len + 1,
            value: value.to_string(),
        };
    }
    Entity::Rejected
}

/// htmlparser2's `Tokenizer` driving its `Parser`, reduced to what `onopentag` sees. Text,
/// comments and declarations are tracked as states only, since they never yield an open tag.
struct Tokenizer {
    buf: Vec<char>,
    state: State,
    base_state: State,
    section_start: i64,
    index: i64,
    entity_start: i64,
    is_special: bool,
    seq: Seq,
    seq_index: usize,
    tagname: String,
    attribname: String,
    attribvalue: String,
    attribs: Option<Vec<(String, String)>>,
    /// Open elements, innermost last.
    stack: Vec<String>,
    /// Foreign-content contexts, innermost last, over a base `None`.
    foreign: Vec<Foreign>,
    target: String,
    found: Vec<Attributes>,
}

impl Tokenizer {
    fn new(html: &str, target: &str) -> Self {
        Self {
            buf: html.chars().collect(),
            state: State::Text,
            base_state: State::Text,
            section_start: 0,
            index: 0,
            entity_start: 0,
            is_special: false,
            seq: Seq::Empty,
            seq_index: 0,
            tagname: String::new(),
            attribname: String::new(),
            attribvalue: String::new(),
            attribs: None,
            stack: Vec::new(),
            foreign: vec![Foreign::None],
            target: target.to_string(),
            found: Vec::new(),
        }
    }

    fn len(&self) -> i64 {
        self.buf.len() as i64
    }

    fn slice(&self, start: i64, end: i64) -> String {
        if start >= end || start < 0 {
            return String::new();
        }
        self.buf[start as usize..end as usize].iter().collect()
    }

    fn seq_byte(&self, i: usize) -> u32 {
        u32::from(self.seq.bytes()[i])
    }

    fn parse(&mut self) {
        while self.index < self.len() {
            let c = u32::from(self.buf[self.index as usize]);
            match self.state {
                State::Text => self.state_text(c),
                State::InPlainText => self.index = self.len() - 1,
                State::SpecialStartSequence => self.state_special_start_sequence(c),
                State::InSpecialTag => self.state_in_special_tag(c),
                State::CdataSequence => self.state_cdata_sequence(c),
                State::DeclarationSequence => self.state_declaration_sequence(c),
                State::InAttributeValueDq => self.handle_in_attribute_value(c, u32::from(b'"')),
                State::InAttributeName => self.state_in_attribute_name(c),
                State::InCommentLike => self.state_in_comment_like(c),
                State::InSpecialComment => self.state_in_special_comment(c),
                State::BeforeAttributeName => self.state_before_attribute_name(c),
                State::InTagName => self.state_in_tag_name(c),
                State::InClosingTagName => self.state_in_closing_tag_name(c),
                State::BeforeTagName => self.state_before_tag_name(c),
                State::AfterAttributeName => self.state_after_attribute_name(c),
                State::InAttributeValueSq => self.handle_in_attribute_value(c, u32::from(b'\'')),
                State::BeforeAttributeValue => self.state_before_attribute_value(c),
                State::BeforeClosingTagName => self.state_before_closing_tag_name(c),
                State::AfterClosingTagName => self.state_after_closing_tag_name(c),
                State::InAttributeValueNq => self.state_in_attribute_value_no_quotes(c),
                State::InSelfClosingTag => self.state_in_self_closing_tag(c),
                State::InDeclaration => self.state_in_declaration(c),
                State::BeforeDeclaration => self.state_before_declaration(c),
                State::BeforeComment => self.state_before_comment(c),
                State::InEntity => self.state_in_entity(),
            }
            self.index += 1;
        }
    }

    fn state_text(&mut self, c: u32) {
        if c == LT {
            self.state = State::BeforeTagName;
            self.section_start = self.index;
        }
    }

    fn fast_forward_to(&mut self, c: u32) -> bool {
        loop {
            self.index += 1;
            if self.index >= self.len() {
                break;
            }
            if u32::from(self.buf[self.index as usize]) == c {
                return true;
            }
        }
        self.index = self.len() - 1;
        false
    }

    fn enter_tag_body(&mut self) {
        if self.seq == Seq::Plaintext {
            self.seq = Seq::Empty;
            self.state = State::InPlainText;
        } else if self.is_special {
            self.state = State::InSpecialTag;
            self.seq_index = 0;
        } else {
            self.state = State::Text;
        }
    }

    fn state_special_start_sequence(&mut self, c: u32) {
        let lower = c | 0x20;
        let len = self.seq.bytes().len();
        if self.seq_index < len {
            if lower == self.seq_byte(self.seq_index) {
                self.seq_index += 1;
                return;
            }
            if self.seq_index == 3 {
                if self.seq == Seq::Script && lower == u32::from(Seq::Style.bytes()[3]) {
                    self.seq = Seq::Style;
                    self.seq_index = 4;
                    return;
                }
                if self.seq == Seq::Title && lower == u32::from(Seq::Textarea.bytes()[3]) {
                    self.seq = Seq::Textarea;
                    self.seq_index = 4;
                    return;
                }
            } else if self.seq_index == 4 && self.seq == Seq::Noembed && lower == u32::from(Seq::Noframes.bytes()[4]) {
                self.seq = Seq::Noframes;
                self.seq_index = 5;
                return;
            }
        } else if is_end_of_tag_section(c) {
            self.seq_index = 0;
            self.state = State::InTagName;
            self.state_in_tag_name(c);
            return;
        }
        self.is_special = false;
        self.seq = Seq::Empty;
        self.seq_index = 0;
        self.state = State::InTagName;
        self.state_in_tag_name(c);
    }

    fn state_cdata_sequence(&mut self, c: u32) {
        if c == u32::from(Seq::Cdata.bytes()[self.seq_index]) {
            self.seq_index += 1;
            if self.seq_index == Seq::Cdata.bytes().len() {
                self.state = State::InCommentLike;
                self.seq = Seq::CdataEnd;
                self.seq_index = 0;
                self.section_start = self.index + 1;
            }
        } else {
            self.seq_index = 0;
            self.state = State::InSpecialComment;
            self.state_in_special_comment(c);
        }
    }

    fn emit_comment(&mut self) {
        self.seq_index = 0;
        self.section_start = self.index + 1;
        self.state = State::Text;
    }

    fn state_in_comment_like(&mut self, c: u32) {
        let len = self.seq.bytes().len();
        // `<!-->` and `<!--->` close abruptly; `--!>` and `-->` close normally.
        let abrupt_close = self.seq_index <= 1 && self.index == self.section_start + self.seq_index as i64;
        if self.seq == Seq::CommentEnd && c == GT && (abrupt_close || self.seq_index == 2) {
            self.emit_comment();
        } else if self.seq == Seq::CommentEnd && self.seq_index == len - 1 && c != GT {
            self.seq_index = usize::from(c == u32::from(b'-'));
        } else if c == self.seq_byte(self.seq_index) {
            self.seq_index += 1;
            if self.seq_index == len {
                self.seq_index = 0;
                self.section_start = self.index + 1;
                self.state = State::Text;
            }
        } else if self.seq_index == 0 {
            if self.fast_forward_to(self.seq_byte(0)) {
                self.seq_index = 1;
            }
        } else if c != self.seq_byte(self.seq_index - 1) {
            self.seq_index = 0;
        }
    }

    fn state_in_special_tag(&mut self, c: u32) {
        let len = self.seq.bytes().len();
        if self.seq_index == len {
            if is_end_of_tag_section(c) {
                let end_of_text = self.index - len as i64;
                self.is_special = false;
                self.section_start = end_of_text + 2;
                self.state_in_closing_tag_name(c);
                return;
            }
            self.seq_index = 0;
        }
        if (c | 0x20) == self.seq_byte(self.seq_index) {
            self.seq_index += 1;
        } else if self.seq_index == 0 {
            // Title and textarea decode entities in their text, which never hides a `<`.
            if self.seq != Seq::Title && self.seq != Seq::Textarea && self.fast_forward_to(LT) {
                self.seq_index = 1;
            }
        } else {
            self.seq_index = usize::from(c == LT);
        }
    }

    fn state_before_tag_name(&mut self, c: u32) {
        if c == u32::from(b'!') {
            self.state = State::BeforeDeclaration;
            self.section_start = self.index + 1;
        } else if c == u32::from(b'?') {
            self.state = State::InSpecialComment;
            self.section_start = self.index;
        } else if is_ascii_alpha(c) {
            self.section_start = self.index;
            let special = if self.is_in_foreign_context() { None } else { Seq::special_start(c | 0x20) };
            match special {
                None => self.state = State::InTagName,
                Some(seq) => {
                    self.is_special = true;
                    self.seq = seq;
                    self.seq_index = 3;
                    self.state = State::SpecialStartSequence;
                }
            }
        } else if c == SLASH {
            self.state = State::BeforeClosingTagName;
        } else {
            self.state = State::Text;
            self.state_text(c);
        }
    }

    fn state_in_tag_name(&mut self, c: u32) {
        if is_end_of_tag_section(c) {
            self.on_open_tag_name(self.section_start, self.index);
            self.section_start = -1;
            self.state = State::BeforeAttributeName;
            self.state_before_attribute_name(c);
        }
    }

    fn state_before_closing_tag_name(&mut self, c: u32) {
        if is_whitespace(c) {
            self.state = State::InSpecialComment;
            self.section_start = self.index;
        } else if c == GT {
            self.state = State::Text;
            self.section_start = self.index + 1;
        } else {
            self.state = if is_ascii_alpha(c) {
                State::InClosingTagName
            } else {
                State::InSpecialComment
            };
            self.section_start = self.index;
        }
    }

    fn state_in_closing_tag_name(&mut self, c: u32) {
        if is_end_of_tag_section(c) {
            self.on_close_tag(self.section_start, self.index);
            self.section_start = -1;
            self.state = State::AfterClosingTagName;
            self.state_after_closing_tag_name(c);
        }
    }

    fn state_after_closing_tag_name(&mut self, c: u32) {
        if c == GT || self.fast_forward_to(GT) {
            self.state = State::Text;
            self.section_start = self.index + 1;
        }
    }

    fn state_before_attribute_name(&mut self, c: u32) {
        if c == GT {
            self.end_open_tag();
            self.enter_tag_body();
            self.section_start = self.index + 1;
        } else if c == SLASH {
            self.state = State::InSelfClosingTag;
        } else if !is_whitespace(c) {
            self.state = State::InAttributeName;
            self.section_start = self.index;
        }
    }

    fn state_in_self_closing_tag(&mut self, c: u32) {
        if c == GT {
            self.on_self_closing_tag();
            self.section_start = self.index + 1;
            self.enter_tag_body();
        } else if !is_whitespace(c) {
            self.state = State::BeforeAttributeName;
            self.state_before_attribute_name(c);
        }
    }

    fn state_in_attribute_name(&mut self, c: u32) {
        if c == u32::from(b'=') || is_end_of_tag_section(c) {
            self.attribname = self.slice(self.section_start, self.index).to_lowercase();
            self.section_start = self.index;
            self.state = State::AfterAttributeName;
            self.state_after_attribute_name(c);
        }
    }

    fn state_after_attribute_name(&mut self, c: u32) {
        if c == u32::from(b'=') {
            self.state = State::BeforeAttributeValue;
        } else if c == SLASH || c == GT {
            self.on_attrib_end();
            self.section_start = -1;
            self.state = State::BeforeAttributeName;
            self.state_before_attribute_name(c);
        } else if !is_whitespace(c) {
            self.on_attrib_end();
            self.state = State::InAttributeName;
            self.section_start = self.index;
        }
    }

    fn state_before_attribute_value(&mut self, c: u32) {
        if c == u32::from(b'"') {
            self.state = State::InAttributeValueDq;
            self.section_start = self.index + 1;
        } else if c == u32::from(b'\'') {
            self.state = State::InAttributeValueSq;
            self.section_start = self.index + 1;
        } else if !is_whitespace(c) {
            self.section_start = self.index;
            self.state = State::InAttributeValueNq;
            self.state_in_attribute_value_no_quotes(c);
        }
    }

    fn handle_in_attribute_value(&mut self, c: u32, quote: u32) {
        if c == quote {
            self.on_attrib_data(self.section_start, self.index);
            self.section_start = -1;
            self.on_attrib_end();
            self.state = State::BeforeAttributeName;
        } else if c == AMP {
            self.start_entity();
        }
    }

    fn state_in_attribute_value_no_quotes(&mut self, c: u32) {
        if is_whitespace(c) || c == GT {
            self.on_attrib_data(self.section_start, self.index);
            self.section_start = -1;
            self.on_attrib_end();
            self.state = State::BeforeAttributeName;
            self.state_before_attribute_name(c);
        } else if c == AMP {
            self.start_entity();
        }
    }

    fn state_before_declaration(&mut self, c: u32) {
        if c == u32::from(b'[') {
            self.state = State::CdataSequence;
            self.seq_index = 0;
        } else if (c | 0x20) == u32::from(Seq::Doctype.bytes()[0]) {
            self.state = State::DeclarationSequence;
            self.seq = Seq::Doctype;
            self.seq_index = 1;
        } else if c == GT {
            self.state = State::Text;
            self.section_start = self.index + 1;
        } else if c == u32::from(b'-') {
            self.state = State::BeforeComment;
        } else {
            self.state = State::InSpecialComment;
        }
    }

    fn state_declaration_sequence(&mut self, c: u32) {
        if self.seq_index == self.seq.bytes().len() {
            self.state = State::InDeclaration;
            self.state_in_declaration(c);
        } else if (c | 0x20) == self.seq_byte(self.seq_index) {
            self.seq_index += 1;
        } else if c == GT {
            self.state = State::Text;
            self.section_start = self.index + 1;
        } else {
            self.state = State::InSpecialComment;
        }
    }

    fn state_in_declaration(&mut self, c: u32) {
        if c == GT || self.fast_forward_to(GT) {
            self.state = State::Text;
            self.section_start = self.index + 1;
        }
    }

    fn state_before_comment(&mut self, c: u32) {
        if c == u32::from(b'-') {
            self.state = State::InCommentLike;
            self.seq = Seq::CommentEnd;
            self.seq_index = 0;
            self.section_start = self.index + 1;
        } else if c == GT {
            self.state = State::Text;
            self.section_start = self.index + 1;
        } else {
            self.state = State::InSpecialComment;
        }
    }

    fn state_in_special_comment(&mut self, c: u32) {
        if c == GT || self.fast_forward_to(GT) {
            self.state = State::Text;
            self.section_start = self.index + 1;
        }
    }

    /// Entities only matter inside attribute values: text never yields an open tag, and a
    /// reference in text never consumes a `<`.
    fn start_entity(&mut self) {
        self.base_state = self.state;
        self.state = State::InEntity;
        self.entity_start = self.index;
    }

    fn state_in_entity(&mut self) {
        match decode_attribute_entity(&self.buf, self.index as usize) {
            Entity::Decoded { consumed, value } => {
                if self.section_start < self.entity_start {
                    self.on_attrib_data(self.section_start, self.entity_start);
                }
                self.section_start = self.entity_start + consumed as i64;
                self.index = self.section_start - 1;
                self.attribvalue.push_str(&value);
                self.state = self.base_state;
            }
            Entity::Rejected => {
                self.state = self.base_state;
                self.index -= 1;
            }
            Entity::Incomplete => self.index = self.len() - 1,
        }
    }

    // Parser callbacks.

    fn is_in_foreign_context(&self) -> bool {
        self.foreign.last() != Some(&Foreign::None)
    }

    fn is_void_element(name: &str) -> bool {
        VOID_ELEMENTS.contains(&name)
    }

    fn read_tag_name(&self, start: i64, end: i64) -> String {
        let name = self.slice(start, end).to_lowercase();
        let svg_adjusted = || {
            SVG_TAG_NAME_ADJUSTMENTS
                .iter()
                .find(|(lower, _)| *lower == name)
                .map(|(_, adjusted)| *adjusted)
        };
        if self.foreign.last() == Some(&Foreign::Svg) {
            return svg_adjusted().map_or(name.clone(), str::to_string);
        }
        if self.foreign.len() > 1
            && let Some(adjusted) = svg_adjusted()
            && self.stack.iter().any(|open| open == adjusted)
        {
            return adjusted.to_string();
        }
        if !self.is_in_foreign_context() && name == "image" {
            return "img".to_string();
        }
        name
    }

    fn on_open_tag_name(&mut self, start: i64, end: i64) {
        let name = self.read_tag_name(start, end);
        self.emit_open_tag(name);
    }

    fn emit_open_tag(&mut self, name: String) {
        self.tagname = name.clone();
        if name == "form" && self.stack.iter().any(|open| open == "form") {
            self.tagname.clear();
            return;
        }
        if let Some(closes) = open_implies_close(&name) {
            while self.stack.last().is_some_and(|top| closes.contains(&top.as_str())) {
                self.pop_element();
            }
        }
        if !Self::is_void_element(&name) {
            if name == "svg" {
                self.foreign.push(Foreign::Svg);
            } else if name == "math" {
                self.foreign.push(Foreign::MathMl);
            } else if HTML_INTEGRATION_ELEMENTS.contains(&name.as_str()) {
                self.foreign.push(Foreign::None);
            }
            self.stack.push(name);
        }
        self.attribs = Some(Vec::new());
    }

    fn end_open_tag(&mut self) {
        if let Some(attribs) = self.attribs.take()
            && self.tagname == self.target
        {
            self.found.push(Attributes(attribs));
        }
        self.tagname.clear();
    }

    fn on_close_tag(&mut self, start: i64, end: i64) {
        let name = self.read_tag_name(start, end);
        if !Self::is_void_element(&name) {
            if let Some(depth) = self.stack.iter().rev().position(|open| *open == name) {
                for _ in 0..=depth {
                    self.pop_element();
                }
            } else if name == "p" {
                self.emit_open_tag("p".to_string());
                self.close_current_tag();
            }
        } else if name == "br" && self.target == "br" {
            self.found.push(Attributes::default());
        }
    }

    fn on_self_closing_tag(&mut self) {
        if self.is_in_foreign_context() {
            self.close_current_tag();
        } else {
            self.end_open_tag();
        }
    }

    fn pop_element(&mut self) {
        if let Some(element) = self.stack.pop()
            && (FOREIGN_CONTEXT_ELEMENTS.contains(&element.as_str())
                || HTML_INTEGRATION_ELEMENTS.contains(&element.as_str()))
        {
            self.foreign.pop();
        }
    }

    fn close_current_tag(&mut self) {
        let name = self.tagname.clone();
        self.end_open_tag();
        if self.stack.last() == Some(&name) {
            self.pop_element();
        }
    }

    fn on_attrib_data(&mut self, start: i64, end: i64) {
        let data = self.slice(start, end);
        self.attribvalue.push_str(&data);
    }

    fn on_attrib_end(&mut self) {
        if let Some(attribs) = self.attribs.as_mut()
            && !attribs.iter().any(|(name, _)| *name == self.attribname)
        {
            attribs.push((self.attribname.clone(), self.attribvalue.clone()));
        }
        self.attribvalue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srcs(html: &str) -> Vec<String> {
        collect_elements(html, "script")
            .iter()
            .map(|a| a.get("src").unwrap_or("<none>").to_string())
            .collect()
    }

    #[test]
    fn meta_tags_parse_csp_and_the_last_referrer() {
        let meta = parse_http_equiv(
            r#"<meta http-equiv=" Content-Security-Policy " content="default-src 'none'">
               <meta name="referrer" content="origin"><meta name="REFERRER" content="no-referrer">
               <meta http-equiv="x-frame-options" content="DENY">"#,
        );
        assert_eq!(meta.content_security_policy, vec!["default-src 'none'"]);
        assert_eq!(meta.referrer_policy, vec!["no-referrer"]);
    }

    #[test]
    fn a_meta_with_http_equiv_and_content_is_never_a_referrer() {
        let meta = parse_http_equiv(r#"<meta http-equiv="x" content="origin" name="referrer">"#);
        assert!(meta.referrer_policy.is_empty());
    }

    #[test]
    fn unterminated_tag_at_end_of_input_is_dropped() {
        assert!(collect_elements(r#"<meta name="referrer" content="origin""#, "meta").is_empty());
    }

    #[test]
    fn duplicate_attributes_keep_the_first() {
        let tags = collect_elements(r#"<script SRC="/a.js" src="/b.js"></script>"#, "script");
        assert_eq!(tags[0].get("src"), Some("/a.js"));
    }

    /// Expected values from htmlparser2 12.0.0 `collectElements(html, "script")`, run under node
    /// on the same inputs.
    #[test]
    fn script_discovery_matches_htmlparser2() {
        let cases: [(&str, &[&str]); 22] = [
            (
                "<script>var s = \"<script src='/no.js'></script>\";</script><script src=\"/yes.js\"></script>",
                &["<none>", "/yes.js"],
            ),
            (
                "<!-- <script src=\"/c.js\"></script> --><script src=\"/d.js\">",
                &["/d.js"],
            ),
            (
                "<textarea><script src=\"/t.js\"></script></textarea><script src=\"/u.js\">",
                &["/u.js"],
            ),
            (
                "<svg><script src=\"/s.js\"/><style><script src=\"/v.js\"></script></style></svg>",
                &["/s.js", "/v.js"],
            ),
            (
                "<style><script src=\"/x.js\"></script></style><script src=/y.js>",
                &["/y.js"],
            ),
            (
                "<script src=\"a&amp;b&ampc&amp=d&lt3&notit;&#x41;&#65\"></script>",
                &["a&b&ampc&amp=d&lt3&notit;AA"],
            ),
            ("<plaintext><script src=\"/p.js\">", &[]),
            (
                "<![CDATA[<script src=\"/cd.js\">]]><script src=\"/after.js\">",
                &["/after.js"],
            ),
            ("<scriptx src=\"/no.js\"><script/src=\"/slash.js\">", &["/slash.js"]),
            (
                "<!doctype html><SCRIPT SRC='/upper.js'></SCRIPT><script src=\"/q.js?a=1&b=2\">",
                &["/upper.js", "/q.js?a=1&b=2"],
            ),
            (
                "<script src=\"&#0;&#x80;&#xD800;\"></script>",
                &["\u{fffd}\u{20ac}\u{fffd}"],
            ),
            ("<script src=\"/z.js\"", &[]),
            (
                "<math><mi><script src=\"/mi.js\"></script></mi><script src=\"/m.js\"/><script src=\"/m2.js\"></math><script src=\"/after-math.js\"></script>",
                &["/mi.js", "/m.js", "/m2.js", "/after-math.js"],
            ),
            ("<form><form><script src=\"/f.js\"></form></form>", &["/f.js"]),
            (
                "<title><script src=\"/title.js\"></title><script src=\"/t2.js\">",
                &["/t2.js"],
            ),
            (
                "<script src=\"/a.js\" src=\"/b.js\" SRC=\"/c.js\"></script>",
                &["/a.js"],
            ),
            ("<noscript><script src=\"/ns.js\"></script></noscript>", &["/ns.js"]),
            (
                "<iframe><script src=\"/if.js\"></script></iframe><xmp><script src=\"/xmp.js\"></xmp><noembed><script src=\"/ne.js\"></noembed><noframes><script src=\"/nf.js\"></noframes>",
                &[],
            ),
            (
                "<!--><script src=\"/ac.js\"><!---><script src=\"/ac2.js\"><!-- a --!><script src=\"/ac3.js\">",
                &["/ac.js"],
            ),
            ("<?xml version=\"1.0\"?><script src=\"/pi.js\">", &["/pi.js"]),
            ("</ script><script src=\"/sp.js\">", &["/sp.js"]),
            (
                "<script src=\"&AMP;&Amp;&nbsp&nbsp;x&copy=1&para;\"></script>",
                &["&&Amp;\u{a0}\u{a0}x&copy=1\u{b6}"],
            ),
        ];
        for (html, expected) in cases {
            assert_eq!(
                srcs(html),
                expected.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "{html}"
            );
        }
    }
}
