use std::collections::HashMap;

use crate::{MAX_HTML_BYTES, MAX_SANITIZE_INPUT_BYTES};

const ALLOWED_TAGS: &[&str] = &[
    "a",
    "b",
    "strong",
    "i",
    "em",
    "u",
    "s",
    "p",
    "br",
    "hr",
    "div",
    "span",
    "blockquote",
    "pre",
    "code",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "td",
    "th",
    "caption",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "img",
    "font",
    "center",
    "big",
    "small",
    "sub",
    "sup",
    "dl",
    "dt",
    "dd",
];

const DROP_WITH_CONTENT_TAGS: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input",
    "button", "textarea", "select", "option", "link", "meta", "base", "svg", "math", "template",
    "noscript",
];

const VOID_TAGS: &[&str] = &["br", "hr", "img"];

const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track",
    "wbr",
];

const ALLOWED_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "alt",
    "title",
    "width",
    "height",
    "colspan",
    "rowspan",
    "align",
    "valign",
    "dir",
    "lang",
    "style",
    "data-blocked-src",
];

const SAFE_STYLE_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font-family",
    "font-size",
    "font-style",
    "font-weight",
    "font-variant",
    "letter-spacing",
    "line-height",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "word-break",
    "word-wrap",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-collapse",
    "border-spacing",
    "border-color",
    "border-style",
    "border-width",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "width",
    "height",
    "max-width",
    "min-width",
];

const MAX_ATTRIBUTE_VALUE_CHARS: usize = 4_096;

const MAX_ATTRIBUTES_PER_TAG: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct SanitizeOptions<'a> {
    pub allow_remote_images: bool,

    pub cid_urls: &'a HashMap<String, String>,
}

impl Default for SanitizeOptions<'_> {
    fn default() -> Self {
        Self {
            allow_remote_images: false,
            cid_urls: &EMPTY_CID_URLS,
        }
    }
}

static EMPTY_CID_URLS: std::sync::LazyLock<HashMap<String, String>> =
    std::sync::LazyLock::new(HashMap::new);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeOutcome {
    pub html: String,

    pub remote_images_blocked: u32,
}

pub fn sanitize_html(input: &str, options: &SanitizeOptions<'_>) -> SanitizeOutcome {
    let limit = MAX_SANITIZE_INPUT_BYTES.min(MAX_HTML_BYTES);
    let input = truncate_on_char_boundary(input, limit);
    let mut out = String::with_capacity(input.len().min(64 * 1024));
    let mut open: Vec<&'static str> = Vec::new();
    let mut blocked = 0u32;
    let mut skip: Option<SkipState> = None;
    let bytes = input.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if out.len() >= MAX_SANITIZE_OUTPUT_BYTES {
            break;
        }
        if let Some(state) = skip.as_mut() {
            if bytes.get(index) != Some(&b'<') {
                match input[index..].find('<') {
                    Some(offset) => index += offset,
                    None => break,
                }
                continue;
            }
            match next_tag(input, index) {
                Some(tag) => {
                    if tag.is_end {
                        if tag.name == state.name {
                            state.depth -= 1;
                            if state.depth == 0 {
                                skip = None;
                            }
                        }
                    } else if tag.name == state.name && !tag.self_closing {
                        state.depth += 1;
                    }
                    index = tag.consumed_to;
                }
                None => break,
            }
            continue;
        }

        if bytes[index] != b'<' {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'<')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            push_text(&mut out, &input[index..end]);
            index = end;
            continue;
        }

        if input[index..].starts_with("<!--") {
            match input[index + 4..].find("-->") {
                Some(end) => {
                    index = index + 4 + end + 3;
                    continue;
                }
                None => break,
            }
        }
        if input[index..].starts_with("<!") || input[index..].starts_with("<?") {
            match input[index..].find('>') {
                Some(end) => {
                    index += end + 1;
                    continue;
                }
                None => break,
            }
        }

        let Some(tag) = parse_tag(input, index) else {
            push_text(&mut out, &input[index..index + 1]);
            index += 1;
            continue;
        };
        index = tag.consumed_to;

        if tag.is_end {
            if VOID_TAGS.contains(&tag.name.as_str()) {
                continue;
            }

            if let Some(position) = open.iter().rposition(|name| *name == tag.name) {
                while open.len() > position {
                    if let Some(name) = open.pop() {
                        out.push_str("</");
                        out.push_str(name);
                        out.push('>');
                    }
                }
            }
            continue;
        }

        if DROP_WITH_CONTENT_TAGS.contains(&tag.name.as_str()) {
            if !VOID_ELEMENTS.contains(&tag.name.as_str()) && !tag.self_closing {
                skip = Some(SkipState {
                    name: tag.name,
                    depth: 1,
                });
            }
            continue;
        }

        if !ALLOWED_TAGS.contains(&tag.name.as_str()) {
            continue;
        }

        let name: &'static str = match ALLOWED_TAGS.iter().find(|allowed| **allowed == tag.name) {
            Some(name) => name,
            None => continue,
        };
        if out.len() + 64 < MAX_SANITIZE_OUTPUT_BYTES {
            out.push('<');
            out.push_str(name);
            sanitize_attributes(name, &tag.attributes, options, &mut out, &mut blocked);
            out.push('>');
        }
        if !VOID_TAGS.contains(&name) {
            open.push(name);
        }
    }

    while let Some(name) = open.pop() {
        if out.len() + name.len() + 3 < MAX_SANITIZE_OUTPUT_BYTES {
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
    }

    SanitizeOutcome {
        html: out,
        remote_images_blocked: blocked,
    }
}

const MAX_SANITIZE_OUTPUT_BYTES: usize = MAX_SANITIZE_INPUT_BYTES + MAX_SANITIZE_INPUT_BYTES / 4;

struct SkipState {
    name: String,
    depth: usize,
}

struct Tag {
    is_end: bool,
    name: String,
    attributes: Vec<(String, String)>,
    self_closing: bool,

    consumed_to: usize,
}

fn next_tag(input: &str, index: usize) -> Option<Tag> {
    debug_assert!(input.as_bytes().get(index) == Some(&b'<'));
    parse_tag(input, index)
}

fn parse_tag(input: &str, start: usize) -> Option<Tag> {
    let bytes = input.as_bytes();
    let mut index = start;
    if bytes.get(index) != Some(&b'<') {
        return None;
    }
    index += 1;
    let is_end = bytes.get(index) == Some(&b'/');
    if is_end {
        index += 1;
    }
    let name_start = index;
    while let Some(byte) = bytes.get(index) {
        if byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b':' || *byte == b'_' {
            index += 1;
        } else {
            break;
        }
    }
    if index == name_start {
        return None;
    }
    let name = input[name_start..index].to_ascii_lowercase();
    let mut attributes: Vec<(String, String)> = Vec::new();
    let self_closing = false;

    loop {
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        match bytes.get(index) {
            None => return None,
            Some(b'>') => {
                return Some(Tag {
                    is_end,
                    name,
                    attributes,
                    self_closing,
                    consumed_to: index + 1,
                })
            }
            Some(b'/') if bytes.get(index + 1) == Some(&b'>') => {
                return Some(Tag {
                    is_end,
                    name,
                    attributes,
                    self_closing: true,
                    consumed_to: index + 2,
                })
            }
            Some(_) => {}
        }
        if is_end {
            let end = input[index..].find('>')?;
            return Some(Tag {
                is_end,
                name,
                attributes,
                self_closing: false,
                consumed_to: index + end + 1,
            });
        }

        let name_start = index;
        while let Some(byte) = bytes.get(index) {
            if byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'>' || *byte == b'/' {
                break;
            }
            index += 1;
        }
        if index == name_start {
            index += 1;
            continue;
        }
        let attribute_name = input[name_start..index].to_ascii_lowercase();
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            if attributes.len() < MAX_ATTRIBUTES_PER_TAG {
                attributes.push((attribute_name, String::new()));
            }
            continue;
        }
        index += 1;
        while bytes
            .get(index)
            .map(|byte| byte.is_ascii_whitespace())
            .unwrap_or(false)
        {
            index += 1;
        }
        let value;
        match bytes.get(index) {
            None => return None,
            Some(b'"') | Some(b'\'') => {
                let quote = bytes[index];
                index += 1;
                let value_start = index;
                while let Some(byte) = bytes.get(index) {
                    if *byte == quote {
                        break;
                    }
                    index += 1;
                }
                if bytes.get(index) != Some(&quote) {
                    return None;
                }
                value = input[value_start..index].to_string();
                index += 1;
            }
            Some(_) => {
                let value_start = index;
                while let Some(byte) = bytes.get(index) {
                    if byte.is_ascii_whitespace() || *byte == b'>' {
                        break;
                    }
                    index += 1;
                }
                value = input[value_start..index].to_string();
            }
        }
        if attributes.len() < MAX_ATTRIBUTES_PER_TAG {
            attributes.push((attribute_name, value));
        }
    }
}

fn sanitize_attributes(
    tag: &'static str,
    attributes: &[(String, String)],
    options: &SanitizeOptions<'_>,
    out: &mut String,
    blocked: &mut u32,
) {
    let mut seen: Vec<&str> = Vec::new();
    for (name, raw_value) in attributes {
        if !ALLOWED_ATTRIBUTES.contains(&name.as_str()) {
            continue;
        }

        if seen.contains(&name.as_str()) {
            continue;
        }
        seen.push(name.as_str());

        match (tag, name.as_str()) {
            ("img", "src") => {
                let decoded = decode_entities_limited(raw_value);
                match classify_image_url(&decoded, options) {
                    ImageSource::Keep(url) => {
                        out.push_str(" src=\"");
                        out.push_str(&escape_attribute(&url));
                        out.push('"');
                    }
                    ImageSource::Blocked(url) => {
                        out.push_str(" data-blocked-src=\"");
                        out.push_str(&escape_attribute(&url));
                        out.push('"');
                        *blocked = blocked.saturating_add(1);
                    }
                    ImageSource::Drop => {}
                }
            }
            ("img", "data-blocked-src") => {
                let decoded = decode_entities_limited(raw_value);
                out.push_str(" data-blocked-src=\"");
                out.push_str(&escape_attribute(&decoded));
                out.push('"');
            }
            ("a", "href") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(url) = safe_link_url(&decoded) {
                    out.push_str(" href=\"");
                    out.push_str(&escape_attribute(&url));
                    out.push('"');
                }
            }
            (_, "href") | (_, "src") => {}
            (_, "style") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(style) = sanitize_style(&decoded) {
                    out.push_str(" style=\"");
                    out.push_str(&escape_attribute(&style));
                    out.push('"');
                }
            }
            (_, "width") | (_, "height") => {
                let decoded = decode_entities_limited(raw_value);
                if let Some(value) = sanitize_dimension(&decoded) {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&value);
                    out.push('"');
                }
            }
            (_, "colspan") | (_, "rowspan") => {
                let decoded = decode_entities_limited(raw_value);
                if let Ok(number) = decoded.trim().parse::<u32>() {
                    if (1..=1000).contains(&number) {
                        out.push(' ');
                        out.push_str(name);
                        out.push_str("=\"");
                        out.push_str(&number.to_string());
                        out.push('"');
                    }
                }
            }
            (_, "align") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(
                    decoded.trim(),
                    "left" | "right" | "center" | "justify" | "top" | "middle" | "bottom"
                ) {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "valign") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(decoded.trim(), "top" | "middle" | "bottom" | "baseline") {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "dir") => {
                let decoded = decode_entities_limited(raw_value).to_ascii_lowercase();
                if matches!(decoded.trim(), "ltr" | "rtl" | "auto") {
                    out.push_str(" dir=\"");
                    out.push_str(&escape_attribute(decoded.trim()));
                    out.push('"');
                }
            }
            (_, "lang") => {
                let decoded = decode_entities_limited(raw_value);
                let trimmed = decoded.trim();
                if !trimmed.is_empty()
                    && trimmed.len() <= 32
                    && trimmed
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                {
                    out.push_str(" lang=\"");
                    out.push_str(&escape_attribute(trimmed));
                    out.push('"');
                }
            }
            (_, "alt") | (_, "title") => {
                let decoded = decode_entities_limited(raw_value);
                let trimmed: String = decoded
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .take(MAX_ATTRIBUTE_VALUE_CHARS)
                    .collect();
                if !trimmed.is_empty() {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str("=\"");
                    out.push_str(&escape_attribute(&trimmed));
                    out.push('"');
                }
            }
            _ => {}
        }
    }

    if tag == "a" {
        out.push_str(" rel=\"noopener noreferrer nofollow\" target=\"_blank\"");
    }
}

enum ImageSource {
    Keep(String),

    Blocked(String),

    Drop,
}

fn classify_image_url(value: &str, options: &SanitizeOptions<'_>) -> ImageSource {
    let trimmed = trim_unsafe(value);
    if trimmed.is_empty() {
        return ImageSource::Drop;
    }
    if let Some(cid) = strip_scheme(trimmed, "cid:") {
        let key = cid.trim_matches(|ch| ch == '<' || ch == '>' || ch == '"');
        let normalized = key.to_ascii_lowercase();
        if let Some(url) = options.cid_urls.get(key) {
            return ImageSource::Keep(url.clone());
        }
        if let Some(url) = options.cid_urls.get(&normalized) {
            return ImageSource::Keep(url.clone());
        }
        return ImageSource::Drop;
    }
    if is_http_url(trimmed) {
        if options.allow_remote_images {
            return ImageSource::Keep(trimmed.to_string());
        }
        return ImageSource::Blocked(trimmed.to_string());
    }

    ImageSource::Drop
}

fn safe_link_url(value: &str) -> Option<String> {
    let trimmed = trim_unsafe(value);
    if trimmed.is_empty() {
        return None;
    }
    if is_http_url(trimmed) || has_scheme(trimmed, "mailto:") {
        return Some(trimmed.to_string());
    }
    None
}

fn is_http_url(value: &str) -> bool {
    has_scheme(value, "http://") || has_scheme(value, "https://")
}

fn has_scheme(value: &str, scheme: &str) -> bool {
    value.len() >= scheme.len() && value[..scheme.len()].eq_ignore_ascii_case(scheme)
}

fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    if has_scheme(value, scheme) {
        Some(&value[scheme.len()..])
    } else {
        None
    }
}

fn trim_unsafe(value: &str) -> &str {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        return "";
    }
    value
}

fn sanitize_style(value: &str) -> Option<String> {
    let mut declarations: Vec<String> = Vec::new();
    for declaration in value.split(';') {
        let Some((property, raw_value)) = declaration.split_once(':') else {
            continue;
        };
        let property = property.trim().to_ascii_lowercase();
        if !SAFE_STYLE_PROPERTIES.contains(&property.as_str()) {
            continue;
        }
        let raw_value = raw_value.trim();
        if raw_value.is_empty() || raw_value.len() > 256 {
            continue;
        }
        let lowered = raw_value.to_ascii_lowercase();

        if lowered.contains("url(")
            || lowered.contains("expression")
            || lowered.contains("javascript")
            || lowered.contains("@import")
            || lowered.contains('\\')
            || lowered.contains("/*")
            || lowered.contains("*/")
            || lowered.contains('<')
            || lowered.contains('>')
            || lowered.contains("behavior")
        {
            continue;
        }
        if raw_value.chars().any(char::is_control) {
            continue;
        }
        declarations.push(format!("{property}: {raw_value}"));
        if declarations.len() >= 32 {
            break;
        }
    }
    if declarations.is_empty() {
        None
    } else {
        Some(declarations.join("; "))
    }
}

fn sanitize_dimension(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let digits = trimmed.strip_suffix('%').unwrap_or(trimmed);
    if digits.is_empty() || digits.len() > 6 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    if trimmed.ends_with('%') {
        Some(format!("{digits}%"))
    } else {
        Some(digits.to_string())
    }
}

fn push_text(out: &mut String, text: &str) {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => {
                out.push_str("&lt;");
                index += 1;
            }
            b'>' => {
                out.push_str("&gt;");
                index += 1;
            }
            b'&' => {
                if let Some(length) = entity_length(&text[index..]) {
                    out.push_str(&text[index..index + length]);
                    index += length;
                } else {
                    out.push_str("&amp;");
                    index += 1;
                }
            }
            _ => {
                let ch = text[index..].chars().next().unwrap_or(' ');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
}

fn entity_length(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'&') {
        return None;
    }
    let semicolon = value.get(1..)?.find(';')?;
    if semicolon > 10 {
        return None;
    }
    let entity = &value[1..1 + semicolon];
    let valid = match entity {
        "amp" | "lt" | "gt" | "quot" | "apos" | "nbsp" => true,
        _ => {
            let number = entity.strip_prefix('#')?;
            let digits = number
                .strip_prefix('x')
                .or_else(|| number.strip_prefix('X'))
                .unwrap_or(number);
            !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_hexdigit())
        }
    };
    valid.then_some(semicolon + 2)
}

fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

fn decode_entities_limited(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&' {
            if let Some(semicolon) = value[index + 1..].find(';') {
                if semicolon <= 10 {
                    let entity = &value[index + 1..index + 1 + semicolon];
                    if let Some(decoded) = decode_one_entity(entity) {
                        out.push(decoded);
                        index += semicolon + 2;
                        continue;
                    }
                }
            }
        }
        let ch = value[index..].chars().next().unwrap_or(' ');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn decode_one_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let number = entity.strip_prefix('#')?;
            if let Some(hex) = number
                .strip_prefix('x')
                .or_else(|| number.strip_prefix('X'))
            {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                number.parse::<u32>().ok().and_then(char::from_u32)
            }
        }
    }
}

fn truncate_on_char_boundary(value: &str, limit: usize) -> &str {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize(input: &str) -> SanitizeOutcome {
        sanitize_html(input, &SanitizeOptions::default())
    }

    fn assert_no_active_content(html: &str) {
        let lower = html.to_ascii_lowercase();
        for needle in [
            "<script",
            "</script",
            "<iframe",
            "<object",
            "<embed",
            "<applet",
            "<form",
            "<input",
            "<button",
            "<textarea",
            "<select",
            "<link",
            "<meta",
            "<base",
            "<svg",
            "<math",
            "<template",
            "<style",
            "onerror",
            "onload",
            "onclick",
            "javascript:",
            "vbscript:",
            "data:text/html",
            "srcdoc",
            "formaction",
        ] {
            assert!(
                !lower.contains(needle),
                "输出仍含危险片段 {needle:?}：{html}"
            );
        }
    }

    const XSS_CORPUS: &[&str] = &[
        "<script>alert(1)</script>",
        "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
        "<img src=x onerror=alert(1)>",
        "<img src=\"x\" OnErRoR=\"alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<a href='jav&#x61;script:alert(1)'>click</a>",
        "<a href=\"data:text/html,<script>alert(1)</script>\">x</a>",
        "<iframe src=\"https://evil.example\"></iframe>",
        "<svg onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext></mtext></math>",
        "<object data=\"x\"></object>",
        "<embed src=\"x\">",
        "<form action=\"https://evil.example\"><input name=x></form>",
        "<style>@import url(https://evil.example/x.css);</style>",
        "<div style=\"background:url(https://evil.example/pixel)\">x</div>",
        "<div style=\"position:fixed;top:0;left:0;width:100vw;height:100vh\">x</div>",
        "<p onclick=alert(1)>x</p>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=\"https://evil.example/pixel.png\">",
        "<base href=\"https://evil.example/\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
        "<video><source onerror=alert(1)></video>",
        "<textarea></textarea><script>alert(1)</script>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\"></noscript>",
        "<a href=\"  javascript:alert(1)\">x</a>",
        "<a href=\"java\nscript:alert(1)\">x</a>",
        "<img src=\"cid:unknown@example\">",
        "<p>&#60;script&#62;alert(1)&#60;/script&#62;</p>",
        "<div style=\"background-image: url(javascript:alert(1))\">x</div>",
        "<a href=\"https://ok.example\" rel=\"opener\">ok</a>",
    ];

    #[test]
    fn webmail_html_sanitizer_strips_scripts_and_event_handlers() {
        for vector in XSS_CORPUS {
            let outcome = sanitize(vector);
            assert_no_active_content(&outcome.html);

            assert!(
                outcome.html.matches('<').count() == outcome.html.matches('>').count(),
                "输出标签不配平：{} ← {vector}",
                outcome.html
            );
        }

        assert!(!sanitize("<script>alert(1)</script>").html.contains("alert"));
        assert!(!sanitize("<img src=x onerror=alert(1)>")
            .html
            .contains("onerror"));
        assert!(!sanitize("<a href=\"javascript:alert(1)\">x</a>")
            .html
            .contains("javascript"));
        assert!(!sanitize("<iframe src=x></iframe>").html.contains("<iframe"));
    }

    #[test]
    fn allowlisted_markup_survives_with_escaped_text() {
        let outcome = sanitize("<p>Hello <b>world</b> &amp; &lt;friends&gt;</p>");
        assert_eq!(
            outcome.html,
            "<p>Hello <b>world</b> &amp; &lt;friends&gt;</p>"
        );

        assert_eq!(sanitize("1 < 2 > 0").html, "1 &lt; 2 &gt; 0");
    }

    #[test]
    fn links_get_target_and_rel_and_only_safe_schemes() {
        let outcome = sanitize("<a href=\"https://example.com/x\">x</a>");
        assert!(outcome.html.contains("href=\"https://example.com/x\""));
        assert!(outcome
            .html
            .contains("rel=\"noopener noreferrer nofollow\""));
        assert!(outcome.html.contains("target=\"_blank\""));

        let relative = sanitize("<a href=\"/settings\">x</a>");
        assert!(!relative.html.contains("href="), "{}", relative.html);
        assert!(relative.html.contains(">x</a>"));

        assert!(sanitize("<a href=\"mailto:a@b.c\">m</a>")
            .html
            .contains("href=\"mailto:a@b.c\""));
    }

    #[test]
    fn webmail_html_sanitizer_blocks_remote_images_by_default() {
        let outcome = sanitize("<p><img src=\"https://evil.example/pixel.png\" alt=\"x\"></p>");

        assert!(
            !outcome.html.contains(" src=\"https://evil.example"),
            "默认必须阻断远程图片：{}",
            outcome.html
        );
        assert!(outcome
            .html
            .contains("data-blocked-src=\"https://evil.example/pixel.png\""));
        assert!(outcome.html.contains("alt=\"x\""));
        assert_eq!(outcome.remote_images_blocked, 1);

        let cid_urls = HashMap::new();
        let allowed = sanitize_html(
            "<img src=\"https://cdn.example/p.png\">",
            &SanitizeOptions {
                allow_remote_images: true,
                cid_urls: &cid_urls,
            },
        );
        assert!(allowed.html.contains("src=\"https://cdn.example/p.png\""));
        assert_eq!(allowed.remote_images_blocked, 0);

        let mut cid_urls = HashMap::new();
        cid_urls.insert(
            "img1@example.com".to_string(),
            "/mail/api/messages/INBOX/7/parts/3".to_string(),
        );
        let rewritten = sanitize_html(
            "<img src=\"cid:img1@example.com\">",
            &SanitizeOptions {
                allow_remote_images: false,
                cid_urls: &cid_urls,
            },
        );
        assert!(rewritten
            .html
            .contains("src=\"/mail/api/messages/INBOX/7/parts/3\""));
    }

    #[test]
    fn unsafe_css_is_dropped_and_safe_subset_is_kept() {
        let outcome = sanitize(
            "<div style=\"color: red; position: fixed; background: url(https://evil.example/x)\">x</div>",
        );
        assert!(outcome.html.contains("color: red"), "{}", outcome.html);
        assert!(!outcome.html.contains("position"));
        assert!(!outcome.html.contains("url("));
        assert!(!outcome.html.contains("evil.example"));
    }

    #[test]
    fn attribute_injection_cannot_break_out_of_the_quotes() {
        let outcome = sanitize("<p title=\"x&quot; onmouseover=&quot;alert(1)\">hi</p>");
        assert_no_active_content(&outcome.html);

        assert!(outcome
            .html
            .contains("title=\"x&quot; onmouseover=&quot;alert(1)\""));
        let idempotent = sanitize(&outcome.html);
        assert_eq!(idempotent.html, outcome.html);
    }

    #[test]
    fn sanitization_is_idempotent_across_the_corpus() {
        for vector in XSS_CORPUS {
            let once = sanitize(vector).html;
            let twice = sanitize(&once).html;
            assert_eq!(twice, once, "消毒不幂等，输入：{vector}");
        }
    }

    #[test]
    fn malformed_markup_does_not_panic_or_loop() {
        for input in [
            "<",
            "<p",
            "<p attr=",
            "<p attr=\"unterminated",
            "<!-- unterminated",
            "<![CDATA[ x",
            ">>><<<",
            "<p><b><i>unclosed",
            "</p></div></b>",
            "<div><p></div></p>",
            "<img src=",
            "a < b && c > d",
            "<p style=\"color: red",
        ] {
            let outcome = sanitize(input);
            assert_no_active_content(&outcome.html);
        }
    }

    #[test]
    fn output_is_bounded_for_oversized_input() {
        let huge = format!("<p>{}</p>", "x".repeat(MAX_SANITIZE_INPUT_BYTES + 4096));
        let outcome = sanitize(&huge);
        assert!(outcome.html.len() <= MAX_SANITIZE_OUTPUT_BYTES + 64);
    }

    #[test]
    fn comments_and_doctype_are_removed() {
        let outcome = sanitize("<!DOCTYPE html><!-- hi --><p>ok</p>");
        assert_eq!(outcome.html, "<p>ok</p>");
    }
}
