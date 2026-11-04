use base64::Engine;
use encoding_rs::Encoding;
use serde::Serialize;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday};

use mailstack_imappop3::mime;

use crate::{
    MAX_ATTACHMENT_TOTAL_BYTES, MAX_BODY_TEXT_CHARS, MAX_DETAIL_BYTES, MAX_HTML_BYTES, MAX_PARTS,
};

pub const MAX_PARSE_DEPTH: usize = 16;

pub const SNIPPET_CHARS: usize = 200;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct AddressView {
    pub name: String,

    pub address: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeadersView {
    pub from: Option<AddressView>,
    pub to: Vec<AddressView>,
    pub cc: Vec<AddressView>,
    pub bcc: Vec<AddressView>,
    pub reply_to: Vec<AddressView>,
    pub subject: String,

    pub date: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub list_unsubscribe: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentView {
    pub part_id: String,
    pub filename: Option<String>,
    pub content_type: String,

    pub size: u64,
    pub disposition: Option<String>,
    pub inline: bool,
    pub cid: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedMessage {
    pub headers: HeadersView,

    pub text: Option<String>,

    pub html: Option<String>,
    pub attachments: Vec<AttachmentView>,

    pub body_truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SummaryFields {
    pub subject: String,
    pub from: Option<AddressView>,
    pub to: Vec<AddressView>,
    pub date: Option<String>,
    pub message_id: Option<String>,
    pub snippet: String,
    pub has_attachments: bool,
}

#[derive(Debug, Clone)]
pub struct LeafPart {
    pub part_id: String,

    pub content_type: String,
    pub charset: Option<String>,
    pub encoding: String,

    pub disposition: Option<String>,
    pub filename: Option<String>,

    pub content_id: Option<String>,

    pub data: Vec<u8>,

    pub size: u64,

    pub truncated: bool,
}

impl LeafPart {
    pub fn is_attachment(&self) -> bool {
        self.disposition.as_deref() == Some("attachment") || self.filename.is_some()
    }

    pub fn is_inline(&self) -> bool {
        self.content_id.is_some() && !self.is_attachment()
    }

    pub fn is_body_text(&self) -> bool {
        matches!(self.content_type.as_str(), "text/plain" | "text/html")
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParsedStructure {
    pub leaves: Vec<LeafPart>,
    pub truncated: bool,
}

pub fn headers_view(headers: &mime::Headers) -> HeadersView {
    let from = address_views(headers.get("from")).into_iter().next();
    let reply_to = address_views(headers.get("reply-to"));
    HeadersView {
        from,
        to: address_views(headers.get("to")),
        cc: address_views(headers.get("cc")),
        bcc: address_views(headers.get("bcc")),
        reply_to,
        subject: decode_rfc2047(headers.get("subject").unwrap_or("")),
        date: headers
            .get("date")
            .and_then(parse_date_header)
            .map(format_rfc3339_utc),
        message_id: headers
            .get("message-id")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        in_reply_to: headers
            .get("in-reply-to")
            .and_then(|value| extract_message_ids(value).into_iter().next()),
        references: headers
            .get("references")
            .map(extract_message_ids)
            .unwrap_or_default(),
        list_unsubscribe: headers
            .get("list-unsubscribe")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    }
}

pub fn address_views(value: Option<&str>) -> Vec<AddressView> {
    let Some(value) = value else {
        return Vec::new();
    };
    mime::parse_addresses(value)
        .into_iter()
        .filter_map(|address| {
            let local = address.mailbox.trim();
            let host = address.host.trim();
            if local.is_empty() && host.is_empty() {
                return None;
            }
            let raw_address = if host.is_empty() {
                local.to_string()
            } else {
                format!("{local}@{host}")
            };
            Some(AddressView {
                name: decode_rfc2047(&address.name),
                address: decode_rfc2047(&raw_address),
            })
        })
        .collect()
}

pub fn extract_message_ids(value: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && ids.len() < 100 {
        if bytes[index] == b'<' {
            if let Some(end) = value[index + 1..].find('>') {
                let id = value[index..index + 1 + end + 1].trim().to_string();
                if id.len() > 2 {
                    ids.push(id);
                }
                index += end + 2;
                continue;
            }
        }
        index += 1;
    }
    ids
}

pub fn collect_parts(message: &[u8], max_leaf_bytes: usize) -> ParsedStructure {
    let mut leaves = Vec::new();
    let mut truncated = false;
    walk_parts(message, "", 0, max_leaf_bytes, &mut leaves, &mut truncated);
    ParsedStructure { leaves, truncated }
}

fn walk_parts(
    message: &[u8],
    prefix: &str,
    depth: usize,
    max_leaf_bytes: usize,
    leaves: &mut Vec<LeafPart>,
    truncated: &mut bool,
) {
    if leaves.len() >= MAX_PARTS {
        *truncated = true;
        return;
    }
    let headers = mime::parse_headers(message);
    let content = mime::content_type(&headers);
    let (_, body) = mime::split_headers_body(message);

    if depth < MAX_PARSE_DEPTH && content.is_multipart() {
        if let Some(boundary) = content.param("boundary") {
            let parts = mime::multipart_parts(body, boundary);
            if !parts.is_empty() {
                for (index, part) in parts.iter().enumerate() {
                    if leaves.len() >= MAX_PARTS {
                        *truncated = true;
                        return;
                    }
                    let child = child_part_id(prefix, index + 1);
                    walk_parts(part, &child, depth + 1, max_leaf_bytes, leaves, truncated);
                }
                return;
            }
        }
    }

    push_leaf(
        &headers,
        &content,
        body,
        prefix,
        max_leaf_bytes,
        leaves,
        truncated,
    );
}

fn child_part_id(prefix: &str, index: usize) -> String {
    if prefix.is_empty() {
        index.to_string()
    } else {
        format!("{prefix}.{index}")
    }
}

fn push_leaf(
    headers: &mime::Headers,
    content: &mime::ContentType,
    body: &[u8],
    prefix: &str,
    max_leaf_bytes: usize,
    leaves: &mut Vec<LeafPart>,
    truncated: &mut bool,
) {
    let part_id = if prefix.is_empty() {
        "1".to_string()
    } else {
        prefix.to_string()
    };
    let encoding = headers
        .get("content-transfer-encoding")
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "7bit".to_string());
    let mut data = mime::decode_transfer_encoding(body, &encoding);
    let full_size = data.len() as u64;
    let mut part_truncated = false;
    if data.len() > max_leaf_bytes {
        data.truncate(max_leaf_bytes);
        part_truncated = true;
        *truncated = true;
    }

    let (disposition, disposition_params) = headers
        .get("content-disposition")
        .map(parse_parameterized)
        .unwrap_or_default();
    let disposition = disposition.trim().to_ascii_lowercase();
    let disposition = if disposition.is_empty() {
        None
    } else {
        Some(disposition)
    };
    let filename = disposition_params
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("filename"))
        .map(|(_, value)| decode_parameter_value(value))
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            content
                .param("name")
                .map(decode_parameter_value)
                .filter(|value| !value.trim().is_empty())
        });
    let content_id = headers
        .get("content-id")
        .map(|value| {
            value
                .trim()
                .trim_matches(|ch| ch == '<' || ch == '>')
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty());

    leaves.push(LeafPart {
        part_id,
        content_type: format!("{}/{}", content.mime_type, content.subtype),
        charset: content.param("charset").map(|value| value.to_string()),
        encoding,
        disposition,
        filename,
        content_id,
        data,
        size: full_size,
        truncated: part_truncated,
    });
}

fn parse_parameterized(value: &str) -> (String, Vec<(String, String)>) {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;
    for ch in value.chars() {
        match ch {
            '\\' if in_quote && !escaped => {
                escaped = true;
                current.push(ch);
            }
            '"' if !escaped => {
                in_quote = !in_quote;
                current.push(ch);
            }
            ';' if !in_quote => {
                segments.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(ch);
                escaped = false;
            }
        }
    }
    segments.push(current);

    let head = segments
        .first()
        .map(|segment| segment.trim().to_string())
        .unwrap_or_default();
    let mut params = Vec::new();
    for segment in segments.iter().skip(1) {
        let Some((key, raw_value)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let raw_value = raw_value.trim();
        let value =
            if raw_value.len() >= 2 && raw_value.starts_with('"') && raw_value.ends_with('"') {
                raw_value[1..raw_value.len() - 1].to_string()
            } else {
                raw_value.to_string()
            };
        params.push((key, value));
    }
    (head, params)
}

pub fn parse_message(message: &[u8]) -> ParsedMessage {
    let headers = mime::parse_headers(message);
    let headers_view = headers_view(&headers);
    let structure = collect_parts(message, MAX_DETAIL_BYTES.max(MAX_ATTACHMENT_TOTAL_BYTES));

    let mut text: Option<String> = None;
    let mut html: Option<String> = None;
    let mut body_truncated = structure.truncated;
    let mut used = vec![false; structure.leaves.len()];

    for (index, leaf) in structure.leaves.iter().enumerate() {
        if leaf.is_attachment() {
            continue;
        }
        match leaf.content_type.as_str() {
            "text/plain" if text.is_none() => {
                used[index] = true;
                let decoded = decode_charset(&leaf.data, leaf.charset.as_deref());
                let (value, cut) = truncate_chars(decoded, MAX_BODY_TEXT_CHARS);
                text = Some(value);
                body_truncated |= cut || leaf.truncated;
            }
            "text/html" if html.is_none() => {
                used[index] = true;
                let decoded = decode_charset(&leaf.data, leaf.charset.as_deref());
                let limit = (MAX_HTML_BYTES / 4).max(1024);
                let (value, cut) = truncate_chars(decoded, limit);
                html = Some(value);
                body_truncated |= cut || leaf.truncated;
            }
            _ => {}
        }
    }

    let mut attachments = Vec::new();
    for (index, leaf) in structure.leaves.iter().enumerate() {
        if used[index] {
            continue;
        }

        let include = leaf.is_attachment() || !leaf.is_body_text();
        if !include {
            continue;
        }
        attachments.push(AttachmentView {
            part_id: leaf.part_id.clone(),
            filename: leaf.filename.clone(),
            content_type: leaf.content_type.clone(),
            size: leaf.size,
            disposition: leaf.disposition.clone(),
            inline: leaf.is_inline(),
            cid: leaf.content_id.clone(),
        });
    }

    ParsedMessage {
        headers: headers_view,
        text,
        html,
        attachments,
        body_truncated,
    }
}

pub fn searchable_text(message: &[u8]) -> String {
    let headers = mime::parse_headers(message);
    let view = headers_view(&headers);
    let mut text = String::new();
    text.push_str(&view.subject);
    text.push('\n');
    if let Some(from) = &view.from {
        text.push_str(&from.name);
        text.push(' ');
        text.push_str(&from.address);
        text.push('\n');
    }
    for address in view.to.iter().chain(view.cc.iter()) {
        text.push_str(&address.name);
        text.push(' ');
        text.push_str(&address.address);
        text.push('\n');
    }
    let structure = collect_parts(message, crate::SEARCH_TEXT_BYTES);
    for leaf in &structure.leaves {
        if leaf.is_attachment() {
            continue;
        }
        match leaf.content_type.as_str() {
            "text/plain" => {
                text.push_str(&decode_charset(&leaf.data, leaf.charset.as_deref()));
                text.push('\n');
            }
            "text/html" => {
                text.push_str(&html_to_text(&decode_charset(
                    &leaf.data,
                    leaf.charset.as_deref(),
                )));
                text.push('\n');
            }
            _ => {}
        }
        if text.len() >= SEARCH_TEXT_LIMIT_CHARS {
            break;
        }
    }
    let (text, _) = truncate_chars(text, SEARCH_TEXT_LIMIT_CHARS);
    text.to_lowercase()
}

const SEARCH_TEXT_LIMIT_CHARS: usize = 300_000;

pub fn summary_fields(message: &[u8]) -> SummaryFields {
    let headers = mime::parse_headers(message);
    let view = headers_view(&headers);
    let structure = collect_parts(message, 64 * 1024);

    let mut snippet = String::new();
    for leaf in &structure.leaves {
        if leaf.is_attachment() || leaf.content_type != "text/plain" {
            continue;
        }
        snippet = collapse_whitespace(&decode_charset(&leaf.data, leaf.charset.as_deref()));
        if !snippet.is_empty() {
            break;
        }
    }
    if snippet.is_empty() {
        for leaf in &structure.leaves {
            if leaf.is_attachment() || leaf.content_type != "text/html" {
                continue;
            }
            let text = html_to_text(&decode_charset(&leaf.data, leaf.charset.as_deref()));
            snippet = collapse_whitespace(&text);
            if !snippet.is_empty() {
                break;
            }
        }
    }
    let (snippet, _) = truncate_chars(snippet, SNIPPET_CHARS);

    let has_attachments = structure
        .leaves
        .iter()
        .any(|leaf| leaf.is_attachment() || !leaf.is_body_text());

    SummaryFields {
        subject: view.subject,
        from: view.from,
        to: view.to,
        date: view.date,
        message_id: view.message_id,
        snippet,
        has_attachments,
    }
}

pub fn thread_key(subject: &str, message_id: Option<&str>) -> String {
    if let Some(message_id) = message_id {
        if !message_id.trim().is_empty() {
            return message_id.trim().to_string();
        }
    }
    normalize_subject(subject)
}

pub fn normalize_subject(subject: &str) -> String {
    let mut value = subject.trim().to_string();
    loop {
        let lowered = value.to_ascii_lowercase();
        let mut stripped = false;
        for prefix in ["re:", "fwd:", "fw:", "aw:", "回复:", "转发:"] {
            if lowered.starts_with(prefix) {
                value = value[prefix.len()..].trim().to_string();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    let collapsed = collapse_whitespace(&value).to_ascii_lowercase();
    if collapsed.is_empty() {
        "(no subject)".to_string()
    } else {
        collapsed
    }
}

pub fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch);
    }
    out.trim().to_string()
}

pub fn html_to_text(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut out = String::with_capacity(html.len() / 2);
    let mut index = 0usize;
    let mut skip: Option<&'static str> = None;
    while index < bytes.len() {
        if let Some(name) = skip {
            let Some(position) = bytes[index..].iter().position(|byte| *byte == b'<') else {
                break;
            };
            let position = index + position;
            if bytes[position..].starts_with(b"</") {
                let Some(end) = bytes[position..].iter().position(|byte| *byte == b'>') else {
                    break;
                };
                let end = position + end;
                let closing = String::from_utf8_lossy(&bytes[position + 2..end])
                    .trim()
                    .to_ascii_lowercase();
                if closing == name {
                    skip = None;
                }
                index = end + 1;
                continue;
            }
            index = position + 1;
            continue;
        }
        if bytes[index] == b'<' {
            if starts_with_ignore_ascii_case(&bytes[index..], b"<script") {
                skip = Some("script");
            } else if starts_with_ignore_ascii_case(&bytes[index..], b"<style") {
                skip = Some("style");
            }
            match bytes[index..].iter().position(|byte| *byte == b'>') {
                Some(end) => {
                    index += end + 1;
                    out.push(' ');
                }
                None => break,
            }
            continue;
        }
        let ch = html[index..].chars().next().unwrap_or(' ');
        out.push(ch);
        index += ch.len_utf8();
    }
    decode_html_entities(&out)
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

pub fn decode_html_entities(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'&' {
            if let Some(semicolon) = value[index + 1..].find(';') {
                let entity = &value[index + 1..index + 1 + semicolon];
                if entity.len() <= 10 {
                    if let Some(decoded) = decode_entity(entity) {
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

fn decode_entity(entity: &str) -> Option<char> {
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

pub fn decode_rfc2047(input: &str) -> String {
    if !input.contains("=?") {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    let mut last_was_encoded = false;
    while index < input.len() {
        if input[index..].starts_with("=?") {
            if let Some((decoded, consumed)) = parse_encoded_word(&input[index..]) {
                out.push_str(&decoded);
                index += consumed;
                last_was_encoded = true;
                continue;
            }
        }
        let ch = input[index..].chars().next().unwrap_or(' ');
        if last_was_encoded && ch.is_ascii_whitespace() {
            let mut lookahead = index;
            while lookahead < input.len() && input.as_bytes()[lookahead].is_ascii_whitespace() {
                lookahead += 1;
            }
            if input[lookahead..].starts_with("=?")
                && parse_encoded_word(&input[lookahead..]).is_some()
            {
                index = lookahead;
                continue;
            }
        }
        out.push(ch);
        index += ch.len_utf8();
        last_was_encoded = false;
    }
    out
}

fn parse_encoded_word(input: &str) -> Option<(String, usize)> {
    let rest = input.strip_prefix("=?")?;
    let charset_end = rest.find('?')?;
    if charset_end == 0 || charset_end > 64 {
        return None;
    }
    let charset = &rest[..charset_end];
    let after_charset = &rest[charset_end + 1..];
    let encoding_end = after_charset.find('?')?;
    if encoding_end != 1 {
        return None;
    }
    let encoding = after_charset.as_bytes()[0].to_ascii_uppercase();
    let text_rest = &after_charset[encoding_end + 1..];
    let text_end = text_rest.find("?=")?;
    let text = &text_rest[..text_end];
    if !text.is_ascii() || text.len() > 4096 {
        return None;
    }
    let bytes = match encoding {
        b'B' => decode_base64_relaxed(text)?,
        b'Q' => decode_q_encoding(text)?,
        _ => return None,
    };

    let charset = charset.split('*').next().unwrap_or(charset);
    let decoded = decode_charset(&bytes, Some(charset));
    Some((
        decoded,
        2 + charset_end + 1 + encoding_end + 1 + text_end + 2,
    ))
}

fn decode_base64_relaxed(text: &str) -> Option<Vec<u8>> {
    let mut cleaned: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    while !cleaned.len().is_multiple_of(4) {
        cleaned.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .ok()
}

fn decode_q_encoding(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => {
                out.push(b' ');
                index += 1;
            }
            b'=' => {
                let high = hex_value(*bytes.get(index + 1)?)?;
                let low = hex_value(*bytes.get(index + 2)?)?;
                out.push((high << 4) | low);
                index += 3;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn decode_charset(bytes: &[u8], charset: Option<&str>) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if let Some(label) = charset.map(str::trim).filter(|label| !label.is_empty()) {
        let label = label.trim_matches('"');
        if let Some(encoding) = Encoding::for_label(label.as_bytes()) {
            let (decoded, _, _) = encoding.decode(bytes);
            return decoded.into_owned();
        }
    }
    match std::str::from_utf8(bytes) {
        Ok(value) => value.to_string(),

        Err(_) => {
            let (decoded, _, _) = encoding_rs::WINDOWS_1252.decode(bytes);
            decoded.into_owned()
        }
    }
}

pub fn decode_parameter_value(raw: &str) -> String {
    let raw = raw.trim();

    if let Some((charset, rest)) = raw.split_once('\'') {
        if let Some((_language, encoded)) = rest.split_once('\'') {
            if let Some(bytes) = percent_decode(encoded) {
                return decode_charset(&bytes, Some(charset));
            }
        }
    }
    decode_rfc2047(raw)
}

pub fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            let high = hex_value(high)?;
            let low = hex_value(low)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Some(out)
}

pub fn encode_rfc2047(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut words = Vec::new();
    for chunk in bytes.chunks(45) {
        words.push(format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(chunk)
        ));
    }
    words.join("\r\n ")
}

pub fn normalize_cid(raw: &str) -> String {
    let trimmed = raw.trim();
    let trimmed = trimmed
        .strip_prefix("cid:")
        .or_else(|| trimmed.strip_prefix("CID:"))
        .unwrap_or(trimmed);
    let trimmed = trimmed.trim_matches(|ch| ch == '<' || ch == '>' || ch == '"');
    match percent_decode(trimmed) {
        Some(bytes) => String::from_utf8_lossy(&bytes).trim().to_string(),
        None => trimmed.to_string(),
    }
}

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn parse_date_header(value: &str) -> Option<OffsetDateTime> {
    let cleaned = strip_comments(value);
    let tokens: Vec<&str> = cleaned
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();

    let mut month_index = None;
    for (index, token) in tokens.iter().enumerate() {
        if month_from_name(token).is_some() {
            month_index = Some(index);
            break;
        }
    }
    let month_index = month_index?;
    let month = month_from_name(tokens[month_index])?;

    let day = tokens[..month_index].iter().rev().find_map(|token| {
        token
            .parse::<u32>()
            .ok()
            .filter(|day| (1..=31).contains(day))
    })?;

    let mut year = None;
    for token in tokens.iter().skip(month_index + 1) {
        let digits = token.trim_start_matches(|ch: char| !ch.is_ascii_digit());
        if digits.len() >= 2 && digits.chars().all(|ch| ch.is_ascii_digit()) && digits.len() <= 4 {
            if let Ok(value) = digits.parse::<i64>() {
                year = Some(if digits.len() <= 2 {
                    if value < 50 {
                        2000 + value
                    } else {
                        1900 + value
                    }
                } else {
                    value
                });
                break;
            }
        }
    }
    let year = year?;
    if !(1970..=2100).contains(&year) {
        return None;
    }

    let mut hour = 0u8;
    let mut minute = 0u8;
    let mut second = 0u8;
    let mut time_index = None;
    for (index, token) in tokens.iter().enumerate() {
        if let Some((h, m, s)) = parse_clock(token) {
            hour = h;
            minute = m;
            second = s;
            time_index = Some(index);
            break;
        }
    }

    let mut offset = UtcOffset::UTC;
    if let Some(time_index) = time_index {
        for token in tokens.iter().skip(time_index + 1).take(2) {
            if let Some(parsed) = parse_zone(token) {
                offset = parsed;
                break;
            }
        }
    }

    let date = Date::from_calendar_date(year as i32, month, day as u8).ok()?;
    let time = Time::from_hms(hour, minute, second.min(59)).ok()?;
    let local = PrimitiveDateTime::new(date, time).assume_offset(offset);
    Some(local.to_offset(UtcOffset::UTC))
}

fn strip_comments(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut depth = 0usize;
    for ch in value.chars() {
        match ch {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

fn month_from_name(value: &str) -> Option<Month> {
    let lowered = value.trim().to_ascii_lowercase();
    let name = lowered.get(..3)?;
    let number = MONTH_NAMES
        .iter()
        .position(|month| month.eq_ignore_ascii_case(name))?;
    Month::try_from((number + 1) as u8).ok()
}

fn parse_clock(value: &str) -> Option<(u8, u8, u8)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u8>().ok()?;
    let minute = parts.next()?.parse::<u8>().ok()?;
    let second = parts
        .next()
        .map(|s| s.parse::<u8>().ok())
        .unwrap_or(Some(0))?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn parse_zone(value: &str) -> Option<UtcOffset> {
    let lowered = value.trim().to_ascii_lowercase();
    if lowered == "z" {
        return Some(UtcOffset::UTC);
    }
    if let Some(rest) = lowered.strip_prefix('+') {
        return parse_numeric_offset(rest, 1);
    }
    if let Some(rest) = lowered.strip_prefix('-') {
        return parse_numeric_offset(rest, -1);
    }
    let hours = match lowered.as_str() {
        "ut" | "utc" | "gmt" => 0,
        "est" => -5,
        "edt" => -4,
        "cst" => -6,
        "cdt" => -5,
        "mst" => -7,
        "mdt" => -6,
        "pst" => -8,
        "pdt" => -7,
        _ => return None,
    };
    UtcOffset::from_hms(hours, 0, 0).ok()
}

fn parse_numeric_offset(digits: &str, sign: i32) -> Option<UtcOffset> {
    if digits.len() != 4 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let hours = digits[..2].parse::<i32>().ok()? * sign;
    let minutes = digits[2..].parse::<i32>().ok()?;
    UtcOffset::from_hms(hours as i8, minutes as i8, 0).ok()
}

pub fn format_rfc3339_utc(datetime: OffsetDateTime) -> String {
    let datetime = datetime.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        datetime.year(),
        datetime.month() as u8,
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

pub fn format_rfc2822(datetime: OffsetDateTime) -> String {
    let datetime = datetime.to_offset(UtcOffset::UTC);
    let weekday = match datetime.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = MONTH_NAMES[(datetime.month() as u8 - 1) as usize];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        weekday,
        datetime.day(),
        month,
        datetime.year(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}

pub fn truncate_chars(value: String, max_chars: usize) -> (String, bool) {
    if value.chars().count() <= max_chars {
        return (value, false);
    }
    let truncated: String = value.chars().take(max_chars).collect();
    (truncated, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"From: =?UTF-8?B?5L2g5aW9?= <alice@example.com>\r\n\
To: Bob <bob@example.org>, carol@example.net\r\n\
Subject: =?UTF-8?B?5L2g5aW9?=\r\n\
Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
Message-ID: <abc@example.com>\r\n\
Content-Type: multipart/alternative; boundary=b1\r\n\
\r\n\
--b1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
hello world\r\n\
--b1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>hello <b>world</b></p>\r\n\
--b1--\r\n";

    #[test]
    fn rfc2047_decodes_base64_q_and_adjacent_words() {
        assert_eq!(decode_rfc2047("=?UTF-8?B?5L2g5aW9?="), "你好");
        assert_eq!(decode_rfc2047("=?ISO-8859-1?Q?Andr=E9?="), "André");
        assert_eq!(
            decode_rfc2047("=?UTF-8?B?5L2g?= =?UTF-8?B?5aW9?="),
            "你好",
            "相邻编码字之间的空白必须被忽略"
        );

        assert_eq!(decode_rfc2047("plain =?broken"), "plain =?broken");
        assert_eq!(decode_rfc2047("Re: hello"), "Re: hello");
    }

    #[test]
    fn charset_conversion_handles_gbk_and_latin1() {
        assert_eq!(
            decode_charset(&[0xC4, 0xE3, 0xBA, 0xC3], Some("gb2312")),
            "你好"
        );

        assert_eq!(
            decode_charset(&[b'A', b'n', b'd', b'r', 0xE9], Some("iso-8859-1")),
            "André"
        );

        assert_eq!(decode_charset("你好".as_bytes(), Some("x-unknown")), "你好");

        assert!(!decode_charset(&[0xFF, 0xFE, 0x80], None).is_empty());
    }

    #[test]
    fn dates_parse_common_rfc2822_shapes() {
        assert_eq!(
            parse_date_header("Fri, 23 Oct 2026 14:30:00 +0800")
                .map(format_rfc3339_utc)
                .as_deref(),
            Some("2026-10-23T06:30:00Z")
        );
        assert_eq!(
            parse_date_header("23 Oct 2026 14:30 GMT")
                .map(format_rfc3339_utc)
                .as_deref(),
            Some("2026-10-23T14:30:00Z")
        );

        assert_eq!(
            parse_date_header("Tue, 03 Nov 26 07:00:00 EST (winter)")
                .map(format_rfc3339_utc)
                .as_deref(),
            Some("2026-11-03T12:00:00Z")
        );
        assert!(parse_date_header("not a date").is_none());
        assert!(parse_date_header("").is_none());
    }

    #[test]
    fn parsed_message_splits_text_html_and_headers() {
        let parsed = parse_message(SAMPLE);
        assert_eq!(parsed.headers.subject, "你好");
        assert_eq!(
            parsed.headers.from.as_ref().map(|from| from.name.as_str()),
            Some("你好")
        );
        assert_eq!(
            parsed.headers.from.as_ref().unwrap().address,
            "alice@example.com"
        );
        assert_eq!(parsed.headers.to.len(), 2);
        assert_eq!(parsed.headers.date.as_deref(), Some("2026-10-23T06:30:00Z"));
        assert_eq!(parsed.text.as_deref().map(str::trim), Some("hello world"));
        assert!(parsed
            .html
            .as_deref()
            .unwrap_or("")
            .contains("<b>world</b>"));
        assert!(parsed.attachments.is_empty());
        assert!(!parsed.body_truncated);
    }

    #[test]
    fn attachment_parts_are_listed_with_numbered_part_ids() {
        let message = b"Content-Type: multipart/mixed; boundary=m\r\n\r\n\
--m\r\n\
Content-Type: text/plain\r\n\r\n\
body\r\n\
--m\r\n\
Content-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Disposition: attachment; filename=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
QUJD\r\n\
--m\r\n\
Content-Type: image/png\r\n\
Content-ID: <img1@example.com>\r\n\
Content-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
QUJD\r\n\
--m--\r\n";
        let parsed = parse_message(message);
        assert_eq!(parsed.attachments.len(), 2);
        assert_eq!(parsed.attachments[0].part_id, "2");
        assert_eq!(parsed.attachments[0].filename.as_deref(), Some("a.pdf"));
        assert_eq!(parsed.attachments[0].size, 3);
        assert!(!parsed.attachments[0].inline);
        assert_eq!(parsed.attachments[1].part_id, "3");
        assert!(parsed.attachments[1].inline);
        assert_eq!(
            parsed.attachments[1].cid.as_deref(),
            Some("img1@example.com")
        );
    }

    #[test]
    fn nested_multipart_part_ids_follow_imap_numbering() {
        let message = b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\r\n\
--inner\r\n\
Content-Type: text/plain\r\n\r\n\
plain\r\n\
--inner\r\n\
Content-Type: text/html\r\n\r\n\
<b>html</b>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"x.bin\"\r\n\r\n\
raw\r\n\
--outer--\r\n";
        let parsed = parse_message(message);
        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].part_id, "2");
        assert!(parsed.text.is_some());
        assert!(parsed.html.is_some());
    }

    #[test]
    fn summary_carries_snippet_attachment_flag_and_thread_key() {
        let fields = summary_fields(SAMPLE);
        assert_eq!(fields.subject, "你好");
        assert!(fields.snippet.starts_with("hello world"));
        assert!(!fields.has_attachments);
        assert_eq!(
            thread_key(&fields.subject, fields.message_id.as_deref()),
            "<abc@example.com>"
        );

        let with_attachment = b"Content-Type: multipart/mixed; boundary=m\r\n\r\n\
--m\r\nContent-Type: text/plain\r\n\r\nhi\r\n\
--m\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\n\r\nx\r\n--m--\r\n";
        assert!(summary_fields(with_attachment).has_attachments);
    }

    #[test]
    fn thread_keys_normalize_reply_prefixes_when_message_id_is_missing() {
        assert_eq!(normalize_subject("Re: Hello World"), "hello world");
        assert_eq!(
            normalize_subject("RE: Re: Fwd:  Hello\tWorld"),
            "hello world"
        );
        assert_eq!(normalize_subject("   "), "(no subject)");
        assert_eq!(thread_key("Re: x", None), "x");
        assert_eq!(thread_key("Re: x", Some("<id@x>")), "<id@x>");
    }

    #[test]
    fn deeply_nested_multipart_is_bounded() {
        let mut message = b"Content-Type: text/plain\r\n\r\nleaf\r\n".to_vec();
        for _ in 0..(MAX_PARSE_DEPTH * 3) {
            let mut outer = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n".to_vec();
            outer.extend_from_slice(&message);
            outer.extend_from_slice(b"\r\n--b--\r\n");
            message = outer;
        }
        let parsed = collect_parts(&message, 1024);

        assert!(parsed.leaves.len() <= MAX_PARTS);
    }

    #[test]
    fn malformed_base64_falls_back_to_raw_bytes_instead_of_dropping_content() {
        let parts = collect_parts(
            b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nnot*base64\r\n",
            1024,
        );
        assert_eq!(parts.leaves.len(), 1);
        assert!(!parts.leaves[0].data.is_empty());
    }

    #[test]
    fn parameter_values_decode_rfc2231_and_2047() {
        assert_eq!(
            decode_parameter_value("UTF-8''%E4%B8%AD%E6%96%87.pdf"),
            "中文.pdf"
        );
        assert_eq!(
            decode_parameter_value("=?UTF-8?B?5L2g5aW9?=.pdf"),
            "你好.pdf"
        );
        assert_eq!(normalize_cid("cid:abc%40example.com"), "abc@example.com");
        assert_eq!(normalize_cid("<abc@example.com>"), "abc@example.com");
    }

    #[test]
    fn rfc2047_encoder_chunks_long_values_below_the_line_limit() {
        let long = "中文主题".repeat(100);
        let encoded = encode_rfc2047(&long);
        for word in encoded.split("\r\n ") {
            assert!(word.len() <= 75, "编码字超过 75 字符：{}", word.len());
            assert!(word.starts_with("=?UTF-8?B?") && word.ends_with("?="));
        }
    }
}
