use std::borrow::Cow;

use crate::date;
use crate::error::{MailError, Result};
use crate::maildir::{FlagSet, MessageMeta};
use crate::mime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    Full,
    Header,
    Text,
    HeaderFields { names: Vec<String>, not: bool },
    Part(Vec<u32>),
    Mime(Vec<u32>),
    HeaderPart(Vec<u32>),
    TextPart(Vec<u32>),
}

impl Section {
    pub fn label(&self) -> String {
        match self {
            Section::Full => String::new(),
            Section::Header => "HEADER".to_string(),
            Section::Text => "TEXT".to_string(),
            Section::HeaderFields { names, not } => {
                let keyword = if *not {
                    "HEADER.FIELDS.NOT"
                } else {
                    "HEADER.FIELDS"
                };
                format!("{keyword} ({})", names.join(" "))
            }
            Section::Part(path) => render_path(path),
            Section::Mime(path) => suffix_path(path, "MIME"),
            Section::HeaderPart(path) => suffix_path(path, "HEADER"),
            Section::TextPart(path) => suffix_path(path, "TEXT"),
        }
    }
}

fn render_path(path: &[u32]) -> String {
    path.iter()
        .map(|segment| segment.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn suffix_path(path: &[u32], suffix: &str) -> String {
    if path.is_empty() {
        suffix.to_string()
    } else {
        format!("{}.{suffix}", render_path(path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySpec {
    pub section: Section,
    pub peek: bool,
    pub partial: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    Flags,
    InternalDate,
    Size,
    Uid,
    ModSeq,
    Envelope,
    BodyStructure,
    Body(BodySpec),
    Rfc822,
    Rfc822Header,
    Rfc822Text,

    Binary(BodySpec),

    BinarySize(Vec<u32>),
}

pub fn needs_message(items: &[FetchItem]) -> bool {
    items.iter().any(|item| {
        !matches!(
            item,
            FetchItem::Flags
                | FetchItem::InternalDate
                | FetchItem::Size
                | FetchItem::Uid
                | FetchItem::ModSeq
        )
    })
}

pub fn needs_full_message(items: &[FetchItem]) -> bool {
    items.iter().any(|item| match item {
        FetchItem::Flags | FetchItem::InternalDate | FetchItem::Size | FetchItem::Uid => false,
        FetchItem::ModSeq => false,
        FetchItem::Envelope | FetchItem::Rfc822Header => false,
        FetchItem::Body(spec) => match &spec.section {
            Section::Header | Section::HeaderFields { .. } => false,
            Section::Mime(path) if path.is_empty() => false,
            _ => true,
        },
        FetchItem::BodyStructure | FetchItem::Rfc822 | FetchItem::Rfc822Text => true,
        FetchItem::Binary(_) | FetchItem::BinarySize(_) => true,
    })
}

pub fn split_changedsince(items: &str) -> Result<(&str, Option<u64>)> {
    let trimmed = items.trim();
    let Some(close) = trimmed.rfind(')') else {
        return Ok((trimmed, None));
    };
    if close != trimmed.len() - 1 {
        return Ok((trimmed, None));
    }
    let Some(open) = trimmed[..close].rfind('(') else {
        return Ok((trimmed, None));
    };
    let inside = &trimmed[open + 1..close];
    let inside_upper = inside.trim().to_ascii_uppercase();
    if !inside_upper.starts_with("CHANGEDSINCE") {
        return Ok((trimmed, None));
    }
    let rest = inside_upper
        .strip_prefix("CHANGEDSINCE")
        .unwrap_or("")
        .trim();
    if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MailError::invalid("CHANGEDSINCE requires a modseq"));
    }
    let modseq: u64 = rest
        .parse()
        .map_err(|_| MailError::invalid("CHANGEDSINCE modseq is out of range"))?;
    Ok((trimmed[..open].trim_end(), Some(modseq)))
}

pub fn parse_items(raw: &str) -> Result<Vec<FetchItem>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(MailError::invalid("FETCH requires at least one item"));
    }
    let inner = strip_outer_parentheses(trimmed)?;
    let mut cursor = Cursor::new(inner);
    let mut items = Vec::new();

    loop {
        cursor.skip_spaces();
        if cursor.done() {
            break;
        }
        let name = cursor.read_until(|byte| byte == b' ' || byte == b'[' || byte == b'<');
        if name.is_empty() {
            return Err(MailError::invalid("empty FETCH item"));
        }
        let upper = name.to_ascii_uppercase();
        match upper.as_str() {
            "FLAGS" => items.push(FetchItem::Flags),
            "INTERNALDATE" => items.push(FetchItem::InternalDate),
            "RFC822.SIZE" => items.push(FetchItem::Size),
            "UID" => items.push(FetchItem::Uid),
            "MODSEQ" => items.push(FetchItem::ModSeq),
            "ENVELOPE" => items.push(FetchItem::Envelope),
            "BODYSTRUCTURE" => items.push(FetchItem::BodyStructure),
            "RFC822" => items.push(FetchItem::Rfc822),
            "RFC822.HEADER" => items.push(FetchItem::Rfc822Header),
            "RFC822.TEXT" => items.push(FetchItem::Rfc822Text),
            "ALL" => items.extend([
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Size,
                FetchItem::Envelope,
            ]),
            "FAST" => items.extend([FetchItem::Flags, FetchItem::InternalDate, FetchItem::Size]),
            "FULL" => items.extend([
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Size,
                FetchItem::Envelope,
                FetchItem::BodyStructure,
            ]),
            "BODY" | "BODY.PEEK" => {
                if cursor.peek() == Some(b'[') {
                    let (section, partial) = cursor.read_section()?;
                    items.push(FetchItem::Body(BodySpec {
                        section,
                        peek: upper == "BODY.PEEK",
                        partial,
                    }));
                } else if upper == "BODY" {
                    items.push(FetchItem::BodyStructure);
                } else {
                    return Err(MailError::invalid("BODY.PEEK requires a section"));
                }
            }
            "BINARY" | "BINARY.PEEK" => {
                if cursor.peek() != Some(b'[') {
                    return Err(MailError::invalid("BINARY requires a section"));
                }
                let (section, partial) = cursor.read_section()?;
                if binary_path(&section).is_none() {
                    return Err(MailError::invalid(
                        "BINARY supports only body part sections",
                    ));
                }

                items.push(FetchItem::Binary(BodySpec {
                    section,
                    peek: upper == "BINARY.PEEK",
                    partial,
                }));
            }
            "BINARY.SIZE" => {
                if cursor.peek() != Some(b'[') {
                    return Err(MailError::invalid("BINARY.SIZE requires a section"));
                }
                let (section, _) = cursor.read_section()?;
                let Some(path) = binary_path(&section) else {
                    return Err(MailError::invalid(
                        "BINARY.SIZE supports only body part sections",
                    ));
                };
                items.push(FetchItem::BinarySize(path));
            }
            _ => {
                return Err(MailError::invalid(format!(
                    "unsupported FETCH item: {name}"
                )))
            }
        }
    }

    if items.is_empty() {
        return Err(MailError::invalid("FETCH requires at least one item"));
    }
    Ok(items)
}

fn strip_outer_parentheses(value: &str) -> Result<&str> {
    let value = value.trim();
    if !value.starts_with('(') {
        return Ok(value);
    }
    if !value.ends_with(')') {
        return Err(MailError::invalid("unbalanced FETCH item list"));
    }

    let mut depth = 0i32;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 && index != value.len() - 1 {
                    return Err(MailError::invalid("unbalanced FETCH item list"));
                }
            }
            _ => {}
        }
    }
    Ok(&value[1..value.len() - 1])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(value: &'a str) -> Self {
        Self {
            bytes: value.as_bytes(),
            position: 0,
        }
    }

    fn done(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn bump(&mut self) {
        self.position += 1;
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ')) {
            self.bump();
        }
    }

    fn read_until(&mut self, stop: impl Fn(u8) -> bool) -> String {
        let start = self.position;
        while let Some(byte) = self.peek() {
            if stop(byte) {
                break;
            }
            self.bump();
        }
        String::from_utf8_lossy(&self.bytes[start..self.position]).to_string()
    }

    fn read_section(&mut self) -> Result<(Section, Option<(u32, u32)>)> {
        if self.peek() != Some(b'[') {
            return Err(MailError::invalid("expected '['"));
        }
        self.bump();
        let start = self.position;
        while let Some(byte) = self.peek() {
            if byte == b']' {
                break;
            }
            self.bump();
        }
        if self.peek() != Some(b']') {
            return Err(MailError::invalid("unterminated section"));
        }
        let content = String::from_utf8_lossy(&self.bytes[start..self.position]).to_string();
        self.bump();

        let mut partial = None;
        if self.peek() == Some(b'<') {
            self.bump();
            let inside = {
                let start = self.position;
                while let Some(byte) = self.peek() {
                    if byte == b'>' {
                        break;
                    }
                    self.bump();
                }
                if self.peek() != Some(b'>') {
                    return Err(MailError::invalid("unterminated partial specifier"));
                }
                let inside = String::from_utf8_lossy(&self.bytes[start..self.position]).to_string();
                self.bump();
                inside
            };
            let Some((start, count)) = inside.split_once('.') else {
                return Err(MailError::invalid(
                    "partial specifier must be <start.count>",
                ));
            };
            let start: u32 = start
                .parse()
                .map_err(|_| MailError::invalid("invalid partial start"))?;
            let count: u32 = count
                .parse()
                .map_err(|_| MailError::invalid("invalid partial count"))?;
            if count == 0 {
                return Err(MailError::invalid("partial count must be positive"));
            }
            partial = Some((start, count));
        }
        Ok((parse_section(&content)?, partial))
    }
}

fn parse_section(content: &str) -> Result<Section> {
    let cleaned = content.replace(['(', ')'], " ");
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(Section::Full);
    }
    let upper = tokens[0].to_ascii_uppercase();
    match upper.as_str() {
        "HEADER" if tokens.len() == 1 => return Ok(Section::Header),
        "TEXT" if tokens.len() == 1 => return Ok(Section::Text),
        "HEADER.FIELDS" | "HEADER.FIELDS.NOT" => {
            let mut names = Vec::new();
            for name in &tokens[1..] {
                let name = name.trim();
                let valid = !name.is_empty()
                    && name.bytes().all(|byte| {
                        byte.is_ascii_graphic()
                            && !matches!(byte, b':' | b'(' | b')' | b'"' | b'\\')
                    });
                if !valid {
                    return Err(MailError::invalid("invalid header field name"));
                }

                names.push(name.to_string());
            }
            if names.is_empty() {
                return Err(MailError::invalid("HEADER.FIELDS requires field names"));
            }
            return Ok(Section::HeaderFields {
                names,
                not: upper == "HEADER.FIELDS.NOT",
            });
        }
        "MIME" if tokens.len() == 1 => return Ok(Section::Mime(Vec::new())),
        _ => {}
    }

    let mut path: Vec<u32> = Vec::new();
    let mut suffix: Option<&str> = None;
    for (index, segment) in upper.split('.').enumerate() {
        match segment {
            "MIME" | "HEADER" | "TEXT" if index > 0 && suffix.is_none() => {
                suffix = Some(match segment {
                    "MIME" => "MIME",
                    "HEADER" => "HEADER",
                    _ => "TEXT",
                });
                break;
            }
            value if value.bytes().all(|byte| byte.is_ascii_digit()) && !value.is_empty() => {
                let number: u32 = value
                    .parse()
                    .map_err(|_| MailError::invalid("invalid part number"))?;
                if number == 0 {
                    return Err(MailError::invalid("part numbers start at 1"));
                }
                path.push(number);
            }
            _ => return Err(MailError::invalid(format!("invalid section: {content}"))),
        }
    }
    if path.is_empty() {
        return Err(MailError::invalid(format!("invalid section: {content}")));
    }
    Ok(match suffix {
        None => Section::Part(path),
        Some("MIME") => Section::Mime(path),
        Some("HEADER") => Section::HeaderPart(path),
        Some(_) => Section::TextPart(path),
    })
}

pub fn format_flags(flags: &FlagSet) -> String {
    let names: Vec<String> = flags.iter().map(|flag| flag.imap_name()).collect();
    format!("({})", names.join(" "))
}

pub fn render(
    items: &[FetchItem],
    meta: &MessageMeta,
    message: Option<&[u8]>,
    uid_mode: bool,
) -> Result<(Vec<u8>, bool)> {
    let mut out: Vec<u8> = Vec::new();
    let mut mark_seen = false;
    let mut first = true;

    let mut push_separator = |out: &mut Vec<u8>| {
        if !first {
            out.push(b' ');
        }
        first = false;
    };

    if uid_mode && !items.contains(&FetchItem::Uid) {
        push_separator(&mut out);
        out.extend_from_slice(format!("UID {}", meta.uid).as_bytes());
    }

    for item in items {
        match item {
            FetchItem::Flags => {
                push_separator(&mut out);
                out.extend_from_slice(format!("FLAGS {}", format_flags(&meta.flags)).as_bytes());
            }
            FetchItem::InternalDate => {
                push_separator(&mut out);
                out.extend_from_slice(
                    format!(
                        "INTERNALDATE \"{}\"",
                        date::format_date_time(meta.internal_date)
                    )
                    .as_bytes(),
                );
            }
            FetchItem::Size => {
                push_separator(&mut out);
                out.extend_from_slice(format!("RFC822.SIZE {}", meta.size).as_bytes());
            }
            FetchItem::Uid => {
                push_separator(&mut out);
                out.extend_from_slice(format!("UID {}", meta.uid).as_bytes());
            }
            FetchItem::ModSeq => {
                push_separator(&mut out);
                out.extend_from_slice(format!("MODSEQ ({})", meta.modseq).as_bytes());
            }
            FetchItem::Envelope => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                push_separator(&mut out);
                out.extend_from_slice(b"ENVELOPE ");
                out.extend_from_slice(mime::envelope(&mime::parse_headers(message)).as_bytes());
            }
            FetchItem::BodyStructure => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                push_separator(&mut out);
                out.extend_from_slice(b"BODYSTRUCTURE ");
                out.extend_from_slice(mime::body_structure(message).as_bytes());
            }
            FetchItem::Body(spec) => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                if !spec.peek {
                    mark_seen = true;
                }
                push_separator(&mut out);
                push_body(&mut out, message, spec);
            }
            FetchItem::Rfc822 => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                mark_seen = true;
                push_separator(&mut out);
                push_literal(&mut out, "RFC822", message);
            }
            FetchItem::Rfc822Header => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                push_separator(&mut out);
                let block = mime::parse_headers(message).raw_block(None);
                push_literal(&mut out, "RFC822.HEADER", &block);
            }
            FetchItem::Rfc822Text => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                mark_seen = true;
                push_separator(&mut out);
                let (_, body) = mime::split_headers_body(message);
                push_literal(&mut out, "RFC822.TEXT", body);
            }
            FetchItem::Binary(spec) => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                if !spec.peek {
                    mark_seen = true;
                }
                push_separator(&mut out);
                push_binary(&mut out, message, spec);
            }
            FetchItem::BinarySize(path) => {
                let message =
                    message.ok_or_else(|| MailError::storage("message body is unavailable"))?;
                push_separator(&mut out);
                let label = format!("BINARY.SIZE[{}]", render_path(path));
                match decode_binary_part(message, path) {
                    Some(data) => {
                        out.extend_from_slice(format!("{label} {}", data.len()).as_bytes());
                    }
                    None => {
                        out.extend_from_slice(label.as_bytes());
                        out.extend_from_slice(b" NIL");
                    }
                }
            }
        }
    }

    Ok((out, mark_seen))
}

fn push_body(out: &mut Vec<u8>, message: &[u8], spec: &BodySpec) {
    let label = format!("BODY[{}]", spec.section.label());
    let label = match spec.partial {
        Some((start, _)) => format!("{label}<{start}>"),
        None => label,
    };
    match extract_section(message, &spec.section) {
        None => {
            out.extend_from_slice(label.as_bytes());
            out.extend_from_slice(b" NIL");
        }
        Some(data) => {
            let data = match spec.partial {
                Some((start, count)) => {
                    let start = start as usize;
                    if start >= data.len() {
                        &[][..]
                    } else {
                        let end = start.saturating_add(count as usize).min(data.len());
                        &data[start..end]
                    }
                }
                None => &data[..],
            };
            push_owned_literal(out, &label, data);
        }
    }
}

fn push_binary(out: &mut Vec<u8>, message: &[u8], spec: &BodySpec) {
    let path = match &spec.section {
        Section::Full => Vec::new(),
        Section::Part(path) => path.clone(),
        _ => Vec::new(),
    };
    let inner = match &spec.section {
        Section::Part(path) => render_path(path),
        _ => String::new(),
    };
    let label = match spec.partial {
        Some((start, _)) => format!("BINARY[{inner}]<{start}>"),
        None => format!("BINARY[{inner}]"),
    };
    match decode_binary_part(message, &path) {
        None => {
            out.extend_from_slice(label.as_bytes());
            out.extend_from_slice(b" NIL");
        }
        Some(data) => {
            let data = match spec.partial {
                Some((start, count)) => {
                    let start = start as usize;
                    if start >= data.len() {
                        &[][..]
                    } else {
                        let end = start.saturating_add(count as usize).min(data.len());
                        &data[start..end]
                    }
                }
                None => &data[..],
            };
            push_owned_literal(out, &label, data);
        }
    }
}

fn push_literal(out: &mut Vec<u8>, label: &str, data: &[u8]) {
    push_owned_literal(out, label, data);
}

fn push_owned_literal(out: &mut Vec<u8>, label: &str, data: &[u8]) {
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(format!(" {{{}}}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
}

pub fn extract_section<'a>(message: &'a [u8], section: &Section) -> Option<Cow<'a, [u8]>> {
    let (_, body) = mime::split_headers_body(message);
    let headers = mime::parse_headers(message);
    match section {
        Section::Full => Some(Cow::Borrowed(message)),
        Section::Header => Some(Cow::Owned(headers.raw_block(None))),
        Section::Text => Some(Cow::Borrowed(body)),
        Section::HeaderFields { names, not } => Some(Cow::Owned(
            headers.raw_block(Some((names.as_slice(), *not))),
        )),
        Section::Part(path) => {
            let part = resolve_part(message, path)?;
            let (_, part_body) = mime::split_headers_body(part);
            Some(Cow::Borrowed(part_body))
        }
        Section::Mime(path) => {
            if path.is_empty() {
                return Some(Cow::Owned(headers.raw_block(None)));
            }
            let part = resolve_part(message, path)?;
            Some(Cow::Owned(mime::parse_headers(part).raw_block(None)))
        }
        Section::HeaderPart(path) => {
            if path.is_empty() {
                return Some(Cow::Owned(headers.raw_block(None)));
            }
            let part = resolve_part(message, path)?;
            Some(Cow::Owned(mime::parse_headers(part).raw_block(None)))
        }
        Section::TextPart(path) => {
            if path.is_empty() {
                return Some(Cow::Borrowed(body));
            }
            let part = resolve_part(message, path)?;
            let (_, part_body) = mime::split_headers_body(part);
            Some(Cow::Borrowed(part_body))
        }
    }
}

fn resolve_part<'a>(message: &'a [u8], path: &[u32]) -> Option<&'a [u8]> {
    if path.is_empty() {
        return Some(message);
    }
    let mut current = message;
    for (depth, index) in path.iter().enumerate() {
        let (_, body) = mime::split_headers_body(current);
        let content = mime::content_type(&mime::parse_headers(current));
        if content.is_multipart() {
            let boundary = content.param("boundary")?;
            let parts = mime::multipart_parts(body, boundary);
            let position = (*index).checked_sub(1)? as usize;
            current = *parts.get(position)?;
        } else if depth == 0 && *index == 1 {
            return Some(current);
        } else {
            return None;
        }
    }
    Some(current)
}

fn decode_binary_part(message: &[u8], path: &[u32]) -> Option<Vec<u8>> {
    let part = resolve_part(message, path)?;
    let headers = mime::parse_headers(part);
    let encoding = headers
        .get("content-transfer-encoding")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let (_, body) = mime::split_headers_body(part);
    Some(mime::decode_transfer_encoding(body, &encoding))
}

fn binary_path(section: &Section) -> Option<Vec<u32>> {
    match section {
        Section::Full => Some(Vec::new()),
        Section::Part(path) => Some(path.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::{Flag, MessageMeta, SystemFlag};
    use std::path::PathBuf;

    fn meta() -> MessageMeta {
        let mut flags = FlagSet::new();
        flags.insert(Flag::System(SystemFlag::Seen));
        MessageMeta {
            uid: 7,
            base: "base".to_string(),
            filename: "base:2,S".to_string(),
            path: PathBuf::from("/nonexistent"),
            size: 42,
            internal_date: 1_700_000_000,
            modseq: 7,
            flags,
            recent: false,
        }
    }

    const MESSAGE: &[u8] = b"From: Alice <alice@example.com>\r\n\
Subject: hello\r\n\
Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
\r\n\
line one\r\n\
line two\r\n";

    #[test]
    fn items_macros_and_sections_parse() {
        assert_eq!(
            parse_items("(FLAGS UID RFC822.SIZE)").unwrap(),
            vec![FetchItem::Flags, FetchItem::Uid, FetchItem::Size]
        );
        assert_eq!(
            parse_items("ALL").unwrap(),
            vec![
                FetchItem::Flags,
                FetchItem::InternalDate,
                FetchItem::Size,
                FetchItem::Envelope
            ]
        );
        let items = parse_items("(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)]<0.10>)").unwrap();
        assert_eq!(
            items,
            vec![FetchItem::Body(BodySpec {
                section: Section::HeaderFields {
                    names: vec!["SUBJECT".into(), "FROM".into()],
                    not: false,
                },
                peek: true,
                partial: Some((0, 10)),
            })]
        );
        assert_eq!(
            parse_items("BODY[1.2.MIME]").unwrap()[0],
            FetchItem::Body(BodySpec {
                section: Section::Mime(vec![1, 2]),
                peek: false,
                partial: None,
            })
        );
        assert_eq!(
            parse_items("BODY[2.TEXT]").unwrap()[0],
            FetchItem::Body(BodySpec {
                section: Section::TextPart(vec![2]),
                peek: false,
                partial: None,
            })
        );
        assert!(parse_items("BODY.PEEK").is_err());
        assert!(parse_items("(UID) (FLAGS)").is_err());
        assert!(parse_items("BOGUS").is_err());
    }

    #[test]
    fn section_labels_round_trip() {
        let cases = [
            (Section::Full, ""),
            (Section::Header, "HEADER"),
            (Section::Text, "TEXT"),
            (
                Section::HeaderFields {
                    names: vec!["SUBJECT".into(), "FROM".into()],
                    not: true,
                },
                "HEADER.FIELDS.NOT (SUBJECT FROM)",
            ),
            (Section::Part(vec![1, 2]), "1.2"),
            (Section::Mime(vec![2]), "2.MIME"),
            (Section::HeaderPart(vec![2]), "2.HEADER"),
            (Section::TextPart(vec![2]), "2.TEXT"),
            (Section::Mime(Vec::new()), "MIME"),
        ];
        for (section, label) in cases {
            assert_eq!(section.label(), label);
        }
    }

    #[test]
    fn fetch_renders_flags_date_size_and_literals() {
        let items = parse_items("(FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[TEXT])").unwrap();
        let (bytes, seen) = render(&items, &meta(), Some(MESSAGE), false).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("FLAGS (\\Seen)"));
        assert!(text.contains("INTERNALDATE \"14-Nov-2023 22:13:20 +0000\""));
        assert!(text.contains("RFC822.SIZE 42"));
        assert!(text.contains("BODY[TEXT] {20}\r\nline one\r\nline two\r\n"));
        assert!(!seen, "PEEK 不得置 \\Seen");
    }

    #[test]
    fn body_without_peek_marks_seen_and_partial_echoes_origin() {
        let items = parse_items("(BODY[]<0.5>)").unwrap();
        let (bytes, seen) = render(&items, &meta(), Some(MESSAGE), false).unwrap();
        assert!(seen);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("BODY[]<0> {5}\r\nFrom:"));
    }

    #[test]
    fn header_fields_extraction_is_case_insensitive_and_filtered() {
        let items = parse_items("(BODY.PEEK[HEADER.FIELDS (subject)])").unwrap();
        let (bytes, _) = render(&items, &meta(), Some(MESSAGE), false).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("BODY[HEADER.FIELDS (subject)] {18}\r\nSubject: hello\r\n\r\n"));
    }

    #[test]
    fn envelope_and_structure_render_into_the_item_list() {
        let items = parse_items("(ENVELOPE BODYSTRUCTURE)").unwrap();
        let (bytes, _) = render(&items, &meta(), Some(MESSAGE), false).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("ENVELOPE (\"Fri, 23 Oct 2026 14:30:00 +0800\" \"hello\""));
        assert!(text.contains("BODYSTRUCTURE (\"TEXT\" \"PLAIN\""));
    }

    #[test]
    fn uid_mode_adds_uid_automatically() {
        let items = parse_items("(FLAGS)").unwrap();
        let (bytes, _) = render(&items, &meta(), None, true).unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "UID 7 FLAGS (\\Seen)");
    }

    #[test]
    fn multipart_sections_resolve() {
        let message = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\n\
Content-Type: text/plain\r\n\r\n\
one\r\n\
--b\r\n\
Content-Type: text/html\r\n\r\n\
<b>two</b>\r\n\
--b--\r\n";
        assert_eq!(
            extract_section(message, &Section::Part(vec![2]))
                .unwrap()
                .as_ref(),
            b"<b>two</b>"
        );
        assert!(extract_section(message, &Section::Part(vec![3])).is_none());
        assert_eq!(
            extract_section(message, &Section::Mime(vec![1]))
                .unwrap()
                .as_ref(),
            b"Content-Type: text/plain\r\n\r\n"
        );
    }

    #[test]
    fn full_text_and_part_sections_borrow_the_message_without_copying() {
        let message: &[u8] = b"Subject: hello\r\n\r\nbody here\r\n";
        assert!(matches!(
            extract_section(message, &Section::Full),
            Some(Cow::Borrowed(_))
        ));
        assert!(matches!(
            extract_section(message, &Section::Text),
            Some(Cow::Borrowed(_))
        ));
        assert!(matches!(
            extract_section(message, &Section::TextPart(vec![1])),
            Some(Cow::Borrowed(_))
        ));
        let multipart = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n\
--b\r\n\r\none\r\n\
--b--\r\n";
        assert!(matches!(
            extract_section(multipart, &Section::Part(vec![1])),
            Some(Cow::Borrowed(_))
        ));
        assert!(matches!(
            extract_section(message, &Section::Header),
            Some(Cow::Owned(_))
        ));
    }

    #[test]
    fn header_only_fetches_do_not_require_the_whole_message() {
        let header_only =
            parse_items("ENVELOPE BODY.PEEK[HEADER] BODY[HEADER.FIELDS (SUBJECT)]").unwrap();
        assert!(needs_message(&header_only));
        assert!(!needs_full_message(&header_only));
        assert!(needs_full_message(&parse_items("BODYSTRUCTURE").unwrap()));
        assert!(needs_full_message(&parse_items("BODY[TEXT]").unwrap()));
        assert!(needs_full_message(&parse_items("RFC822").unwrap()));
        assert!(!needs_full_message(&parse_items("FLAGS UID").unwrap()));
    }

    #[test]
    fn modseq_and_changedsince_are_parsed_and_rendered() {
        let items = parse_items("(FLAGS MODSEQ)").unwrap();
        assert!(items.contains(&FetchItem::ModSeq));
        assert!(!needs_message(&items));
        let (bytes, _) = render(&items, &meta(), None, false).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("MODSEQ (7)"));

        let (stripped, since) = split_changedsince("(FLAGS MODSEQ) (CHANGEDSINCE 5)").unwrap();
        assert_eq!(stripped, "(FLAGS MODSEQ)");
        assert_eq!(since, Some(5));
        let (same, none) = split_changedsince("(FLAGS)").unwrap();
        assert_eq!(same, "(FLAGS)");
        assert!(none.is_none());
        assert!(split_changedsince("(FLAGS) (CHANGEDSINCE)").is_err());
        assert!(split_changedsince("(FLAGS) (CHANGEDSINCE x)").is_err());
    }

    #[test]
    fn missing_section_renders_nil() {
        let items = parse_items("(BODY[9])").unwrap();
        let (bytes, _) = render(&items, &meta(), Some(MESSAGE), false).unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "BODY[9] NIL");
    }

    #[test]
    fn binary_items_parse_and_decode_transfer_encoding() {
        assert_eq!(
            parse_items("BINARY[1]").unwrap(),
            vec![FetchItem::Binary(BodySpec {
                section: Section::Part(vec![1]),
                peek: false,
                partial: None,
            })]
        );
        assert_eq!(
            parse_items("BINARY.PEEK[1]").unwrap(),
            vec![FetchItem::Binary(BodySpec {
                section: Section::Part(vec![1]),
                peek: true,
                partial: None,
            })]
        );
        let items = parse_items("(BINARY[] BINARY[1] BINARY.SIZE[1])").unwrap();
        assert!(matches!(&items[0], FetchItem::Binary(_)));
        assert!(matches!(&items[1], FetchItem::Binary(_)));
        assert_eq!(items[2], FetchItem::BinarySize(vec![1]));
        assert!(needs_message(&items));

        assert!(parse_items("(BINARY[HEADER])").is_err());
        assert!(parse_items("BINARY.PEEK").is_err());

        let message =
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=";
        let items = parse_items("(BINARY.PEEK[])").unwrap();
        let (bytes, seen) = render(&items, &meta(), Some(message), false).unwrap();
        assert!(!seen, "BINARY.PEEK 不应改变 \\Seen");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("BINARY[] {5}\r\nhello"), "{text:?}");

        let items = parse_items("(BINARY[])").unwrap();
        let (_, seen) = render(&items, &meta(), Some(message), false).unwrap();
        assert!(seen);

        let items = parse_items("(BINARY.SIZE[])").unwrap();
        let (bytes, _) = render(&items, &meta(), Some(message), false).unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "BINARY.SIZE[] 5");
    }
}
