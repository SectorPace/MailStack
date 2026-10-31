//! 邮件头、ENVELOPE 与 BODYSTRUCTURE（RFC 3501 §7.4.2 / §7.4.3）。
//!
//! ## 为什么不用现成的 MIME 库
//!
//! FETCH 的 `BODY[HEADER.FIELDS (...)]` 要求**按原始字节**回吐指定的头（客户端会
//! 拿它做 DKIM 之外的二次校验）；`BODYSTRUCTURE` 则要求部件大小、行数、参数与嵌套
//! 结构，而完整 MIME 库通常会把「解码后的正文」当成第一公民。两套语义对不上时，
//! 用现成库反而要再拆出原始字节。这里只实现 IMAP 需要的**结构视图**：
//!
//! * 头：保留原始行（含折行），另外给出去折行的值；
//! * 结构：递归 multipart，部件大小/行数/编码/参数；
//! * 传输解码只服务 `BINARY`（RFC 3516，[`decode_transfer_encoding`]）；普通
//!   `BODY[...]` 仍回**原始字节**，RFC 2047 也不解 —— 客户端的 MUA 本来就会解。
//!
//! ## 边界
//!
//! 解析是**纯函数**，输入上限写死（[`MAX_HEADER_BYTES`]、[`MAX_HEADER_LINES`]、
//! [`MAX_PARTS`]、[`MAX_DEPTH`]）。恶意邮件不能通过 10 万层嵌套或 1 GB 头把
//! IMAP worker 拖垮；超过上限时按「无结构」降级为 `application/octet-stream`，
//! 而不是 panic。

use base64::Engine;

use crate::render;

pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
pub const MAX_HEADER_LINES: usize = 2_000;
pub const MAX_PARTS: usize = 1_000;
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone)]
pub struct HeaderLine {
    /// 小写头名（比较用）。
    pub name: String,
    /// 原始行（含折行与行尾 CRLF），`BODY[HEADER.FIELDS]` 原样回吐。
    pub raw: Vec<u8>,
    /// 去折行后的值（多个空白压成一个空格）。
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Headers {
    pub lines: Vec<HeaderLine>,
}

impl Headers {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.lines
            .iter()
            .find(|line| line.name.eq_ignore_ascii_case(name))
            .map(|line| line.value.as_str())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.lines
            .iter()
            .filter(move |line| line.name.eq_ignore_ascii_case(name))
            .map(|line| line.value.as_str())
    }

    /// 回吐原始头块。`filter` 为 `Some((names, not))` 时按字段名筛选；
    /// 末尾补一个空行（BODY[HEADER] 的定义包含结束头的那个 CRLF）。
    pub fn raw_block(&self, filter: Option<(&[String], bool)>) -> Vec<u8> {
        let mut out = Vec::new();
        for line in &self.lines {
            let include = match filter {
                None => true,
                Some((names, not)) => {
                    let matched = names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(&line.name));
                    if not {
                        !matched
                    } else {
                        matched
                    }
                }
            };
            if include {
                out.extend_from_slice(&line.raw);
                if !line.raw.ends_with(b"\n") {
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// 拆出「头」与「正文」。头不含终止空行。
pub fn split_headers_body(message: &[u8]) -> (&[u8], &[u8]) {
    if let Some(position) = find(message, b"\r\n\r\n") {
        (&message[..position + 2], &message[position + 4..])
    } else if let Some(position) = find(message, b"\n\n") {
        (&message[..position + 1], &message[position + 2..])
    } else {
        (message, &[])
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn parse_headers(message: &[u8]) -> Headers {
    let (header_bytes, _) = split_headers_body(message);
    let header_bytes = &header_bytes[..header_bytes.len().min(MAX_HEADER_BYTES)];
    let mut headers = Headers::default();
    let mut current: Option<usize> = None;

    for raw_line in header_bytes.split_inclusive(|byte| *byte == b'\n') {
        if headers.lines.len() >= MAX_HEADER_LINES {
            break;
        }
        let trimmed = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
        if trimmed.is_empty() {
            break;
        }
        let continuation = matches!(trimmed.first(), Some(b' ') | Some(b'\t'));
        if continuation {
            if let Some(index) = current {
                let line: &mut HeaderLine = &mut headers.lines[index];
                line.raw.extend_from_slice(raw_line);
                let value = String::from_utf8_lossy(trimmed).trim().to_string();
                if !value.is_empty() {
                    if !line.value.is_empty() {
                        line.value.push(' ');
                    }
                    line.value.push_str(&value);
                }
                continue;
            }
            // 首个头之前的折行是坏数据；忽略。
            continue;
        }
        let Some(colon) = trimmed.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = String::from_utf8_lossy(&trimmed[..colon])
            .trim()
            .to_ascii_lowercase();
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
            continue;
        }
        let value = String::from_utf8_lossy(&trimmed[colon + 1..])
            .trim()
            .to_string();
        headers.lines.push(HeaderLine {
            name,
            raw: raw_line.to_vec(),
            value,
        });
        current = Some(headers.lines.len() - 1);
    }
    headers
}

// ---------------------------------------------------------------------------
// 地址与 ENVELOPE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub name: String,
    pub mailbox: String,
    pub host: String,
}

/// 解析地址头。只支持最常见的 `Name <local@host>` / `local@host` 形式；
/// group 语法（`Group: a@b;`）里的成员会被当作普通地址，组名被丢弃。
pub fn parse_addresses(value: &str) -> Vec<Address> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut escaped = false;
    let mut angle_depth = 0usize;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quote => {
                current.push(ch);
                escaped = true;
            }
            '"' => {
                in_quote = !in_quote;
                current.push(ch);
            }
            '<' if !in_quote => {
                angle_depth += 1;
                current.push(ch);
            }
            '>' if !in_quote => {
                angle_depth = angle_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' | ';' if !in_quote && angle_depth == 0 => {
                push_address(&mut out, &current);
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    push_address(&mut out, &current);
    out
}

fn push_address(out: &mut Vec<Address>, raw: &str) {
    let mut token = raw.trim();
    if token.is_empty() {
        return;
    }
    // group 的 `Name:` 前缀。
    if let Some(position) = token.find(':') {
        if !token[..position].contains('@') && !token[..position].contains('<') {
            token = token[position + 1..].trim();
        }
    }
    if token.is_empty() {
        return;
    }
    let (name, addr) = match (token.rfind('<'), token.rfind('>')) {
        (Some(open), Some(close)) if close > open => {
            let name = unquote(token[..open].trim());
            (name, token[open + 1..close].trim().to_string())
        }
        _ => (String::new(), token.to_string()),
    };
    if addr.is_empty() {
        return;
    }
    let (mailbox, host) = match addr.rsplit_once('@') {
        Some((mailbox, host)) => (mailbox.trim().to_string(), host.trim().to_string()),
        None => (addr, String::new()),
    };
    out.push(Address {
        name,
        mailbox: mailbox.trim_matches('"').to_string(),
        host: host.trim_matches('"').to_string(),
    });
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        value.to_string()
    }
}

fn address_list(value: Option<&str>) -> String {
    let Some(value) = value else {
        return "NIL".to_string();
    };
    let addresses = parse_addresses(value);
    if addresses.is_empty() {
        return "NIL".to_string();
    }
    let mut out = String::from("(");
    for address in addresses {
        out.push('(');
        out.push_str(&render::nstring(if address.name.is_empty() {
            None
        } else {
            Some(&address.name)
        }));
        out.push_str(" NIL ");
        out.push_str(&render::nstring(Some(&address.mailbox)));
        out.push(' ');
        out.push_str(&render::nstring(if address.host.is_empty() {
            None
        } else {
            Some(&address.host)
        }));
        out.push(')');
    }
    out.push(')');
    out
}

/// 完整的 IMAP ENVELOPE。
pub fn envelope(headers: &Headers) -> String {
    let from = headers.get("from");
    let sender = headers.get("sender").or(from);
    let reply_to = headers.get("reply-to").or(from);
    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        render::nstring(headers.get("date")),
        render::nstring(headers.get("subject")),
        address_list(from),
        address_list(sender),
        address_list(reply_to),
        address_list(headers.get("to")),
        address_list(headers.get("cc")),
        address_list(headers.get("bcc")),
        render::nstring(headers.get("in-reply-to")),
        render::nstring(headers.get("message-id")),
    )
}

// ---------------------------------------------------------------------------
// 结构
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ContentType {
    pub mime_type: String,
    pub subtype: String,
    pub params: Vec<(String, String)>,
}

impl ContentType {
    pub fn is_multipart(&self) -> bool {
        self.mime_type.eq_ignore_ascii_case("multipart")
    }

    pub fn is_message(&self) -> bool {
        self.mime_type.eq_ignore_ascii_case("message")
            && self.subtype.eq_ignore_ascii_case("rfc822")
    }

    pub fn is_text(&self) -> bool {
        self.mime_type.eq_ignore_ascii_case("text")
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub fn content_type(headers: &Headers) -> ContentType {
    parse_content_type_value(headers.get("content-type"))
}

pub fn parse_content_type_value(value: Option<&str>) -> ContentType {
    let Some(value) = value else {
        return ContentType {
            mime_type: "text".to_string(),
            subtype: "plain".to_string(),
            params: Vec::new(),
        };
    };
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

    let head = segments.first().map(|value| value.trim()).unwrap_or("");
    let (mime_type, subtype) = match head.split_once('/') {
        Some((mime_type, subtype)) => (
            mime_type.trim().to_ascii_lowercase(),
            subtype
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase(),
        ),
        None if !head.is_empty() => (head.to_ascii_lowercase(), String::new()),
        None => ("application".to_string(), "octet-stream".to_string()),
    };
    let (mime_type, subtype) = if mime_type.is_empty() || subtype.is_empty() {
        ("application".to_string(), "octet-stream".to_string())
    } else {
        (mime_type, subtype)
    };

    let mut params = Vec::new();
    for segment in segments.iter().skip(1) {
        let Some((key, raw_value)) = segment.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_ascii_uppercase();
        let value = unquote(raw_value.trim());
        if !key.is_empty() {
            params.push((key, value));
        }
    }
    ContentType {
        mime_type,
        subtype,
        params,
    }
}

/// 按 boundary 切分 multipart 正文（不含边界行本身，去掉部件尾部的分隔 CRLF）。
pub fn multipart_parts<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let marker = format!("--{boundary}");
    let closing = format!("--{boundary}--");
    let mut parts = Vec::new();
    let mut part_start: Option<usize> = None;
    let mut offset = 0usize;
    let mut closed = false;

    for line in body.split_inclusive(|byte| *byte == b'\n') {
        let line_start = offset;
        offset += line.len();
        let trimmed = trim_ascii(line);
        if trimmed == marker.as_bytes() {
            if let Some(start) = part_start {
                parts.push(trim_one_crlf(&body[start..line_start]));
            }
            part_start = Some(offset);
            if parts.len() >= MAX_PARTS {
                break;
            }
        } else if trimmed == closing.as_bytes() {
            if let Some(start) = part_start {
                parts.push(trim_one_crlf(&body[start..line_start]));
            }
            part_start = None;
            closed = true;
            break;
        }
    }
    if let (Some(start), false) = (part_start, closed) {
        parts.push(trim_one_crlf(&body[start..]));
    }
    parts
}

fn trim_ascii(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    &line[..end]
}

fn trim_one_crlf(value: &[u8]) -> &[u8] {
    if value.ends_with(b"\r\n") {
        &value[..value.len() - 2]
    } else if value.ends_with(b"\n") {
        &value[..value.len() - 1]
    } else {
        value
    }
}

fn line_count(body: &[u8]) -> usize {
    if body.is_empty() {
        return 0;
    }
    let newlines = body.iter().filter(|byte| **byte == b'\n').count();
    if body.ends_with(b"\n") {
        newlines
    } else {
        newlines + 1
    }
}

/// IMAP BODYSTRUCTURE。刻意不输出扩展字段（disposition / MD5 / 语言）：
/// 扩展字段是**可选**的，省略后客户端仍能正确展示；输出错的扩展比不输出更糟。
pub fn body_structure(message: &[u8]) -> String {
    part_structure(message, 0)
}

fn part_structure(message: &[u8], depth: usize) -> String {
    let (_, body) = split_headers_body(message);
    let headers = parse_headers(message);
    let mut content = content_type(&headers);

    // 深度上限必须同时约束 multipart **与** message/rfc822：后者此前无条件
    // 递归，一封嵌套上千层的邮件会让 BODYSTRUCTURE 栈溢出（进程 abort）。
    if depth >= MAX_DEPTH {
        content = ContentType {
            mime_type: "application".to_string(),
            subtype: "octet-stream".to_string(),
            params: Vec::new(),
        };
    }

    if content.is_multipart() && depth < MAX_DEPTH {
        if let Some(boundary) = content.param("boundary") {
            let parts = multipart_parts(body, boundary);
            if !parts.is_empty() {
                let mut out = String::from("(");
                for part in parts.iter().take(MAX_PARTS) {
                    out.push_str(&part_structure(part, depth + 1));
                }
                out.push(' ');
                out.push_str(&render::string(&content.subtype.to_ascii_uppercase()));
                out.push(')');
                return out;
            }
        }
        // 声称是 multipart 却切不出部件（缺 boundary 或 boundary 不出现）：
        // 按 `application/octet-stream` 报告。回一个没有子部件的 multipart
        // 结构会让严格解析器直接报错，比「结构不精确」更糟。
        content = ContentType {
            mime_type: "application".to_string(),
            subtype: "octet-stream".to_string(),
            params: Vec::new(),
        };
    }

    let encoding = headers
        .get("content-transfer-encoding")
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_uppercase()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "7BIT".to_string());

    let params = if content.params.is_empty() {
        "NIL".to_string()
    } else {
        let mut out = String::from("(");
        let mut first = true;
        for (key, value) in &content.params {
            if !first {
                out.push(' ');
            }
            first = false;
            out.push_str(&render::string(&key.to_ascii_uppercase()));
            out.push(' ');
            out.push_str(&render::string(value));
        }
        out.push(')');
        out
    };

    let id = headers.get("content-id");
    let description = headers.get("content-description");
    let size = body.len();
    let base = format!(
        "({} {} {} {} {} {} {}",
        render::string(&content.mime_type.to_ascii_uppercase()),
        render::string(&content.subtype.to_ascii_uppercase()),
        params,
        render::nstring(id),
        render::nstring(description),
        render::string(&encoding),
        size
    );

    if content.is_text() {
        format!("{base} {})", line_count(body))
    } else if content.is_message() {
        let inner_headers = parse_headers(body);
        format!(
            "{base} {} {} {})",
            envelope(&inner_headers),
            part_structure(body, depth + 1),
            line_count(body)
        )
    } else {
        format!("{base})")
    }
}

/// 按 Content-Transfer-Encoding 解码正文（RFC 2045）。未知编码原样返回。
///
/// `BINARY`（RFC 3516）需要它；普通 `BODY[...]` 仍返回原始字节（客户端自己解）。
/// base64 解码失败时退回原始字节，而不是丢数据。
pub fn decode_transfer_encoding(body: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            let cleaned: Vec<u8> = body
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .unwrap_or_else(|_| body.to_vec())
        }
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.to_vec(),
    }
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'=' {
            out.push(input[index]);
            index += 1;
            continue;
        }
        // 软换行 `=CRLF` / `=LF` 直接删除。
        if input.get(index + 1) == Some(&b'\r') && input.get(index + 2) == Some(&b'\n') {
            index += 3;
            continue;
        }
        if input.get(index + 1) == Some(&b'\n') {
            index += 2;
            continue;
        }
        if let (Some(high), Some(low)) = (input.get(index + 1), input.get(index + 2)) {
            if let (Some(high), Some(low)) = (hex_digit(*high), hex_digit(*low)) {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        out.push(b'=');
        index += 1;
    }
    out
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: Alice <alice@example.com>\r\n\
To: Bob <bob@example.org>, carol@example.net\r\n\
Subject: =?UTF-8?B?5L2g5aW9?=\r\n\
Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
Message-ID: <abc@example.com>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: 8bit\r\n\
\r\n\
hello\r\nworld\r\n";

    #[test]
    fn headers_keep_raw_lines_and_unfold_values() {
        let message = b"Subject: a\r\n b\r\nFrom: x@example.com\r\n\r\nbody";
        let headers = parse_headers(message);
        assert_eq!(headers.get("subject"), Some("a b"));
        assert_eq!(headers.get("from"), Some("x@example.com"));
        let raw = headers.raw_block(None);
        assert!(raw.starts_with(b"Subject: a\r\n b\r\n"));
        assert!(raw.ends_with(b"\r\n"));
    }

    #[test]
    fn header_field_filter_echoes_raw_folded_lines() {
        let headers = parse_headers(MESSAGE);
        let fields = vec!["subject".to_string()];
        let block = headers.raw_block(Some((&fields, false)));
        let text = String::from_utf8_lossy(&block);
        assert!(text.starts_with("Subject: =?UTF-8?B?5L2g5aW9?=\r\n"));
        assert!(!text.contains("From:"));

        let block = headers.raw_block(Some((&fields, true)));
        let text = String::from_utf8_lossy(&block);
        assert!(text.contains("From:"));
        assert!(!text.contains("Subject:"));
    }

    #[test]
    fn envelope_renders_addresses_and_nil() {
        let headers = parse_headers(MESSAGE);
        let envelope = envelope(&headers);
        assert!(envelope.starts_with("(\"Fri, 23 Oct 2026 14:30:00 +0800\" "));
        assert!(envelope.contains("(\"Alice\" NIL \"alice\" \"example.com\")"));
        assert!(envelope.contains("(\"Bob\" NIL \"bob\" \"example.org\")"));
        assert!(envelope.contains("(NIL NIL \"carol\" \"example.net\")"));
        assert!(envelope.ends_with("NIL \"<abc@example.com>\")"));
    }

    #[test]
    fn display_names_are_unquoted_and_escapes_are_kept_as_data() {
        let addresses = parse_addresses("\"Doe, John\" <john@example.com>");
        assert_eq!(addresses.len(), 1, "引号内的逗号不是分隔符");
        assert_eq!(addresses[0].name, "Doe, John");
        assert_eq!(addresses[0].mailbox, "john");
        assert_eq!(addresses[0].host, "example.com");
    }

    #[test]
    fn multipart_structure_nests_parts() {
        let message = b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
preamble\r\n\
--b1\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\r\n\
part one\r\n\
--b1\r\n\
Content-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\n\
QUJD\r\n\
--b1--\r\n";
        let structure = body_structure(message);
        assert!(structure.starts_with("(("), "{}", structure);
        assert!(structure.contains("\"TEXT\" \"PLAIN\" (\"CHARSET\" \"us-ascii\")"));
        assert!(structure.contains("\"APPLICATION\" \"PDF\""));
        assert!(structure.contains("\"BASE64\" 4)"));
        assert!(structure.ends_with("\"MIXED\")"), "{}", structure);
    }

    #[test]
    fn broken_multipart_falls_back_instead_of_looping() {
        let message = b"Content-Type: multipart/mixed; boundary=zz\r\n\r\nno delimiters";
        let structure = body_structure(message);
        assert!(
            structure.contains("\"APPLICATION\" \"OCTET-STREAM\""),
            "无法切分的 multipart 必须降级为单部件：{structure}"
        );
    }

    #[test]
    fn content_type_parameters_are_parsed_without_losing_quoted_semicolons() {
        let content =
            parse_content_type_value(Some("multipart/mixed; boundary=\"a;b\"; charset=utf-8"));
        assert_eq!(content.mime_type, "multipart");
        assert_eq!(content.subtype, "mixed");
        assert_eq!(content.param("boundary"), Some("a;b"));
        assert_eq!(content.param("charset"), Some("utf-8"));

        let default = parse_content_type_value(None);
        assert_eq!(default.mime_type, "text");
        assert_eq!(default.subtype, "plain");
    }

    #[test]
    fn deeply_nested_rfc822_messages_are_bounded_instead_of_overflowing_the_stack() {
        let mut message = b"Content-Type: text/plain\r\n\r\nleaf\r\n".to_vec();
        for _ in 0..(MAX_DEPTH * 4) {
            let mut outer = b"Content-Type: message/rfc822\r\n\r\n".to_vec();
            outer.extend_from_slice(&message);
            message = outer;
        }
        let structure = body_structure(&message);
        assert!(structure.contains("\"MESSAGE\" \"RFC822\""));
        assert!(
            structure.contains("\"APPLICATION\" \"OCTET-STREAM\""),
            "超过深度上限必须降级为不透明部件：{structure}"
        );
    }

    #[test]
    fn message_rfc822_parts_include_an_envelope() {
        let inner = b"From: a@b.c\r\nSubject: inner\r\n\r\nbody\r\n";
        let mut outer = Vec::new();
        outer.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
        outer.extend_from_slice(inner);
        let structure = body_structure(&outer);
        assert!(structure.contains("\"MESSAGE\" \"RFC822\""));
        assert!(structure.contains("\"inner\""));
    }

    #[test]
    fn transfer_decoding_handles_base64_and_quoted_printable() {
        // base64，允许折行空白。
        assert_eq!(
            decode_transfer_encoding(b"aGVs\r\nbG8=", "BASE64"),
            b"hello".to_vec()
        );
        // 非法 base64 原样返回，不丢数据。
        assert_eq!(
            decode_transfer_encoding(b"not*base64", "base64"),
            b"not*base64".to_vec()
        );

        // quoted-printable：=XX 与软换行。
        assert_eq!(
            decode_transfer_encoding(b"line1=\r\nline2 =3D ok =ZZ", "quoted-printable"),
            b"line1line2 = ok =ZZ".to_vec()
        );

        // 7bit / 8bit / 未知编码原样返回。
        assert_eq!(decode_transfer_encoding(b"raw", "8bit"), b"raw".to_vec());
        assert_eq!(decode_transfer_encoding(b"raw", ""), b"raw".to_vec());
    }
}
