//! 写信：地址 / 头部校验与 RFC 5322 / MIME 构造。
//!
//! ## 为什么服务端要自己构造 MIME
//!
//! 前端给的是「主题 + 两种正文 + 附件」这样的业务数据；把它变成一封合法邮件
//! 需要做一串**安全敏感**的决定：头部编码、折行、边界随机性、传输编码、Bcc 不进
//! 头部、附件文件名编码。任何一处交给前端（或简单字符串拼接）都会打开头注入
//! 或 MIME 走私的口子，所以这一层全部在服务端完成。
//!
//! ## 头注入防线
//!
//! * 主题 / 地址 / In-Reply-To / References **拒绝** CR/LF/NUL 与控制字符；
//! * 主题走 RFC 2047 编码（非 ASCII 时），编码结果只含 base64 字符，不可能含 CRLF；
//! * 地址走 RFC 5321 简化校验（非空、含 `@`、长度 ≤ 320、字符集白名单）；
//! * Bcc 只进信封（队列收件人），**不进头部**——否则每个收件人都能看到密送名单。
//!
//! ## 大小边界
//!
//! 附件 base64 解码后总量 ≤ 25 MiB（契约 §2.2）；构造完成的报文 ≤ 32 MiB
//! （否则队列条目会超出入站/出站链路的预期）。base64 会膨胀 33%，因此最终
//! 报文大小必须再查一次，不能只查输入。

use std::collections::BTreeSet;

use base64::Engine;
use rand::RngCore;
use time::OffsetDateTime;

use crate::account::Account;
use crate::error::{WebmailError, WebmailResult};
use crate::mime_view;
use crate::{
    COMPOSE_BODY_LIMIT_BYTES, MAX_ADDRESS_LEN, MAX_ATTACHMENTS, MAX_ATTACHMENT_TOTAL_BYTES,
    MAX_SUBJECT_CHARS,
};

/// 构造用途：发信还是存草稿。
///
/// 差别只有两处：草稿允许没有收件人，且草稿保留 `Bcc:` 头（用户重新打开草稿时
/// 要看到自己填过的密送地址）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Send,
    Draft,
}

/// 单封邮件正文（text/html）的字符上限。
const MAX_COMPOSE_BODY_CHARS: usize = 2_000_000;

/// RFC 5322 行长度上限（不含 CRLF）；主题等头部超长会被 MUA 拒绝。
const MAX_HEADER_LINE_BYTES: usize = 998;

/// 收件人（To+Cc+Bcc）总数上限。
///
/// 契约没给数字，但不封顶时一封请求可以让队列条目塞进十万个收件人，出站投递
/// 会被一条消息拖死。100 覆盖正常群发场景。
pub const MAX_RECIPIENTS: usize = 100;

/// 附件输入（前端 JSON）。
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInput {
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub data_base64: String,
}

/// 写信请求（契约 §2.1 `ComposeRequest`）。
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComposeRequest {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<AttachmentInput>,
}

/// 草稿请求 = ComposeRequest + 目标邮箱 + 被替换的旧草稿 uid（契约 §2）。
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DraftRequest {
    #[serde(flatten)]
    pub compose: ComposeRequest,
    /// 只允许 `Drafts`。
    pub mailbox: Option<String>,
    /// 给出时，保存成功后 expunge 旧草稿。
    pub draft_uid: Option<u32>,
}

/// 解码后的附件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// 通过校验、解码完成的写信数据。
#[derive(Debug, Clone)]
pub struct ValidatedCompose {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<DecodedAttachment>,
    /// To + Cc + Bcc 去重后的信封收件人（Bcc 只出现在这里）。
    pub recipients: Vec<String>,
}

/// 构造完成的报文。
#[derive(Debug, Clone)]
pub struct BuiltMessage {
    /// RFC 5322 文本（CRLF 行结束，纯 ASCII：正文与附件都走 base64）。
    pub data: String,
    /// 信封发件人（账号地址）。
    pub envelope_from: String,
    /// 信封收件人（To+Cc+Bcc 去重）。
    pub recipients: Vec<String>,
    /// 规范化后的主题（已验证无头注入）。
    pub subject: String,
}

/// 校验并解码写信请求。
pub fn validate_compose(
    request: &ComposeRequest,
    purpose: Purpose,
) -> WebmailResult<ValidatedCompose> {
    let to = validate_address_list(&request.to, "to")?;
    let cc = validate_address_list(&request.cc, "cc")?;
    let bcc = validate_address_list(&request.bcc, "bcc")?;

    // 信封收件人去重（大小写不敏感；不改变头部里各自列表的内容）。
    let mut recipients = Vec::new();
    let mut seen = BTreeSet::new();
    for address in to.iter().chain(cc.iter()).chain(bcc.iter()) {
        let key = address.to_ascii_lowercase();
        if seen.insert(key) {
            recipients.push(address.clone());
        }
    }
    if purpose == Purpose::Send && recipients.is_empty() {
        return Err(WebmailError::bad_request(
            "NO_RECIPIENTS",
            "at least one recipient (to, cc or bcc) is required",
        ));
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(WebmailError::bad_request(
            "TOO_MANY_RECIPIENTS",
            format!("at most {MAX_RECIPIENTS} recipients are allowed"),
        ));
    }

    let subject = validate_subject(&request.subject)?;
    let text = validate_body(request.text.as_deref(), "text")?;
    let html = validate_body(request.html.as_deref(), "html")?;
    let in_reply_to = validate_message_id(request.in_reply_to.as_deref(), "inReplyTo")?;
    let mut references = Vec::new();
    for reference in &request.references {
        let value = validate_message_id(Some(reference), "references")?;
        if let Some(value) = value {
            references.push(value);
        }
    }
    let attachments = decode_attachments(&request.attachments)?;

    Ok(ValidatedCompose {
        to,
        cc,
        bcc,
        subject,
        text,
        html,
        in_reply_to,
        references,
        attachments,
        recipients,
    })
}

/// 校验 + 构造报文。
pub fn build_message(
    account: &Account,
    request: &ComposeRequest,
    purpose: Purpose,
) -> WebmailResult<BuiltMessage> {
    let validated = validate_compose(request, purpose)?;
    let alt_boundary = unique_boundary("alt");
    let mix_boundary = unique_boundary("mix");

    let mut message = String::new();
    message.push_str(&format!("From: {}\r\n", encode_from(account)));
    if !validated.to.is_empty() {
        message.push_str(&format!("To: {}\r\n", validated.to.join(", ")));
    }
    if !validated.cc.is_empty() {
        message.push_str(&format!("Cc: {}\r\n", validated.cc.join(", ")));
    }
    if purpose == Purpose::Draft && !validated.bcc.is_empty() {
        // 只有草稿保留 Bcc 头；真正发信时 Bcc 仅存在于信封。
        message.push_str(&format!("Bcc: {}\r\n", validated.bcc.join(", ")));
    }
    message.push_str(&format!(
        "Subject: {}\r\n",
        encode_header_value(&validated.subject)
    ));
    let now = OffsetDateTime::now_utc();
    message.push_str(&format!("Date: {}\r\n", mime_view::format_rfc2822(now)));
    message.push_str(&format!(
        "Message-ID: {}\r\n",
        generate_message_id(&account.email)
    ));
    if let Some(in_reply_to) = &validated.in_reply_to {
        message.push_str(&format!("In-Reply-To: {in_reply_to}\r\n"));
    }
    if !validated.references.is_empty() {
        message.push_str(&format!(
            "References: {}\r\n",
            validated.references.join(" ")
        ));
    }
    message.push_str("MIME-Version: 1.0\r\n");

    let (content_type, transfer_encoding, body) =
        build_body(&validated, &alt_boundary, &mix_boundary);
    message.push_str(&format!("Content-Type: {content_type}\r\n"));
    if let Some(transfer_encoding) = transfer_encoding {
        message.push_str(&format!(
            "Content-Transfer-Encoding: {transfer_encoding}\r\n"
        ));
    }
    message.push_str("\r\n");
    message.push_str(&body);
    if !message.ends_with("\r\n") {
        message.push_str("\r\n");
    }
    if message.len() > COMPOSE_BODY_LIMIT_BYTES {
        return Err(WebmailError::payload_too_large(
            "composed message exceeds the 32 MiB limit",
        ));
    }
    if !message.is_ascii() {
        // 全链路都应是 7bit 安全的 ASCII（正文/附件 base64、头部 RFC2047）；
        // 出现非 ASCII 说明编码逻辑有漏，宁可拒绝也不能把未编码的 8bit 写进队列。
        return Err(WebmailError::internal(
            "compose",
            "composed message contains non-ascii bytes",
        ));
    }

    Ok(BuiltMessage {
        data: message,
        envelope_from: account.email.clone(),
        recipients: validated.recipients,
        subject: validated.subject,
    })
}

/// 构造正文部分，返回 `(Content-Type, 顶层 Content-Transfer-Encoding, body)`。
fn build_body(
    validated: &ValidatedCompose,
    alt_boundary: &str,
    mix_boundary: &str,
) -> (String, Option<&'static str>, String) {
    let has_text = validated.text.is_some();
    let has_html = validated.html.is_some();
    let both = has_text && has_html;

    // 正文实体：两种正文都有时是 multipart/alternative；否则是单个文本部件。
    let (body_content_type, body_body) = if both {
        let mut body = String::new();
        body.push_str(&format!(
            "--{alt_boundary}\r\n{}\r\n",
            text_part("text/plain", validated.text.as_deref().unwrap_or(""))
        ));
        body.push_str(&format!(
            "--{alt_boundary}\r\n{}\r\n",
            text_part("text/html", validated.html.as_deref().unwrap_or(""))
        ));
        body.push_str(&format!("--{alt_boundary}--\r\n"));
        (
            format!("multipart/alternative; boundary=\"{alt_boundary}\""),
            body,
        )
    } else if has_html {
        (
            "text/html; charset=utf-8".to_string(),
            text_part_body(validated.html.as_deref().unwrap_or("")),
        )
    } else {
        (
            "text/plain; charset=utf-8".to_string(),
            text_part_body(validated.text.as_deref().unwrap_or("")),
        )
    };

    if validated.attachments.is_empty() {
        if both {
            return (body_content_type, None, format!("{body_body}\r\n"));
        }
        return (
            body_content_type,
            Some("base64"),
            format!("{body_body}\r\n"),
        );
    }

    // multipart/mixed：第一个子部件是正文实体（带自己的 Content-Type 头），
    // 其后是各附件。
    let mut body = String::new();
    body.push_str(&format!("--{mix_boundary}\r\n"));
    if both {
        body.push_str(&format!("Content-Type: {body_content_type}\r\n\r\n"));
        body.push_str(&body_body);
        body.push_str("\r\n");
    } else {
        let content_type = if has_html {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        };
        body.push_str(&format!(
            "Content-Type: {content_type}\r\nContent-Transfer-Encoding: base64\r\n\r\n{body_body}\r\n"
        ));
    }
    for attachment in &validated.attachments {
        body.push_str(&format!("--{mix_boundary}\r\n"));
        body.push_str(&attachment_part(attachment));
        body.push_str("\r\n");
    }
    body.push_str(&format!("--{mix_boundary}--\r\n"));
    (
        format!("multipart/mixed; boundary=\"{mix_boundary}\""),
        None,
        body,
    )
}

/// 一个带头的文本部件（用于 multipart 内部）。
fn text_part(content_type: &str, content: &str) -> String {
    format!(
        "Content-Type: {content_type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        base64_lines(content.as_bytes())
    )
}

/// 只有正文行（用于单部件顶层，头部在报文头里）。
fn text_part_body(content: &str) -> String {
    base64_lines(content.as_bytes())
}

/// 一个附件部件。
fn attachment_part(attachment: &DecodedAttachment) -> String {
    let filename = &attachment.filename;
    let mut disposition = String::from("attachment");
    let ascii_fallback = ascii_filename_fallback(filename);
    disposition.push_str(&format!(
        "; filename=\"{}\"",
        escape_header_quoted(&ascii_fallback)
    ));
    if !filename.is_ascii() {
        disposition.push_str(&format!("; filename*=UTF-8''{}", rfc2231_encode(filename)));
    }
    format!(
        "Content-Type: {}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: {disposition}\r\n\r\n{}",
        attachment.content_type,
        base64_lines(&attachment.data)
    )
}

/// base64 编码并按 RFC 2045 折成 76 字符行（行间 CRLF，末尾不带 CRLF）。
fn base64_lines(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2 + 2);
    for (index, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if index > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

/// 生成一个 MIME boundary。
///
/// 144 位随机（18 字节 hex）足以让「出现在正文里」的概率可忽略；boundary 只由
/// 十六进制与固定前缀/后缀组成，不会引入头部注入字符。
fn unique_boundary(prefix: &str) -> String {
    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{prefix}-{}-mailstack", hex::encode(bytes))
}

// ---------------------------------------------------------------------------
// 校验
// ---------------------------------------------------------------------------

/// 地址列表校验（空元素视为非法：契约要求「非空」）。
fn validate_address_list(addresses: &[String], field: &str) -> WebmailResult<Vec<String>> {
    let mut out = Vec::with_capacity(addresses.len());
    for raw in addresses {
        out.push(validate_address(raw, field)?);
    }
    Ok(out)
}

/// 单地址校验（RFC 5321 简化版，契约 §2.2）。
pub fn validate_address(raw: &str, field: &str) -> WebmailResult<String> {
    let address = raw.trim();
    if address.is_empty() {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an empty address"),
        ));
    }
    if address.len() > MAX_ADDRESS_LEN {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address longer than {MAX_ADDRESS_LEN} characters"),
        ));
    }
    // 头注入 / SMTP 命令注入的第一道闸：任何控制字符直接拒绝。
    if address.chars().any(char::is_control) {
        return Err(WebmailError::bad_request(
            "HEADER_INJECTION",
            format!("{field} contains control characters"),
        ));
    }
    let Some((local, domain)) = address.rsplit_once('@') else {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address without '@'"),
        ));
    };
    if local.is_empty() || domain.is_empty() {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address with an empty local part or domain"),
        ));
    }
    if local.contains('@') {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address with multiple '@'"),
        ));
    }
    // 本实现的地址白名单刻意窄（ASCII）：CJK/带引号的本地部分是 RFC 5321 的
    // 边缘语法，简化实现明确拒绝而不是半支持。
    let local_valid = !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                )
        });
    if !local_valid {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address with unsupported local-part characters"),
        ));
    }
    let domain_labels_valid = !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !domain_labels_valid {
        return Err(WebmailError::bad_request(
            "INVALID_ADDRESS",
            format!("{field} contains an address with an invalid domain"),
        ));
    }
    Ok(address.to_string())
}

/// 主题校验：拒绝控制字符（头注入）并限制长度。
fn validate_subject(raw: &str) -> WebmailResult<String> {
    let subject = raw.trim();
    if subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(WebmailError::bad_request(
            "INVALID_SUBJECT",
            format!("subject must be at most {MAX_SUBJECT_CHARS} characters"),
        ));
    }
    if subject.chars().any(char::is_control) {
        return Err(WebmailError::bad_request(
            "HEADER_INJECTION",
            "subject contains control characters (CR/LF/NUL are never folded)",
        ));
    }
    Ok(subject.to_string())
}

/// 正文校验：只限长度（HTML 在详情读取时消毒；草稿保存的是用户原始 HTML）。
fn validate_body(raw: Option<&str>, field: &str) -> WebmailResult<Option<String>> {
    let Some(body) = raw else {
        return Ok(None);
    };
    if body.chars().count() > MAX_COMPOSE_BODY_CHARS {
        return Err(WebmailError::payload_too_large(format!(
            "{field} body exceeds {MAX_COMPOSE_BODY_CHARS} characters"
        )));
    }
    Ok(Some(body.to_string()))
}

/// Message-ID / References 校验：必须是 `<...>` 形状且不含控制字符。
fn validate_message_id(raw: Option<&str>, field: &str) -> WebmailResult<Option<String>> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().any(char::is_control) {
        return Err(WebmailError::bad_request(
            "HEADER_INJECTION",
            format!("{field} contains control characters"),
        ));
    }
    if value.len() > MAX_HEADER_LINE_BYTES {
        return Err(WebmailError::bad_request(
            "INVALID_REFERENCES",
            format!("{field} value is too long"),
        ));
    }
    if !value.starts_with('<') || !value.ends_with('>') || value.len() < 3 {
        return Err(WebmailError::bad_request(
            "INVALID_REFERENCES",
            format!("{field} must be a <message-id> value"),
        ));
    }
    Ok(Some(value.to_string()))
}

/// 解码/校验附件。
fn decode_attachments(inputs: &[AttachmentInput]) -> WebmailResult<Vec<DecodedAttachment>> {
    if inputs.len() > MAX_ATTACHMENTS {
        return Err(WebmailError::bad_request(
            "TOO_MANY_ATTACHMENTS",
            format!("at most {MAX_ATTACHMENTS} attachments are allowed"),
        ));
    }
    let mut attachments = Vec::with_capacity(inputs.len());
    let mut total = 0usize;
    for input in inputs {
        let cleaned: String = input
            .data_base64
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        let data = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|_| {
                WebmailError::bad_request(
                    "INVALID_ATTACHMENT",
                    "attachment data is not valid base64",
                )
            })?;
        total = total.saturating_add(data.len());
        if total > MAX_ATTACHMENT_TOTAL_BYTES {
            return Err(WebmailError::payload_too_large(format!(
                "attachments exceed the {} MiB total limit",
                MAX_ATTACHMENT_TOTAL_BYTES / (1024 * 1024)
            )));
        }
        let content_type = match &input.content_type {
            Some(raw) => validate_content_type(raw)?,
            None => "application/octet-stream".to_string(),
        };
        let filename = sanitize_filename(&input.filename);
        attachments.push(DecodedAttachment {
            filename,
            content_type,
            data,
        });
    }
    Ok(attachments)
}

/// Content-Type 校验：只接受 `type/subtype` 形状的 MIME token。
///
/// 拒绝参数、空格、控制字符：参数会带来 `name=` / `charset=` 的二次解析面，
/// 而这里只需要一个静态类型；文件名走 Content-Disposition。
pub fn validate_content_type(raw: &str) -> WebmailResult<String> {
    let trimmed = raw.trim();
    let (mime_type, subtype) = trimmed.split_once('/').ok_or_else(|| {
        WebmailError::bad_request(
            "INVALID_ATTACHMENT",
            "attachment contentType must be in type/subtype form",
        )
    })?;
    let token = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    };
    if !token(mime_type) || !token(subtype) {
        return Err(WebmailError::bad_request(
            "INVALID_ATTACHMENT",
            "attachment contentType contains invalid characters",
        ));
    }
    Ok(format!(
        "{}/{}",
        mime_type.to_ascii_lowercase(),
        subtype.to_ascii_lowercase()
    ))
}

/// 附件文件名清洗：去掉 `/`、`\` 与控制字符，限长 200 字符。
///
/// 空结果回落为 `attachment`：没有文件名的附件在 Content-Disposition 里无法
/// 表达，回落是唯一不会产生非法头的选择。
pub fn sanitize_filename(raw: &str) -> String {
    // `"` / `;` / `:` 是 Content-Disposition 的 quoted-string 与参数分隔符：
    // 留着它们会构造出畸形的参数（虽然 CR/LF 已被滤掉、不构成头注入）。
    let cleaned: String = raw
        .chars()
        .filter(|ch| !matches!(ch, '/' | '\\' | '"' | ';' | ':') && !ch.is_control())
        .collect();
    let trimmed = cleaned.trim();
    let trimmed = if trimmed.is_empty() {
        "attachment"
    } else {
        trimmed
    };
    trimmed.chars().take(200).collect()
}

// ---------------------------------------------------------------------------
// 头部编码
// ---------------------------------------------------------------------------

/// 构造 `From:` 头（显示名按需编码）。
fn encode_from(account: &Account) -> String {
    let name = account.display_name.trim();
    if name.is_empty() {
        return account.email.clone();
    }
    if name.is_ascii() {
        let needs_quotes = name.starts_with(' ')
            || name.ends_with(' ')
            || name.chars().any(|ch| {
                matches!(
                    ch,
                    '(' | ')' | '<' | '>' | '[' | ']' | ':' | ';' | '@' | '\\' | ',' | '.' | '"'
                )
            });
        if needs_quotes {
            let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\" <{}>", account.email)
        } else {
            format!("{name} <{}>", account.email)
        }
    } else {
        format!("{} <{}>", mime_view::encode_rfc2047(name), account.email)
    }
}

/// 头部值编码：ASCII 原样（已排除控制字符），非 ASCII 走 RFC 2047。
fn encode_header_value(value: &str) -> String {
    if value.is_ascii() {
        value.to_string()
    } else {
        mime_view::encode_rfc2047(value)
    }
}

/// 文件名里的 ASCII 兜底表示（非 ASCII 字符替换为 `_`）。
fn ascii_filename_fallback(filename: &str) -> String {
    let fallback: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii() && !matches!(ch, '"' | '\\') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if fallback.trim().is_empty() {
        "attachment".to_string()
    } else {
        fallback
    }
}

/// RFC 2231 的 UTF-8 百分号编码。
fn rfc2231_encode(filename: &str) -> String {
    let mut out = String::with_capacity(filename.len() * 3);
    for byte in filename.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                *byte,
                b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            )
        {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 引号内字符串转义（只用于 ASCII 兜底文件名与显示名）。
fn escape_header_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' | '\n' | '\0' => {}
            _ => out.push(ch),
        }
    }
    out
}

/// 生成 Message-ID：`<随机@域名>`。
fn generate_message_id(email: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let domain = email
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .filter(|domain| !domain.is_empty())
        .unwrap_or("localhost");
    format!("<{}@{}>", hex::encode(bytes), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            email: "alice@example.com".to_string(),
            account: "alice".to_string(),
            display_name: "Alice".to_string(),
            unix_user: "alice".to_string(),
            maildir: std::path::PathBuf::from("/nonexistent/Maildir"),
        }
    }

    fn compose(subject: &str, text: &str) -> ComposeRequest {
        ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: subject.to_string(),
            text: Some(text.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn header_injection_in_subject_and_addresses_is_rejected() {
        for bad in [
            "hello\r\nBcc: evil@example.com",
            "hello\nBcc: evil@example.com",
            "hello\0world",
        ] {
            let error = build_message(&account(), &compose(bad, "body"), Purpose::Send)
                .expect_err("主题含控制字符必须被拒绝");
            assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
            assert_eq!(error.code, "HEADER_INJECTION");
        }

        let mut request = compose("ok", "body");
        request.to = vec!["bob@example.org\r\nBcc: evil@example.com".to_string()];
        let error = build_message(&account(), &request, Purpose::Send).unwrap_err();
        assert!(
            matches!(error.code, "HEADER_INJECTION" | "INVALID_ADDRESS"),
            "地址注入必须被拒绝：{}",
            error.code
        );

        // In-Reply-To 也不得被注入。
        let mut request = compose("ok", "body");
        request.in_reply_to = Some("<a@b>\r\nBcc: evil@example.com".to_string());
        assert!(build_message(&account(), &request, Purpose::Send).is_err());
    }

    #[test]
    fn send_without_recipients_is_rejected_but_a_draft_is_not() {
        let request = ComposeRequest {
            subject: "solo".to_string(),
            text: Some("draft".to_string()),
            ..Default::default()
        };
        let error = build_message(&account(), &request, Purpose::Send).unwrap_err();
        assert_eq!(error.code, "NO_RECIPIENTS");
        assert!(
            build_message(&account(), &request, Purpose::Draft).is_ok(),
            "草稿允许没有收件人"
        );
    }

    #[test]
    fn text_only_message_is_a_single_base64_part() {
        let built =
            build_message(&account(), &compose("Hello", "hi there"), Purpose::Send).unwrap();
        assert!(built
            .data
            .starts_with("From: Alice <alice@example.com>\r\n"));
        assert!(built.data.contains("To: bob@example.org\r\n"));
        assert!(built.data.contains("Subject: Hello\r\n"));
        assert!(built.data.contains("MIME-Version: 1.0\r\n"));
        assert!(built
            .data
            .contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(built.data.contains("Content-Transfer-Encoding: base64\r\n"));
        assert!(!built.data.contains("Bcc:"), "发信时 Bcc 不得进头部");
        assert!(built.data.ends_with("\r\n"));
        assert!(built.data.is_ascii());

        // 正文 base64 能解回原文。
        let body = built.data.split("\r\n\r\n").nth(1).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.replace("\r\n", ""))
            .unwrap();
        assert_eq!(decoded, b"hi there");
    }

    #[test]
    fn text_and_html_produce_multipart_alternative() {
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "alt".to_string(),
            text: Some("plain".to_string()),
            html: Some("<p>html</p>".to_string()),
            ..Default::default()
        };
        let built = build_message(&account(), &request, Purpose::Send).unwrap();
        assert!(built.data.contains("multipart/alternative; boundary="));
        assert!(built
            .data
            .contains("Content-Type: text/plain; charset=utf-8"));
        assert!(built
            .data
            .contains("Content-Type: text/html; charset=utf-8"));
        assert!(built.data.is_ascii());
    }

    #[test]
    fn attachments_produce_multipart_mixed_with_rfc2231_filenames() {
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "files".to_string(),
            text: Some("see attached".to_string()),
            attachments: vec![AttachmentInput {
                filename: "报告.pdf".to_string(),
                content_type: Some("application/pdf".to_string()),
                data_base64: base64::engine::general_purpose::STANDARD.encode(b"PDFDATA"),
            }],
            ..Default::default()
        };
        let built = build_message(&account(), &request, Purpose::Send).unwrap();
        assert!(built.data.contains("multipart/mixed; boundary="));
        assert!(built.data.contains("Content-Type: application/pdf"));
        assert!(built.data.contains("Content-Disposition: attachment;"));
        assert!(
            built
                .data
                .contains("filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf"),
            "非 ASCII 文件名必须走 RFC2231"
        );
        assert!(built.data.is_ascii());
        assert!(built.data.contains("UERGREFUQQ=="));
    }

    #[test]
    fn attachment_size_limit_is_enforced() {
        // 25 MiB + 1 字节的附件（base64 解码后）。
        let payload = vec![b'x'; MAX_ATTACHMENT_TOTAL_BYTES + 1];
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "huge".to_string(),
            attachments: vec![AttachmentInput {
                filename: "huge.bin".to_string(),
                content_type: Some("application/octet-stream".to_string()),
                data_base64: base64::engine::general_purpose::STANDARD.encode(&payload),
            }],
            ..Default::default()
        };
        let error = build_message(&account(), &request, Purpose::Send).unwrap_err();
        assert_eq!(
            error.status,
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "超过 25 MiB 的附件必须回 413"
        );
    }

    #[test]
    fn filenames_are_sanitised_against_paths_and_controls() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "....etcpasswd");
        assert_eq!(sanitize_filename("a\r\nb.txt"), "ab.txt");
        assert_eq!(sanitize_filename("   "), "attachment");
        assert_eq!(sanitize_filename(&"x".repeat(500)).chars().count(), 200);
        // 构造出的头部不能被文件名注入。
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "s".to_string(),
            attachments: vec![AttachmentInput {
                filename: "a\";\r\nX-Evil: 1".to_string(),
                content_type: Some("text/plain".to_string()),
                data_base64: "aGk=".to_string(),
            }],
            ..Default::default()
        };
        let built = build_message(&account(), &request, Purpose::Send).unwrap();
        assert!(
            !built.data.contains("X-Evil:"),
            "文件名注入到头部：{}",
            built.data
        );
    }

    #[test]
    fn addresses_are_validated_against_the_simplified_rfc5321_rules() {
        assert!(validate_address("bob@example.org", "to").is_ok());
        for bad in [
            "",
            "bob",
            "@example.org",
            "bob@",
            "bob@@example.org",
            "bob@exa mple.org",
            "bob@example..org",
            ".bob@example.org",
            "bob@-example.org",
            "bob@example-.org",
        ] {
            assert!(validate_address(bad, "to").is_err(), "{bad:?} 必须被拒绝");
        }
        assert!(validate_address(&format!("{}@example.org", "a".repeat(400)), "to").is_err());
    }

    #[test]
    fn content_types_are_restricted_to_bare_mime_tokens() {
        assert_eq!(
            validate_content_type("Application/PDF").unwrap(),
            "application/pdf"
        );
        for bad in [
            "",
            "pdf",
            "text/html; charset=x",
            "text/ plain",
            "text/plain\r\nX: y",
            "text/<html>",
        ] {
            assert!(validate_content_type(bad).is_err(), "{bad:?} 必须被拒绝");
        }
    }

    #[test]
    fn non_ascii_subject_and_display_name_are_rfc2047_encoded() {
        let mut account = account();
        account.display_name = "张三".to_string();
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            subject: "你好世界".to_string(),
            text: Some("hi".to_string()),
            ..Default::default()
        };
        let built = build_message(&account, &request, Purpose::Send).unwrap();
        assert!(built.data.is_ascii(), "整体必须是 ASCII 安全的 7bit");
        assert!(built.data.contains("From: =?UTF-8?B?"));
        assert!(built.data.contains("Subject: =?UTF-8?B?"));
        // 解码回来必须等于原文。
        let subject_line = built
            .data
            .lines()
            .find(|line| line.starts_with("Subject: "))
            .unwrap();
        let encoded = subject_line.trim_start_matches("Subject: ");
        assert_eq!(mime_view::decode_rfc2047(encoded), "你好世界");
    }

    #[test]
    fn bcc_is_included_in_recipients_but_not_headers_for_send() {
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            bcc: vec!["secret@example.net".to_string()],
            subject: "bcc".to_string(),
            text: Some("hi".to_string()),
            ..Default::default()
        };
        let built = build_message(&account(), &request, Purpose::Send).unwrap();
        assert!(built.recipients.contains(&"secret@example.net".to_string()));
        assert!(built.recipients.contains(&"bob@example.org".to_string()));
        assert!(!built.data.contains("secret@example.net"));
        assert!(!built.data.contains("Bcc:"));

        let draft = build_message(&account(), &request, Purpose::Draft).unwrap();
        assert!(
            draft.data.contains("Bcc: secret@example.net"),
            "草稿必须保留 Bcc 头"
        );
    }

    #[test]
    fn duplicate_recipients_are_collapsed_in_the_envelope_only() {
        let request = ComposeRequest {
            to: vec!["bob@example.org".to_string()],
            cc: vec!["BOB@example.org".to_string()],
            subject: "dup".to_string(),
            text: Some("hi".to_string()),
            ..Default::default()
        };
        let built = build_message(&account(), &request, Purpose::Send).unwrap();
        assert_eq!(built.recipients.len(), 1, "信封收件人必须去重");
        assert!(built.data.contains("To: bob@example.org\r\n"));
        assert!(built.data.contains("Cc: BOB@example.org\r\n"));
    }
}
