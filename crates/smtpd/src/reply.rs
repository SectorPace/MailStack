//! SMTP 应答的构造与渲染（RFC 5321 §4.2、RFC 3463 增强状态码）。
//!
//! ## 为什么文本必须在这里净化
//!
//! 应答文本是**对端可控输入的投影**：拒绝某个收件人时我们通常会把地址原样回显
//! （「550 5.1.1 <x@y> unknown user」）。如果那串文本里混进了 `\r\n`，对端收到的
//! 就是**两行应答** —— 第二行可以伪装成一条它自己编造的服务端应答。
//!
//! 这是应答注入（response injection），与 HTTP 头注入同源。防线放在**唯一的
//! 构造入口**上，而不是指望每个调用点都记得消毒。

/// 一条 SMTP 应答。多行应答的每一行共享同一个状态码（RFC 5321 §4.2.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// RFC 3463 增强状态码（如 `5.1.1`），可选。
    pub enhanced: Option<&'static str>,
    /// 文本行；至少一行。所有内容都已净化（不含 CR/LF/NUL）。
    pub lines: Vec<String>,
}

impl Reply {
    /// 单行应答。
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: None,
            lines: vec![sanitize(&text.into())],
        }
    }

    /// 带增强状态码的单行应答。
    pub fn with_enhanced(code: u16, enhanced: &'static str, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: Some(enhanced),
            lines: vec![sanitize(&text.into())],
        }
    }

    /// 多行应答（如 EHLO 的能力列表）。
    pub fn multiline(code: u16, lines: impl IntoIterator<Item = String>) -> Self {
        let lines: Vec<String> = lines.into_iter().map(|line| sanitize(&line)).collect();
        Self {
            code,
            enhanced: None,
            lines: if lines.is_empty() {
                vec![String::new()]
            } else {
                lines
            },
        }
    }

    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }

    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    /// 据增强状态码取「类别描述」（RFC 3463 §2 的 subject 部分）。
    ///
    /// 注意增强状态码只描述**类别**，真正的细节在文本里；把 `5.1.1` 当成
    /// 「用户不存在」的通用判据是过度解读，这里不做那种映射。
    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or("")
    }

    /// 渲染成线缆上的字节（**必定**以 CRLF 结束）。
    ///
    /// 多行规则：最后一行用空格分隔，其余用 `-`。写错会让对端把多行应答读成
    /// 一条单行应答，或者一直等下一行。
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(64);
        let last = self.lines.len() - 1;
        for (index, line) in self.lines.iter().enumerate() {
            out.push_str(&self.code.to_string());
            out.push(if index == last { ' ' } else { '-' });
            if index == 0 {
                if let Some(enhanced) = self.enhanced {
                    out.push_str(enhanced);
                    if !line.is_empty() {
                        out.push(' ');
                    }
                }
            }
            out.push_str(line);
            out.push_str("\r\n");
        }
        out
    }
}

/// 去掉会破坏应答分帧的字符。
///
/// 保留可打印 ASCII 与常见非 ASCII（对端可能是 UTF-8 客户端），但把
/// CR / LF / NUL 换成空格 —— 它们正是应答注入的载体。
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .collect()
}

/// 常用应答的单一来源。
///
/// 文案是**对外契约**：对端（以及排障的人）靠它判断发生了什么，因此集中定义、
/// 不允许各处临时拼字符串。
pub mod texts {
    pub const GREETING: &str = "MailStack ESMTP ready";
    pub const OK: &str = "OK";
    pub const BYE: &str = "Bye";
    pub const EHLO_OK: &str = "MailStack greets you";
    pub const NOOP_OK: &str = "OK";
    pub const RSET_OK: &str = "Session reset";
    pub const HELP: &str = "See RFC 5321";
    /// RFC 5321 §4.1.4：VRFY 对未实现该命令的服务器必须拒绝（502），
    /// 且**不得**据此确认地址是否存在（那是目录枚举）。
    pub const VRFY_DISABLED: &str = "VRFY is disabled";
    pub const SEQUENCE: &str = "Bad sequence of commands";
    pub const NESTED_MAIL: &str = "Sender already specified";
    pub const MAIL_OK: &str = "Sender OK";
    pub const RCPT_OK: &str = "Recipient OK";
    pub const NO_RECIPIENTS: &str = "Need RCPT before DATA";
    pub const DATA_START: &str = "End data with <CR><LF>.<CR><LF>";
    pub const DATA_OK: &str = "Message accepted for delivery";
    pub const LINE_TOO_LONG: &str = "Line too long";
    pub const SYNTAX: &str = "Syntax error in parameters or arguments";
    pub const UNKNOWN_COMMAND: &str = "Command unrecognized";
    pub const TOO_MANY_RECIPIENTS: &str = "Too many recipients";
    pub const MESSAGE_TOO_LARGE: &str = "Message size exceeds fixed maximum message size";
    pub const BARE_LINE_FEED: &str = "Bare line feed in message data (use CRLF)";
    pub const STARTTLS_UNAVAILABLE: &str = "STARTTLS not available";
    pub const ALREADY_TLS: &str = "TLS already active";
    pub const AUTH_UNAVAILABLE: &str = "Authentication not available";
    pub const AUTH_REQUIRED_FIRST: &str = "Issue STARTTLS first";
    pub const INTERNAL_ERROR: &str = "Internal server error";

    // ── SASL 提交认证（RFC 4954）──
    /// 504：机制不认识。**不得**用 502 含糊带过 —— 客户端要靠它决定换哪个机制。
    pub const AUTH_MECHANISM_UNKNOWN: &str = "Unrecognized authentication type";
    /// 503：同一次会话里重复认证（RFC 4954 §4 要求拒绝）。
    pub const AUTH_ALREADY: &str = "Authentication already completed";
    /// 501：应答不是合法 base64。它同时是一个注入防护点（见 `sasl` 模块说明）。
    pub const AUTH_BAD_BASE64: &str = "Invalid base64 authentication response";
    pub const AUTH_CANCELLED: &str = "Authentication exchange cancelled";
    pub const AUTH_OK: &str = "Authentication successful";
    /// 535：凭据确实不对。**不区分**用户不存在与口令错误，避免目录枚举。
    pub const AUTH_FAILED: &str = "Authentication credentials invalid";
    /// 454：无法判定（后端不可达/超时）。与 535 严格区分，否则客户端会去改密码。
    pub const AUTH_TEMPORARY_FAILURE: &str = "Authentication temporarily unavailable";

    // ── 连接准入（限速 / 封禁）──
    /// 连接频率超限；具体重试秒数由调用方拼接。
    pub const RATE_LIMITED: &str = "Too many connections from your address";
    pub const BANNED_TEMPORARILY: &str = "Your address is temporarily blocked";
    pub const BANNED_PERMANENTLY: &str = "Your address is permanently blocked";

    // ── 入站认证与入队 ──
    /// 认证评估本身失败（无法判定），按临时错误处理而不是放行。
    pub const AUTH_EVAL_FAILED: &str = "Message authentication could not be evaluated";
    pub const DMARC_REJECTED: &str = "Message rejected by the sender domain DMARC policy";
    pub const MESSAGE_NOT_UTF8: &str = "Message body is not valid UTF-8";
    pub const QUEUE_WRITE_FAILED: &str = "Cannot write message to the local queue";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_reply_is_terminated_with_crlf() {
        let reply = Reply::new(250, texts::OK);
        assert_eq!(reply.render(), "250 OK\r\n");
    }

    #[test]
    fn enhanced_status_code_is_rendered_after_the_code() {
        let reply = Reply::with_enhanced(550, "5.1.1", "unknown user");
        assert_eq!(reply.render(), "550 5.1.1 unknown user\r\n");
    }

    #[test]
    fn multiline_uses_dash_on_every_line_but_the_last() {
        // 写错分隔符会让对端把多行读成一行、或者一直等下一行。
        let reply = Reply::multiline(250, ["A".to_string(), "B".to_string(), "C".to_string()]);
        assert_eq!(reply.render(), "250-A\r\n250-B\r\n250 C\r\n");
    }

    #[test]
    fn control_characters_in_text_cannot_forge_a_second_reply() {
        // 应答注入：地址里的 CRLF 不得变成新的一行应答。
        let reply = Reply::new(550, "no such user <a@b>\r\n250 OK\r\n");
        let rendered = reply.render();
        assert_eq!(
            rendered.matches("\r\n").count(),
            1,
            "应答里只允许有一个 CRLF（结尾），实际：{rendered:?}"
        );

        let body = rendered.strip_suffix("\r\n").expect("应以 CRLF 结尾");
        assert!(
            !body.contains('\r') && !body.contains('\n'),
            "正文里不得再有任何换行：{body:?}"
        );
        assert!(body.starts_with("550 no such user <a@b>"), "内容不应被丢弃");
        assert!(
            body.contains("250 OK"),
            "对端注入的文本只能作为同一行里的普通字符存在：{body:?}"
        );
    }

    #[test]
    fn nul_is_also_neutralised() {
        let reply = Reply::new(250, "a\0b");
        assert_eq!(reply.render(), "250 a b\r\n");
    }

    #[test]
    fn multiline_text_is_sanitised_too() {
        let reply = Reply::multiline(250, ["a\rb".to_string()]);
        assert_eq!(reply.render(), "250 a b\r\n");
    }

    #[test]
    fn codes_are_classified_by_leading_digit() {
        assert!(Reply::new(250, "").is_positive_completion());
        assert!(Reply::new(354, "").is_positive());
        assert!(!Reply::new(354, "").is_positive_completion());
        assert!(!Reply::new(550, "").is_positive());
    }
}
