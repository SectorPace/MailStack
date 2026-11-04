#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,

    pub enhanced: Option<&'static str>,

    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: None,
            lines: vec![sanitize(&text.into())],
        }
    }

    pub fn with_enhanced(code: u16, enhanced: &'static str, text: impl Into<String>) -> Self {
        Self {
            code,
            enhanced: Some(enhanced),
            lines: vec![sanitize(&text.into())],
        }
    }

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

    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or("")
    }

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

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .collect()
}

pub mod texts {
    pub const GREETING: &str = "MailStack ESMTP ready";
    pub const OK: &str = "OK";
    pub const BYE: &str = "Bye";
    pub const EHLO_OK: &str = "MailStack greets you";
    pub const NOOP_OK: &str = "OK";
    pub const RSET_OK: &str = "Session reset";
    pub const HELP: &str = "See RFC 5321";

    pub const VRFY_DISABLED: &str = "VRFY is disabled";
    pub const SEQUENCE: &str = "Bad sequence of commands";
    pub const NESTED_MAIL: &str = "Sender already specified";
    pub const MAIL_OK: &str = "Sender OK";
    pub const RCPT_OK: &str = "Recipient OK";

    pub const RECIPIENT_UNKNOWN: &str = "No such user";
    pub const NO_RECIPIENTS: &str = "Need RCPT before DATA";
    pub const DATA_START: &str = "End data with <CR><LF>.<CR><LF>";
    pub const DATA_OK: &str = "Message accepted for delivery";
    pub const LINE_TOO_LONG: &str = "Line too long";
    pub const SYNTAX: &str = "Syntax error in parameters or arguments";
    pub const UNKNOWN_COMMAND: &str = "Command unrecognized";
    pub const TOO_MANY_RECIPIENTS: &str = "Too many recipients";
    pub const MESSAGE_TOO_LARGE: &str = "Message size exceeds fixed maximum message size";
    pub const DATA_BACKPRESSURE: &str = "Server is busy accepting other messages, try again later";
    pub const BARE_LINE_FEED: &str = "Bare line feed in message data (use CRLF)";
    pub const STARTTLS_UNAVAILABLE: &str = "STARTTLS not available";
    pub const ALREADY_TLS: &str = "TLS already active";
    pub const AUTH_UNAVAILABLE: &str = "Authentication not available";
    pub const AUTH_REQUIRED_FIRST: &str = "Issue STARTTLS first";
    pub const INTERNAL_ERROR: &str = "Internal server error";

    pub const AUTH_MECHANISM_UNKNOWN: &str = "Unrecognized authentication type";

    pub const AUTH_ALREADY: &str = "Authentication already completed";

    pub const AUTH_BAD_BASE64: &str = "Invalid base64 authentication response";
    pub const AUTH_CANCELLED: &str = "Authentication exchange cancelled";
    pub const AUTH_OK: &str = "Authentication successful";

    pub const AUTH_FAILED: &str = "Authentication credentials invalid";

    pub const AUTH_TEMPORARY_FAILURE: &str = "Authentication temporarily unavailable";

    pub const RATE_LIMITED: &str = "Too many connections from your address";

    pub const TOO_MANY_CONNECTIONS: &str =
        "Too many concurrent connections from your address, try again later";
    pub const BANNED_TEMPORARILY: &str = "Your address is temporarily blocked";
    pub const BANNED_PERMANENTLY: &str = "Your address is permanently blocked";

    pub const SESSION_TIMEOUT: &str = "session timeout";

    pub const SUBMISSION_AUTH_REQUIRED: &str = "Authentication required";

    pub const SENDER_NOT_OWNED: &str =
        "Sender address rejected: not owned by the authenticated user";

    pub const AUTH_EVAL_FAILED: &str = "Message authentication could not be evaluated";
    pub const DMARC_REJECTED: &str = "Message rejected by the sender domain DMARC policy";
    pub const MESSAGE_NOT_UTF8: &str = "Message body is not valid UTF-8";
    pub const QUEUE_WRITE_FAILED: &str = "Cannot write message to the local queue";

    pub const TOO_MANY_HOPS: &str = "Too many hops / mail loop detected";
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
        let reply = Reply::multiline(250, ["A".to_string(), "B".to_string(), "C".to_string()]);
        assert_eq!(reply.render(), "250-A\r\n250-B\r\n250 C\r\n");
    }

    #[test]
    fn control_characters_in_text_cannot_forge_a_second_reply() {
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
