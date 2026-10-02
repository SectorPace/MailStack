//! SMTP 命令解析（RFC 5321 §4.1）。
//!
//! ## 这里为什么值得单独成模块
//!
//! 命令解析是**对端完全可控**的第一段代码。历史上绝大多数 SMTP 远程缺陷都落在
//! 「输入被当成结构」这件事上：
//!
//! * **命令注入**：地址里带 CR/LF，事务中凭空多出一条 `RCPT TO:<victim>`。
//!   本模块拒绝一切控制字符；而 CR/LF 在驱动层切行时就已经不可能出现在一行里。
//! * **应答注入**：地址被原样回显到应答里 —— 由 [`crate::reply`] 的净化负责。
//! * **行长度**：不设上限就是一条内存耗尽路径（RFC 5321 §4.5.3.1.4 给的是 512）。
//!
//! ## 刻意宽松的两处
//!
//! 1. `MAIL FROM: <a@b>`（冒号后带空格）—— 语法上不合法，但现实中大量客户端这么发，
//!    拒绝它们只会误伤正常邮件（Postfix 同样接受）。
//! 2. 源路由 `<@a,@b:user@dom>` —— RFC 5321 §4.1.1.2 要求**接受并忽略**。
//!    不接受会把合法邮件拒之门外，而它本身没有任何安全含义。

use crate::reply::Reply;

/// 命令行的长度上限（RFC 5321 §4.5.3.1.4）。超出即拒绝，不得无界缓冲。
pub const MAX_COMMAND_LINE: usize = 512;

/// 路径（`<...>` 内含）的长度上限（RFC 5321 §4.5.3.1.3 为 256，含尖括号）。
pub const MAX_PATH_LEN: usize = 254;

/// `MAIL FROM` 的参数（只保留有语义的，其余记录后忽略）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailParams {
    /// `SIZE=` —— 客户端声明的报文大小，用于**在收 DATA 之前**就拒绝超大邮件。
    pub size: Option<u64>,
    /// `BODY=8BITMIME` / `BODY=7BIT`。
    pub body: Option<String>,
    /// `AUTH=` —— 提交时所用的认证身份（可观测性用）。
    pub auth: Option<String>,
    /// 其余未被识别的参数（RFC 5321 §4.1.1.11：**不得**因为不认识而拒信）。
    pub unknown: Vec<String>,
}

/// 一条已解析的命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        from: String,
        params: MailParams,
    },
    Rcpt {
        to: String,
    },
    Data,
    Rset,
    Noop,
    Quit,
    Vrfy(String),
    Help(Option<String>),
    StartTls,
    Auth {
        mechanism: String,
        initial: Option<String>,
    },
    /// 未识别的动词（原样保留，供日志定位；**不回显给对端**）。
    Unknown(String),
}

/// 解析失败。每一种都自带对应的应答，避免调用方各自拼错误码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    LineTooLong,
    /// 控制字符、非法编码、长度越界等。
    Syntax,
}

impl CommandError {
    pub fn reply(&self) -> Reply {
        match self {
            CommandError::LineTooLong => {
                Reply::with_enhanced(500, "5.5.6", crate::reply::texts::LINE_TOO_LONG)
            }
            CommandError::Syntax => Reply::with_enhanced(501, "5.5.4", crate::reply::texts::SYNTAX),
        }
    }
}

/// 解析一行命令（**不含**行结束符）。
pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(CommandError::LineTooLong);
    }
    // 控制字符一律拒绝。CR/LF 正常不会出现（驱动层已切行）——真出现了说明
    // 上游没有按行切分，此时继续解析就是在把注入当结构用。
    if line.iter().any(|&b| b < 0x20 || b == 0x7f || b == 0x00) {
        return Err(CommandError::Syntax);
    }
    let text = std::str::from_utf8(line).map_err(|_| CommandError::Syntax)?;

    let (verb, rest) = match text.split_once(' ') {
        Some((verb, rest)) => (verb, rest.trim_start()),
        None => (text, ""),
    };
    let verb = verb.to_ascii_uppercase();

    Ok(match verb.as_str() {
        "EHLO" => Command::Ehlo(require_argument(rest)?),
        "HELO" => Command::Helo(require_argument(rest)?),
        "MAIL" => {
            // `<>` 是合法的反向路径（null sender），DSN 必须用它。
            let (from, tail) = parse_prefixed_path(rest, "FROM:", true)?;
            Command::Mail {
                from,
                params: parse_mail_params(tail),
            }
        }
        "RCPT" => {
            // 正向路径**不允许**为空：`RCPT TO:<>` 没有可投递的目标。
            let (to, _) = parse_prefixed_path(rest, "TO:", false)?;
            Command::Rcpt { to }
        }
        "DATA" => Command::Data,
        "RSET" => Command::Rset,
        "NOOP" => Command::Noop,
        "QUIT" => Command::Quit,
        "VRFY" => Command::Vrfy(require_argument(rest)?),
        "HELP" => Command::Help(if rest.is_empty() {
            None
        } else {
            Some(rest.to_string())
        }),
        "STARTTLS" => Command::StartTls,
        "AUTH" => {
            let (mechanism, initial) = match rest.split_once(' ') {
                Some((mechanism, initial)) => (mechanism, Some(initial.trim().to_string())),
                None => (rest, None),
            };
            if mechanism.is_empty() {
                return Err(CommandError::Syntax);
            }
            Command::Auth {
                mechanism: mechanism.to_ascii_uppercase(),
                initial: initial.filter(|value| !value.is_empty()),
            }
        }
        _ => Command::Unknown(verb),
    })
}

fn require_argument(rest: &str) -> Result<String, CommandError> {
    if rest.is_empty() {
        return Err(CommandError::Syntax);
    }
    Ok(rest.trim_start().to_string())
}

/// 解析 `FROM:<path> [...]` / `TO:<path> [...]`，返回地址与剩余参数。
fn parse_prefixed_path<'a>(
    rest: &'a str,
    prefix: &str,
    allow_null: bool,
) -> Result<(String, &'a str), CommandError> {
    let rest = rest.trim_start();
    let head = rest.get(..prefix.len()).unwrap_or_default();
    if !head.eq_ignore_ascii_case(prefix) {
        return Err(CommandError::Syntax);
    }
    // 冒号后允许空格：语法上不合法，但现实客户端普遍这么发，拒绝只会误伤正常邮件。
    parse_path(rest[prefix.len()..].trim_start(), allow_null)
}

/// 解析 `<path>`，返回规范化后的地址（`<>` → 空串）与剩余内容。
fn parse_path(input: &str, allow_null: bool) -> Result<(String, &str), CommandError> {
    let rest = input.strip_prefix('<').ok_or(CommandError::Syntax)?;
    let end = rest.find('>').ok_or(CommandError::Syntax)?;
    let inner = &rest[..end];
    let tail = &rest[end + 1..];
    Ok((normalise_path(inner, allow_null)?, tail))
}

/// 规范化路径内容。
fn normalise_path(inner: &str, allow_null: bool) -> Result<String, CommandError> {
    // `<>` 是 null sender（DSN 必须用它）—— 只在反向路径上合法。
    if inner.is_empty() {
        return if allow_null {
            Ok(String::new())
        } else {
            Err(CommandError::Syntax)
        };
    }
    if inner.len() > MAX_PATH_LEN {
        return Err(CommandError::Syntax);
    }

    // 源路由：`<@relay1,@relay2:user@dom>`。按 RFC 5321 §4.1.1.2 接受并忽略。
    let address = match inner.split_once(':') {
        Some((route, address)) if route.starts_with('@') => address,
        _ => inner,
    };

    if address.is_empty() || address.len() > MAX_PATH_LEN {
        return Err(CommandError::Syntax);
    }
    // 空白与控制字符：地址里出现它们只可能是注入尝试。
    if address.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CommandError::Syntax);
    }

    // `<postmaster>` 是 RFC 5321 §4.1.1.3 要求必须接受的保留名，它没有域。
    // 保留原样交给会话去补上本机域，本模块不做策略判断。
    if address.eq_ignore_ascii_case("postmaster") {
        return Ok("postmaster".to_string());
    }

    // local-part **大小写敏感**（RFC 5321 §2.3.11），只有域部分可以小写化。
    let (local, domain) = address.rsplit_once('@').ok_or(CommandError::Syntax)?;
    if local.is_empty() || domain.is_empty() {
        return Err(CommandError::Syntax);
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

/// 解析 `MAIL FROM` 之后的 ESMTP 参数。
fn parse_mail_params(tail: &str) -> MailParams {
    let mut params = MailParams::default();
    for token in tail.split_whitespace() {
        let (key, value) = match token.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (token, None),
        };
        match key.to_ascii_uppercase().as_str() {
            "SIZE" => params.size = value.and_then(|value| value.parse().ok()),
            "BODY" => params.body = value.map(|value| value.to_ascii_uppercase()),
            "AUTH" => params.auth = value.map(str::to_string),
            // 不认识的参数必须忽略而不是拒信（否则新扩展会变成拒信原因）。
            _ => params.unknown.push(token.to_string()),
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> Command {
        parse(line.as_bytes()).unwrap_or_else(|e| panic!("{line:?} 应解析成功，实际 {e:?}"))
    }

    #[test]
    fn verbs_are_case_insensitive() {
        assert_eq!(
            ok("ehlo mail.example.org"),
            Command::Ehlo("mail.example.org".into())
        );
        assert_eq!(
            ok("EHLO mail.example.org"),
            Command::Ehlo("mail.example.org".into())
        );
        assert_eq!(ok("QuIt"), Command::Quit);
        assert_eq!(ok("rset"), Command::Rset);
        assert_eq!(ok("NoOp"), Command::Noop);
        assert_eq!(ok("data"), Command::Data);
    }

    #[test]
    fn mail_path_accepts_the_optional_space_and_brackets() {
        // 语法上 `MAIL FROM:<a@b>` 没有空格，但现实客户端普遍带空格。
        for line in [
            "MAIL FROM:<alice@example.com>",
            "MAIL FROM: <alice@example.com>",
            "MAIL FROM:<alice@EXAMPLE.com>",
            "MAIL FROM:  <alice@example.com>",
        ] {
            assert_eq!(
                ok(line),
                Command::Mail {
                    from: "alice@example.com".into(),
                    params: MailParams::default()
                },
                "{line:?}"
            );
        }
    }

    #[test]
    fn null_sender_is_an_empty_path_not_an_error() {
        // DSN 必须使用 null sender；把它当语法错误会让退信根本发不出去。
        assert_eq!(
            ok("MAIL FROM:<>"),
            Command::Mail {
                from: String::new(),
                params: MailParams::default()
            }
        );
    }

    #[test]
    fn local_part_keeps_its_case_but_the_domain_is_lowercased() {
        // RFC 5321 §2.3.11：local-part 大小写敏感，只有域可以归一化。
        assert_eq!(
            ok("RCPT TO:<Alice@Example.COM>"),
            Command::Rcpt {
                to: "Alice@example.com".into()
            }
        );
    }

    #[test]
    fn source_routes_are_accepted_and_ignored() {
        // RFC 5321 §4.1.1.2 要求接受；拒绝会把合法邮件挡在外面。
        assert_eq!(
            ok("MAIL FROM:<@relay1.example,@relay2.example:alice@example.com>"),
            Command::Mail {
                from: "alice@example.com".into(),
                params: MailParams::default()
            }
        );
    }

    #[test]
    fn mail_parameters_are_split_into_known_and_unknown() {
        let Command::Mail { from, params } =
            ok("MAIL FROM:<a@b.com> SIZE=2048 BODY=8BITMIME AUTH=alice FUTURE=1 X")
        else {
            panic!("应解析成 MAIL");
        };
        assert_eq!(from, "a@b.com");
        assert_eq!(params.size, Some(2048));
        assert_eq!(params.body.as_deref(), Some("8BITMIME"));
        assert_eq!(params.auth.as_deref(), Some("alice"));
        // 不认识的参数必须忽略而不是拒信。
        assert_eq!(
            params.unknown,
            vec!["FUTURE=1".to_string(), "X".to_string()]
        );
    }

    #[test]
    fn unparseable_optional_size_is_ignored_not_fatal() {
        let Command::Mail { params, .. } = ok("MAIL FROM:<a@b.com> SIZE=abc") else {
            panic!("应解析成 MAIL");
        };
        assert_eq!(params.size, None, "SIZE 解析不出数字时退化为「未提供」");
    }

    #[test]
    fn auth_and_help_take_optional_arguments() {
        assert_eq!(ok("HELP"), Command::Help(None));
        assert_eq!(ok("HELP MAIL"), Command::Help(Some("MAIL".into())));
        assert_eq!(
            ok("AUTH PLAIN"),
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial: None
            }
        );
        assert_eq!(
            ok("AUTH PLAIN AGJvYg=="),
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial: Some("AGJvYg==".into())
            }
        );
    }

    #[test]
    fn control_characters_are_rejected() {
        // 命令注入的第一形态。CR/LF 由驱动层切行处理，这里覆盖其余控制字符。
        for bad in [
            &b"MAIL FROM:<a@b\0.com>"[..],
            &b"EHLO mail\x01example.org"[..],
            &b"RSET\x7f"[..],
        ] {
            assert_eq!(
                parse(bad),
                Err(CommandError::Syntax),
                "{:?} 必须被拒绝",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn crlf_inside_a_command_cannot_smuggle_a_second_command() {
        // 驱动层保证不会把一个「含 CRLF 的块」当一行送来；这里守住第二道：
        // 真收到了也不得解析成合法命令。
        let smuggled = b"MAIL FROM:<a@b.com>\r\nRCPT TO:<victim@example.com>";
        assert_eq!(parse(smuggled), Err(CommandError::Syntax));
    }

    #[test]
    fn addresses_with_whitespace_are_rejected() {
        assert_eq!(parse(b"RCPT TO:<a b@c.com>"), Err(CommandError::Syntax));
        assert_eq!(parse(b"RCPT TO:<a@c.com >"), Err(CommandError::Syntax));
    }

    #[test]
    fn missing_brackets_or_at_sign_are_syntax_errors() {
        for bad in [
            &b"MAIL FROM:alice@example.com"[..],
            &b"MAIL FROM:<aliceexample.com>"[..],
            &b"MAIL FROM:<@example.com>"[..],
            &b"RCPT TO:<>"[..],
            &b"MAIL FROM:"[..],
            &b"RCPT TO"[..],
            &b"EHLO"[..],
            &b"VRFY"[..],
            &b"AUTH"[..],
        ] {
            assert_eq!(
                parse(bad),
                Err(CommandError::Syntax),
                "{:?} 应判语法错误",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn bare_postmaster_is_accepted_and_left_for_the_session_to_resolve() {
        // RFC 5321 §4.1.1.3：`<postmaster>` MUST be accepted。它没有域，
        // 补域是会话的策略决定（见 session.rs），解析器不做策略。
        assert_eq!(
            ok("RCPT TO:<postmaster>"),
            Command::Rcpt {
                to: "postmaster".into()
            }
        );
        assert_eq!(
            ok("RCPT TO:<POSTMASTER>"),
            Command::Rcpt {
                to: "postmaster".into()
            }
        );
    }

    #[test]
    fn overlong_lines_are_rejected_before_anything_else() {
        let long = format!("EHLO {}", "a".repeat(MAX_COMMAND_LINE));
        assert_eq!(parse(long.as_bytes()), Err(CommandError::LineTooLong));
        // 恰好等于上限（不含 CRLF）是可以接受的。
        let exact = format!("EHLO {}", "a".repeat(MAX_COMMAND_LINE - 5));
        assert!(parse(exact.as_bytes()).is_ok());
    }

    #[test]
    fn overlong_paths_are_rejected() {
        let long = format!("MAIL FROM:<{}@example.com>", "a".repeat(MAX_PATH_LEN));
        assert_eq!(parse(long.as_bytes()), Err(CommandError::Syntax));
    }

    #[test]
    fn non_utf8_lines_are_rejected_rather_than_lossily_decoded() {
        // lossy 转换会把地址悄悄改掉 —— 宁可拒信也不改写收件人。
        assert_eq!(
            parse(b"RCPT TO:<\xff\xfe@example.com>"),
            Err(CommandError::Syntax)
        );
    }

    #[test]
    fn unknown_verbs_are_reported_without_echoing_back_to_the_peer() {
        // 动词原样保留供日志定位，但会话不得把它回显（否则是反射面）。
        assert_eq!(ok("XYZZY arg"), Command::Unknown("XYZZY".into()));
    }

    #[test]
    fn error_replies_carry_the_right_codes() {
        assert_eq!(CommandError::LineTooLong.reply().code, 500);
        assert_eq!(CommandError::Syntax.reply().code, 501);
        assert_eq!(CommandError::LineTooLong.reply().enhanced, Some("5.5.6"));
    }
}
