use crate::reply::Reply;

pub const MAX_COMMAND_LINE: usize = 512;

pub const MAX_PATH_LEN: usize = 254;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailParams {
    pub size: Option<u64>,

    pub body: Option<String>,

    pub auth: Option<String>,

    pub unknown: Vec<String>,
}

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

    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    LineTooLong,

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

pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(CommandError::LineTooLong);
    }

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
            let (from, tail) = parse_prefixed_path(rest, "FROM:", true)?;
            Command::Mail {
                from,
                params: parse_mail_params(tail),
            }
        }
        "RCPT" => {
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

    parse_path(rest[prefix.len()..].trim_start(), allow_null)
}

fn parse_path(input: &str, allow_null: bool) -> Result<(String, &str), CommandError> {
    let rest = input.strip_prefix('<').ok_or(CommandError::Syntax)?;
    let end = rest.find('>').ok_or(CommandError::Syntax)?;
    let inner = &rest[..end];
    let tail = &rest[end + 1..];
    Ok((normalise_path(inner, allow_null)?, tail))
}

fn normalise_path(inner: &str, allow_null: bool) -> Result<String, CommandError> {
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

    let address = match inner.split_once(':') {
        Some((route, address)) if route.starts_with('@') => address,
        _ => inner,
    };

    if address.is_empty() || address.len() > MAX_PATH_LEN {
        return Err(CommandError::Syntax);
    }

    if address.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CommandError::Syntax);
    }

    if address.eq_ignore_ascii_case("postmaster") {
        return Ok("postmaster".to_string());
    }

    let (local, domain) = address.rsplit_once('@').ok_or(CommandError::Syntax)?;
    if local.is_empty() || domain.is_empty() {
        return Err(CommandError::Syntax);
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

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
        assert_eq!(
            ok("RCPT TO:<Alice@Example.COM>"),
            Command::Rcpt {
                to: "Alice@example.com".into()
            }
        );
    }

    #[test]
    fn source_routes_are_accepted_and_ignored() {
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
        assert_eq!(
            parse(b"RCPT TO:<\xff\xfe@example.com>"),
            Err(CommandError::Syntax)
        );
    }

    #[test]
    fn unknown_verbs_are_reported_without_echoing_back_to_the_peer() {
        assert_eq!(ok("XYZZY arg"), Command::Unknown("XYZZY".into()));
    }

    #[test]
    fn error_replies_carry_the_right_codes() {
        assert_eq!(CommandError::LineTooLong.reply().code, 500);
        assert_eq!(CommandError::Syntax.reply().code, 501);
        assert_eq!(CommandError::LineTooLong.reply().enhanced, Some("5.5.6"));
    }
}
