use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::dial::{EstablishedStream, PinnedDialer, TlsMode};
use crate::error::{SmtpError, SmtpResult};
use crate::target::PinnedTarget;

pub const SESSION_BUDGET: Duration = Duration::from_secs(300);

pub const MAX_RESPONSE_LINE_BYTES: usize = 4096;

pub const MAX_RESPONSE_LINES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Response {
    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or("")
    }

    pub fn banner(&self) -> String {
        self.lines.join(" ").chars().take(200).collect()
    }

    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOutcome {
    Accepted {
        response: Response,
    },

    Rejected {
        response: Response,
        permanent: bool,
        accepted: Vec<String>,
    },
}

impl MessageOutcome {
    pub fn code(&self) -> u16 {
        match self {
            MessageOutcome::Accepted { response } | MessageOutcome::Rejected { response, .. } => {
                response.code
            }
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, MessageOutcome::Accepted { .. })
    }

    pub fn is_permanent_failure(&self) -> bool {
        matches!(
            self,
            MessageOutcome::Rejected {
                permanent: true,
                ..
            }
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub starttls: bool,
    pub auth_mechanisms: Vec<String>,
    pub raw: Vec<String>,
}

impl Capabilities {
    pub fn supports(&self, mechanism: &str) -> bool {
        self.auth_mechanisms
            .iter()
            .any(|m| m.eq_ignore_ascii_case(mechanism))
    }
}

struct LineIo {
    inner: EstablishedStream,
    buf: Vec<u8>,
    pos: usize,
}

impl LineIo {
    fn new(inner: EstablishedStream) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(2048),
            pos: 0,
        }
    }

    fn is_encrypted(&self) -> bool {
        self.inner.is_encrypted()
    }

    async fn read_line(&mut self) -> std::io::Result<String> {
        loop {
            if let Some(idx) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let end = self.pos + idx + 1;
                let line = String::from_utf8_lossy(&self.buf[self.pos..end]).into_owned();
                self.pos = end;
                return Ok(line);
            }

            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
            }

            if self.buf.len() >= MAX_RESPONSE_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "response line exceeded {MAX_RESPONSE_LINE_BYTES} bytes without a newline"
                    ),
                ));
            }

            let mut chunk = [0u8; 2048];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed by server",
                    ));
                }

                let leftover = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("connection closed with an incomplete response: {leftover:?}"),
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let payload = format!("{line}\r\n");
        self.inner.write_all(payload.as_bytes()).await?;
        self.inner.flush().await
    }

    fn into_inner(self) -> EstablishedStream {
        self.inner
    }
}

pub struct SmtpSession {
    io: LineIo,
    timeout: Duration,

    deadline: Instant,

    budget: Duration,
    capabilities: Capabilities,
}

impl SmtpSession {
    pub async fn connect(
        dialer: &PinnedDialer,
        target: &PinnedTarget,
        mode: TlsMode,
        timeout: Duration,
    ) -> SmtpResult<(Self, Response)> {
        let stream = dialer.connect_with_mode(target, mode).await?;
        let mut session = Self::from_stream(stream, timeout);

        let banner = session.read_response().await?;
        Ok((session, banner))
    }

    pub fn from_stream(stream: EstablishedStream, timeout: Duration) -> Self {
        Self::from_stream_with_budget(stream, timeout, SESSION_BUDGET)
    }

    pub fn from_stream_with_budget(
        stream: EstablishedStream,
        timeout: Duration,
        budget: Duration,
    ) -> Self {
        Self {
            io: LineIo::new(stream),
            timeout,
            deadline: Instant::now() + budget,
            budget,
            capabilities: Capabilities::default(),
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn is_encrypted(&self) -> bool {
        self.io.is_encrypted()
    }

    fn wait_budget(&self) -> Duration {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        self.timeout.min(remaining)
    }

    fn timeout_error(&self, what: &str) -> SmtpError {
        if Instant::now() >= self.deadline {
            SmtpError::Protocol(format!(
                "SMTP session deadline ({}ms) exceeded while {what}",
                self.budget.as_millis()
            ))
        } else {
            SmtpError::Protocol(format!("timed out {what}"))
        }
    }

    pub async fn read_response(&mut self) -> SmtpResult<Response> {
        let mut lines = Vec::new();
        let mut code: Option<u16> = None;

        loop {
            let wait = self.wait_budget();
            let line = tokio::time::timeout(wait, self.io.read_line())
                .await
                .map_err(|_| self.timeout_error("waiting for server response"))?
                .map_err(SmtpError::Io)?;

            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let (this_code, continued) = parse_response_line(&trimmed)?;

            match code {
                None => code = Some(this_code),
                Some(first) if first == this_code => {}
                Some(first) => {
                    return Err(SmtpError::Protocol(format!(
                        "multiline reply mixed status codes: {first} then {this_code}"
                    )));
                }
            }
            lines.push(trimmed);

            if !continued {
                break;
            }

            if lines.len() > MAX_RESPONSE_LINES {
                return Err(SmtpError::Protocol(format!(
                    "response exceeded {MAX_RESPONSE_LINES} lines"
                )));
            }
        }

        Ok(Response {
            code: code.unwrap_or(0),
            lines,
        })
    }

    pub async fn command(&mut self, line: &str) -> SmtpResult<Response> {
        let wait = self.wait_budget();
        tokio::time::timeout(wait, self.io.write_line(line))
            .await
            .map_err(|_| self.timeout_error("writing command"))?
            .map_err(SmtpError::Io)?;
        self.read_response().await
    }

    pub async fn ehlo(&mut self, client_name: &str) -> SmtpResult<Response> {
        let response = self.command(&format!("EHLO {client_name}")).await?;
        if response.is_positive_completion() {
            self.capabilities = parse_capabilities(&response);
        }
        Ok(response)
    }

    pub async fn starttls(
        mut self,
        dialer: &PinnedDialer,
        target: &PinnedTarget,
    ) -> SmtpResult<(Self, Response)> {
        let response = self.command("STARTTLS").await?;
        if !response.is_positive_completion() {
            return Err(SmtpError::Rejected(response.banner()));
        }

        let timeout = self.timeout;
        let deadline = self.deadline;
        let budget = self.budget;

        let upgraded = self.io.into_inner().upgrade(dialer, target).await?;
        let mut next = Self::from_stream_with_budget(upgraded, timeout, budget);

        next.deadline = deadline;
        Ok((next, response))
    }

    pub async fn authenticate(&mut self, username: &str, password: &str) -> SmtpResult<Response> {
        for (label, value) in [("username", username), ("password", password)] {
            if value.contains(['\r', '\n', '\0', ' ', '\t']) {
                return Err(SmtpError::HeaderInjection(format!(
                    "SMTP {label} must not contain CR, LF, NUL or whitespace"
                )));
            }
        }

        if self.capabilities.supports("PLAIN") {
            let payload = base64(&format!("\0{username}\0{password}"));
            return self.command(&format!("AUTH PLAIN {payload}")).await;
        }

        if self.capabilities.supports("LOGIN") {
            let challenge = self.command("AUTH LOGIN").await?;
            if challenge.code != 334 {
                return Err(SmtpError::Rejected(challenge.banner()));
            }
            let user_step = self.command(&base64(username)).await?;
            if user_step.code != 334 {
                return Err(SmtpError::Rejected(user_step.banner()));
            }
            return self.command(&base64(password)).await;
        }

        Err(SmtpError::Rejected(
            "no supported AUTH mechanism offered by the server".to_string(),
        ))
    }

    pub async fn send_message(
        &mut self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> SmtpResult<Response> {
        let outcome = self
            .send_message_detailed(mail_from, recipients, data)
            .await?;
        match outcome {
            MessageOutcome::Accepted { response } => Ok(response),
            MessageOutcome::Rejected { response, .. } => {
                Err(SmtpError::Rejected(response.banner()))
            }
        }
    }

    pub async fn send_message_detailed(
        &mut self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> SmtpResult<MessageOutcome> {
        let mail = self
            .command(&format!("MAIL FROM:<{}>", checked_addr(mail_from)?))
            .await?;
        if !mail.is_positive_completion() {
            return Ok(MessageOutcome::Rejected {
                permanent: mail.code >= 500,
                response: mail,
                accepted: Vec::new(),
            });
        }

        if recipients.is_empty() {
            return Ok(MessageOutcome::Rejected {
                permanent: true,
                response: Response {
                    code: 554,
                    lines: vec!["no valid recipients".to_string()],
                },
                accepted: Vec::new(),
            });
        }

        let mut rcpt_accepted: Vec<String> = Vec::new();
        let mut first_transient: Option<Response> = None;
        let mut first_permanent: Option<Response> = None;
        for rcpt in recipients {
            let response = self
                .command(&format!("RCPT TO:<{}>", checked_addr(rcpt)?))
                .await?;
            if response.is_positive_completion() {
                rcpt_accepted.push(rcpt.clone());
            } else if response.code >= 500 {
                first_permanent = first_permanent.or(Some(response));
            } else {
                first_transient = first_transient.or(Some(response));
            }
        }

        let rcpt_rejection = first_transient
            .as_ref()
            .or(first_permanent.as_ref())
            .cloned();

        if rcpt_accepted.is_empty() {
            let response = rcpt_rejection.expect("全部被拒时至少存在一个拒绝响应");
            return Ok(MessageOutcome::Rejected {
                permanent: first_transient.is_none(),
                response,
                accepted: Vec::new(),
            });
        }

        let data_cmd = self.command("DATA").await?;
        if data_cmd.code != 354 {
            return Ok(MessageOutcome::Rejected {
                permanent: data_cmd.code >= 500,
                response: data_cmd,
                accepted: Vec::new(),
            });
        }

        let terminated = terminate_data(data);
        for chunk in terminated.as_bytes().chunks(DATA_WRITE_CHUNK_BYTES) {
            let wait = self.wait_budget();
            tokio::time::timeout(wait, self.io.write_chunk_raw(chunk))
                .await
                .map_err(|_| self.timeout_error("writing message body"))?
                .map_err(SmtpError::Io)?;
        }
        let wait = self.wait_budget();
        tokio::time::timeout(wait, self.io.flush_raw())
            .await
            .map_err(|_| self.timeout_error("flushing message body"))?
            .map_err(SmtpError::Io)?;

        let response = self.read_response().await?;
        if response.is_positive_completion() {
            match rcpt_rejection {
                None => Ok(MessageOutcome::Accepted { response }),

                Some(response) => Ok(MessageOutcome::Rejected {
                    permanent: first_transient.is_none(),
                    response,
                    accepted: rcpt_accepted,
                }),
            }
        } else {
            Ok(MessageOutcome::Rejected {
                permanent: response.code >= 500,
                response,
                accepted: Vec::new(),
            })
        }
    }

    pub async fn quit(&mut self) -> SmtpResult<Response> {
        self.command("QUIT").await
    }
}

impl LineIo {
    async fn write_chunk_raw(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(payload).await
    }

    async fn flush_raw(&mut self) -> std::io::Result<()> {
        self.inner.flush().await
    }
}

const DATA_WRITE_CHUNK_BYTES: usize = 32 * 1024;

pub fn checked_addr(addr: &str) -> SmtpResult<&str> {
    if addr.contains(['\r', '\n', '\0']) {
        return Err(SmtpError::HeaderInjection(addr.to_string()));
    }
    Ok(addr)
}

pub fn terminate_data(data: &str) -> String {
    let body = dot_stuff(data);
    let separator = if body.ends_with("\r\n") { "" } else { "\r\n" };
    format!("{body}{separator}.\r\n")
}

pub fn dot_stuff(data: &str) -> String {
    data.split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn parse_response_line(line: &str) -> SmtpResult<(u16, bool)> {
    let bytes = line.as_bytes();
    if bytes.len() < 3 {
        return Err(SmtpError::Protocol(format!("malformed response: {line:?}")));
    }

    let digits = &bytes[..3];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(SmtpError::Protocol(format!(
            "malformed status code: {line:?}"
        )));
    }
    let code: u16 = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| SmtpError::Protocol(format!("malformed status code: {line:?}")))?;
    let continued = bytes.get(3) == Some(&b'-');
    Ok((code, continued))
}

fn parse_capabilities(response: &Response) -> Capabilities {
    let mut caps = Capabilities {
        raw: response.lines.clone(),
        ..Default::default()
    };

    for line in &response.lines {
        let body = line.get(4..).unwrap_or("").trim();
        let upper = body.to_ascii_uppercase();

        if upper.starts_with("STARTTLS") {
            caps.starttls = true;
        } else if let Some(rest) = upper.strip_prefix("AUTH ") {
            for mech in rest.split_whitespace() {
                let mech = mech.to_string();
                if !caps.auth_mechanisms.contains(&mech) {
                    caps.auth_mechanisms.push(mech);
                }
            }
        }
    }

    caps
}

pub fn base64(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_line_response() {
        let (code, continued) = parse_response_line("250 OK").unwrap();
        assert_eq!(code, 250);
        assert!(!continued);
    }

    #[test]
    fn parses_multiline_continuation() {
        let (code, continued) = parse_response_line("250-STARTTLS").unwrap();
        assert_eq!(code, 250);
        assert!(continued, "连字符表示后续还有行");
    }

    #[test]
    fn rejects_malformed_status_lines() {
        assert!(parse_response_line("hi").is_err());
        assert!(parse_response_line("abc def").is_err());
        assert!(parse_response_line("").is_err());
    }

    #[test]
    fn parses_starttls_and_auth_capabilities() {
        let response = Response {
            code: 250,
            lines: vec![
                "250-mail.example.com".to_string(),
                "250-STARTTLS".to_string(),
                "250-AUTH PLAIN LOGIN".to_string(),
                "250 SIZE 52428800".to_string(),
            ],
        };
        let caps = parse_capabilities(&response);
        assert!(caps.starttls);
        assert!(caps.supports("PLAIN"));
        assert!(caps.supports("LOGIN"));
        assert!(caps.supports("plain"), "机制匹配应大小写不敏感");
        assert!(!caps.supports("CRAM-MD5"));
    }

    #[test]
    fn capability_parsing_handles_absent_starttls() {
        let response = Response {
            code: 250,
            lines: vec!["250 mail.example.com".to_string()],
        };
        let caps = parse_capabilities(&response);
        assert!(!caps.starttls, "未声明 STARTTLS 时不得假定支持");
        assert!(caps.auth_mechanisms.is_empty());
    }

    #[test]
    fn banner_is_truncated_to_two_hundred_chars() {
        let response = Response {
            code: 220,
            lines: vec!["x".repeat(500)],
        };
        assert_eq!(response.banner().chars().count(), 200);
    }

    #[test]
    fn response_classification() {
        let positive = Response {
            code: 250,
            lines: vec![],
        };
        assert!(positive.is_positive());
        assert!(positive.is_positive_completion());

        let intermediate = Response {
            code: 334,
            lines: vec![],
        };
        assert!(intermediate.is_positive(), "3xx 是中间响应");
        assert!(!intermediate.is_positive_completion());

        let failure = Response {
            code: 535,
            lines: vec![],
        };
        assert!(!failure.is_positive());
    }

    #[test]
    fn base64_matches_reference_vectors() {
        assert_eq!(base64(""), "");
        assert_eq!(base64("f"), "Zg==");
        assert_eq!(base64("fo"), "Zm8=");
        assert_eq!(base64("foo"), "Zm9v");
        assert_eq!(base64("foob"), "Zm9vYg==");
        assert_eq!(base64("fooba"), "Zm9vYmE=");
        assert_eq!(base64("foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encodes_auth_plain_payload() {
        assert_eq!(base64("\0user\0pass"), "AHVzZXIAcGFzcw==");
    }

    #[test]
    fn base64_handles_non_ascii() {
        assert_eq!(base64("密码"), "5a+G56CB");
    }

    #[test]
    fn dot_stuffing_prefixes_leading_dots_only() {
        assert_eq!(dot_stuff("hello"), "hello");
        assert_eq!(dot_stuff(".hidden"), "..hidden");
        assert_eq!(dot_stuff("a.b"), "a.b");
        assert_eq!(dot_stuff(".a\r\n.b"), "..a\r\n..b");
        assert_eq!(dot_stuff("text\r\n.\r\nmore"), "text\r\n..\r\nmore");
    }

    #[test]
    fn a_bare_lf_dot_line_is_stuffed_too() {
        assert_eq!(
            dot_stuff("body\n.evil\nrest"),
            "body\r\n..evil\r\nrest",
            "裸 LF 后的句点行必须被加倍，否则邮件在该行被截断"
        );

        assert_eq!(dot_stuff("a\r\n.b\n.c"), "a\r\n..b\r\n..c");

        assert_eq!(dot_stuff("a\nb"), "a\r\nb");
    }

    #[test]
    fn an_address_containing_crlf_is_refused() {
        for evil in [
            "a@example.org\r\nRCPT TO:<victim@elsewhere>",
            "a@example.org\nRCPT TO:<victim@elsewhere>",
            "a@example.org\rDATA",
            "evil\0null",
        ] {
            match checked_addr(evil) {
                Ok(_) => panic!("地址 {evil:?} 含 CR/LF/NUL，必须被拒绝"),
                Err(SmtpError::HeaderInjection(_)) => {}
                Err(other) => panic!("应报 HeaderInjection，实际 {other:?}"),
            }
        }

        assert_eq!(checked_addr("a@example.org").unwrap(), "a@example.org");
        assert_eq!(
            checked_addr("Real Name <a@example.org>").unwrap(),
            "Real Name <a@example.org>"
        );
    }

    #[test]
    fn dot_stuffing_preserves_empty_lines() {
        assert_eq!(dot_stuff("a\r\n\r\nb"), "a\r\n\r\nb");
    }

    #[test]
    fn data_is_terminated_with_crlf_dot_crlf_and_the_body_is_never_rewritten() {
        assert_eq!(terminate_data("body"), "body\r\n.\r\n");
        assert!(terminate_data("body").ends_with("\r\n.\r\n"));

        assert_eq!(terminate_data("body\r\n"), "body\r\n.\r\n");

        assert_eq!(terminate_data(".\r\n"), "..\r\n.\r\n");
    }

    #[test]
    fn message_outcome_classification() {
        let accepted = MessageOutcome::Accepted {
            response: Response {
                code: 250,
                lines: vec!["250 OK".to_string()],
            },
        };
        assert!(accepted.is_accepted());
        assert!(!accepted.is_permanent_failure());
        assert_eq!(accepted.code(), 250);

        let transient = MessageOutcome::Rejected {
            response: Response {
                code: 450,
                lines: vec!["450 try later".to_string()],
            },
            permanent: false,
            accepted: Vec::new(),
        };
        assert!(!transient.is_accepted());
        assert!(!transient.is_permanent_failure(), "4xx 是可重试的临时失败");
        assert_eq!(transient.code(), 450);

        let permanent = MessageOutcome::Rejected {
            response: Response {
                code: 550,
                lines: vec!["550 no such user".to_string()],
            },
            permanent: true,
            accepted: Vec::new(),
        };
        assert!(
            permanent.is_permanent_failure(),
            "5xx 是永久失败，重试无意义"
        );
    }

    async fn scripted_session(script: Vec<&'static str>) -> SmtpSession {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = server.into_split();

        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(read_half);
            let mut line = String::new();
            for response in script {
                if !response.starts_with("220 ") {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
                if write_half
                    .write_all(format!("{response}\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = write_half.flush().await;
            }

            let mut buf = [0u8; 1024];
            let _ = reader.read(&mut buf).await;
        });

        let mut session = SmtpSession::from_stream(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
        );
        session.read_response().await.unwrap();
        session
    }

    #[tokio::test]
    async fn detailed_send_reports_acceptance() {
        let mut session = scripted_session(vec![
            "220 ready",
            "250 sender ok",
            "250 rcpt ok",
            "354 go",
            "250 queued",
        ])
        .await;

        let outcome = session
            .send_message_detailed(
                "a@example.com",
                &["b@example.net".to_string()],
                "Subject: x\r\n\r\nbody",
            )
            .await
            .unwrap();
        assert!(outcome.is_accepted());
        assert_eq!(outcome.code(), 250);
    }

    #[tokio::test]
    async fn detailed_send_classifies_transient_and_permanent_rejections() {
        let mut session =
            scripted_session(vec!["220 ready", "250 sender ok", "450 mailbox busy"]).await;
        let outcome = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await
            .unwrap();
        assert!(!outcome.is_accepted());
        assert!(!outcome.is_permanent_failure(), "450 必须可重试");
        assert_eq!(outcome.code(), 450);

        let mut session =
            scripted_session(vec!["220 ready", "250 sender ok", "550 no such user"]).await;
        let outcome = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await
            .unwrap();
        assert!(outcome.is_permanent_failure(), "550 必须判定为永久失败");
        assert_eq!(outcome.code(), 550);
    }

    #[tokio::test]
    async fn detailed_send_keeps_protocol_failures_as_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(server);

        let mut session = SmtpSession::from_stream(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
        );
        let result = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await;
        assert!(result.is_err(), "未知结果不得伪装成已判定的拒绝");
    }

    #[tokio::test]
    async fn a_trickling_server_is_stopped_by_the_session_deadline() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            if server.write_all(b"220 ready\r\n").await.is_err() {
                return;
            }
            loop {
                if server.write_all(b"2").await.is_err() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        });

        let mut session = SmtpSession::from_stream_with_budget(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(300),
        );
        let banner = session.read_response().await.expect("banner 应可读");
        assert_eq!(banner.code, 220);

        let started = tokio::time::Instant::now();
        let error = session
            .command("EHLO client.test")
            .await
            .expect_err("滴水对端必须在会话 deadline 处失败");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "会话级 deadline 未生效：耗时 {:?}",
            started.elapsed()
        );
        assert!(
            error.to_string().contains("session deadline"),
            "错误应指明是会话总预算耗尽：{error}"
        );
    }
}
