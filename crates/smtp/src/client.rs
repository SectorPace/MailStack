//! 最小 SMTP 客户端（请求-响应式）。
//!
//! 刻意自研而不是直接用高层客户端：分阶段中继测试需要**逐步可观测**
//! （DNS → connect → TLS → auth 各自独立成阶段，§5.9.4），而队列投递又需要
//! 精确控制拨号目标（IP 固定）。两者都要求对会话有完全控制权。
//!
//! 行读取用自带的缓冲而不是 `BufReader`：`BufReader` 无法在 `&mut self` 下交出
//! 底层流的所有权，而 STARTTLS 恰好需要「升级底层流」，且升级时**必须丢弃**
//! 明文读缓冲（否则 TLS 握手后可能读到握手前的残留字节）。

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::dial::{EstablishedStream, PinnedDialer, TlsMode};
use crate::error::{SmtpError, SmtpResult};
use crate::target::PinnedTarget;

/// 单条响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Response {
    /// 首行（不含状态码）。
    pub fn first_line(&self) -> &str {
        self.lines.first().map(String::as_str).unwrap_or("")
    }

    /// banner/文本前 200 字符（§5.9.4 规定）。
    pub fn banner(&self) -> String {
        self.lines.join(" ").chars().take(200).collect()
    }

    /// 2xx/3xx 视为「非失败」。
    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }

    /// 2xx 视为完成。
    pub fn is_positive_completion(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// 一次投递尝试的**已判定**结果（服务器给出了明确答复）。
///
/// 与「协议层失败」相对：后者是未知结果（可能已投递也可能没有），不得据此退信。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOutcome {
    /// 服务器接受。
    Accepted { response: Response },
    /// 服务器拒绝。`permanent` 为真表示 5xx（永久失败，重试无意义）。
    Rejected { response: Response, permanent: bool },
}

impl MessageOutcome {
    /// 状态码。
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

    /// 是否应停止重试。
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

/// EHLO 能力。
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

/// 自有缓冲的行式 IO 包装。
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

    /// 读一行（含结尾换行；EOF 前无换行时返回残余内容）。
    async fn read_line(&mut self) -> std::io::Result<String> {
        loop {
            if let Some(idx) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let end = self.pos + idx + 1;
                let line = String::from_utf8_lossy(&self.buf[self.pos..end]).into_owned();
                self.pos = end;
                return Ok(line);
            }

            // 压缩已消费的前缀，避免缓冲区无界增长。
            if self.pos > 0 {
                self.buf.drain(..self.pos);
                self.pos = 0;
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
                let line = String::from_utf8_lossy(&self.buf).into_owned();
                self.buf.clear();
                return Ok(line);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let payload = format!("{line}\r\n");
        self.inner.write_all(payload.as_bytes()).await?;
        self.inner.flush().await
    }

    /// 交出底层流（升级 TLS 用）。**缓冲被一并丢弃**，这是有意的：
    /// TLS 之后任何明文残留字节都属于协议违规输入。
    fn into_inner(self) -> EstablishedStream {
        self.inner
    }
}

/// SMTP 会话。
pub struct SmtpSession {
    io: LineIo,
    timeout: Duration,
    capabilities: Capabilities,
}

impl SmtpSession {
    /// 建立连接并读取 banner（尚未发送 EHLO）。
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
        Self {
            io: LineIo::new(stream),
            timeout,
            capabilities: Capabilities::default(),
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn is_encrypted(&self) -> bool {
        self.io.is_encrypted()
    }

    /// 读取一条（可能多行的）响应。
    pub async fn read_response(&mut self) -> SmtpResult<Response> {
        let mut lines = Vec::new();
        let mut code: Option<u16> = None;

        loop {
            let line = tokio::time::timeout(self.timeout, self.io.read_line())
                .await
                .map_err(|_| SmtpError::Protocol("timed out waiting for server response".into()))?
                .map_err(SmtpError::Io)?;

            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let (this_code, continued) = parse_response_line(&trimmed)?;

            if code.is_none() {
                code = Some(this_code);
            }
            lines.push(trimmed);

            if !continued {
                break;
            }
        }

        Ok(Response {
            code: code.unwrap_or(0),
            lines,
        })
    }

    /// 发送一行命令并读取响应。
    pub async fn command(&mut self, line: &str) -> SmtpResult<Response> {
        tokio::time::timeout(self.timeout, self.io.write_line(line))
            .await
            .map_err(|_| SmtpError::Protocol("timed out writing command".into()))?
            .map_err(SmtpError::Io)?;
        self.read_response().await
    }

    /// 发送 EHLO 并解析能力。
    pub async fn ehlo(&mut self, client_name: &str) -> SmtpResult<Response> {
        let response = self.command(&format!("EHLO {client_name}")).await?;
        if response.is_positive_completion() {
            self.capabilities = parse_capabilities(&response);
        }
        Ok(response)
    }

    /// STARTTLS 升级。
    ///
    /// **按值消费并返回新会话**，而不是原地修改：STARTTLS 在语义上就是一次状态跃迁
    /// （能力必须重算、明文缓冲必须丢弃、此后所有 IO 都经 TLS）。用类型表达这个跃迁，
    /// 就不会出现「升级后忘了重算能力」或「复用了明文缓冲」这类错误。
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
        // 明文读缓冲在此被丢弃 —— 这是必须的：TLS 之后任何明文残留字节
        // 都属于协议违规输入，绝不能进入解密后的读路径。
        let upgraded = self.io.into_inner().upgrade(dialer, target).await?;
        Ok((Self::from_stream(upgraded, timeout), response))
    }

    /// AUTH PLAIN / LOGIN。
    pub async fn authenticate(&mut self, username: &str, password: &str) -> SmtpResult<Response> {
        if self.capabilities.supports("PLAIN") || self.capabilities.auth_mechanisms.is_empty() {
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

    /// 投递一封邮件：MAIL FROM → RCPT TO → DATA（失败即 `Err`）。
    ///
    /// 队列投递需要区分「4xx 临时失败（应重试）」与「5xx 永久失败（应退信）」，
    /// 因此队列路径请用 [`SmtpSession::send_message_detailed`]：本方法会把两者
    /// 一并压成 [`SmtpError::Rejected`]，丢失状态码这一关键信息。
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
            MessageOutcome::Rejected {
                response,
                permanent: _,
            } => Err(SmtpError::Rejected(response.banner())),
        }
    }

    /// 投递一封邮件，并**保留最终响应的状态码**供调用方分类。
    ///
    /// 协议层失败（连接断开、超时、格式错误）仍以 `Err` 返回；只有服务器明确
    /// 拒绝了信封或正文时才返回 [`MessageOutcome::Rejected`]。这一区分是有意的：
    /// 前者是**未知**结果，后者是**已判定**结果，队列对两者的处理不同
    /// （未知结果不得直接退信，必须是可重试失败）。
    pub async fn send_message_detailed(
        &mut self,
        mail_from: &str,
        recipients: &[String],
        data: &str,
    ) -> SmtpResult<MessageOutcome> {
        let mail = self.command(&format!("MAIL FROM:<{mail_from}>")).await?;
        if !mail.is_positive_completion() {
            return Ok(MessageOutcome::Rejected {
                permanent: mail.code >= 500,
                response: mail,
            });
        }

        for rcpt in recipients {
            let response = self.command(&format!("RCPT TO:<{rcpt}>")).await?;
            if !response.is_positive_completion() {
                return Ok(MessageOutcome::Rejected {
                    permanent: response.code >= 500,
                    response,
                });
            }
        }

        let data_cmd = self.command("DATA").await?;
        if data_cmd.code != 354 {
            return Ok(MessageOutcome::Rejected {
                permanent: data_cmd.code >= 500,
                response: data_cmd,
            });
        }

        // DATA 阶段：内容后跟单独一行的 "."，且必须对行首句点做 dot-stuffing。
        let terminated = terminate_data(data);
        tokio::time::timeout(self.timeout, self.io.write_line_raw(&terminated))
            .await
            .map_err(|_| SmtpError::Protocol("timed out writing message body".into()))?
            .map_err(SmtpError::Io)?;

        let response = self.read_response().await?;
        if response.is_positive_completion() {
            Ok(MessageOutcome::Accepted { response })
        } else {
            Ok(MessageOutcome::Rejected {
                permanent: response.code >= 500,
                response,
            })
        }
    }

    pub async fn quit(&mut self) -> SmtpResult<Response> {
        self.command("QUIT").await
    }
}

impl LineIo {
    /// 原样写入（调用方已负责 CRLF 与终止符）。
    async fn write_line_raw(&mut self, payload: &str) -> std::io::Result<()> {
        self.inner.write_all(payload.as_bytes()).await?;
        self.inner.flush().await
    }
}

/// 把正文封成 DATA 阶段的字节：dot-stuffing + `CRLF.CRLF` 终止符。
///
/// 两处细节都是**真机联调才会暴露**的（自建的脚本化测试服务端不读正文，所以看不见）：
///
/// 1. 终止符必须是 `CRLF.CRLF`，结尾那个 CRLF **不能少**。少了它，对端会一直等
///    「这一行还没结束」—— 表现为双方都觉得自己没错、却永远投递超时。
/// 2. 正文**已经**以 CRLF 结尾时不再补一个，否则每封外发邮件尾部会凭空多出一个空行。
///    那是对正文的改写，会让上游发件人的 DKIM 签名失效。
pub fn terminate_data(data: &str) -> String {
    let body = dot_stuff(data);
    let separator = if body.ends_with("\r\n") { "" } else { "\r\n" };
    format!("{body}{separator}.\r\n")
}

/// 对行首的 `.` 做 dot-stuffing（RFC 5321 §4.5.2）。
pub fn dot_stuff(data: &str) -> String {
    data.split("\r\n")
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// 解析 `250-FOO` / `250 FOO` → (code, continued)。
fn parse_response_line(line: &str) -> SmtpResult<(u16, bool)> {
    if line.len() < 3 {
        return Err(SmtpError::Protocol(format!("malformed response: {line:?}")));
    }
    let code: u16 = line[..3]
        .parse()
        .map_err(|_| SmtpError::Protocol(format!("malformed status code: {line:?}")))?;
    let continued = line.as_bytes().get(3) == Some(&b'-');
    Ok((code, continued))
}

/// 解析 EHLO 能力行。
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

/// 标准 base64 编码（避免为一个编码引入额外依赖）。
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
        // 行首句点必须加倍，行中间的句点不动。
        assert_eq!(dot_stuff("hello"), "hello");
        assert_eq!(dot_stuff(".hidden"), "..hidden");
        assert_eq!(dot_stuff("a.b"), "a.b");
        assert_eq!(dot_stuff(".a\r\n.b"), "..a\r\n..b");
        assert_eq!(dot_stuff("text\r\n.\r\nmore"), "text\r\n..\r\nmore");
    }

    #[test]
    fn dot_stuffing_preserves_empty_lines() {
        assert_eq!(dot_stuff("a\r\n\r\nb"), "a\r\n\r\nb");
    }

    #[test]
    fn data_is_terminated_with_crlf_dot_crlf_and_the_body_is_never_rewritten() {
        // 终止符少了结尾的 CRLF 时，对端会一直等这一行结束 —— 实机投递会永久超时。
        assert_eq!(terminate_data("body"), "body\r\n.\r\n");
        assert!(terminate_data("body").ends_with("\r\n.\r\n"));

        // 正文已以 CRLF 结尾：**不得**再补一个（那会在每封邮件尾部多出一个空行，
        // 并让上游的 DKIM 签名失效）。
        assert_eq!(terminate_data("body\r\n"), "body\r\n.\r\n");

        // dot-stuffing 与终止符一起生效。
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
        };
        assert!(
            permanent.is_permanent_failure(),
            "5xx 是永久失败，重试无意义"
        );
    }

    /// 起一个按脚本应答的最小 SMTP 服务端，返回已连接的客户端流。
    ///
    /// 脚本首行是 banner，其余每行对应「读一条客户端命令 → 写一条应答」。
    /// 注意 [`SmtpSession::send_message_detailed`] 会依次发出 MAIL FROM / RCPT TO /
    /// DATA / 正文，**不发 EHLO** —— 脚本必须与这条命令序列一一对应。
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
            // 保持连接直到客户端关闭（过早 RST 会污染断言）。
            let mut buf = [0u8; 1024];
            let _ = reader.read(&mut buf).await;
        });

        let mut session = SmtpSession::from_stream(
            crate::dial::EstablishedStream::Plain(client),
            std::time::Duration::from_secs(5),
        );
        session.read_response().await.unwrap(); // banner
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
        // 450（RCPT 阶段）→ 临时失败，应重试。
        let mut session =
            scripted_session(vec!["220 ready", "250 sender ok", "450 mailbox busy"]).await;
        let outcome = session
            .send_message_detailed("a@example.com", &["b@example.net".to_string()], "body")
            .await
            .unwrap();
        assert!(!outcome.is_accepted());
        assert!(!outcome.is_permanent_failure(), "450 必须可重试");
        assert_eq!(outcome.code(), 450);

        // 550（RCPT 阶段）→ 永久失败，应退信而不是无休止重试。
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
        // 连接提前关闭：结果**未知**，必须是 Err 而不是 Rejected —— 队列据此
        // 只重试、绝不退信。
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
}
