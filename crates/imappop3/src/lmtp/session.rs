//! LMTP 会话（RFC 2033）：`LHLO` / `MAIL` / `RCPT` / `DATA` / `RSET` / `NOOP` / `QUIT`。
//!
//! ## 与 SMTP 的关键差异
//!
//! `DATA` 结束后**每个收件人各回一条应答**，而不是一条全局应答。少读一条会让
//! 客户端把下一条应答错配给下一个事务，连接就此错位。
//!
//! ## 数据区
//!
//! 逐行读取并做 dot-unstuffing（`..` → `.`），总大小超过 `max_message_size`
//! 后继续读到终止点但不再缓冲，然后对每个收件人回 `552` —— 直接断开会让上游
//! MTA 无法区分「临时失败」与「永久过大」。
//!
//! ## 投递
//!
//! 每个收件人经 [`LmtpRouter`] 映射到独立 Maildir，写盘走 blocking 线程池。
//! 一封信的分发是**逐收件人独立成功/失败**：一个邮箱磁盘满不影响其他收件人。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::blocking;
use crate::error::{MailError, Result};
use crate::lineio::LineIo;
use crate::lmtp::router::LmtpRouter;
use crate::maildir::MailStore;
use crate::outbound::OutboundSink;
use crate::sieve::{self, Delivery};

#[derive(Debug, Clone)]
pub struct LmtpConfig {
    pub hostname: String,
    pub read_timeout: Duration,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_line: usize,
}

impl Default for LmtpConfig {
    fn default() -> Self {
        Self {
            hostname: "mailstack".to_string(),
            read_timeout: Duration::from_secs(5 * 60),
            max_message_size: 32 * 1024 * 1024,
            max_recipients: 100,
            max_line: 64 * 1024,
        }
    }
}

pub struct LmtpContext {
    pub router: Arc<dyn LmtpRouter>,
    pub config: LmtpConfig,
    /// Sieve `redirect`/`vacation` 的外发出口；`None` 时这两个动作会被跳过并告警。
    pub outbound: Option<Arc<dyn OutboundSink>>,
}

pub enum LmtpExit<S> {
    Quit(S),
    Closed(S),
}

struct Recipient {
    address: String,
    store: Arc<MailStore>,
}

enum Control {
    Continue,
    Quit,
}

struct LmtpSession<'a, S> {
    io: LineIo<S>,
    ctx: &'a LmtpContext,
    peer: SocketAddr,
    helo: bool,
    mail_from: Option<String>,
    recipients: Vec<Recipient>,
}

pub async fn serve_connection<S>(io: S, ctx: &LmtpContext, peer: SocketAddr) -> Result<LmtpExit<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    LmtpSession {
        io: LineIo::new(io),
        ctx,
        peer,
        helo: false,
        mail_from: None,
        recipients: Vec::new(),
    }
    .run()
    .await
}

impl<'a, S> LmtpSession<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self) -> Result<LmtpExit<S>> {
        self.write_line(&format!("220 {} LMTP ready", self.ctx.config.hostname))
            .await?;
        loop {
            let read = tokio::time::timeout(
                self.ctx.config.read_timeout,
                self.io.read_line(self.ctx.config.max_line),
            )
            .await;
            let line = match read {
                Err(_) => {
                    let _ = self.write_line("421 4.4.2 Idle timeout").await;
                    return Ok(LmtpExit::Closed(self.io.into_inner()));
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(None)) => return Ok(LmtpExit::Closed(self.io.into_inner())),
                Ok(Ok(Some(line))) => line,
            };
            let text = String::from_utf8_lossy(&line).to_string();
            match self.dispatch(&text).await? {
                Control::Continue => {}
                Control::Quit => return Ok(LmtpExit::Quit(self.io.into_inner())),
            }
        }
    }

    async fn dispatch(&mut self, line: &str) -> Result<Control> {
        let (command, argument) = match line.split_once(' ') {
            Some((command, rest)) => (command.to_ascii_uppercase(), Some(rest.trim())),
            None => (line.trim().to_ascii_uppercase(), None),
        };
        match command.as_str() {
            "LHLO" | "EHLO" => self.handle_lhlo(argument).await,
            "MAIL" => self.handle_mail(argument).await,
            "RCPT" => self.handle_rcpt(argument).await,
            "DATA" => self.handle_data(argument).await,
            "RSET" => {
                self.reset_transaction();
                self.write_line("250 2.0.0 Ok").await?;
                Ok(Control::Continue)
            }
            "NOOP" => {
                self.write_line("250 2.0.0 Ok").await?;
                Ok(Control::Continue)
            }
            "VRFY" => {
                self.write_line("252 2.5.2 Cannot verify user").await?;
                Ok(Control::Continue)
            }
            "EXPN" => {
                self.write_line("502 5.5.1 EXPN not supported").await?;
                Ok(Control::Continue)
            }
            "HELP" => {
                self.write_line("214 2.0.0 Commands: LHLO MAIL RCPT DATA RSET NOOP VRFY QUIT")
                    .await?;
                Ok(Control::Continue)
            }
            "QUIT" => {
                self.write_line("221 2.0.0 Bye").await?;
                Ok(Control::Quit)
            }
            "" => {
                self.write_line("500 5.5.2 Empty command").await?;
                Ok(Control::Continue)
            }
            _ => {
                self.write_line("500 5.5.1 Command unrecognized").await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn handle_lhlo(&mut self, argument: Option<&str>) -> Result<Control> {
        if argument.is_none_or(|value| value.is_empty()) {
            self.write_line("501 5.5.4 LHLO requires a domain").await?;
            return Ok(Control::Continue);
        }
        self.helo = true;
        self.reset_transaction();
        self.write_line(&format!("250-{}", self.ctx.config.hostname))
            .await?;
        self.write_line("250-PIPELINING").await?;
        self.write_line("250-8BITMIME").await?;
        self.write_line("250-ENHANCEDSTATUSCODES").await?;
        self.write_line(&format!("250 SIZE {}", self.ctx.config.max_message_size))
            .await?;
        Ok(Control::Continue)
    }

    async fn handle_mail(&mut self, argument: Option<&str>) -> Result<Control> {
        if !self.helo {
            self.write_line("503 5.5.1 Send LHLO first").await?;
            return Ok(Control::Continue);
        }
        let Some(argument) = argument else {
            self.write_line("501 5.5.4 MAIL requires FROM").await?;
            return Ok(Control::Continue);
        };
        // 新的 MAIL 开始新事务；即使参数被拒，也不保留上一事务的收件人。
        self.reset_transaction();
        let (sender, size) = match parse_path(argument, "FROM") {
            Ok(parsed) => parsed,
            Err(message) => {
                self.write_line(&format!("501 5.5.4 {message}")).await?;
                return Ok(Control::Continue);
            }
        };
        if let Some(size) = size {
            if size > self.ctx.config.max_message_size {
                self.write_line("552 5.3.4 Message size exceeds fixed limit")
                    .await?;
                return Ok(Control::Continue);
            }
        }
        self.mail_from = Some(sender);
        self.recipients.clear();
        self.write_line("250 2.1.0 Ok").await?;
        Ok(Control::Continue)
    }

    async fn handle_rcpt(&mut self, argument: Option<&str>) -> Result<Control> {
        if self.mail_from.is_none() {
            self.write_line("503 5.5.1 Send MAIL first").await?;
            return Ok(Control::Continue);
        }
        let Some(argument) = argument else {
            self.write_line("501 5.5.4 RCPT requires TO").await?;
            return Ok(Control::Continue);
        };
        let (address, _) = match parse_path(argument, "TO") {
            Ok(parsed) => parsed,
            Err(message) => {
                self.write_line(&format!("501 5.5.4 {message}")).await?;
                return Ok(Control::Continue);
            }
        };
        if address.is_empty() {
            self.write_line("501 5.1.3 Bad recipient address syntax")
                .await?;
            return Ok(Control::Continue);
        }
        if self.recipients.len() >= self.ctx.config.max_recipients {
            self.write_line("452 4.5.3 Too many recipients").await?;
            return Ok(Control::Continue);
        }
        match self.ctx.router.route(&address) {
            Some(store) => {
                self.recipients.push(Recipient { address, store });
                self.write_line("250 2.1.5 Ok").await?;
            }
            None => {
                tracing::info!(peer = %self.peer, recipient = %address, "LMTP recipient not found");
                self.write_line("550 5.1.1 No such user").await?;
            }
        }
        Ok(Control::Continue)
    }

    async fn handle_data(&mut self, argument: Option<&str>) -> Result<Control> {
        if argument.is_some_and(|value| !value.is_empty()) {
            self.write_line("501 5.5.4 DATA takes no arguments").await?;
            return Ok(Control::Continue);
        }
        if self.mail_from.is_none() || self.recipients.is_empty() {
            self.write_line("503 5.5.1 Need MAIL and RCPT first")
                .await?;
            return Ok(Control::Continue);
        }
        self.write_line("354 End data with <CR><LF>.<CR><LF>")
            .await?;
        let data = self.read_data().await?;
        let Some(data) = data else {
            let recipient_count = self.recipients.len();
            for _ in 0..recipient_count {
                self.write_line("552 5.3.4 Message size exceeds fixed limit")
                    .await?;
            }
            self.reset_transaction();
            return Ok(Control::Continue);
        };

        let sender = self.mail_from.clone().unwrap_or_default();
        let mut responses = Vec::with_capacity(self.recipients.len());
        for recipient in &self.recipients {
            let store = Arc::clone(&recipient.store);
            let payload = data.clone();
            let from = sender.clone();
            let to = recipient.address.clone();
            let outbound = self.ctx.outbound.clone();
            // 过滤器与投递都在 blocking 线程里完成：要读 `.sieve`、建文件夹、发外发。
            let result = blocking::maildir(&store, move |store| {
                sieve::deliver_envelope(store, &payload, &from, &to, outbound.as_deref())
            })
            .await;
            match result {
                Ok(Delivery::Delivered { folders, uids }) => {
                    tracing::info!(
                        peer = %self.peer,
                        sender = %sender,
                        recipient = %recipient.address,
                        folders = ?folders,
                        uid = uids.first().copied().unwrap_or(0),
                        "LMTP delivered"
                    );
                    responses.push("250 2.0.0 Ok: delivered".to_string());
                }
                Ok(Delivery::Rejected(reason)) => {
                    tracing::info!(
                        peer = %self.peer,
                        sender = %sender,
                        recipient = %recipient.address,
                        %reason,
                        "LMTP rejected by Sieve"
                    );
                    responses.push(format!("550 5.7.1 {}", sanitize_reason(&reason)));
                }
                Err(error) => {
                    tracing::warn!(
                        peer = %self.peer,
                        recipient = %recipient.address,
                        %error,
                        "LMTP delivery failed"
                    );
                    responses.push(lmtp_failure(&error));
                }
            }
        }
        for response in responses {
            self.write_line(&response).await?;
        }
        self.reset_transaction();
        Ok(Control::Continue)
    }

    /// 读 DATA 区。返回 `None` 表示超过大小上限（已读到终止点）。
    async fn read_data(&mut self) -> Result<Option<Vec<u8>>> {
        let mut out: Vec<u8> = Vec::new();
        let mut total = 0usize;
        let mut too_large = false;
        loop {
            let read = tokio::time::timeout(
                self.ctx.config.read_timeout,
                self.io.read_line(self.ctx.config.max_line),
            )
            .await;
            let line = match read {
                Err(_) => {
                    return Err(MailError::Timeout);
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(None)) => {
                    return Err(MailError::protocol(
                        "connection closed in the middle of DATA",
                    ))
                }
                Ok(Ok(Some(line))) => line,
            };
            if line == b"." {
                break;
            }
            let line = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            total = total.saturating_add(line.len() + 2);
            if total > self.ctx.config.max_message_size {
                too_large = true;
                continue;
            }
            if !too_large {
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
            }
        }
        Ok(if too_large { None } else { Some(out) })
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
    }

    async fn write_line(&mut self, line: &str) -> Result<()> {
        self.io.write_all(line.as_bytes()).await?;
        self.io.write_all(b"\r\n").await?;
        self.io.flush().await
    }
}

/// 解析 `FROM:<addr> [SIZE=n ...]` / `TO:<addr>`。
fn parse_path(
    argument: &str,
    keyword: &str,
) -> std::result::Result<(String, Option<usize>), &'static str> {
    let Some((tag, rest)) = argument.split_once(':') else {
        return Err("missing ':' in path");
    };
    if !tag.trim().eq_ignore_ascii_case(keyword) {
        return Err("unexpected path keyword");
    }
    let rest = rest.trim();
    let (address, parameters) = if let Some(stripped) = rest.strip_prefix('<') {
        let Some(end) = stripped.find('>') else {
            return Err("unterminated path");
        };
        (
            stripped[..end].trim().to_string(),
            stripped[end + 1..].trim(),
        )
    } else {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let address = parts.next().unwrap_or("").to_string();
        (address, parts.next().unwrap_or("").trim())
    };
    let mut size = None;
    for token in parameters.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        if key.eq_ignore_ascii_case("SIZE") {
            size = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "invalid SIZE parameter")?,
            );
        }
    }
    Ok((address, size))
}

fn lmtp_failure(error: &MailError) -> String {
    match error {
        MailError::NotFound(_) => "550 5.1.1 Recipient mailbox unavailable".to_string(),
        MailError::QuotaExceeded(_) => "552 5.2.2 Mailbox full".to_string(),
        MailError::Invalid(_) => "550 5.1.0 Message rejected".to_string(),
        _ => "451 4.2.0 Mailbox unavailable".to_string(),
    }
}

/// 把 Sieve `reject` 的理由压成单行：脚本里的 CR/LF 不能注入到 LMTP 应答。
fn sanitize_reason(reason: &str) -> String {
    reason
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmtp::router::MapRouter;
    use crate::maildir::{SystemClock, INBOX};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    struct Client {
        io: BufReader<DuplexStream>,
    }

    impl Client {
        fn new(stream: DuplexStream) -> Self {
            Self {
                io: BufReader::new(stream),
            }
        }

        async fn send(&mut self, line: &str) {
            let io = self.io.get_mut();
            io.write_all(line.as_bytes()).await.unwrap();
            io.write_all(b"\r\n").await.unwrap();
            io.flush().await.unwrap();
        }

        async fn line(&mut self) -> String {
            let mut line = String::new();
            self.io.read_line(&mut line).await.unwrap();
            assert!(!line.is_empty(), "connection closed");
            line
        }
    }

    fn fixture() -> (tempfile::TempDir, Arc<MailStore>, Arc<MailStore>) {
        let directory = tempfile::tempdir().unwrap();
        let alice = Arc::new(
            MailStore::new(directory.path().join("alice"), Arc::new(SystemClock)).unwrap(),
        );
        let bob =
            Arc::new(MailStore::new(directory.path().join("bob"), Arc::new(SystemClock)).unwrap());
        (directory, alice, bob)
    }

    #[tokio::test]
    async fn deliveries_are_per_recipient_and_dot_unstuffed() {
        let (_dir, alice, bob) = fixture();
        let mut router = MapRouter::new();
        router.insert("alice@example.com", Arc::clone(&alice));
        router.insert("bob@example.com", Arc::clone(&bob));
        let context = Arc::new(LmtpContext {
            router: Arc::new(router),
            config: LmtpConfig {
                max_message_size: 1024 * 1024,
                ..LmtpConfig::default()
            },
            outbound: None,
        });
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(server_io, &context, "127.0.0.1:1".parse().unwrap()).await
        });
        let mut client = Client::new(client_io);
        assert!(client.line().await.starts_with("220 "));
        client.send("LHLO test.example").await;
        loop {
            let line = client.line().await;
            if line.starts_with("250 ") {
                break;
            }
        }
        client.send("MAIL FROM:<sender@example.org> SIZE=100").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("RCPT TO:<Alice@Example.com>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("RCPT TO:<missing@example.com>").await;
        assert!(client.line().await.starts_with("550 "));
        client.send("RCPT TO:<bob@example.com>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("DATA").await;
        assert!(client.line().await.starts_with("354 "));
        client.send("Subject: hi").await;
        client.send("").await;
        client.send("..dot line").await;
        client.send(".").await;
        assert!(client.line().await.starts_with("250 "));
        assert!(client.line().await.starts_with("250 "));
        client.send("QUIT").await;
        assert!(client.line().await.starts_with("221 "));
        let exit = server.await.unwrap().unwrap();
        assert!(matches!(exit, LmtpExit::Quit(_)));

        for store in [&alice, &bob] {
            let state = store.open_folder(INBOX, false).unwrap();
            assert_eq!(state.messages.len(), 1);
            let data = store.read(&state.messages[0]).unwrap();
            let text = String::from_utf8_lossy(&data);
            assert!(
                text.contains("Subject: hi\r\n\r\n.dot line\r\n"),
                "{text:?}"
            );
        }
    }

    #[tokio::test]
    async fn sieve_fileinto_routes_delivery_and_reject_is_per_recipient() {
        let (_dir, alice, bob) = fixture();
        std::fs::write(
            alice.root().join(".sieve"),
            r#"require ["fileinto"];
               if header :contains "subject" "invoice" { fileinto :create "Invoices"; } else { keep; }"#,
        )
        .unwrap();
        std::fs::write(
            bob.root().join(".sieve"),
            r#"require ["reject"]; reject "not here";"#,
        )
        .unwrap();

        let mut router = MapRouter::new();
        router.insert("alice@example.com", Arc::clone(&alice));
        router.insert("bob@example.com", Arc::clone(&bob));
        let context = Arc::new(LmtpContext {
            router: Arc::new(router),
            config: LmtpConfig::default(),
            outbound: None,
        });
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(server_io, &context, "127.0.0.1:1".parse().unwrap()).await
        });
        let mut client = Client::new(client_io);
        assert!(client.line().await.starts_with("220 "));
        client.send("LHLO test.example").await;
        loop {
            if client.line().await.starts_with("250 ") {
                break;
            }
        }
        client.send("MAIL FROM:<sender@example.org>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("RCPT TO:<alice@example.com>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("RCPT TO:<bob@example.com>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("DATA").await;
        assert!(client.line().await.starts_with("354 "));
        client.send("Subject: Your invoice 42").await;
        client.send("").await;
        client.send("body").await;
        client.send(".").await;
        let alice_reply = client.line().await;
        let bob_reply = client.line().await;
        assert!(alice_reply.starts_with("250 "), "{alice_reply}");
        assert!(bob_reply.starts_with("550 "), "{bob_reply}");
        client.send("QUIT").await;
        assert!(client.line().await.starts_with("221 "));
        let _ = server.await.unwrap().unwrap();

        let invoices = alice.open_folder("Invoices", false).unwrap();
        assert_eq!(invoices.messages.len(), 1);
        assert_eq!(alice.open_folder(INBOX, false).unwrap().messages.len(), 0);
        assert_eq!(bob.open_folder(INBOX, false).unwrap().messages.len(), 0);
    }

    #[tokio::test]
    async fn oversized_messages_are_drained_and_rejected_per_recipient() {
        let (_dir, alice, _bob) = fixture();
        let mut router = MapRouter::new();
        router.insert("alice@example.com", Arc::clone(&alice));
        let context = Arc::new(LmtpContext {
            router: Arc::new(router),
            config: LmtpConfig {
                max_message_size: 32,
                ..LmtpConfig::default()
            },
            outbound: None,
        });
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            serve_connection(server_io, &context, "127.0.0.1:1".parse().unwrap()).await
        });
        let mut client = Client::new(client_io);
        let _ = client.line().await;
        client.send("LHLO x").await;
        loop {
            if client.line().await.starts_with("250 ") {
                break;
            }
        }
        client.send("MAIL FROM:<>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("RCPT TO:<alice@example.com>").await;
        assert!(client.line().await.starts_with("250 "));
        client.send("DATA").await;
        assert!(client.line().await.starts_with("354 "));
        client
            .send("0123456789012345678901234567890123456789")
            .await;
        client.send(".").await;
        assert!(client.line().await.starts_with("552 "));
        client.send("QUIT").await;
        let _ = client.line().await;
        let _ = server.await.unwrap().unwrap();
        assert_eq!(alice.open_folder(INBOX, false).unwrap().messages.len(), 0);
    }

    #[test]
    fn path_parsing_handles_null_sender_and_size() {
        assert_eq!(
            parse_path("FROM:<>", "FROM").unwrap(),
            (String::new(), None)
        );
        assert_eq!(
            parse_path("FROM:<a@b.c> SIZE=42", "FROM").unwrap(),
            ("a@b.c".to_string(), Some(42))
        );
        assert!(parse_path("TO:<unterminated", "TO").is_err());
        assert!(parse_path("FROM:x@y", "TO").is_err());
    }
}
