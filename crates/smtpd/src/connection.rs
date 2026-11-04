use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::command::{self, Command};
use crate::data::{BareNewlinePolicy, DataEvent, DataSink};
use crate::reply::{texts, Reply};
use crate::sasl::{AuthOutcome, AuthRequest, Authenticator};
use crate::session::{AcceptedMessage, Action, Session};

pub const MAX_COMMAND_BUFFER: usize = 2048;

#[derive(Debug, Clone)]
pub struct ServerLimits {
    pub command_timeout: Duration,

    pub data_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(600),
        }
    }
}

pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Reply>> + Send + 'a>>;

pub trait MessageSink: Send + Sync {
    fn accept<'a>(&'a self, message: AcceptedMessage, peer: SocketAddr) -> SinkFuture<'a>;
}

pub const MAX_CONSECUTIVE_AUTH_FAILURES: u32 = 5;

pub(crate) async fn write_reply<S>(stream: &mut S, reply: &Reply) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(reply.render().as_bytes()).await?;
    stream.flush().await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    Closed,

    StartTls,

    ClosedAfterAuthFailures { failures: u32 },
}

enum LineOutcome {
    Line(Vec<u8>, usize),
    NeedMore,

    BareLineFeed,
    TooLong,
}

fn next_line(buffer: &[u8], policy: BareNewlinePolicy) -> LineOutcome {
    for (index, &byte) in buffer.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let has_cr = index > 0 && buffer[index - 1] == b'\r';

        if !has_cr && policy == BareNewlinePolicy::Reject {
            return LineOutcome::BareLineFeed;
        }
        let line_end = if has_cr { index - 1 } else { index };
        return LineOutcome::Line(buffer[..line_end].to_vec(), index + 1);
    }

    if buffer.len() > MAX_COMMAND_BUFFER {
        LineOutcome::TooLong
    } else {
        LineOutcome::NeedMore
    }
}

pub async fn serve<S, K, A>(
    stream: S,
    session: &mut Session<'_>,
    sink: &K,
    auth: &A,
    peer: SocketAddr,
    limits: ServerLimits,
) -> std::io::Result<ServeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: MessageSink + ?Sized,
    A: Authenticator + ?Sized,
{
    drive(stream, session, sink, auth, peer, limits, true).await
}

pub async fn serve_after_upgrade<S, K, A>(
    stream: S,
    session: &mut Session<'_>,
    sink: &K,
    auth: &A,
    peer: SocketAddr,
    limits: ServerLimits,
) -> std::io::Result<ServeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: MessageSink + ?Sized,
    A: Authenticator + ?Sized,
{
    drive(stream, session, sink, auth, peer, limits, false).await
}

async fn drive<S, K, A>(
    mut stream: S,
    session: &mut Session<'_>,
    sink: &K,
    auth: &A,
    peer: SocketAddr,
    limits: ServerLimits,
    greet: bool,
) -> std::io::Result<ServeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
    K: MessageSink + ?Sized,
    A: Authenticator + ?Sized,
{
    let policy = session.config().bare_newline_policy;
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);

    let mut auth_failures: u32 = 0;

    if greet {
        write_reply(&mut stream, &session.greeting()).await?;
    }

    loop {
        let line = loop {
            match next_line(&buffer, policy) {
                LineOutcome::Line(line, consumed) => {
                    buffer.drain(..consumed);
                    break Some(line);
                }
                LineOutcome::BareLineFeed => {
                    let reply = Reply::with_enhanced(500, "5.5.2", texts::BARE_LINE_FEED);
                    write_reply(&mut stream, &reply).await?;
                    return Ok(ServeOutcome::Closed);
                }
                LineOutcome::TooLong => {
                    let reply = Reply::with_enhanced(500, "5.5.6", texts::LINE_TOO_LONG);
                    write_reply(&mut stream, &reply).await?;
                    return Ok(ServeOutcome::Closed);
                }
                LineOutcome::NeedMore => {
                    let mut chunk = [0u8; 4096];
                    let read =
                        match tokio::time::timeout(limits.command_timeout, stream.read(&mut chunk))
                            .await
                        {
                            Ok(Ok(0)) => return Ok(ServeOutcome::Closed),
                            Ok(Ok(read)) => read,
                            Ok(Err(error)) => return Err(error),

                            Err(_) => return Ok(ServeOutcome::Closed),
                        };
                    buffer.extend_from_slice(&chunk[..read]);
                }
            }
        };

        let Some(line) = line else {
            return Ok(ServeOutcome::Closed);
        };

        let action = if session.awaiting_auth_response() {
            session.continue_auth(&line)
        } else {
            match command::parse(&line) {
                Ok(Command::Data) => session.handle(Command::Data),
                Ok(other) => session.handle(other),
                Err(error) => Action::Reply(error.reply()),
            }
        };

        match action {
            Action::Reply(reply) => write_reply(&mut stream, &reply).await?,
            Action::Close(reply) => {
                write_reply(&mut stream, &reply).await?;
                return Ok(ServeOutcome::Closed);
            }
            Action::StartTls(reply) => {
                write_reply(&mut stream, &reply).await?;

                return Ok(ServeOutcome::StartTls);
            }
            Action::AuthChallenge(reply) => {
                write_reply(&mut stream, &reply).await?;
            }
            Action::AuthVerify {
                mechanism,
                response,
            } => {
                let request = AuthRequest {
                    mechanism,
                    response,
                    secured: session.is_tls_active(),
                    peer,
                };
                let outcome = auth.authenticate(request).await;
                match &outcome {
                    AuthOutcome::Success { user } => {
                        tracing::info!(peer = %peer, user = %user, "提交认证成功");

                        auth_failures = 0;
                    }
                    AuthOutcome::TemporaryFailure(reason) => {
                        tracing::warn!(peer = %peer, reason = %reason, "认证后端暂时不可用");
                    }
                    AuthOutcome::InvalidCredentials => {
                        auth_failures = auth_failures.saturating_add(1);
                        tracing::info!(
                            peer = %peer,
                            consecutive_failures = auth_failures,
                            "提交认证失败"
                        );
                    }
                }
                let reply = session.complete_auth(outcome);
                write_reply(&mut stream, &reply).await?;

                if auth_failures >= MAX_CONSECUTIVE_AUTH_FAILURES {
                    return Ok(ServeOutcome::ClosedAfterAuthFailures {
                        failures: auth_failures,
                    });
                }
            }
            Action::EnterData(reply) => {
                let Some(_data_slot) = DataSlot::acquire(session.config().max_message_size) else {
                    let backpressure = Reply::with_enhanced(451, "4.3.2", texts::DATA_BACKPRESSURE);
                    write_reply(&mut stream, &backpressure).await?;
                    continue;
                };
                write_reply(&mut stream, &reply).await?;
                match collect_data(&mut stream, &mut buffer, session, &limits).await? {
                    DataOutcome::Closed => return Ok(ServeOutcome::Closed),
                    DataOutcome::Rejected(reply) => {
                        write_reply(&mut stream, &reply).await?;

                        return Ok(ServeOutcome::Closed);
                    }

                    DataOutcome::Discarded => session.discard_data(),
                    DataOutcome::Received(data) => {
                        let (reply, accepted) = session.finish_data(data);
                        match accepted {
                            None => write_reply(&mut stream, &reply).await?,
                            Some(message) => match sink.accept(message, peer).await {
                                Ok(()) => write_reply(&mut stream, &reply).await?,
                                Err(rejection) => write_reply(&mut stream, &rejection).await?,
                            },
                        }
                    }
                }
            }
        }
    }
}

enum DataOutcome {
    Received(Vec<u8>),

    Discarded,

    Rejected(Reply),

    Closed,
}

const DATA_MEMORY_BUDGET: usize = 1024 * 1024 * 1024;
static ACTIVE_DATA_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct DataSlot {
    bytes: usize,
}

impl DataSlot {
    fn acquire(message_size: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;

        let request = message_size.max(1);
        let mut current = ACTIVE_DATA_BYTES.load(Ordering::Relaxed);
        loop {
            if current.saturating_add(request) > DATA_MEMORY_BUDGET {
                return None;
            }
            match ACTIVE_DATA_BYTES.compare_exchange_weak(
                current,
                current + request,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(DataSlot { bytes: request }),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for DataSlot {
    fn drop(&mut self) {
        ACTIVE_DATA_BYTES.fetch_sub(self.bytes, std::sync::atomic::Ordering::Relaxed);
    }
}

async fn collect_data<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    session: &mut Session<'_>,
    limits: &ServerLimits,
) -> std::io::Result<DataOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = session.config().clone();
    let mut sink = DataSink::new(config.max_message_size, config.bare_newline_policy);
    let mut told_too_large = false;

    loop {
        if !buffer.is_empty() {
            let (event, consumed) = sink.feed(buffer);
            buffer.drain(..consumed);
            match event {
                DataEvent::NeedMore => {}
                DataEvent::Complete { data } => {
                    return Ok(match data {
                        Some(data) => DataOutcome::Received(data),
                        None => DataOutcome::Discarded,
                    })
                }
                DataEvent::TooLarge => {
                    if !told_too_large {
                        told_too_large = true;
                        write_reply(
                            stream,
                            &Reply::with_enhanced(552, "5.3.4", texts::MESSAGE_TOO_LARGE),
                        )
                        .await?;
                    }

                    continue;
                }
                DataEvent::BareLineFeed => {
                    return Ok(DataOutcome::Rejected(Reply::with_enhanced(
                        550,
                        "5.6.0",
                        texts::BARE_LINE_FEED,
                    )))
                }
            }
        }

        let mut chunk = [0u8; 8192];
        let read = match tokio::time::timeout(limits.data_timeout, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(DataOutcome::Closed),
            Ok(Ok(read)) => read,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(DataOutcome::Closed),
        };
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_smtp::RelayPolicy;
    use std::sync::Mutex;

    use crate::sasl::{AuthFuture, UnavailableAuthenticator};
    use crate::session::{RecipientChecker, SessionConfig};

    #[derive(Default)]
    struct RecordingSink {
        accepted: Mutex<Vec<AcceptedMessage>>,
        reject: Mutex<Option<Reply>>,
    }

    impl MessageSink for RecordingSink {
        fn accept<'a>(&'a self, message: AcceptedMessage, _peer: SocketAddr) -> SinkFuture<'a> {
            Box::pin(async move {
                if let Some(reply) = self.reject.lock().unwrap().clone() {
                    return Err(reply);
                }
                self.accepted.lock().unwrap().push(message);
                Ok(())
            })
        }
    }

    fn session_config() -> SessionConfig {
        SessionConfig {
            hostname: "mail.example.org".to_string(),
            postmaster: Some("postmaster@example.org".to_string()),
            ..SessionConfig::default()
        }
    }

    async fn run_collect_with(
        input: &[u8],
        limits: ServerLimits,
        config: SessionConfig,
        sink: &RecordingSink,
    ) -> (String, Vec<AcceptedMessage>) {
        run_collect_with_auth(input, limits, config, sink, &UnavailableAuthenticator).await
    }

    async fn run_collect_with_auth<A: Authenticator + ?Sized>(
        input: &[u8],
        limits: ServerLimits,
        config: SessionConfig,
        sink: &RecordingSink,
        auth: &A,
    ) -> (String, Vec<AcceptedMessage>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(config, RelayPolicy::new(["example.org"]));
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();

        let client_task = async {
            client.write_all(input).await.unwrap();

            client.shutdown().await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        };
        let (out, served) = tokio::join!(
            client_task,
            serve(server, &mut session, sink, auth, peer, limits)
        );
        served.expect("会话驱动不应返回 I/O 错误");
        (out, sink.accepted.lock().unwrap().clone())
    }

    async fn run_collect_outcome<A: Authenticator + ?Sized>(
        input: &[u8],
        limits: ServerLimits,
        config: SessionConfig,
        sink: &RecordingSink,
        auth: &A,
    ) -> (String, ServeOutcome) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(config, RelayPolicy::new(["example.org"]));
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();

        let client_task = async {
            client.write_all(input).await.unwrap();
            client.shutdown().await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        };
        let (out, served) = tokio::join!(
            client_task,
            serve(server, &mut session, sink, auth, peer, limits)
        );
        (out, served.expect("会话驱动不应返回 I/O 错误"))
    }

    #[derive(Default)]
    struct RecordingAuth {
        seen: Mutex<Vec<AuthRequest>>,
        outcome: Mutex<Option<AuthOutcome>>,
    }

    impl RecordingAuth {
        fn with_outcome(outcome: AuthOutcome) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                outcome: Mutex::new(Some(outcome)),
            }
        }

        fn requests(&self) -> Vec<AuthRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Authenticator for RecordingAuth {
        fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_> {
            Box::pin(async move {
                self.seen.lock().unwrap().push(request);
                self.outcome
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(AuthOutcome::InvalidCredentials)
            })
        }
    }

    fn submission_config() -> SessionConfig {
        SessionConfig {
            offer_auth: true,
            tls_active: true,
            ..session_config()
        }
    }

    async fn run_collect(input: &[u8], limits: ServerLimits) -> (String, Vec<AcceptedMessage>) {
        let sink = RecordingSink::default();
        run_collect_with(input, limits, session_config(), &sink).await
    }

    fn limits() -> ServerLimits {
        ServerLimits {
            command_timeout: Duration::from_secs(2),
            data_timeout: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn a_full_transaction_is_accepted_and_handed_to_the_sink() {
        let input = concat!(
            "EHLO client.test\r\n",
            "MAIL FROM:<alice@remote.test>\r\n",
            "RCPT TO:<bob@example.org>\r\n",
            "DATA\r\n",
            "Subject: hi\r\n",
            "\r\n",
            "body\r\n",
            ".\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) = run_collect(input.as_bytes(), limits()).await;

        assert_eq!(accepted.len(), 1, "整封邮件应交到 sink，应答：{out}");
        assert_eq!(accepted[0].mail_from, "alice@remote.test");
        assert_eq!(accepted[0].recipients, vec!["bob@example.org".to_string()]);
        assert_eq!(accepted[0].data, b"Subject: hi\r\n\r\nbody\r\n");
        assert!(out.starts_with("220 "));
        assert!(out.contains("250 2.0.0 Message accepted for delivery"));
        assert!(out.contains("221 "));
    }

    #[tokio::test]
    async fn the_sink_runs_before_the_250_is_sent() {
        let sink = RecordingSink::default();
        *sink.reject.lock().unwrap() =
            Some(Reply::with_enhanced(451, "4.3.0", "queue write failed"));

        let input = concat!(
            "EHLO c.test\r\n",
            "MAIL FROM:<a@remote.test>\r\n",
            "RCPT TO:<b@example.org>\r\n",
            "DATA\r\n",
            "x\r\n",
            ".\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) =
            run_collect_with(input.as_bytes(), limits(), session_config(), &sink).await;

        assert!(accepted.is_empty());
        assert!(out.contains("451 4.3.0 queue write failed"), "{out}");
        assert!(
            !out.contains("250 2.0.0 Message accepted"),
            "落盘失败时绝不能回 250：{out}"
        );
    }

    #[tokio::test]
    async fn opening_the_transaction_gets_the_greeting_first() {
        let (out, _) = run_collect(b"QUIT\r\n", limits()).await;
        assert!(out.starts_with("220 mail.example.org "), "{out}");
        assert!(out.contains("221 "));
    }

    #[tokio::test]
    async fn a_pipelined_transaction_in_one_segment_is_handled_in_order() {
        let input = concat!(
            "EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<b@example.org>\r\n",
            "DATA\r\nSubject: p\r\n\r\nbody\r\n.\r\nQUIT\r\n"
        );
        let (out, accepted) = run_collect(input.as_bytes(), limits()).await;
        assert_eq!(accepted.len(), 1, "{out}");
        assert_eq!(accepted[0].data, b"Subject: p\r\n\r\nbody\r\n");
        assert!(out.contains("354 "), "应先在 354 之后才收正文：{out}");
    }

    #[tokio::test]
    async fn commands_pipelined_after_the_data_terminator_are_not_lost() {
        let input = concat!(
            "EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<b@example.org>\r\n",
            "DATA\r\nbody\r\n.\r\nRSET\r\nQUIT\r\n"
        );
        let (out, accepted) = run_collect(input.as_bytes(), limits()).await;
        assert_eq!(accepted.len(), 1, "{out}");
        assert!(
            out.contains("250 Session reset"),
            "结束标记之后的 RSET 必须被处理，而不是被吞掉：{out}"
        );
        assert!(out.contains("221 "), "QUIT 也必须被处理：{out}");
    }

    #[tokio::test]
    async fn a_bare_line_feed_in_a_command_closes_the_session() {
        let (out, accepted) = run_collect(b"EHLO c.test\nMAIL FROM:<a@b.test>\r\n", limits()).await;
        assert!(accepted.is_empty());
        assert!(out.contains("500 5.5.2"), "{out}");
        assert!(
            !out.contains("250"),
            "边界认知分叉后必须断开，不能再解析后续字节：{out}"
        );
    }

    #[tokio::test]
    async fn a_bare_line_feed_in_data_closes_the_session() {
        let input = concat!(
            "EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<b@example.org>\r\n",
            "DATA\r\nbody\nmore\r\n.\r\n"
        );
        let (out, accepted) = run_collect(input.as_bytes(), limits()).await;
        assert!(accepted.is_empty(), "裸 LF 的正文不得被接受");
        assert!(out.contains("550 5.6.0"), "{out}");
    }

    #[tokio::test]
    async fn an_overlong_command_line_closes_the_session() {
        let long = format!("EHLO {}\r\n", "a".repeat(MAX_COMMAND_BUFFER + 16));
        let (out, _) = run_collect(long.as_bytes(), limits()).await;
        assert!(out.contains("500 5.5.6"), "{out}");
    }

    #[tokio::test]
    async fn an_oversized_message_is_refused_and_the_session_stays_in_sync() {
        let mut config = session_config();
        config.max_message_size = 32;
        let sink = RecordingSink::default();

        let input = concat!(
            "EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<b@example.org>\r\n",
            "DATA\r\n",
            "0123456789012345678901234567890123456789\r\n",
            "still-body\r\n",
            ".\r\n",
            "RSET\r\nQUIT\r\n"
        );
        let (out, accepted) = run_collect_with(input.as_bytes(), limits(), config, &sink).await;

        assert!(accepted.is_empty(), "超限的报文不得被接受：{out}");
        assert_eq!(out.matches("552 5.3.4").count(), 1, "552 只应回一次：{out}");
        assert!(
            out.contains("250 Session reset"),
            "结束标记之后的 RSET 必须被当作命令处理，说明会话没错位：{out}"
        );
        assert!(out.contains("221 "), "QUIT 也必须被处理：{out}");
        assert!(
            !out.contains("250 2.0.0 Message accepted"),
            "不得把超限报文当成功：{out}"
        );
    }

    #[tokio::test]
    async fn a_peer_that_disappears_mid_command_ends_the_session_quietly() {
        let (out, accepted) = run_collect(b"EHLO c.test\r\n", limits()).await;
        assert!(accepted.is_empty());
        assert!(out.contains("250"), "{out}");
    }

    #[tokio::test]
    async fn starttls_returns_the_upgrade_outcome_and_discards_pipelined_plaintext() {
        let mut config = session_config();
        config.offer_starttls = true;

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(config, RelayPolicy::new(["example.org"]));
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let sink = RecordingSink::default();

        client
            .write_all(b"EHLO c.test\r\nSTARTTLS\r\nMAIL FROM:<evil@remote.test>\r\n")
            .await
            .unwrap();

        let outcome = serve(
            server,
            &mut session,
            &sink,
            &UnavailableAuthenticator,
            peer,
            limits(),
        )
        .await
        .expect("驱动不应返回 I/O 错误");
        assert_eq!(outcome, ServeOutcome::StartTls, "必须交回升级信号");
        assert!(
            session.mail_from().is_none(),
            "明文缓冲里的 MAIL FROM 不得被处理"
        );
        assert!(sink.accepted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_upgraded_session_never_repeats_the_220_greeting() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session = Session::new(session_config(), RelayPolicy::new(["example.org"]));
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let sink = RecordingSink::default();

        client.write_all(b"EHLO c.test\r\nQUIT\r\n").await.unwrap();
        let outcome = serve_after_upgrade(
            server,
            &mut session,
            &sink,
            &UnavailableAuthenticator,
            peer,
            limits(),
        )
        .await
        .expect("驱动不应返回 I/O 错误");
        assert_eq!(outcome, ServeOutcome::Closed);

        let mut out = String::new();
        let _ = client.shutdown().await;
        let _ = client.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("250"), "升级后不得再发 220：{out:?}");
    }

    #[tokio::test]
    async fn an_authenticated_submission_may_relay_to_a_foreign_domain() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::Success {
            user: "alice@example.org".to_string(),
        });
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO client.test\r\n",
            "AUTH PLAIN AGFsaWNlQGV4YW1wbGUub3JnAHNlY3JldA==\r\n",
            "MAIL FROM:<alice@example.org>\r\n",
            "RCPT TO:<bob@gmail.com>\r\n",
            "DATA\r\n",
            "Subject: hi\r\n",
            "\r\n",
            "body\r\n",
            ".\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) = run_collect_with_auth(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(out.contains("235 2.7.0"), "认证成功应答缺失：{out}");
        assert_eq!(
            accepted.len(),
            1,
            "认证后应能向外域投递（提交语义），实际：{out}"
        );
        assert_eq!(accepted[0].recipients, vec!["bob@gmail.com".to_string()]);

        let requests = auth.requests();
        assert_eq!(requests.len(), 1, "只应校验一次");
        assert_eq!(requests[0].mechanism, "PLAIN");
        assert!(requests[0].secured, "TLS 之上必须如实声明 secured");

        assert_eq!(requests[0].response, "AGFsaWNlQGV4YW1wbGUub3JnAHNlY3JldA==");
    }

    #[tokio::test]
    async fn a_bare_auth_gets_a_challenge_and_the_next_line_is_taken_as_the_response() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::Success {
            user: "alice".to_string(),
        });
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO client.test\r\n",
            "AUTH PLAIN\r\n",
            "AGFsaWNlAHNlY3JldA==\r\n",
            "QUIT\r\n"
        );
        let (out, _) = run_collect_with_auth(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(out.contains("334 "), "应先发空挑战：{out}");
        assert!(out.contains("235 2.7.0"), "应答行应被当作凭据：{out}");
        assert_eq!(auth.requests().len(), 1);
        assert_eq!(auth.requests()[0].response, "AGFsaWNlAHNlY3JldA==");
    }

    #[tokio::test]
    async fn a_sasl_response_that_is_not_base64_never_reaches_the_auth_backend() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::Success {
            user: "attacker".to_string(),
        });
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO client.test\r\n",
            "AUTH PLAIN\r\n",
            "AAAA\tresp=c3VwcGxpZWQ=\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) = run_collect_with_auth(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(out.contains("501 5.5.2"), "应回 501 语法错误：{out}");
        assert!(
            auth.requests().is_empty(),
            "非 base64 应答绝不能被转发到 auth socket"
        );
        assert!(accepted.is_empty());
        assert!(!out.contains("235 "), "不得因为拒绝而误判为认证成功：{out}");
    }

    #[tokio::test]
    async fn an_unreachable_auth_backend_yields_454_and_never_535() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::TemporaryFailure(
            "dovecot socket refused".to_string(),
        ));
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO client.test\r\n",
            "AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n",
            "QUIT\r\n"
        );
        let (out, _) = run_collect_with_auth(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(out.contains("454 4.7.0"), "{out}");
        assert!(!out.contains("535 "), "后端不可达不得说成凭据错：{out}");
    }

    #[tokio::test]
    async fn a_rejected_credential_does_not_grant_relay() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::InvalidCredentials);
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO client.test\r\n",
            "AUTH PLAIN AGJhZABwYXNz\r\n",
            "MAIL FROM:<alice@example.org>\r\n",
            "RCPT TO:<bob@gmail.com>\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) = run_collect_with_auth(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(out.contains("535 5.7.8"), "{out}");
        assert!(out.contains("554 5.7.1"), "认证失败后仍不得中继：{out}");
        assert!(accepted.is_empty());
    }

    #[tokio::test]
    async fn repeated_auth_failures_are_counted_and_the_connection_is_dropped() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::InvalidCredentials);
        let sink = RecordingSink::default();

        let mut input = String::from("EHLO client.test\r\n");
        for _ in 0..MAX_CONSECUTIVE_AUTH_FAILURES + 1 {
            input.push_str("AUTH PLAIN AGJhZABwYXNz\r\n");
        }
        input.push_str("MAIL FROM:<alice@example.org>\r\n");

        let (out, outcome) = run_collect_outcome(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert_eq!(
            outcome,
            ServeOutcome::ClosedAfterAuthFailures {
                failures: MAX_CONSECUTIVE_AUTH_FAILURES
            },
            "达到阈值后必须断开并把次数回传给监听层（供封禁表记账）"
        );

        let attempts = auth.requests().len();
        assert_eq!(
            attempts,
            MAX_CONSECUTIVE_AUTH_FAILURES as usize,
            "第 {} 次 AUTH 不该再打到认证后端",
            MAX_CONSECUTIVE_AUTH_FAILURES + 1
        );

        let after_first_auth = out
            .find("535 5.7.8")
            .map(|idx| &out[idx..])
            .unwrap_or_default();
        assert!(
            !after_first_auth.contains("250 MAIL") && !after_first_auth.contains("250 2"),
            "断开后不得再处理 MAIL FROM：{after_first_auth}"
        );
        assert!(
            !after_first_auth.contains("354 "),
            "不得进入 DATA：{after_first_auth}"
        );
        assert!(
            sink.accepted.lock().unwrap().is_empty(),
            "认证从未成功，不得有邮件被接受"
        );
    }

    #[tokio::test]
    async fn a_success_resets_the_consecutive_failure_count() {
        struct FlakyAuth {
            calls: Mutex<usize>,
        }
        impl Authenticator for FlakyAuth {
            fn authenticate<'a>(
                &'a self,
                request: AuthRequest,
            ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
                let n = {
                    let mut guard = self.calls.lock().unwrap();
                    *guard += 1;
                    *guard
                };
                Box::pin(async move {
                    let _ = request;
                    if n < MAX_CONSECUTIVE_AUTH_FAILURES as usize {
                        AuthOutcome::InvalidCredentials
                    } else {
                        AuthOutcome::Success {
                            user: "alice".to_string(),
                        }
                    }
                })
            }
        }

        let auth = FlakyAuth {
            calls: Mutex::new(0),
        };
        let sink = RecordingSink::default();
        let mut input = String::from("EHLO client.test\r\n");
        for _ in 0..MAX_CONSECUTIVE_AUTH_FAILURES - 1 {
            input.push_str("AUTH PLAIN AGJhZABwYXNz\r\n");
        }
        input.push_str("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\nQUIT\r\n");

        let (out, outcome) = run_collect_outcome(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(
            matches!(outcome, ServeOutcome::Closed),
            "成功认证后不得再因之前的失败而断开，实际 {outcome:?}"
        );
        assert!(out.contains("235"), "最后一次 AUTH 应当成功：{out}");
    }

    #[tokio::test]
    async fn a_temporary_backend_failure_does_not_accumulate() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::TemporaryFailure(
            "dovecot socket refused".to_string(),
        ));
        let sink = RecordingSink::default();
        let mut input = String::from("EHLO client.test\r\n");
        for _ in 0..MAX_CONSECUTIVE_AUTH_FAILURES + 2 {
            input.push_str("AUTH PLAIN AGJhZABwYXNz\r\n");
        }
        input.push_str("QUIT\r\n");

        let (out, outcome) = run_collect_outcome(
            input.as_bytes(),
            limits(),
            submission_config(),
            &sink,
            &auth,
        )
        .await;

        assert!(
            matches!(outcome, ServeOutcome::Closed),
            "454 不应累计成断开（否则后端抖动会误伤正常用户），实际 {outcome:?}"
        );
        assert!(out.contains("454"), "{out}");
        assert_eq!(
            auth.requests().len(),
            MAX_CONSECUTIVE_AUTH_FAILURES as usize + 2
        );
    }

    struct OnlyAlice;

    impl RecipientChecker for OnlyAlice {
        fn exists(&self, address: &str) -> Result<bool, String> {
            Ok(address == "alice@example.org")
        }
    }

    struct BrokenDirectory;

    impl RecipientChecker for BrokenDirectory {
        fn exists(&self, _address: &str) -> Result<bool, String> {
            Err("registry is unreadable".to_string())
        }
    }

    async fn run_collect_with_directory<D: RecipientChecker>(
        input: &[u8],
        config: SessionConfig,
        sink: &RecordingSink,
        directory: &D,
    ) -> (String, Vec<AcceptedMessage>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut session =
            Session::with_recipients(config, RelayPolicy::new(["example.org"]), directory);
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();

        let client_task = async {
            client.write_all(input).await.unwrap();
            client.shutdown().await.unwrap();
            let mut out = String::new();
            client.read_to_string(&mut out).await.unwrap();
            out
        };
        let (out, served) = tokio::join!(
            client_task,
            serve(
                server,
                &mut session,
                sink,
                &UnavailableAuthenticator,
                peer,
                limits()
            )
        );
        served.expect("会话驱动不应返回 I/O 错误");
        (out, sink.accepted.lock().unwrap().clone())
    }

    #[tokio::test]
    async fn an_unknown_local_recipient_is_refused_and_never_reaches_the_sink() {
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO c.test\r\n",
            "MAIL FROM:<victim@third.com>\r\n",
            "RCPT TO:<nobody@example.org>\r\n",
            "DATA\r\n",
            "Subject: t\r\n\r\nbody\r\n.\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) =
            run_collect_with_directory(input.as_bytes(), session_config(), &sink, &OnlyAlice).await;

        assert!(
            out.contains("550 5.1.1"),
            "不存在的本域收件人必须 550：{out}"
        );
        assert!(
            accepted.is_empty(),
            "被拒的收件人绝不能进 MessageSink：{out}"
        );

        assert!(out.contains("221 "), "QUIT 必须被处理：{out}");
    }

    #[tokio::test]
    async fn a_known_local_recipient_still_reaches_the_sink() {
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO c.test\r\n",
            "MAIL FROM:<a@remote.test>\r\n",
            "RCPT TO:<alice@example.org>\r\n",
            "DATA\r\n",
            "body\r\n.\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) =
            run_collect_with_directory(input.as_bytes(), session_config(), &sink, &OnlyAlice).await;

        assert!(out.contains("250 2.1.5"), "{out}");
        assert_eq!(accepted.len(), 1, "真实收件人必须被接受：{out}");
        assert_eq!(
            accepted[0].recipients,
            vec!["alice@example.org".to_string()]
        );
    }

    #[tokio::test]
    async fn an_unavailable_directory_does_not_reject_a_real_message() {
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO c.test\r\n",
            "MAIL FROM:<a@remote.test>\r\n",
            "RCPT TO:<alice@example.org>\r\n",
            "DATA\r\n",
            "body\r\n.\r\n",
            "QUIT\r\n"
        );
        let (out, accepted) =
            run_collect_with_directory(input.as_bytes(), session_config(), &sink, &BrokenDirectory)
                .await;

        assert!(!out.contains("550 5.1.1"), "查不了时不得误拒真邮件：{out}");
        assert_eq!(
            accepted.len(),
            1,
            "查不了时应保持现状（只判域），邮件继续投递：{out}"
        );
    }

    #[tokio::test]
    async fn a_remote_recipient_is_unaffected_by_the_local_directory() {
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO c.test\r\n",
            "MAIL FROM:<a@remote.test>\r\n",
            "RCPT TO:<bob@gmail.com>\r\n",
            "QUIT\r\n"
        );
        let (out, _) =
            run_collect_with_directory(input.as_bytes(), session_config(), &sink, &OnlyAlice).await;

        assert!(
            out.contains("554 5.7.1"),
            "未认证的外域必须仍按反中继拒：{out}"
        );
        assert!(
            !out.contains("550 5.1.1"),
            "外域收件人不得走本地名录判定：{out}"
        );
    }

    #[test]
    fn the_data_memory_budget_is_byte_based_and_released_on_drop() {
        assert!(
            DataSlot::acquire(usize::MAX / 2).is_none(),
            "超过总预算的 DATA 必须被 451 背压拒绝"
        );

        {
            let first = DataSlot::acquire(1024).expect("预算内应放行");
            let second = DataSlot::acquire(2048).expect("预算内应放行");
            drop(first);
            drop(second);
        }

        assert!(
            DataSlot::acquire(4096).is_some(),
            "DATA 结束后必须归还字节额度"
        );
    }
}
