//! 会话驱动：把字节流接到 [`Session`] 上（规格书 §5.10）。
//!
//! ## 只有一个输入缓冲
//!
//! 命令阶段与 DATA 阶段**共用**同一个缓冲，且缓冲里始终是「尚未消费的字节」。
//! 这不是实现细节而是正确性要求：客户端可以把正文与后续命令**流水线**在同一个
//! TCP 段里发出来，若命令读取器与 [`DataSink`] 各自持有一份缓冲，必然有一方读到
//! 另一方的字节。`DataSink::feed` 返回「已消费多少字节」正是为此。
//!
//! ## 命令阶段也拒绝裸 LF
//!
//! 与 DATA 阶段用**同一条策略**（[`crate::data::BareNewlinePolicy`]）。命令阶段的
//! 边界歧义同样可以被利用：上游按裸 LF 切、本机不切，两边对「哪一段是命令」理解
//! 不一致。默认 `Reject` —— 遇到裸 LF 就回 500 并**断开**，因为此时双方对边界的
//! 认知已经分叉，继续解析是在拿对方的理解当自己的。

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

/// 命令行的原始缓冲上限（含未结束的行）。
///
/// 解析器自己还有 512 的上限；这个更宽松的上限用来兜住「永远不发 CRLF」的行，
/// 否则我们会在解析之前就把内存吃光。
pub const MAX_COMMAND_BUFFER: usize = 2048;

/// 驱动限制。
#[derive(Debug, Clone)]
pub struct ServerLimits {
    /// 等待下一条命令的时长（RFC 5321 §4.5.3.2）。
    pub command_timeout: Duration,
    /// 等待 DATA 正文的时长（RFC 5321 建议 10 分钟）。
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

/// 投递失败时返回给对端的应答。
pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Reply>> + Send + 'a>>;

/// 收下一封邮件的去处。
///
/// 实现者负责「真正接管这封邮件」：跑入站认证、写入队列。**只有**返回 `Ok(())`
/// 之后驱动才会回 250 —— 先答 250 再落盘，等于对发送方说谎。
pub trait MessageSink: Send + Sync {
    fn accept<'a>(&'a self, message: AcceptedMessage, peer: SocketAddr) -> SinkFuture<'a>;
}

/// 把一条已渲染的应答写出去。
pub(crate) async fn write_reply<S>(stream: &mut S, reply: &Reply) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(reply.render().as_bytes()).await?;
    stream.flush().await
}

/// 一次 `serve` 调用的结束原因。
///
/// 监听层据此决定「关掉连接」还是「就地升级到 TLS 后重新进入会话」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeOutcome {
    /// 会话正常结束（QUIT、对端断开、超时或协议违规断开）。
    Closed,
    /// 对端要求 STARTTLS；**明文读缓冲已在返回前丢弃**，
    /// 调用方应完成 TLS 握手后以 [`serve_after_upgrade`] 重新进入。
    StartTls,
}

/// 取出一行（不含行结束符）以及「已消费到哪」。
enum LineOutcome {
    /// 拿到的行 + 该行在缓冲中占用的字节数（含行结束符）。
    Line(Vec<u8>, usize),
    NeedMore,
    /// 裸 LF（`Reject` 策略）。
    BareLineFeed,
    TooLong,
}

fn next_line(buffer: &[u8], policy: BareNewlinePolicy) -> LineOutcome {
    for (index, &byte) in buffer.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }
        let has_cr = index > 0 && buffer[index - 1] == b'\r';
        // 裸 LF：默认拒绝（见模块说明），归一化策略下当作行结束符接受。
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

/// 驱动一次会话直到连接结束（发送 220 问候）。
///
/// `stream` 可以是任何字节流：生产里是 TCP（或 TLS），测试里是
/// `tokio::io::duplex`。`session` 以可变引用传入，是为了让调用方在
/// STARTTLS 握手成功后调用 [`Session::activate_tls`] 并重新进入。
///
/// `auth` 是 SASL 认证后端（见 [`crate::sasl`]）：只有驱动做 I/O，状态机只收结果。
pub async fn serve<S, K, A>(
    stream: S,
    session: &mut Session,
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

/// STARTTLS 升级完成后重新进入会话。
///
/// **不**再发送 220 问候：客户端在连接建立时已经收到过一次，RFC 3207 规定升级后
/// 由客户端首先发 EHLO。若这里再问一次，客户端会把它当成对 EHLO 的应答而错位。
pub async fn serve_after_upgrade<S, K, A>(
    stream: S,
    session: &mut Session,
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
    session: &mut Session,
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

    if greet {
        write_reply(&mut stream, &session.greeting()).await?;
    }

    loop {
        // ── 取一条命令行 ──
        let line = loop {
            match next_line(&buffer, policy) {
                LineOutcome::Line(line, consumed) => {
                    buffer.drain(..consumed);
                    break Some(line);
                }
                LineOutcome::BareLineFeed => {
                    // 双方对命令边界的认知已经分叉，不能继续解析。
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
                            Ok(Ok(0)) => return Ok(ServeOutcome::Closed), // 对端正常关闭
                            Ok(Ok(read)) => read,
                            Ok(Err(error)) => return Err(error),
                            // 超时：安静地关掉，不猜对方想干什么。
                            Err(_) => return Ok(ServeOutcome::Closed),
                        };
                    buffer.extend_from_slice(&chunk[..read]);
                }
            }
        };

        let Some(line) = line else {
            return Ok(ServeOutcome::Closed);
        };

        // ── 解析并处理 ──
        //
        // SASL 交换进行中时，这一行是**凭据应答**（base64），不是命令：把它交给
        // 命令解析器只会得到一个 "Unknown" 动词。这是会话层与驱动之间唯一的
        // 「原始行」通道，由 `awaiting_auth_response()` 显式标出。
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
                // 明文读缓冲在此**随函数返回被丢弃**：升级前注入的字节绝不能
                // 带进 TLS 之后的会话。这不是疏漏，是刻意的确定性行为。
                return Ok(ServeOutcome::StartTls);
            }
            Action::AuthChallenge(reply) => {
                // 空挑战（PLAIN）。下一轮循环读到的行由 `continue_auth` 消费。
                write_reply(&mut stream, &reply).await?;
            }
            Action::AuthVerify {
                mechanism,
                response,
            } => {
                // 凭据校验要 I/O，只有驱动能做；状态机拿结果（`complete_auth`）并
                // 决定最终应答。口令只在这两个值之间传递，绝不写日志。
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
                    }
                    AuthOutcome::TemporaryFailure(reason) => {
                        // 只记原因，不记凭据 —— 这是排查「Dovecot 挂了」与
                        // 「用户口令错」的唯一区分点。
                        tracing::warn!(peer = %peer, reason = %reason, "认证后端暂时不可用");
                    }
                    AuthOutcome::InvalidCredentials => {
                        tracing::info!(peer = %peer, "提交认证失败");
                    }
                }
                let reply = session.complete_auth(outcome);
                write_reply(&mut stream, &reply).await?;
            }
            Action::EnterData(reply) => {
                write_reply(&mut stream, &reply).await?;
                match collect_data(&mut stream, &mut buffer, session, &limits).await? {
                    DataOutcome::Closed => return Ok(ServeOutcome::Closed),
                    DataOutcome::Rejected(reply) => {
                        write_reply(&mut stream, &reply).await?;
                        // 裸 LF：边界认知已分叉，断开而不是继续。
                        return Ok(ServeOutcome::Closed);
                    }
                    // 552 已经在收集过程中发过了（那时才知道超限），这里不再重复。
                    DataOutcome::Discarded => {}
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
    /// 报文收完并保留。
    Received(Vec<u8>),
    /// 因超限被丢弃；552 已在收集过程中发给对端（那时才知道超限）。
    Discarded,
    /// 必须断开（裸 LF）。
    Rejected(Reply),
    /// 对端提前关闭。
    Closed,
}

/// 收一封正文，直到结束标记。
///
/// 超限时**先回 552、再继续读到结束标记**。少了后半步，客户端剩下的正文会被当成
/// 命令解析 —— 一条正常的 `MAIL` 就可能被当成对超限的回应，整个会话错位。
async fn collect_data<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    session: &mut Session,
    limits: &ServerLimits,
) -> std::io::Result<DataOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let config = session.config().clone();
    let mut sink = DataSink::new(config.max_message_size, config.bare_newline_policy);
    let mut told_too_large = false;

    loop {
        // 先把缓冲里已有的字节喂进去（流水线场景）。
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
                    // 缓冲里可能还有后续字节（正文剩余 + 下一条命令）。这里必须回头
                    // 继续消化，而不能往下走去 read：对端可能已经半关闭，read 会立刻
                    // 返回 0，那批缓冲字节就被当成「对端断线」丢掉了。
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
    use crate::session::SessionConfig;

    /// 记录收到的邮件，并可被要求拒绝。
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

    /// 跑一次会话：把 `input` 当客户端发的东西，返回客户端读到的全部文本。
    ///
    /// 客户端与服务端用 `join!` 并发跑在同一条任务上 —— 写成「先写完再读」会在
    /// 任何一方填满管道时死锁，而这正是这类测试最容易假绿的地方。
    async fn run_collect_with(
        input: &[u8],
        limits: ServerLimits,
        config: SessionConfig,
        sink: &RecordingSink,
    ) -> (String, Vec<AcceptedMessage>) {
        run_collect_with_auth(input, limits, config, sink, &UnavailableAuthenticator).await
    }

    /// 同上，但可以注入一个认证后端。
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
            // 半关闭：让驱动看到 EOF，但读侧仍然可用。
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

    /// 记录认证请求并回一个可配置的结果。
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

    /// 提交端口上的会话配置：已在 TLS 之上且通告 AUTH。
    ///
    /// 用 `tls_active: true` 直接表达「隐式 TLS 已经握手完成」—— 这里的重点不是
    /// 握手本身（那有独立测试），而是认证之后的事务行为。
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
        // 先答 250 再落盘等于对发送方说谎：一旦落盘失败，邮件就凭空消失了。
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
        // 客户端可以把整段会话一次性发出来；驱动必须在同一个缓冲里按序消费。
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
        // 正文的结束标记与下一条命令在同一个 TCP 段里 —— 这在真实网络下很常见。
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
        // 超限时若丢掉正文读取器，剩下的正文会被当成命令解析 —— 会话直接错位。
        // 这条断言「超限之后的下一条命令仍然被正确执行」，正是那个缺陷的回归守卫。
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
        // 断线不是错误：安静收尾，不留下半开状态。
        let (out, accepted) = run_collect(b"EHLO c.test\r\n", limits()).await;
        assert!(accepted.is_empty());
        assert!(out.contains("250"), "{out}");
    }

    #[tokio::test]
    async fn starttls_returns_the_upgrade_outcome_and_discards_pipelined_plaintext() {
        // 攻击面：在 STARTTLS 之前把后续命令与 STARTTLS 流水线在同一段里发出来。
        // 若升级后仍保留明文读缓冲，那条「MAIL FROM」就会在 TLS 建立之后被当作
        // 加密会话里的命令执行 —— 攻击者借此把明文注入到加密会话中。
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
        // RFC 3207：升级后由客户端首发 EHLO，服务端不得再发 220。
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
        // 这一条把三件事串起来验：`AUTH` 被真正校验、状态机据结果置位、
        // 反中继（INV-17）随后放行外域收件人。少任何一环，587 就只是个空壳。
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
        // 原样转发：状态机不解析、不解码凭据（口令不进任何中间结构）。
        assert_eq!(requests[0].response, "AGFsaWNlQGV4YW1wbGUub3JnAHNlY3JldA==");
    }

    #[tokio::test]
    async fn a_bare_auth_gets_a_challenge_and_the_next_line_is_taken_as_the_response() {
        // 两段式交换：`AUTH PLAIN` → `334 ` → base64 单独一行。第二行绝不能
        // 走命令解析器，否则它会被当成一个未知动词。
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
        // 一行非 base64 的应答如果被转发，就会在 Dovecot 的制表符分隔协议行里
        // 凭空多出字段（TAB 注入）。必须在这里被拦下，且**后端一次都不能被调用**。
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
        // 454（临时不可用）与 535（凭据错）混同，会让客户端在 Dovecot 抖动时
        // 去改密码 —— 这正是要避免的运维事故。
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
        // 认证失败必须保持「未认证」，反中继随后仍拒绝外域收件人。
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
}
