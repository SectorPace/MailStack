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

/// 同一连接内允许的**连续**认证失败次数，超过即断开。
///
/// ## 为什么必须有这个上限
///
/// RFC 4954 允许客户端在一条连接上重试 `AUTH`，但**没有规定次数上限**。
/// 原实现对认证失败只打日志、不计数、不封禁，于是同一条连接可以无限次重发
/// `AUTH PLAIN`，每次都真的打到 Dovecot auth socket —— 一次成功的爆破可以
/// 持续整条 TCP 连接的时长（提交端口的空闲超时是分钟级）。
///
/// 与封禁表的关系：这里是**每连接**的止损（让爆破必须重新建连、重新过准入），
/// [`BanList`](crate::ban::BanList) 是**跨连接**的封禁（真正的惩罚）。两者都要有：
/// 只有前者则换个 IP 即可重来；只有后者则连接内的重试完全免费。
pub const MAX_CONSECUTIVE_AUTH_FAILURES: u32 = 5;

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
    /// 会话期间发生了**这么多次**认证失败（凭据错，不是后端不可用）。
    ///
    /// ## 为什么把它带回监听层
    ///
    /// 封禁表（[`BanList`](crate::ban::BanList)）归监听层所有，`drive` 拿不到它。
    /// 而认证失败必须计入封禁 —— 否则提交端口（465/587）上同一条连接可以
    /// 无限次重发 `AUTH`，每次都真打到 Dovecot auth socket，而
    /// 「替代 fail2ban」的那套封禁表**对爆破完全失明**（限速只按连接数计数，
    /// 认证尝试不消耗任何配额）。
    ///
    /// 只回传**计数**而不是「要不要封禁」：阈值与封禁时长是监听层的策略，
    /// 会话驱动不该知道全局策略。
    ClosedAfterAuthFailures {
        /// 连续的凭据错误次数。
        failures: u32,
    },
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

/// STARTTLS 升级完成后重新进入会话。
///
/// **不**再发送 220 问候：客户端在连接建立时已经收到过一次，RFC 3207 规定升级后
/// 由客户端首先发 EHLO。若这里再问一次，客户端会把它当成对 EHLO 的应答而错位。
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
    // 连续凭据错误次数。`InvalidCredentials` 才 +1；`TemporaryFailure`（后端挂了）
    // 不算 —— 否则 Dovecot 一抖动就把正常用户全封了。
    let mut auth_failures: u32 = 0;

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
                        // 成功即清零：限流要罚的是**连续**爆破，不是累计次数。
                        auth_failures = 0;
                    }
                    AuthOutcome::TemporaryFailure(reason) => {
                        // 只记原因，不记凭据 —— 这是排查「Dovecot 挂了」与
                        // 「用户口令错」的唯一区分点。
                        tracing::warn!(peer = %peer, reason = %reason, "认证后端暂时不可用");
                    }
                    AuthOutcome::InvalidCredentials => {
                        // 原来这里只打日志就放过 —— 于是同一条连接可以无限次重发
                        // `AUTH`，每次都真的打到后端，封禁表完全不知情。
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

                // 达阈值就断开：连接留着等于给了爆破一个**零成本**的无限重试通道。
                // 阈值用会话侧的常量（见 `MAX_CONSECUTIVE_AUTH_FAILURES`），封禁
                // 仍由监听层的表决定。
                if auth_failures >= MAX_CONSECUTIVE_AUTH_FAILURES {
                    return Ok(ServeOutcome::ClosedAfterAuthFailures {
                        failures: auth_failures,
                    });
                }
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
    use crate::session::{RecipientChecker, SessionConfig};

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

    /// 同 [`run_collect_with_auth`]，但把 [`ServeOutcome`] 也带回来。
    ///
    /// 需要它来断言「认证失败达阈值后**主动断开**」—— 那条信息只出现在
    /// 返回值里，光看输出文本无法区分「回 535 后继续」与「回 535 后断开」。
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

    /// 反例守卫：同一条连接上的**重复**认证失败必须被计数并在阈值处断开。
    ///
    /// ## 为什么原测试全都漏了它
    ///
    /// 原有的认证测试每条只发**一次** `AUTH`（失败或成功），所以它们完全
    /// 看不到「连续多次」这条路径 —— 而这正是爆破的形态。RFC 4954 允许
    /// 在一条连接上重试 `AUTH` 且不规定次数上限，原实现也不计数、不封禁、
    /// 不断开，于是同一条连接可以无限次重发、每次都真的打到 Dovecot auth socket。
    ///
    /// 断言两件事：返回值的 `failures`（供监听层记账）与**确实断开**
    /// （后面几条命令不得有应答）。
    #[tokio::test]
    async fn repeated_auth_failures_are_counted_and_the_connection_is_dropped() {
        let auth = RecordingAuth::with_outcome(AuthOutcome::InvalidCredentials);
        let sink = RecordingSink::default();
        // 连发 6 次 AUTH：阈值是 5，第 6 次根本不该被处理。
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
        // 断开后不得再处理任何命令。注意 `250-` 是 EHLO 的能力行（正常），
        // 所以要看**最后一次 AUTH 之后**有没有出现收尾应答 `250 `（带空格）
        // 或 `250 MAIL`——那些都说明连接还活着。
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

    /// 反例守卫：**一次成功就把连续失败计数清零**。
    ///
    /// 要罚的是**连续**爆破，不是累计次数。否则一个每次都换错口令的用户
    /// （比如口误的老手）会在第 N 次被误断开，而真正的爆破在成功那一刻就已结束。
    #[tokio::test]
    async fn a_success_resets_the_consecutive_failure_count() {
        // 前 4 次失败、第 5 次成功 —— 不应触发断开。
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

    /// 反例守卫：后端**临时不可用**不得计入连续失败。
    ///
    /// 否则 Dovecot 一抖动，正在提交邮件的正常用户会在 5 次 454 之后被断开。
    /// 凭据错（535）与后端不可用（454）的区分正是这一条要守的东西。
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

    // ────────────── 本地收件人存在性：从 RCPT 到 MessageSink 的端到端 ──────────────

    /// 只放行一个地址的假名录；其余一律「确认不存在」。
    struct OnlyAlice;

    impl RecipientChecker for OnlyAlice {
        fn exists(&self, address: &str) -> Result<bool, String> {
            Ok(address == "alice@example.org")
        }
    }

    /// 名录后端不可用。
    struct BrokenDirectory;

    impl RecipientChecker for BrokenDirectory {
        fn exists(&self, _address: &str) -> Result<bool, String> {
            Err("registry is unreadable".to_string())
        }
    }

    /// 跑一次带名录的会话。
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

    /// 反例守卫：**不存在的本域收件人不得进 `MessageSink`**。
    ///
    /// 这是任务里点名的两条之一。只断言 550 是不够的 —— 拒了但邮件仍被
    /// 交给投递方，等于什么都没做（还会产生 backscatter）。
    #[tokio::test]
    async fn an_unknown_local_recipient_is_refused_and_never_reaches_the_sink() {
        let sink = RecordingSink::default();
        let input = concat!(
            "EHLO c.test\r\n",
            // 伪造第三方发件人 + 不存在的本域收件人 = 典型 backscatter 组合。
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
        // 会话没有错位：QUIT 仍被处理。
        assert!(out.contains("221 "), "QUIT 必须被处理：{out}");
    }

    /// 回归守卫：名录里的收件人照旧一路走到 sink。
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

    /// 反例守卫：名录不可用时**不得**误拒 —— 邮件必须继续走到 sink。
    ///
    /// 若「查不了」被当成「不存在」，磁盘一抖就会全站拒收真邮件。
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

    /// 远程域**不得**因为挂了名录就被拒 —— 反中继与提交语义不受影响。
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
}
