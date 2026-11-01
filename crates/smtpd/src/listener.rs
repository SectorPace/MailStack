//! TCP 监听与连接生命周期（规格书 §5.10）。
//!
//! ## 一条连接上发生的事情，以及顺序为什么是这样
//!
//! ```text
//! accept ──► 连接数配额（Semaphore，满了直接关掉，不排队）
//!   │
//!   ├─► 封禁检查        ── 命中 → 421 + 断开（不计失败，因为没做任何事）
//!   ├─► 限速检查        ── 超速 → 421 + 断开 + **计入失败**（多次触发会升级为封禁）
//!   ├─► （隐式 TLS）握手 ── 失败 → 计入失败 + 断开
//!   ├─► 会话（明文 STARTTLS）
//!   │     └─ STARTTLS → 就地握手 ── 失败 → 计入失败 + 断开
//!   │                              └─ 成功 → 重新进入会话（不再发 220）
//!   └─► 会话 I/O 错误   ── 计入失败 + 断开
//! ```
//!
//! **顺序是刻意的**：封禁/限速在握手之前，因此被拦下的连接**不会**消耗一次 TLS
//! 握手（那正是攻击者想让我们花的 CPU）。而「封禁检查命中」不计入失败 —— 否则
//! 一个已经被封的 IP 会因为不断重连而把 `strike` 越滚越高。
//!
//! 整条连接还受**会话级总时限**（`SESSION_TOTAL_TIMEOUT`，15 分钟）约束：从
//! accept 起算，覆盖 STARTTLS 升级前后的两轮 `serve`，到点尽力回 `421 4.4.2`
//! 后断开。per-read 超时（`ServerLimits`）只约束**单次**读取，管不住每次都在
//! 超时前喂 1 字节的滴水客户端；会话级上限把「占住连接许可不放」这件事本身
//! 变成有时限的。
//!
//! ## 时间源是注入的
//!
//! [`Clock`] 让「限速窗口」与「封禁到期」这类行为的验证不需要 `sleep`。生产用
//! [`SystemClock`]，测试用固定时钟。

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mailstack_smtp::RelayPolicy;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::ban::{BanConfig, BanList};
use crate::connection::{
    serve, serve_after_upgrade, write_reply, MessageSink, ServeOutcome, ServerLimits,
};
use crate::ratelimit::{RateDecision, RateLimitConfig, RateLimiter};
use crate::reply::{texts, Reply};
use crate::sasl::{AuthBackend, Authenticator, UnavailableAuthenticator};
use crate::session::{RecipientChecker, Session, SessionConfig};
use crate::tls::{BoxedStream, TlsMode};

/// TLS 握手超时。IMAP 侧同为 15 秒；没有它，每个卡住的握手都会永久占用一个
/// 连接许可（`max_connections`），少量 IP 即可耗尽全部许可造成全端口拒绝服务。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// 会话级总时限：一条 TCP 连接从 accept 到关闭的最长占用时间。
///
/// 15 分钟 = 25 × `data_timeout`（600s）。对慢链路上的合法大报文投递足够宽裕
/// （DATA 阶段单次读超时是 10 分钟，整条会话的预算还有 25 倍于它的余量），同时
/// 给「滴水」客户端划上硬上界：per-read 超时只约束**单次** read 等了多久，一个
/// 每次都在超时前喂 1 字节的客户端可以把连接（连同它的连接许可）无限期占下去
/// —— 没有会话级上限，slowloris 式占位就没有终点。时钟从 accept 起算，覆盖
/// STARTTLS 升级前后的**两轮** `serve`；到点先尽力回 `421 4.4.2` 再断开。
const SESSION_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// 时间源。注入的目的是让时间相关行为可被确定性验证。
pub trait Clock: Send + Sync + 'static {
    /// 当前 Unix 毫秒。
    fn now_millis(&self) -> i64;
}

/// 生产用时钟。
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// 服务端配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 会话状态机配置（问候名、上限、裸 LF 策略等）。
    pub session: SessionConfig,
    /// 反中继策略（INV-17）。
    pub relay: RelayPolicy,
    /// 超时限制。
    pub limits: ServerLimits,
    /// 同时在处理的连接数上限。
    pub max_connections: usize,
    /// 连接限速参数。
    pub rate_limit: RateLimitConfig,
    /// 自动封禁参数。
    pub ban: BanConfig,
    /// 停机时等待在途会话收尾的时长。
    pub shutdown_grace: Duration,
    /// SASL 认证后端（§3.5）。**会话通告 AUTH 时它必须存在**，由构造期校验 ——
    /// 通告了却做不到会让客户端白跑一次认证。
    pub auth: Option<AuthBackend>,
    /// 本地收件人名录（`RCPT` 阶段的存在性判定）。
    ///
    /// `None` 表示**不查**（只判域）—— 与引入该判定之前的行为一致。刻意做成
    /// `Option` 而不是默认实现：生产装配（`mailstackd`）必须显式提供名录，
    /// 「忘了配」与「有意不查」因此在代码里是两件可分辨的事。
    pub recipients: Option<Arc<dyn RecipientChecker>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            relay: RelayPolicy::new(Vec::<String>::new()),
            limits: ServerLimits::default(),
            max_connections: 512,
            rate_limit: RateLimitConfig::default(),
            ban: BanConfig::default(),
            shutdown_grace: Duration::from_secs(10),
            auth: None,
            recipients: None,
        }
    }
}

/// 构造期的配置错误。
///
/// 这些错误都指向同一类问题：**配置让服务端声称自己能做一件它其实做不到的事**。
/// 与其在运行时静默降级（例如通告了 STARTTLS 却无法握手），不如在启动时就拒绝。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("隐式 TLS 需要提供 TlsAcceptor")]
    ImplicitTlsWithoutAcceptor,
    #[error("会话通告了 STARTTLS 但未提供 TlsAcceptor")]
    StartTlsAdvertisedWithoutAcceptor,
    #[error("隐式 TLS 与 STARTTLS 不能同时启用")]
    ImplicitTlsWithStartTls,
    #[error("会话通告了 AUTH 但未提供认证后端")]
    AuthAdvertisedWithoutAuthenticator,
}

/// 监听服务。
pub struct MailServer<S: MessageSink + ?Sized> {
    listener: TcpListener,
    config: ServerConfig,
    tls: Option<TlsAcceptor>,
    tls_mode: TlsMode,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,
    /// 与 `config.recipients` 同源，但单独持有一份以便在每条连接上借用。
    recipients: Option<Arc<dyn RecipientChecker>>,
    /// 会话级总时限。生产固定为 [`SESSION_TOTAL_TIMEOUT`]；可注入是为了让
    /// 同模块测试能在真实时钟下用秒级时限验证滴水防线（不依赖 test-util）。
    session_timeout: Duration,
}

impl<S: MessageSink + ?Sized + 'static> MailServer<S> {
    /// 构造服务端，并按 `config` 自建**独立**的限速器与封禁表。
    ///
    /// 只跑一个监听时用这个。**同时起多个监听（25/465/587）时必须用
    /// [`MailServer::with_shared`]** —— 否则每个端口一份配额，攻击者轮换端口即可
    /// 拿到成倍配额，且 `strike` 永远攒不满、永久封禁无从触发。
    pub fn new(
        listener: TcpListener,
        config: ServerConfig,
        tls: Option<TlsAcceptor>,
        tls_mode: TlsMode,
        sink: Arc<S>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ConfigError> {
        let rate = Arc::new(RateLimiter::new(config.rate_limit));
        let bans = Arc::new(BanList::new(config.ban));
        Self::with_shared(listener, config, tls, tls_mode, sink, clock, rate, bans)
    }

    /// 构造服务端，复用调用方提供的限速器与封禁表。
    ///
    /// 多个监听共用同一对 `Arc` 时，准入判定才是**按 IP 全局**生效的：限速配额只有
    /// 一份、`strike` 在端口之间累加、永久封禁对三个端口同时生效。
    #[allow(clippy::too_many_arguments)]
    pub fn with_shared(
        listener: TcpListener,
        config: ServerConfig,
        tls: Option<TlsAcceptor>,
        tls_mode: TlsMode,
        sink: Arc<S>,
        clock: Arc<dyn Clock>,
        rate: Arc<RateLimiter>,
        bans: Arc<BanList>,
    ) -> Result<Self, ConfigError> {
        validate(&config, tls.as_ref(), tls_mode)?;
        let recipients = config.recipients.clone();
        Ok(Self {
            listener,
            config,
            tls,
            tls_mode,
            sink,
            clock,
            rate,
            bans,
            recipients,
            session_timeout: SESSION_TOTAL_TIMEOUT,
        })
    }

    /// 实际监听的地址（端口为 0 时用于测试取回真实端口）。
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate
    }

    pub fn ban_list(&self) -> &Arc<BanList> {
        &self.bans
    }

    /// 接受连接直到 `shutdown` 完成；随后给在途会话一个上限时间收尾。
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> std::io::Result<()> {
        let MailServer {
            listener,
            config,
            tls,
            tls_mode,
            sink,
            clock,
            rate,
            bans,
            recipients,
            session_timeout,
        } = self;

        let semaphore = Arc::new(Semaphore::new(config.max_connections.max(1)));
        let grace = config.shutdown_grace;
        let mut shutdown = std::pin::pin!(shutdown);
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("收到停机信号，停止接受新连接");
                    break;
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, peer)) => {
                            // 连接数配额：满了就**直接关掉**而不是排队。
                            // 排队会让内存随攻击者的连接数增长，而拒绝对端立刻可重试。
                            let permit = match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    tracing::warn!(peer = %peer, "连接数已达上限，拒绝新连接");
                                    drop(stream);
                                    continue;
                                }
                            };
                            let context = ConnectionContext {
                                config: config.clone(),
                                tls: tls.clone(),
                                tls_mode,
                                sink: Arc::clone(&sink),
                                clock: Arc::clone(&clock),
                                rate: Arc::clone(&rate),
                                bans: Arc::clone(&bans),
                                recipients: recipients.clone(),
                                session_timeout,
                            };
                            tasks.spawn(async move {
                                let _permit = permit;
                                context.handle(stream, peer).await;
                            });
                        }
                        Err(error) => {
                            // 瞬时错误（如 EMFILE）不应让整个服务退出。
                            tracing::warn!(error = %error, "accept 失败");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }

        let drained =
            tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
        if drained.is_err() {
            tracing::warn!("在途会话未在宽限期内结束，强制中止");
            tasks.shutdown().await;
        }
        Ok(())
    }
}

/// 构造期的配置一致性校验。
///
/// 四条判定的共同点：**配置让服务端声称自己能做到一件它其实做不到的事**。与其在
/// 运行时静默降级（例如通告了 STARTTLS 却无法握手、通告了 AUTH 却没有后端），
/// 不如在启动时就拒绝。
fn validate(
    config: &ServerConfig,
    tls: Option<&TlsAcceptor>,
    tls_mode: TlsMode,
) -> Result<(), ConfigError> {
    if tls_mode == TlsMode::Implicit && tls.is_none() {
        return Err(ConfigError::ImplicitTlsWithoutAcceptor);
    }
    if tls_mode == TlsMode::Implicit && config.session.offer_starttls {
        return Err(ConfigError::ImplicitTlsWithStartTls);
    }
    if config.session.offer_starttls && tls.is_none() {
        return Err(ConfigError::StartTlsAdvertisedWithoutAcceptor);
    }
    // 通告 AUTH 却没有后端 = 每次认证都必然 454；那是在骗客户端，不只是不好用。
    if config.session.offer_auth && config.auth.is_none() {
        return Err(ConfigError::AuthAdvertisedWithoutAuthenticator);
    }
    Ok(())
}

/// 每条连接处理所需的共享上下文。
struct ConnectionContext<S: MessageSink + ?Sized> {
    config: ServerConfig,
    tls: Option<TlsAcceptor>,
    tls_mode: TlsMode,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,
    recipients: Option<Arc<dyn RecipientChecker>>,
    /// 会话级总时限（自 `MailServer.session_timeout` 注入；生产为 15 分钟）。
    session_timeout: Duration,
}

impl<S: MessageSink + ?Sized> ConnectionContext<S> {
    async fn handle(&self, mut stream: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();

        // ── 1) 准入：封禁 / 限速。判定与真实拒绝路径共用同一份实现 ──
        match admit(&self.rate, &self.bans, ip, self.clock.now_millis()) {
            AdmitVerdict::Allowed => {}
            AdmitVerdict::BannedPermanently => {
                let reply = Reply::with_enhanced(421, "4.7.0", texts::BANNED_PERMANENTLY);
                let _ = write_reply(&mut stream, &reply).await;
                return;
            }
            AdmitVerdict::BannedTemporarily => {
                let reply = Reply::with_enhanced(421, "4.7.0", texts::BANNED_TEMPORARILY);
                let _ = write_reply(&mut stream, &reply).await;
                return;
            }
            AdmitVerdict::RateLimited { retry_after_secs } => {
                let reply = Reply::with_enhanced(
                    421,
                    "4.7.0",
                    format!(
                        "{}; retry after {} seconds",
                        texts::RATE_LIMITED,
                        retry_after_secs
                    ),
                );
                let _ = write_reply(&mut stream, &reply).await;
                return;
            }
        }

        // ── 2) 隐式 TLS（465）：建连即握手 ──
        let mut session_config = self.config.session.clone();
        let mut stream: BoxedStream = match self.tls_mode {
            TlsMode::Implicit => {
                let acceptor = self
                    .tls
                    .as_ref()
                    .expect("隐式 TLS 已在构造时校验 acceptor 存在");
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(encrypted)) => Box::new(encrypted),
                    Ok(Err(error)) => {
                        tracing::warn!(peer = %peer, error = %error, "隐式 TLS 握手失败");
                        self.bans.record_failure(ip, self.clock.now_millis() / 1000);
                        return;
                    }
                    Err(_) => {
                        // 握手没有超时会永久占用一个连接许可（max_connections）：
                        // 对端收到 TCP 后不发 ClientHello，少量 IP 就能耗尽全部
                        // 许可，把所有启用 TLS 的端口拖成全端口拒绝服务。
                        tracing::warn!(
                            peer = %peer,
                            timeout_secs = TLS_HANDSHAKE_TIMEOUT.as_secs(),
                            "TLS 握手超时"
                        );
                        self.bans.record_failure(ip, self.clock.now_millis() / 1000);
                        return;
                    }
                }
            }
            TlsMode::StartTls => Box::new(stream),
        };
        session_config.tls_active = self.tls_mode == TlsMode::Implicit;
        let mut session = Session::with_recipients(
            session_config,
            self.config.relay.clone(),
            self.recipients
                .as_deref()
                .unwrap_or(&crate::session::AnyRecipient),
        );
        let mut upgraded = false;

        // 没有后端时用占位实现：此时会话不会通告 AUTH（构造期已校验），
        // 因此它实际不会被调用；真被调用说明配置被绕过，按临时错误处理。
        let auth: &dyn Authenticator = match self.config.auth.as_ref() {
            Some(backend) => backend.as_dyn(),
            None => &UnavailableAuthenticator,
        };

        // ── 4) 会话（可能因 STARTTLS 重入一次）──
        //
        // 会话级总时限：deadline 是在 accept 时取定的**绝对时刻**，两轮 `serve` 与
        // STARTTLS 握手的每个 await 都受**同一个** deadline 约束 —— 若每轮 serve
        // 各自起算，升级重入会把占位时限重置回满额，滴水客户端就能无限期续命。
        // 到点先尽力回 `421 4.4.2` 再断开：连接随即关闭，连接许可随之释放。
        //
        // 用 `timeout_at(deadline, …)` 包每个 await 点而不是把整个循环包进一个
        // `timeout`：STARTTLS 分支要把明文流 move 进握手，整体包装会迫使循环体
        // 按值捕获 `stream` —— 超时弃掉 future 时流会被一并丢弃，421 就无处可写。
        let deadline = tokio::time::Instant::now() + self.session_timeout;
        loop {
            let served = if upgraded {
                tokio::time::timeout_at(
                    deadline,
                    serve_after_upgrade(
                        &mut stream,
                        &mut session,
                        &*self.sink,
                        auth,
                        peer,
                        self.config.limits.clone(),
                    ),
                )
                .await
            } else {
                tokio::time::timeout_at(
                    deadline,
                    serve(
                        &mut stream,
                        &mut session,
                        &*self.sink,
                        auth,
                        peer,
                        self.config.limits.clone(),
                    ),
                )
                .await
            };

            let outcome = match served {
                Ok(outcome) => outcome,
                Err(_) => {
                    session_deadline_elapsed(&mut stream, peer, self.session_timeout).await;
                    return;
                }
            };

            match outcome {
                Ok(ServeOutcome::Closed) => return,
                Ok(ServeOutcome::ClosedAfterAuthFailures { failures }) => {
                    // 认证失败必须进封禁表。这是本项目自称「替代 fail2ban」的那套
                    // 机制最该管的场景，而原实现的 `record_failure` 只出现在
                    // TLS 握手失败 / I/O 错误 / 触发限速三处 —— 认证失败一条都没有，
                    // 于是提交端口上的口令爆破**永远不会被封**。
                    //
                    // 逐次记账（而不是只记一次）：阈值判定在封禁表里，
                    // 这里只负责把「又失败了一次」如实喂进去。
                    let now = self.clock.now_millis() / 1000;
                    let mut ban = None;
                    for _ in 0..failures.max(1) {
                        ban = self.bans.record_failure(ip, now);
                    }
                    match ban {
                        Some(ban) => tracing::warn!(
                            peer = %peer,
                            failures,
                            until = ban.until_unix,
                            permanent = ban.permanent,
                            "认证失败已达封禁阈值"
                        ),
                        None => tracing::warn!(
                            peer = %peer,
                            failures,
                            "认证失败已记账，尚未达到封禁阈值"
                        ),
                    }
                    return;
                }
                Ok(ServeOutcome::StartTls) => {
                    let Some(acceptor) = self.tls.as_ref() else {
                        // 状态机只在 offer_starttls 时回 StartTls，而构造期已保证
                        // offer_starttls ⇒ 有 acceptor。走到这里说明配置被绕过，
                        // 断开而不是继续明文会话。
                        tracing::error!(peer = %peer, "收到 STARTTLS 但没有可用的 TLS 配置");
                        return;
                    };
                    // 握手受「15s 握手超时」与「会话级总时限」中**先到**者的约束。
                    // 总时限先到时不写 421：TLS 协商进行到一半，明文应答只会是对端
                    // 解不了的噪声 —— 直接断开。
                    let next: BoxedStream = match tokio::time::timeout_at(
                        deadline,
                        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)),
                    )
                    .await
                    {
                        Ok(Ok(Ok(encrypted))) => Box::new(encrypted),
                        Ok(Ok(Err(error))) => {
                            tracing::warn!(peer = %peer, error = %error, "STARTTLS 握手失败");
                            self.bans.record_failure(ip, self.clock.now_millis() / 1000);
                            return;
                        }
                        Ok(Err(_)) => {
                            // 与隐式 TLS 同理：无超时的握手会永久占用连接许可。
                            tracing::warn!(
                                peer = %peer,
                                timeout_secs = TLS_HANDSHAKE_TIMEOUT.as_secs(),
                                "STARTTLS 握手超时"
                            );
                            self.bans.record_failure(ip, self.clock.now_millis() / 1000);
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(
                                peer = %peer,
                                timeout_secs = self.session_timeout.as_secs(),
                                "会话总时限在 STARTTLS 握手期间到点，关闭连接"
                            );
                            return;
                        }
                    };
                    stream = next;
                    session.activate_tls();
                    upgraded = true;
                }
                Err(error) => {
                    // 客户端主动断开（回程 RST / 半关）不是攻击行为：记进封禁表
                    // 只会惩罚 NAT 后的正常用户（默认 8 次/600 秒即封 1 小时），
                    // 还会用 TCP 重置噪音灌满封禁表。
                    let benign_disconnect = matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    );
                    if benign_disconnect {
                        return;
                    }
                    tracing::warn!(peer = %peer, error = %error, "会话 I/O 错误");
                    self.bans.record_failure(ip, self.clock.now_millis() / 1000);
                    return;
                }
            }
        }
    }
}

/// 会话总时限在 `serve` 期间到点：尽力发出 `421 4.4.2` 后由调用方断开。
///
/// 「尽力」：对端可能早已不在，写失败不改变「连接即将关闭」的结果。
async fn session_deadline_elapsed(stream: &mut BoxedStream, peer: SocketAddr, timeout: Duration) {
    tracing::warn!(
        peer = %peer,
        timeout_secs = timeout.as_secs(),
        "会话总时限已到，关闭连接"
    );
    let reply = Reply::with_enhanced(421, "4.4.2", texts::SESSION_TIMEOUT);
    let _ = write_reply(stream, &reply).await;
}

/// 连接准入判定：封禁优先于限速，限速触发即计入失败。
///
/// 抽成函数是为了让「准入」这条决策链**只有一份实现**，同时可以在不起真实 socket
/// 的情况下被穷举测试。
fn admit(
    rate: &RateLimiter,
    bans: &BanList,
    ip: std::net::IpAddr,
    now_millis: i64,
) -> AdmitVerdict {
    let now = now_millis / 1000;
    if let Some(ban) = bans.check(ip, now) {
        return if ban.permanent {
            AdmitVerdict::BannedPermanently
        } else {
            AdmitVerdict::BannedTemporarily
        };
    }
    match rate.check(ip, now_millis) {
        RateDecision::Allowed => AdmitVerdict::Allowed,
        RateDecision::Limited { retry_after_secs } => {
            // 与真实路径一致：触发限速即计入失败。
            bans.record_failure(ip, now);
            AdmitVerdict::RateLimited { retry_after_secs }
        }
    }
}

/// [`admit`] 的判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmitVerdict {
    Allowed,
    RateLimited { retry_after_secs: u64 },
    BannedTemporarily,
    BannedPermanently,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ban::BanConfig;
    use crate::ratelimit::RateLimitConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
    }

    #[test]
    fn an_over_rate_ip_is_admitted_then_limited_and_counted_as_a_failure() {
        let rate = RateLimiter::new(RateLimitConfig {
            burst: 2,
            refill_per_second: 1.0,
            max_entries: 100,
        });
        let bans = BanList::new(BanConfig {
            max_failures: 2,
            window_secs: 60,
            temp_ban_secs: 300,
            permanent_after: 0,
            max_entries: 100,
        });

        assert_eq!(admit(&rate, &bans, ip(), 0), AdmitVerdict::Allowed);
        assert_eq!(admit(&rate, &bans, ip(), 0), AdmitVerdict::Allowed);
        // 第三次超速：计入一次失败。
        assert!(matches!(
            admit(&rate, &bans, ip(), 0),
            AdmitVerdict::RateLimited { .. }
        ));
        // 再超速一次 → 失败达到阈值 → 封禁。
        assert!(matches!(
            admit(&rate, &bans, ip(), 0),
            AdmitVerdict::RateLimited { .. }
        ));
        assert_eq!(
            admit(&rate, &bans, ip(), 0),
            AdmitVerdict::BannedTemporarily,
            "连续触发限速必须升级为封禁"
        );
    }

    #[test]
    fn a_banned_ip_is_not_re_counted_while_banned() {
        let rate = RateLimiter::new(RateLimitConfig::default());
        let bans = BanList::new(BanConfig {
            max_failures: 1,
            window_secs: 60,
            temp_ban_secs: 300,
            permanent_after: 2,
            max_entries: 100,
        });
        // 一次失败即封禁（阈值 1）。
        bans.record_failure(ip(), 0);
        for _ in 0..10 {
            assert_eq!(
                admit(&rate, &bans, ip(), 0),
                AdmitVerdict::BannedTemporarily
            );
        }
        assert_eq!(
            bans.check(ip(), 0).unwrap().strikes,
            1,
            "被拦下的连接不得把 strike 越滚越高"
        );
    }

    /// 三个监听（25/465/587）必须共用**同一份**准入状态。
    ///
    /// 若各端口自建，攻击者只需在端口之间轮换，就能拿到成倍配额；更糟的是 `strike`
    /// 被摊薄到每个端口都不够阈值，**永久封禁永远不会触发**。这条断言「配额只有一份」
    /// 是结构性的，不依赖网络。
    #[tokio::test]
    async fn servers_sharing_a_limiter_use_one_budget_across_listeners() {
        struct NullSink;
        impl MessageSink for NullSink {
            fn accept<'a>(
                &'a self,
                _message: crate::session::AcceptedMessage,
                _peer: SocketAddr,
            ) -> crate::connection::SinkFuture<'a> {
                Box::pin(async { Ok(()) })
            }
        }

        let rate = Arc::new(RateLimiter::new(RateLimitConfig {
            burst: 1,
            refill_per_second: 0.001,
            max_entries: 16,
        }));
        let bans = Arc::new(BanList::new(BanConfig::default()));
        let sink = Arc::new(NullSink);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        let starttls = |listener| {
            MailServer::with_shared(
                listener,
                ServerConfig::default(),
                None,
                TlsMode::StartTls,
                Arc::clone(&sink),
                Arc::clone(&clock),
                Arc::clone(&rate),
                Arc::clone(&bans),
            )
            .expect("构造监听")
        };
        let first = starttls(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let second = starttls(TcpListener::bind("127.0.0.1:0").await.unwrap());

        assert!(
            Arc::ptr_eq(first.rate_limiter(), second.rate_limiter()),
            "多个监听必须共用同一份限速配额"
        );
        assert!(
            Arc::ptr_eq(first.ban_list(), second.ban_list()),
            "多个监听必须共用同一份封禁表"
        );

        // 行为证据：配额只有一份 —— 在第一个监听上耗尽后，第二个立刻超速。
        assert!(first.rate_limiter().check(ip(), 0).is_allowed());
        assert!(
            !second.rate_limiter().check(ip(), 0).is_allowed(),
            "端口之间不得各自记账"
        );
    }

    /// 滴水客户端（持续喂零散字节，永远凑不出一行命令）必须在会话级总时限处
    /// 收到 `421 4.4.2` 并被断开。
    ///
    /// ## 这条测试为什么必须「滴水」而不是干等
    ///
    /// 客户端不发字节时，per-read 超时（300s）先于会话总时限到点，
    /// 那条路径安静地回 `Closed`、没有 421 —— 它验证不了本条防线。只有让每次
    /// read 都在超时前恰好等到 1 字节，per-read 超时被不断重置，才轮得到会话级
    /// 上限出场 —— 这正是 slowloris 的真实形态。
    ///
    /// 时限是**可注入**的（`MailServer.session_timeout`）：测试用 500ms 的真实
    /// 时钟时限，滴水间隔 50ms 远小于 per-read 超时 —— 不依赖 `test-util`
    /// 的虚拟时钟。
    #[tokio::test]
    async fn a_dribbling_session_is_bounded_by_the_total_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct NullSink;
        impl MessageSink for NullSink {
            fn accept<'a>(
                &'a self,
                _message: crate::session::AcceptedMessage,
                _peer: SocketAddr,
            ) -> crate::connection::SinkFuture<'a> {
                Box::pin(async { Ok(()) })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut server = MailServer::new(
            listener,
            ServerConfig::default(),
            None,
            TlsMode::StartTls,
            Arc::new(NullSink),
            Arc::new(SystemClock),
        )
        .expect("构造监听");
        // 秒级总时限：滴水间隔（50ms）仍远小于 per-read 超时（300s），
        // 防线的「被滴水不断喂活」前提不变，但真实时钟下瞬时走完。
        server.session_timeout = Duration::from_millis(500);
        tokio::spawn(async move { server.run(std::future::pending()).await });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // 先读完整的 220 问候行（以 CRLF 结尾），确认会话已进入命令阶段。
        let mut greeting = Vec::new();
        let mut chunk = [0u8; 128];
        while !greeting.windows(2).any(|window| window == b"\r\n") {
            let read = client.read(&mut chunk).await.unwrap();
            assert!(read > 0, "连接在问候行之前就断了");
            greeting.extend_from_slice(&chunk[..read]);
        }
        assert!(
            greeting.starts_with(b"220 "),
            "应先收到问候再开始滴水：{:?}",
            String::from_utf8_lossy(&greeting)
        );

        // 滴水节奏 50ms < per-read 超时 300s：每次 read 都在超时前被喂活，
        // per-read 超时永远到不了点。写失败（连接已被服务端关掉）即退出。
        // tokio 的 TcpStream 不能 try_clone —— 拆成读写两半，写半给滴水任务。
        let (mut reader, mut writer) = client.into_split();
        tokio::spawn(async move {
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if writer.write_all(b"A").await.is_err() {
                    return;
                }
            }
        });

        // 读到 421（或对端关闭）。外层给一个真实上限：回归（总时限失效）时
        // 滴水 eventually 耗尽、连接安静关闭，断言会给出明确失败而不是挂死。
        let mut seen = Vec::new();
        let mut chunk = [0u8; 128];
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let read = reader.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&chunk[..read]);
                if seen.windows(3).any(|window| window == b"421") {
                    break;
                }
            }
        })
        .await
        .expect("会话总时限未生效：虚拟 24 小时内没有 421 也没有断开");

        let out = String::from_utf8_lossy(&seen);
        assert!(
            out.contains("421 4.4.2 session timeout"),
            "滴水会话必须在总时限处收到 421，实际：{out}"
        );
    }
}
