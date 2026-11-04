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
use crate::peer::PeerKey;
use crate::ratelimit::{RateDecision, RateLimitConfig, RateLimiter};
use crate::reply::{texts, Reply};
use crate::sasl::{AuthBackend, Authenticator, UnavailableAuthenticator};
use crate::session::{RecipientChecker, Session, SessionConfig};
use crate::tls::{BoxedStream, TlsMode};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const SESSION_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub trait Clock: Send + Sync + 'static {
    fn now_millis(&self) -> i64;
}

#[derive(Debug)]
struct PeerConnections {
    max_per_peer: usize,
    active: std::sync::Mutex<std::collections::HashMap<PeerKey, usize>>,
}

impl PeerConnections {
    fn new(max_per_peer: usize) -> Self {
        Self {
            max_per_peer: max_per_peer.max(1),
            active: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, ip: std::net::IpAddr) -> Option<PeerConnectionSlot> {
        let key = PeerKey::from_ip(ip);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(key).or_insert(0);
        if *count >= self.max_per_peer {
            return None;
        }
        *count += 1;
        Some(PeerConnectionSlot {
            owner: Arc::clone(self),
            key,
        })
    }

    #[cfg(test)]
    fn active_for(&self, ip: std::net::IpAddr) -> usize {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&PeerKey::from_ip(ip))
            .copied()
            .unwrap_or(0)
    }
}

struct PeerConnectionSlot {
    owner: Arc<PeerConnections>,
    key: PeerKey,
}

impl Drop for PeerConnectionSlot {
    fn drop(&mut self) {
        let mut active = self
            .owner
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = active.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.key);
            }
        }
    }
}

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

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub session: SessionConfig,

    pub relay: RelayPolicy,

    pub limits: ServerLimits,

    pub max_connections: usize,

    pub max_connections_per_ip: usize,

    pub rate_limit: RateLimitConfig,

    pub ban: BanConfig,

    pub shutdown_grace: Duration,

    pub auth: Option<AuthBackend>,

    pub recipients: Option<Arc<dyn RecipientChecker>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            relay: RelayPolicy::new(Vec::<String>::new()),
            limits: ServerLimits::default(),
            max_connections: 512,

            max_connections_per_ip: 16,
            rate_limit: RateLimitConfig::default(),
            ban: BanConfig::default(),
            shutdown_grace: Duration::from_secs(10),
            auth: None,
            recipients: None,
        }
    }
}

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

pub struct MailServer<S: MessageSink + ?Sized> {
    listener: TcpListener,
    config: ServerConfig,
    tls: Option<TlsAcceptor>,
    tls_mode: TlsMode,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,

    peers: Arc<PeerConnections>,

    recipients: Option<Arc<dyn RecipientChecker>>,

    session_timeout: Duration,
}

impl<S: MessageSink + ?Sized + 'static> MailServer<S> {
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
        let peers = Arc::new(PeerConnections::new(config.max_connections_per_ip));
        Ok(Self {
            listener,
            config,
            tls,
            tls_mode,
            sink,
            clock,
            rate,
            bans,
            peers,
            recipients,
            session_timeout: SESSION_TOTAL_TIMEOUT,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate
    }

    pub fn ban_list(&self) -> &Arc<BanList> {
        &self.bans
    }

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
            peers,
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
                        Ok((mut stream, peer)) => {

                            let Some(peer_slot) = peers.try_acquire(peer.ip()) else {
                                tracing::warn!(
                                    peer = %peer,
                                    max = config.max_connections_per_ip,
                                    "每来源并发连接已达上限，拒绝新连接"
                                );
                                let reply = Reply::with_enhanced(
                                    421,
                                    "4.7.0",
                                    texts::TOO_MANY_CONNECTIONS,
                                );
                                let _ = write_reply(&mut stream, &reply).await;
                                continue;
                            };

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
                                let _peer_slot = peer_slot;
                                context.handle(stream, peer).await;
                            });
                        }
                        Err(error) => {

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

    if config.session.offer_auth && config.auth.is_none() {
        return Err(ConfigError::AuthAdvertisedWithoutAuthenticator);
    }
    Ok(())
}

struct ConnectionContext<S: MessageSink + ?Sized> {
    config: ServerConfig,
    tls: Option<TlsAcceptor>,
    tls_mode: TlsMode,
    sink: Arc<S>,
    clock: Arc<dyn Clock>,
    rate: Arc<RateLimiter>,
    bans: Arc<BanList>,
    recipients: Option<Arc<dyn RecipientChecker>>,

    session_timeout: Duration,
}

impl<S: MessageSink + ?Sized> ConnectionContext<S> {
    async fn handle(&self, mut stream: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();

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

                        return;
                    }
                    Err(_) => {
                        tracing::warn!(
                            peer = %peer,
                            timeout_secs = TLS_HANDSHAKE_TIMEOUT.as_secs(),
                            "TLS 握手超时"
                        );

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

        let auth: &dyn Authenticator = match self.config.auth.as_ref() {
            Some(backend) => backend.as_dyn(),
            None => &UnavailableAuthenticator,
        };

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
                        tracing::error!(peer = %peer, "收到 STARTTLS 但没有可用的 TLS 配置");
                        return;
                    };

                    let next: BoxedStream = match tokio::time::timeout_at(
                        deadline,
                        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)),
                    )
                    .await
                    {
                        Ok(Ok(Ok(encrypted))) => Box::new(encrypted),
                        Ok(Ok(Err(error))) => {
                            tracing::warn!(peer = %peer, error = %error, "STARTTLS 握手失败");

                            return;
                        }
                        Ok(Err(_)) => {
                            tracing::warn!(
                                peer = %peer,
                                timeout_secs = TLS_HANDSHAKE_TIMEOUT.as_secs(),
                                "STARTTLS 握手超时"
                            );
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

async fn session_deadline_elapsed(stream: &mut BoxedStream, peer: SocketAddr, timeout: Duration) {
    tracing::warn!(
        peer = %peer,
        timeout_secs = timeout.as_secs(),
        "会话总时限已到，关闭连接"
    );
    let reply = Reply::with_enhanced(421, "4.4.2", texts::SESSION_TIMEOUT);
    let _ = write_reply(stream, &reply).await;
}

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
            bans.record_failure(ip, now);
            AdmitVerdict::RateLimited { retry_after_secs }
        }
    }
}

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

        assert!(matches!(
            admit(&rate, &bans, ip(), 0),
            AdmitVerdict::RateLimited { .. }
        ));

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

        assert!(first.rate_limiter().check(ip(), 0).is_allowed());
        assert!(
            !second.rate_limiter().check(ip(), 0).is_allowed(),
            "端口之间不得各自记账"
        );
    }

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

        server.session_timeout = Duration::from_millis(500);
        tokio::spawn(async move { server.run(std::future::pending()).await });

        let mut client = TcpStream::connect(addr).await.unwrap();

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

        let (mut reader, mut writer) = client.into_split();
        tokio::spawn(async move {
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if writer.write_all(b"A").await.is_err() {
                    return;
                }
            }
        });

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

    #[test]
    fn a_single_peer_cannot_exceed_its_concurrent_connection_quota() {
        let peers = Arc::new(PeerConnections::new(3));
        let attacker: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let other: std::net::IpAddr = "203.0.113.10".parse().unwrap();

        let mut slots = Vec::new();
        for _ in 0..3 {
            slots.push(peers.try_acquire(attacker).expect("配额内应放行"));
        }
        assert!(
            peers.try_acquire(attacker).is_none(),
            "超过每 IP 并发上限必须拒绝"
        );

        assert!(peers.try_acquire(other).is_some(), "另一个来源应仍可建连");
        assert_eq!(peers.active_for(attacker), 3);

        drop(slots);
        assert_eq!(peers.active_for(attacker), 0, "连接结束后必须归还额度");
        assert!(peers.try_acquire(attacker).is_some(), "额度应可复用");
    }

    #[test]
    fn ipv6_concurrency_is_aggregated_by_slash_64() {
        let peers = Arc::new(PeerConnections::new(2));
        let first: std::net::IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let second: std::net::IpAddr = "2001:db8:1:2::2".parse().unwrap();
        let other_prefix: std::net::IpAddr = "2001:db8:1:3::1".parse().unwrap();

        let _a = peers.try_acquire(first).expect("放行");
        let _b = peers.try_acquire(second).expect("同一 /64 的第二条");
        assert!(
            peers.try_acquire(second).is_none(),
            "同一 /64 的第 3 条必须被拒（即使换地址）"
        );
        assert!(
            peers.try_acquire(other_prefix).is_some(),
            "另一 /64 不受影响"
        );
    }
}
