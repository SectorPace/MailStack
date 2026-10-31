//! 凭据校验：`Maildir + 口令记录` 的自包含认证面（替代 Dovecot passdb + auth socket）。
//!
//! ## 为什么不再问 Dovecot
//!
//! 去掉 Dovecot 之后，「口令的真相源」必须有一个新家。本 crate 选择直接读
//! `mailstack_core::password::PasswordRecord`（PBKDF2-SHA256，310,000 次）：
//!
//! * 算法、迭代次数、记录形状规则与管理员/邮箱口令**同一份实现**（INV-37）；
//! * 不引入第二份哈希表，改密后不存在「管理面已改、邮件面还没改」的漂移窗口；
//! * 记录损坏时 [`verify_password`] fail-closed（空摘要恒真的历史缺陷已被钉死）。
//!
//! ## 用户不存在也要付一次 PBKDF2
//!
//! 只对存在的用户跑 310k 次 PBKDF2，会让「响应时间」变成用户名枚举信道。因此
//! 用户不存在时仍对一条固定记录做一次校验，再返回失败。这是有意的 CPU 开销：
//! 攻击者拿不到「这个地址是否存在」的时序信号。
//!
//! ## 凭据不进日志
//!
//! [`AuthRequest`] 的 `Debug` 实现**不打印口令**；认证失败的日志只记录用户名与
//! 来源地址。所有实现者都被要求遵守这一点。

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use mailstack_core::password::{
    verify_password, PasswordRecord, HASH_LEN, PASSWORD_ALGORITHM, PBKDF2_ITERATIONS, SALT_LEN,
};
use sha2::{Digest, Sha256};

use crate::maildir::Clock;

/// 一次认证请求。
#[derive(Clone)]
pub struct AuthRequest {
    pub user: String,
    pub password: String,
    /// 连接是否已在 TLS 之上。明文连接上的口令在传输面是可读的，由会话层决定
    /// 是否允许。
    pub secured: bool,
    pub peer: SocketAddr,
    /// `imap` / `pop3`，只用于日志归类。
    pub service: &'static str,
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 口令永远不出现；用户名出现是因为运维需要定位被撞库的账号。
        f.debug_struct("AuthRequest")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("secured", &self.secured)
            .field("peer", &self.peer)
            .field("service", &self.service)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Success {
        user: String,
    },
    InvalidCredentials,
    /// 后端故障（目录不可达、任务取消）。对外是临时错误，**不是**「口令错」——
    /// 把后端抖动当成口令错会让客户端提示用户改密码。
    TemporaryFailure(String),
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;

/// SCRAM-SHA-256 的服务端凭据（由 PBKDF2 记录派生，不新增凭据存储）。
#[derive(Clone)]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    /// H(ClientKey)
    pub stored_key: [u8; 32],
    /// HMAC(SaltedPassword, "Server Key")
    pub server_key: [u8; 32],
}

impl fmt::Debug for ScramCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramCredentials")
            .field("salt", &"<redacted>")
            .field("iterations", &self.iterations)
            .field("stored_key", &"<redacted>")
            .field("server_key", &"<redacted>")
            .finish()
    }
}

impl ScramCredentials {
    /// 用户不存在时使用的等时凭据：结构合法但客户端无法算出正确 proof。
    /// 盐由用户名派生，避免「未知用户盐恒为零」成为用户名枚举信号。
    pub fn dummy_for(user: &str) -> Self {
        use sha2::{Digest, Sha256};
        let salted = [0u8; 32];
        let client_key = hmac_sha256(&salted, b"Client Key");
        let digest = Sha256::digest(format!("mailstack-scram-dummy:{user}").as_bytes());
        Self {
            salt: digest[..SALT_LEN].to_vec(),
            iterations: PBKDF2_ITERATIONS,
            stored_key: Sha256::digest(client_key).into(),
            server_key: hmac_sha256(&salted, b"Server Key"),
        }
    }
}

/// 从现有 PBKDF2 记录派生 SCRAM 凭据。
///
/// PBKDF2-HMAC-SHA256 的输出 `SaltedPassword` 就是记录里的 `hash`，因此不需要
/// 保存额外的 SCRAM verifier；记录损坏或迭代次数低于策略下界时返回 `None`
/// （与 [`verify_password`] 的 fail-closed 判据一致）。
pub fn scram_credentials_from_record(record: &PasswordRecord) -> Option<ScramCredentials> {
    if record.algorithm != PASSWORD_ALGORITHM
        || record.iterations < PBKDF2_ITERATIONS
        || record.salt.len() != SALT_LEN * 2
        || record.hash.len() != HASH_LEN * 2
    {
        return None;
    }
    let salt = hex::decode(&record.salt).ok()?;
    let salted = hex::decode(&record.hash).ok()?;
    if salt.len() != SALT_LEN || salted.len() != HASH_LEN {
        return None;
    }
    Some(ScramCredentials {
        salt,
        iterations: record.iterations,
        stored_key: Sha256::digest(hmac_sha256(&salted, b"Client Key")).into(),
        server_key: hmac_sha256(&salted, b"Server Key"),
    })
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        normalized[..32].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

pub type ScramFuture<'a> = Pin<Box<dyn Future<Output = Option<ScramCredentials>> + Send + 'a>>;

/// 认证后端。实现者必须保证「不把口令写进日志」。
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_>;

    /// SCRAM-SHA-256 凭据查询。默认不支持（只有声明了 `AUTH=SCRAM-SHA-256`
    /// 的后端才需要覆盖）。
    fn scram_credentials<'a>(&'a self, user: &'a str) -> ScramFuture<'a> {
        Box::pin(async move {
            let _ = user;
            None
        })
    }
}

/// 可克隆的认证后端句柄（配置结构需要 `Clone`，而 `dyn Authenticator` 不能）。
#[derive(Clone)]
pub struct AuthBackend(Arc<dyn Authenticator>);

impl AuthBackend {
    pub fn new(authenticator: Arc<dyn Authenticator>) -> Self {
        Self(authenticator)
    }

    pub fn as_dyn(&self) -> &dyn Authenticator {
        self.0.as_ref()
    }

    pub fn scram_credentials<'a>(&'a self, user: &'a str) -> ScramFuture<'a> {
        self.0.scram_credentials(user)
    }
}

impl From<Arc<dyn Authenticator>> for AuthBackend {
    fn from(authenticator: Arc<dyn Authenticator>) -> Self {
        Self::new(authenticator)
    }
}

impl fmt::Debug for AuthBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthBackend")
    }
}

// ---------------------------------------------------------------------------
// 每用户认证节流（penalty）
// ---------------------------------------------------------------------------

/// 每用户认证失败节流配置。
///
/// 与 [`crate::limiter::RateLimiter`]（每 IP 连接限速）互补：限速挡住「同一来源疯狂
/// 重连」，本节流挡住「换着来源、盯着同一个账号爆破」。后者才是撞库/定向爆破的真实
/// 形态 —— 攻击者用一堆肉鸡各试几次，每 IP 计数永远到不了阈值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthThrottleConfig {
    /// 窗口内累计多少次失败后锁定该账号。
    pub max_failures: u32,
    /// 失败计数窗口（秒）。窗口内无新失败则计数清零。
    pub window_secs: i64,
    /// 触发锁定后拒绝该账号的时长（秒）。
    pub lockout_secs: i64,
    /// 最多跟踪多少个账号，防止内存被无限拉扯。
    pub max_tracked: usize,
}

impl Default for AuthThrottleConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window_secs: 300,
            lockout_secs: 900,
            max_tracked: 65_536,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleDecision {
    Allow,
    /// 账号处于锁定期，`retry_after_secs` 后可重试。
    Deny {
        retry_after_secs: i64,
    },
}

#[derive(Debug, Clone, Copy)]
struct PenaltyState {
    window_start: i64,
    failures: u32,
    /// 锁定截止（Unix 秒）；`0` 表示未锁定。
    locked_until: i64,
}

/// 跨连接共享的每用户失败计数与锁定状态。所有方法都注入 `now`（Unix 秒），便于用
/// 固定时钟精确验证边界；锁中毒一律 fail-closed（当作锁定/放弃计数），与
/// [`crate::limiter::RateLimiter`] 一致。
pub struct AuthThrottle {
    config: AuthThrottleConfig,
    states: Mutex<HashMap<String, PenaltyState>>,
}

impl AuthThrottle {
    pub fn new(config: AuthThrottleConfig) -> Self {
        Self {
            config,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// 认证**前**查询：账号是否处于锁定期。
    pub fn check(&self, user: &str, now: i64) -> ThrottleDecision {
        let states = match self.states.lock() {
            Ok(states) => states,
            // 锁中毒意味着上一次持锁 panic —— fail-closed，按锁定处理。
            Err(_) => {
                return ThrottleDecision::Deny {
                    retry_after_secs: self.config.lockout_secs,
                }
            }
        };
        match states.get(user) {
            Some(state) if state.locked_until > now => ThrottleDecision::Deny {
                retry_after_secs: state.locked_until.saturating_sub(now),
            },
            _ => ThrottleDecision::Allow,
        }
    }

    /// 认证**失败后**记账：累计到阈值即锁定一个 `lockout_secs` 窗口。
    pub fn record_failure(&self, user: &str, now: i64) {
        if self.config.max_failures == 0 {
            return;
        }
        let mut states = match self.states.lock() {
            Ok(states) => states,
            Err(_) => return,
        };
        if states.len() >= self.config.max_tracked {
            // 先清理既过期又未锁定的条目。
            states.retain(|_, state| {
                state.locked_until > now
                    || now.saturating_sub(state.window_start) < self.config.window_secs
            });
            if states.len() >= self.config.max_tracked && !states.contains_key(user) {
                // 表满且是全新账号：放弃跟踪（fail-open）。定向爆破只盯少量账号，它们
                // 已在表内；被挤出的是海量一次性用户名，对它们节流没有意义。
                return;
            }
        }
        let state = states.entry(user.to_string()).or_insert(PenaltyState {
            window_start: now,
            failures: 0,
            locked_until: 0,
        });
        // 上一轮锁定已到期：重开计数窗口。
        if state.locked_until != 0 && state.locked_until <= now {
            state.locked_until = 0;
            state.failures = 0;
            state.window_start = now;
        }
        // 窗口过期或时钟回拨：重开窗口，而不是把账号锁死到时间追上来。
        if now.saturating_sub(state.window_start) >= self.config.window_secs
            || now < state.window_start
        {
            state.window_start = now;
            state.failures = 0;
        }
        state.failures += 1;
        if state.failures >= self.config.max_failures {
            state.locked_until = now.saturating_add(self.config.lockout_secs);
            state.failures = 0;
        }
    }

    /// 认证**成功后**清除该账号的失败记录（合法用户偶发输错不应被累积锁定）。
    pub fn record_success(&self, user: &str) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(user);
        }
    }
}

/// 给任意 [`Authenticator`] 套一层「每用户失败锁定」的包装。
///
/// 只覆盖口令路径（`LOGIN` / `PLAIN`）—— 那是要跑满 31 万次 PBKDF2 的昂贵路径，也是
/// 定向爆破的首选。锁定期内**直接拒绝、不再跑 PBKDF2**，这正是节流要省的 CPU。SCRAM
/// 的服务端开销低、且客户端每次都要自付一次 PBKDF2，不在此包装的节流范围内。
pub struct ThrottledAuthenticator<A> {
    inner: A,
    throttle: AuthThrottle,
    clock: Arc<dyn Clock>,
}

impl<A> ThrottledAuthenticator<A> {
    pub fn new(inner: A, config: AuthThrottleConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner,
            throttle: AuthThrottle::new(config),
            clock,
        }
    }

    /// 暴露内部节流器，便于装配层做观测或与会话级节流共享同一份状态。
    pub fn throttle(&self) -> &AuthThrottle {
        &self.throttle
    }
}

impl<A: Authenticator> Authenticator for ThrottledAuthenticator<A> {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async move {
            let key = request.user.trim().to_ascii_lowercase();
            if !key.is_empty()
                && self.throttle.check(&key, self.clock.now_secs()) != ThrottleDecision::Allow
            {
                return AuthOutcome::InvalidCredentials;
            }
            let outcome = self.inner.authenticate(request).await;
            if !key.is_empty() {
                match &outcome {
                    AuthOutcome::Success { user } => self.throttle.record_success(user),
                    AuthOutcome::InvalidCredentials => {
                        self.throttle.record_failure(&key, self.clock.now_secs())
                    }
                    // 后端抖动不是「口令错」，不应据此惩罚账号。
                    AuthOutcome::TemporaryFailure(_) => {}
                }
            }
            outcome
        })
    }

    fn scram_credentials<'a>(&'a self, user: &'a str) -> ScramFuture<'a> {
        self.inner.scram_credentials(user)
    }
}

/// 用户目录：把「登录名」映射到口令记录。
///
/// 登录名按**小写**查询（IMAP/POP3 用户名的域部分大小写不敏感是通行惯例）；
/// 实现方不应再做二次归一化。
pub trait UserDirectory: Send + Sync {
    fn lookup<'a>(
        &'a self,
        user: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PasswordRecord>> + Send + 'a>>;
}

/// 基于口令记录的认证后端。
pub struct PasswordDirectory<D: UserDirectory> {
    directory: D,
}

impl<D: UserDirectory> PasswordDirectory<D> {
    pub fn new(directory: D) -> Self {
        Self { directory }
    }
}

impl<D: UserDirectory> Authenticator for PasswordDirectory<D> {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async move {
            let user = request.user.trim().to_ascii_lowercase();
            if user.is_empty() {
                return AuthOutcome::InvalidCredentials;
            }
            let record = self.directory.lookup(&user).await;
            let password = request.password;

            // PBKDF2 是 CPU-bound；放到 blocking 池，避免一艘 daemon 在恶意连接下
            // 把 async worker 全部堵死。`spawn_blocking` 的 JoinError 代表任务
            // panic/取消 —— 那是临时故障，不是口令错。
            let verified = tokio::task::spawn_blocking(move || match record {
                Some(record) => verify_password(&record, &password),
                None => {
                    // 等时失败：用户不存在时也跑一次完整 PBKDF2。
                    let _ = verify_password(&dummy_record(), &password);
                    false
                }
            })
            .await;

            match verified {
                Ok(true) => AuthOutcome::Success { user },
                Ok(false) => AuthOutcome::InvalidCredentials,
                Err(error) => AuthOutcome::TemporaryFailure(format!(
                    "password verification task failed: {error}"
                )),
            }
        })
    }

    fn scram_credentials<'a>(&'a self, user: &'a str) -> ScramFuture<'a> {
        let user = user.trim().to_ascii_lowercase();
        Box::pin(async move {
            let record = self.directory.lookup(&user).await?;
            scram_credentials_from_record(&record)
        })
    }
}

/// 固定形状的假记录：salt 与摘要都是 0，但长度合法，因此 `verify_password`
/// 会真的跑满迭代次数再返回 `false`。
fn dummy_record() -> PasswordRecord {
    PasswordRecord {
        username: "invalid".to_string(),
        algorithm: "pbkdf2-sha256".to_string(),
        iterations: mailstack_core::password::PBKDF2_ITERATIONS,
        salt: "00".repeat(mailstack_core::password::SALT_LEN),
        hash: "00".repeat(mailstack_core::password::HASH_LEN),
        updated_at: String::new(),
    }
}

/// 内存目录：测试与小规模部署的兜底（生产由 `mailstackd` 从注册表装载）。
#[derive(Default)]
pub struct MemoryDirectory {
    users: HashMap<String, PasswordRecord>,
}

impl MemoryDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: PasswordRecord) {
        self.users
            .insert(record.username.to_ascii_lowercase(), record);
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

impl UserDirectory for MemoryDirectory {
    fn lookup<'a>(
        &'a self,
        user: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PasswordRecord>> + Send + 'a>> {
        let found = self.users.get(user).cloned();
        Box::pin(async move { found })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn request(user: &str, password: &str) -> AuthRequest {
        AuthRequest {
            user: user.to_string(),
            password: password.to_string(),
            secured: true,
            peer: "192.0.2.1:12345".parse().unwrap(),
            service: "imap",
        }
    }

    fn backend() -> AuthBackend {
        // `password_record` 只接受管理员风格的登录名；这里构造后改回邮箱形状，
        // 与生产装载路径一致（记录里的 username 是账号，不是登录名）。
        let mut record =
            mailstack_core::password::password_record("alice", "Tr0ubadour9x").unwrap();
        record.username = "alice@example.com".to_string();
        let mut directory = MemoryDirectory::new();
        directory.insert(record);
        AuthBackend::new(Arc::new(PasswordDirectory::new(directory)))
    }

    #[tokio::test]
    async fn correct_credentials_authenticate_and_wrong_ones_do_not() {
        let auth = backend();
        assert_eq!(
            auth.as_dyn()
                .authenticate(request("Alice@Example.com", "Tr0ubadour9x"))
                .await,
            AuthOutcome::Success {
                user: "alice@example.com".into()
            }
        );
        assert_eq!(
            auth.as_dyn()
                .authenticate(request("alice@example.com", "wrong"))
                .await,
            AuthOutcome::InvalidCredentials
        );
        assert_eq!(
            auth.as_dyn()
                .authenticate(request("nobody@example.com", "Tr0ubadour9x"))
                .await,
            AuthOutcome::InvalidCredentials
        );
    }

    #[test]
    fn debug_never_prints_the_password() {
        let rendered = format!("{:?}", request("alice", "hunter2"));
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("alice"));
    }

    #[tokio::test]
    async fn unknown_users_still_pay_for_one_pbkdf2() {
        let auth = backend();
        let start = std::time::Instant::now();
        let outcome = auth
            .as_dyn()
            .authenticate(request("ghost@example.com", "whatever"))
            .await;
        assert_eq!(outcome, AuthOutcome::InvalidCredentials);
        // 只验证「确实做了重活」的量级，不钉死具体耗时（CI 机器差异大）。
        assert!(
            start.elapsed() > Duration::from_millis(5),
            "未知用户路径不得跳过 PBKDF2（否则是用户名枚举信道）"
        );
    }

    #[test]
    fn auth_throttle_locks_after_repeated_failures_and_recovers() {
        let throttle = AuthThrottle::new(AuthThrottleConfig {
            max_failures: 3,
            window_secs: 60,
            lockout_secs: 120,
            max_tracked: 100,
        });
        assert_eq!(throttle.check("bob", 1000), ThrottleDecision::Allow);
        throttle.record_failure("bob", 1000);
        throttle.record_failure("bob", 1010);
        assert_eq!(
            throttle.check("bob", 1020),
            ThrottleDecision::Allow,
            "尚未达到阈值不得锁定"
        );
        throttle.record_failure("bob", 1020);
        assert_eq!(
            throttle.check("bob", 1021),
            ThrottleDecision::Deny {
                retry_after_secs: 119
            }
        );
        assert_eq!(
            throttle.check("bob", 1141),
            ThrottleDecision::Allow,
            "锁定期结束后应恢复"
        );
        assert_eq!(
            throttle.check("alice", 1021),
            ThrottleDecision::Allow,
            "不同账号独立计数"
        );
    }

    #[test]
    fn auth_throttle_success_clears_and_stale_window_resets() {
        let throttle = AuthThrottle::new(AuthThrottleConfig {
            max_failures: 2,
            window_secs: 60,
            lockout_secs: 120,
            max_tracked: 100,
        });
        throttle.record_failure("bob", 1000);
        throttle.record_success("bob");
        throttle.record_failure("bob", 1010);
        assert_eq!(
            throttle.check("bob", 1011),
            ThrottleDecision::Allow,
            "成功登录后失败计数应清零"
        );
        // 窗口过期后旧失败不再累计到新失败上。
        throttle.record_failure("carol", 1000);
        throttle.record_failure("carol", 1200);
        assert_eq!(throttle.check("carol", 1201), ThrottleDecision::Allow);
    }

    struct StepClock(Mutex<i64>);
    impl StepClock {
        fn advance(&self, secs: i64) {
            *self.0.lock().unwrap() += secs;
        }
    }
    impl Clock for StepClock {
        fn now_secs(&self) -> i64 {
            *self.0.lock().unwrap()
        }
    }

    fn password_directory(user: &str, password: &str) -> PasswordDirectory<MemoryDirectory> {
        let mut record = mailstack_core::password::password_record("alice", password).unwrap();
        record.username = user.to_string();
        let mut directory = MemoryDirectory::new();
        directory.insert(record);
        PasswordDirectory::new(directory)
    }

    #[tokio::test]
    async fn throttled_authenticator_locks_a_brute_forced_account() {
        let clock = Arc::new(StepClock(Mutex::new(1000)));
        let throttled = ThrottledAuthenticator::new(
            password_directory("alice@example.com", "Tr0ubadour9x"),
            AuthThrottleConfig {
                max_failures: 2,
                window_secs: 60,
                lockout_secs: 120,
                max_tracked: 16,
            },
            Arc::clone(&clock) as Arc<dyn Clock>,
        );

        for _ in 0..2 {
            assert_eq!(
                throttled
                    .authenticate(request("alice@example.com", "wrong"))
                    .await,
                AuthOutcome::InvalidCredentials
            );
            clock.advance(1);
        }
        // 锁定期内即使口令正确也被拒（且不再跑 PBKDF2）。
        assert_eq!(
            throttled
                .authenticate(request("alice@example.com", "Tr0ubadour9x"))
                .await,
            AuthOutcome::InvalidCredentials,
            "锁定期内正确口令也必须被拒"
        );
        // 锁定期过后正确口令恢复通过，且成功会清账。
        clock.advance(200);
        assert_eq!(
            throttled
                .authenticate(request("alice@example.com", "Tr0ubadour9x"))
                .await,
            AuthOutcome::Success {
                user: "alice@example.com".into()
            }
        );
    }
}
