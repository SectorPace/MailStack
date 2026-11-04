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

#[derive(Clone)]
pub struct AuthRequest {
    pub user: String,
    pub password: String,

    pub secured: bool,
    pub peer: SocketAddr,

    pub service: &'static str,
}

impl fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    Success { user: String },
    InvalidCredentials,

    TemporaryFailure(String),
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;

#[derive(Clone)]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,

    pub stored_key: [u8; 32],

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

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_>;

    fn scram_credentials<'a>(&'a self, user: &'a str) -> ScramFuture<'a> {
        Box::pin(async move {
            let _ = user;
            None
        })
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthThrottleConfig {
    pub max_failures: u32,

    pub window_secs: i64,

    pub lockout_secs: i64,

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

    Deny { retry_after_secs: i64 },
}

#[derive(Debug, Clone, Copy)]
struct PenaltyState {
    window_start: i64,
    failures: u32,

    locked_until: i64,
}

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

    pub fn check(&self, user: &str, now: i64) -> ThrottleDecision {
        let states = match self.states.lock() {
            Ok(states) => states,

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

    pub fn record_failure(&self, user: &str, now: i64) {
        if self.config.max_failures == 0 {
            return;
        }
        let mut states = match self.states.lock() {
            Ok(states) => states,
            Err(_) => return,
        };
        if states.len() >= self.config.max_tracked {
            states.retain(|_, state| {
                state.locked_until > now
                    || now.saturating_sub(state.window_start) < self.config.window_secs
            });
            if states.len() >= self.config.max_tracked && !states.contains_key(user) {
                return;
            }
        }
        let state = states.entry(user.to_string()).or_insert(PenaltyState {
            window_start: now,
            failures: 0,
            locked_until: 0,
        });

        if state.locked_until != 0 && state.locked_until <= now {
            state.locked_until = 0;
            state.failures = 0;
            state.window_start = now;
        }

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

    pub fn record_success(&self, user: &str) {
        if let Ok(mut states) = self.states.lock() {
            states.remove(user);
        }
    }
}

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

pub trait UserDirectory: Send + Sync {
    fn lookup<'a>(
        &'a self,
        user: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PasswordRecord>> + Send + 'a>>;
}

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

            let verified = tokio::task::spawn_blocking(move || match record {
                Some(record) => verify_password(&record, &password),
                None => {
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

        assert_eq!(
            throttled
                .authenticate(request("alice@example.com", "Tr0ubadour9x"))
                .await,
            AuthOutcome::InvalidCredentials,
            "锁定期内正确口令也必须被拒"
        );

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
