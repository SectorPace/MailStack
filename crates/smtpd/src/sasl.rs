use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use mailstack_core::mailbox_passwords::MailboxPasswords;
use mailstack_core::password::{
    verify_password, PasswordRecord, HASH_LEN, PBKDF2_ITERATIONS, SALT_LEN,
};

pub const DEFAULT_AUTH_SOCKET: &str = "/run/dovecot/auth-client";

const MAX_LINE: usize = 16 * 1024;

const MAX_HANDSHAKE_LINES: usize = 64;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub mechanism: String,

    pub response: String,

    pub secured: bool,

    pub peer: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Success { user: String },

    InvalidCredentials,

    TemporaryFailure(String),
}

pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableAuthenticator;

impl Authenticator for UnavailableAuthenticator {
    fn authenticate(&self, _request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async { AuthOutcome::TemporaryFailure("no authentication backend".to_string()) })
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
}

impl From<Arc<dyn Authenticator>> for AuthBackend {
    fn from(authenticator: Arc<dyn Authenticator>) -> Self {
        Self::new(authenticator)
    }
}

impl std::fmt::Debug for AuthBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthBackend")
    }
}

pub const MAX_CONCURRENT_PBKDF2: usize = 8;

pub const PBKDF2_QUEUE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct MailboxPasswordsAuthenticator {
    passwords: MailboxPasswords,

    dummy: PasswordRecord,

    verify_slots: Arc<tokio::sync::Semaphore>,
}

impl MailboxPasswordsAuthenticator {
    pub fn new(passwords: MailboxPasswords) -> Self {
        Self {
            passwords,
            dummy: dummy_record(),
            verify_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PBKDF2)),
        }
    }

    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.verify_slots = Arc::new(tokio::sync::Semaphore::new(max.max(1)));
        self
    }

    pub fn at(paths: &mailstack_core::Paths) -> Self {
        Self::new(MailboxPasswords::at(paths))
    }

    pub fn from_path(path: impl Into<std::path::PathBuf>) -> Self {
        Self::new(MailboxPasswords::new(path))
    }
}

fn verify_on_blocking_pool(
    passwords: MailboxPasswords,
    dummy: PasswordRecord,
    user: String,
    password: String,
) -> AuthOutcome {
    for candidate in mailstack_core::mailbox_passwords::candidate_keys(&user) {
        match passwords.get(&candidate) {
            Ok(Some(record)) => {
                return if verify_password(&record, &password) {
                    let confirmed = if record.username.is_empty() {
                        user
                    } else {
                        record.username
                    };
                    AuthOutcome::Success { user: confirmed }
                } else {
                    AuthOutcome::InvalidCredentials
                };
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %passwords.path().display(),
                    "邮箱口令库不可读，拒绝本次认证"
                );

                let _ = verify_password(&dummy, &password);
                return AuthOutcome::InvalidCredentials;
            }
        }
    }
    let _ = verify_password(&dummy, &password);
    AuthOutcome::InvalidCredentials
}

impl Authenticator for MailboxPasswordsAuthenticator {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async move {
            if !request.mechanism.eq_ignore_ascii_case("PLAIN") {
                return AuthOutcome::TemporaryFailure("unsupported SASL mechanism".to_string());
            }
            let Some((user, password)) = decode_plain(&request.response) else {
                return AuthOutcome::InvalidCredentials;
            };

            let permit = match tokio::time::timeout(
                PBKDF2_QUEUE_TIMEOUT,
                Arc::clone(&self.verify_slots).acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_closed)) => {
                    return AuthOutcome::TemporaryFailure(
                        "password verification queue is closed".to_string(),
                    )
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = PBKDF2_QUEUE_TIMEOUT.as_secs(),
                        "PBKDF2 校验队列已满，本次认证按临时失败处理"
                    );
                    return AuthOutcome::TemporaryFailure(
                        "password verification queue is saturated".to_string(),
                    );
                }
            };

            let passwords = self.passwords.clone();
            let dummy = self.dummy.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                verify_on_blocking_pool(passwords, dummy, user, password)
            })
            .await;

            match joined {
                Ok(outcome) => outcome,

                Err(error) => AuthOutcome::TemporaryFailure(format!(
                    "password verification task failed: {error}"
                )),
            }
        })
    }
}

fn decode_plain(response: &str) -> Option<(String, String)> {
    let payload = base64::engine::general_purpose::STANDARD
        .decode(response.as_bytes())
        .ok()?;
    let fields: Vec<&[u8]> = payload.split(|byte| *byte == 0).collect();
    let (user, password) = match fields.as_slice() {
        [_, user, password] => (*user, *password),
        [user, password] => (*user, *password),
        _ => return None,
    };
    let user = String::from_utf8_lossy(user).to_string();
    if user.trim().is_empty() {
        return None;
    }
    Some((user, String::from_utf8_lossy(password).to_string()))
}

fn dummy_record() -> PasswordRecord {
    PasswordRecord {
        username: "invalid".to_string(),
        algorithm: "pbkdf2-sha256".to_string(),
        iterations: PBKDF2_ITERATIONS,
        salt: "00".repeat(SALT_LEN),
        hash: "00".repeat(HASH_LEN),
        updated_at: String::new(),
    }
}

pub fn is_valid_base64(value: &str) -> bool {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return false;
    }
    let bytes = value.as_bytes();

    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let body = &bytes[..bytes.len() - padding];
    if body.is_empty() {
        return false;
    }
    body.iter()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
}

#[derive(Debug, Clone)]
pub struct DovecotAuthClient {
    socket: PathBuf,
    service: String,
    timeout: Duration,
}

impl DovecotAuthClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            service: "smtp".to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn from_env() -> Self {
        let socket = std::env::var("MAILSTACK_DOVECOT_AUTH_SOCKET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTH_SOCKET));
        Self::new(socket)
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    async fn exchange(&self, request: &AuthRequest) -> std::io::Result<AuthOutcome> {
        let stream = UnixStream::connect(&self.socket).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let handshake = format!("VERSION\t1\t2\nCPID\t{}\n", std::process::id());
        write_half.write_all(handshake.as_bytes()).await?;
        write_half.flush().await?;

        let mechanisms = read_handshake(&mut reader).await?;
        if !mechanisms.iter().any(|name| name == &request.mechanism) {
            return Ok(AuthOutcome::TemporaryFailure(format!(
                "dovecot does not offer mechanism {}",
                request.mechanism
            )));
        }

        let mut line = format!("AUTH\t1\t{}\tservice={}", request.mechanism, self.service);
        if request.secured {
            line.push_str("\tsecured=tls");
        }
        line.push_str(&format!(
            "\trip={}\trport={}\tresp={}\n",
            request.peer.ip(),
            request.peer.port(),
            request.response
        ));
        write_half.write_all(line.as_bytes()).await?;
        write_half.flush().await?;

        let response = read_bounded_line(&mut reader)
            .await?
            .ok_or_else(|| protocol_error("auth socket closed before replying"))?;
        parse_auth_response(&response)
    }
}

impl Authenticator for DovecotAuthClient {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async move {
            if !is_safe_token(&request.mechanism) {
                return AuthOutcome::TemporaryFailure("unsafe mechanism token".to_string());
            }
            if !is_valid_base64(&request.response) {
                return AuthOutcome::TemporaryFailure("unsafe auth response".to_string());
            }
            match tokio::time::timeout(self.timeout, self.exchange(&request)).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => AuthOutcome::TemporaryFailure(error.to_string()),
                Err(_) => AuthOutcome::TemporaryFailure("auth socket timed out".to_string()),
            }
        })
    }
}

async fn read_handshake<R>(reader: &mut R) -> std::io::Result<Vec<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut mechanisms = Vec::new();
    let mut saw_version = false;
    for _ in 0..MAX_HANDSHAKE_LINES {
        let Some(line) = read_bounded_line(reader).await? else {
            return Err(protocol_error("auth socket closed during handshake"));
        };
        let mut fields = line.split('\t');
        match fields.next() {
            Some("VERSION") => {
                let major = fields.next().unwrap_or_default();
                if major != "1" {
                    return Err(protocol_error("unsupported dovecot auth protocol version"));
                }
                saw_version = true;
            }
            Some("MECH") => {
                if let Some(name) = fields.next() {
                    mechanisms.push(name.to_ascii_uppercase());
                }
            }
            Some("DONE") => {
                if !saw_version {
                    return Err(protocol_error("handshake finished without a VERSION line"));
                }
                return Ok(mechanisms);
            }

            _ => {}
        }
    }
    Err(protocol_error("handshake did not finish"))
}

fn parse_auth_response(line: &str) -> std::io::Result<AuthOutcome> {
    let mut fields = line.split('\t');
    let status = fields.next().unwrap_or_default();

    let id = fields.next().unwrap_or_default();
    if id != "1" {
        return Err(protocol_error("auth response id mismatch"));
    }
    let parameters: Vec<&str> = fields.collect();

    match status {
        "OK" => Ok(AuthOutcome::Success {
            user: lookup_parameter(&parameters, "user").unwrap_or_else(|| "unknown".to_string()),
        }),
        "FAIL" => {
            let temporary = parameters
                .iter()
                .any(|field| *field == "temp" || field.starts_with("temp="));
            if temporary {
                let reason = lookup_parameter(&parameters, "reason")
                    .unwrap_or_else(|| "temporary failure".to_string());
                Ok(AuthOutcome::TemporaryFailure(reason))
            } else {
                Ok(AuthOutcome::InvalidCredentials)
            }
        }

        "CONT" => Err(protocol_error(
            "unexpected CONT for a single-shot mechanism",
        )),
        _ => Err(protocol_error("unrecognised auth socket status")),
    }
}

fn lookup_parameter(parameters: &[&str], key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    parameters
        .iter()
        .find_map(|field| field.strip_prefix(&prefix))
        .map(|value| sanitize_identity(&unescape_tab(value)))
}

fn unescape_tab(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\u{1}' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('\0'),
            Some('1') => out.push('\u{1}'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('l') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn sanitize_identity(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

async fn read_bounded_line<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buffer.is_empty() {
                return Ok(None);
            }
            break;
        }
        let (consumed, ends_with_newline) = match available.iter().position(|&byte| byte == b'\n') {
            Some(position) => (position + 1, true),
            None => (available.len(), false),
        };
        buffer.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if buffer.len() > MAX_LINE {
            return Err(protocol_error("line exceeds the auth protocol limit"));
        }
        if ends_with_newline {
            break;
        }
    }

    while matches!(buffer.last(), Some(b'\n' | b'\r')) {
        buffer.pop();
    }
    String::from_utf8(buffer)
        .map(Some)
        .map_err(|_| protocol_error("auth socket sent non-UTF-8"))
}

fn protocol_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_core::password::password_record;

    #[test]
    fn base64_validation_rejects_anything_that_could_inject_a_protocol_field() {
        assert!(is_valid_base64("AGJvYg=="));
        assert!(is_valid_base64("AAAA"));
        assert!(is_valid_base64("+/=="));

        assert!(!is_valid_base64(""));
        assert!(!is_valid_base64("AAAA\tresp=injected"), "TAB 必须被拒");
        assert!(!is_valid_base64("AAAA\n"), "LF 必须被拒");
        assert!(!is_valid_base64("AA\rAA"), "CR 必须被拒");
        assert!(!is_valid_base64("AAA"), "长度不是 4 的倍数");
        assert!(!is_valid_base64("====="), "填充过多");
        assert!(!is_valid_base64("="));
        assert!(!is_valid_base64("AB=A"), "填充只能出现在结尾");
        assert!(!is_valid_base64("AB$D"));
    }

    #[test]
    fn tab_escaping_is_undone_exactly() {
        assert_eq!(unescape_tab("plain"), "plain");
        assert_eq!(unescape_tab("a\u{1}tb"), "a\tb");
        assert_eq!(unescape_tab("a\u{1}rb\u{1}lc"), "a\rb\nc");

        assert_eq!(unescape_tab("a\u{1}xb"), "axb");
    }

    #[test]
    fn an_ok_response_yields_the_authenticated_identity_without_control_characters() {
        let outcome = parse_auth_response("OK\t1\tuser=alice@example.org\thome=/var/vmail")
            .expect("应能解析");
        assert_eq!(
            outcome,
            AuthOutcome::Success {
                user: "alice@example.org".to_string()
            }
        );

        let outcome = parse_auth_response("OK\t1\tuser=ali\u{1}rce").expect("应能解析");
        match outcome {
            AuthOutcome::Success { user } => assert_eq!(user, "alice"),
            other => panic!("应为成功，实际 {other:?}"),
        }
    }

    #[test]
    fn an_ok_without_a_user_field_still_succeeds() {
        assert_eq!(
            parse_auth_response("OK\t1").unwrap(),
            AuthOutcome::Success {
                user: "unknown".to_string()
            }
        );
    }

    #[test]
    fn a_fail_without_temp_is_a_credential_failure_but_one_with_temp_is_not() {
        assert_eq!(
            parse_auth_response("FAIL\t1").unwrap(),
            AuthOutcome::InvalidCredentials
        );
        assert_eq!(
            parse_auth_response("FAIL\t1\treason=Password+expired").unwrap(),
            AuthOutcome::InvalidCredentials
        );
        match parse_auth_response("FAIL\t1\ttemp\treason=Internal+error").unwrap() {
            AuthOutcome::TemporaryFailure(reason) => assert_eq!(reason, "Internal+error"),
            other => panic!("应为临时失败，实际 {other:?}"),
        }
    }

    #[test]
    fn a_response_for_another_request_id_is_a_protocol_error() {
        assert!(parse_auth_response("OK\t2\tuser=alice").is_err());
        assert!(
            parse_auth_response("CONT\t1\tAAA=").is_err(),
            "PLAIN 不应有第二轮"
        );
        assert!(parse_auth_response("WHAT\t1").is_err());
        assert!(parse_auth_response("").is_err());
    }

    #[tokio::test]
    async fn a_handshake_without_a_version_or_done_is_refused() {
        let mut reader = BufReader::new(&b"MECH\tPLAIN\nDONE\n"[..]);
        assert!(
            read_handshake(&mut reader).await.is_err(),
            "缺 VERSION 必须拒绝"
        );

        let mut reader = BufReader::new(&b"VERSION\t2\t0\nMECH\tPLAIN\nDONE\n"[..]);
        assert!(
            read_handshake(&mut reader).await.is_err(),
            "主版本不符必须拒绝"
        );

        let mut reader = BufReader::new(&b"VERSION\t1\t2\nMECH\tPLAIN\n"[..]);
        assert!(
            read_handshake(&mut reader).await.is_err(),
            "没有 DONE 必须拒绝"
        );
    }

    #[tokio::test]
    async fn a_well_formed_handshake_reports_the_offered_mechanisms() {
        let mut reader = BufReader::new(
            &b"VERSION\t1\t2\nSPID\t42\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\nDONE\n"[..],
        );
        assert_eq!(
            read_handshake(&mut reader).await.unwrap(),
            vec!["PLAIN", "LOGIN"]
        );
    }

    #[test]
    fn machine_names_that_could_break_the_protocol_line_are_rejected() {
        assert!(is_safe_token("PLAIN"));
        assert!(is_safe_token("X-OAUTH2"));
        assert!(!is_safe_token(""));
        assert!(!is_safe_token("PL\tAIN"), "TAB 不得进入协议行");
        assert!(!is_safe_token("PLAIN\nAUTH\t1\tPLAIN"));
        assert!(!is_safe_token(&"A".repeat(33)));
    }

    #[tokio::test]
    async fn the_unavailable_backend_is_a_temporary_failure_not_a_pass() {
        let outcome = UnavailableAuthenticator
            .authenticate(AuthRequest {
                mechanism: "PLAIN".to_string(),
                response: "AGJvYg==".to_string(),
                secured: true,
                peer: "203.0.113.7:54321".parse().unwrap(),
            })
            .await;
        assert!(matches!(outcome, AuthOutcome::TemporaryFailure(_)));
    }

    const STRONG: &str = "Correct-Horse-9-Battery";

    fn plain_response(user: &str, password: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"))
    }

    fn password_request(user: &str, password: &str) -> AuthRequest {
        AuthRequest {
            mechanism: "PLAIN".to_string(),
            response: plain_response(user, password),
            secured: true,
            peer: "203.0.113.7:54321".parse().unwrap(),
        }
    }

    fn store_with(dir: &std::path::Path, records: &[PasswordRecord]) -> MailboxPasswords {
        let passwords = MailboxPasswords::new(dir.join("mailbox-passwords.json"));
        for record in records {
            passwords.upsert(record).unwrap();
        }
        passwords
    }

    fn address_record(address: &str) -> PasswordRecord {
        mailstack_core::password::mailbox_password_record(address, STRONG).unwrap()
    }

    #[tokio::test]
    async fn a_full_address_authenticates_against_the_mailbox_password_store() {
        let dir = tempfile::tempdir().unwrap();
        let passwords = store_with(dir.path(), &[address_record("alice@example.com")]);
        let auth = MailboxPasswordsAuthenticator::new(passwords);
        assert_eq!(
            auth.authenticate(password_request("Alice@Example.com", STRONG))
                .await,
            AuthOutcome::Success {
                user: "alice@example.com".to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_bare_account_name_matches_its_bare_record_but_not_an_address() {
        let dir = tempfile::tempdir().unwrap();
        let passwords = store_with(dir.path(), &[password_record("alice", STRONG).unwrap()]);
        let auth = MailboxPasswordsAuthenticator::new(passwords);
        assert!(matches!(
            auth.authenticate(password_request("alice", STRONG)).await,
            AuthOutcome::Success { .. }
        ));
        assert_eq!(
            auth.authenticate(password_request("bob@other.example", STRONG))
                .await,
            AuthOutcome::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn a_wrong_password_or_unknown_user_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let passwords = store_with(dir.path(), &[address_record("alice@example.com")]);
        let auth = MailboxPasswordsAuthenticator::new(passwords);
        assert_eq!(
            auth.authenticate(password_request(
                "alice@example.com",
                "Wrong-Horse-9-Battery"
            ))
            .await,
            AuthOutcome::InvalidCredentials
        );
        assert_eq!(
            auth.authenticate(password_request("nobody@example.com", STRONG))
                .await,
            AuthOutcome::InvalidCredentials
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn password_verification_does_not_block_the_async_worker() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();

        let auth = MailboxPasswordsAuthenticator::from_path(dir.path().join("missing.json"))
            .with_max_concurrent(2);

        let ticks = std::sync::Arc::new(AtomicUsize::new(0));
        let ticker_ticks = std::sync::Arc::clone(&ticks);
        let ticker = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                ticker_ticks.fetch_add(1, Ordering::Relaxed);
            }
        });

        let outcome = auth
            .authenticate(password_request("nobody@example.com", STRONG))
            .await;
        assert_eq!(outcome, AuthOutcome::InvalidCredentials);
        ticker.abort();
        assert!(
            ticks.load(Ordering::Relaxed) > 0,
            "PBKDF2 期间 async worker 必须能继续调度其他任务（当前被同步阻塞）"
        );
    }

    #[tokio::test]
    async fn a_corrupt_store_fails_closed_instead_of_passing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox-passwords.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let auth = MailboxPasswordsAuthenticator::from_path(&path);
        assert_eq!(
            auth.authenticate(password_request("alice@example.com", STRONG))
                .await,
            AuthOutcome::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn an_unsupported_mechanism_or_malformed_response_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let auth = MailboxPasswordsAuthenticator::new(store_with(dir.path(), &[]));
        let mut request = password_request("alice@example.com", STRONG);
        request.mechanism = "LOGIN".to_string();
        assert!(matches!(
            auth.authenticate(request).await,
            AuthOutcome::TemporaryFailure(_)
        ));
        let mut request = password_request("alice@example.com", STRONG);
        request.response = "not*base64".to_string();
        assert_eq!(
            auth.authenticate(request).await,
            AuthOutcome::InvalidCredentials
        );
    }
}
