//! 提交端口的 SASL 认证（RFC 4954）与 Dovecot auth socket 客户端（规格书 §3.5）。
//!
//! ## 为什么认证要问 Dovecot，而不是自己读一份口令表
//!
//! 重写后**没有** Postfix，也就没有 `smtpd_sasl_type = dovecot` 这层转接；但口令的
//! 真相源仍然只有一份 —— Dovecot 的 passdb。自己去读 `/etc/shadow` 或另建一份哈希
//! 表，等于凭空多出第二份真相源，改密时必然漂移。所以这里实现的是 Dovecot 的
//! **auth-client 协议**（v1.2）的一个最小客户端：把凭据转给 Dovecot，只拿回
//! 「成功/失败」。
//!
//! ## 只发 PLAIN，且只在 TLS 之上
//!
//! PLAIN 的应答就是 `\0user\0pass` 的 base64 —— 口令本身。因此：
//!
//! 1. 会话层（[`crate::session`]）在明文连接上直接拒绝 `AUTH`（538），这一层
//!    永远拿不到凭据；
//! 2. 本模块**不解析**凭据内容，原样转发 base64 给 Dovecot，因此口令既不进入日志，
//!    也不进入任何字符串拼接之外的中间结构。
//!
//! ## 为什么 base64 必须在这里校验（安全，而不是正确性）
//!
//! Dovecot 的协议行是**制表符分隔**的。若把对端给的应答原样拼进协议行，一个含
//! TAB 的「应答」就会在 auth socket 上凭空多出一个字段 —— 这与 SMTP 命令注入同源，
//! 只不过注入面从 SMTP 搬到了 auth socket。防线：只接受严格 base64 字符集
//! （[`is_valid_base64`]），制表符与换行都不在其中。
//!
//! ## 失败分类
//!
//! * 连不上/超时/协议错乱 → [`AuthOutcome::TemporaryFailure`]（对外 454）：
//!   Dovecot 抖动不该被当成「口令错」，否则客户端会去改密码。
//! * Dovecot 明确回 `FAIL` 且不带 `temp` → [`AuthOutcome::InvalidCredentials`]（535）。

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Dovecot auth-client 的默认 socket 路径。
///
/// 去掉 Postfix 之后不再有 `/var/spool/postfix/private/auth` 这个 chroot 路径；外部
/// SASL 客户端连接的是 Dovecot 自己的 `auth-client` 监听器。可用 `MAILSTACK_DOVECOT_AUTH_SOCKET`
/// 覆盖（见 [`DovecotAuthClient::from_env`]）。
pub const DEFAULT_AUTH_SOCKET: &str = "/run/dovecot/auth-client";

/// 单行响应的长度上限。
///
/// Dovecot 保证认证相关数据能放进 16 KiB（协议文档原话），超过即视为协议错乱 ——
/// 不能因为对端（哪怕它是本机的 Dovecot）而无限缓冲。
const MAX_LINE: usize = 16 * 1024;

/// 握手横幅的行数上限。正常实现只有 VERSION/SPID/CUID/COOKIE + 若干 MECH。
const MAX_HANDSHAKE_LINES: usize = 64;

/// 默认的认证后端超时。
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// 一次认证请求（会话层已确认可以在当前连接上发起）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// SASL 机制名（当前只支持 `PLAIN`）。
    pub mechanism: String,
    /// 客户端给的 base64 应答；**已通过 [`is_valid_base64`]**。
    pub response: String,
    /// 会话是否已在 TLS 之上。仅用于向 Dovecot 声明 `secured`。
    pub secured: bool,
    /// 对端地址，用于传给 Dovecot 做日志/策略（`rip=` / `rport=`）。
    pub peer: SocketAddr,
}

/// 认证结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// 认证通过；`user` 为 Dovecot 确认的身份（仅用于日志与 `AUTH=` 参数）。
    Success { user: String },
    /// 凭据无效（口令错、用户不存在）。对外 535。
    InvalidCredentials,
    /// 无法判定（后端不可达、超时、协议错乱）。对外 454 —— 临时错误。
    TemporaryFailure(String),
}

/// 认证后端（可注入，便于测试与替换）。
pub type AuthFuture<'a> = Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>>;

/// 提交认证后端。
///
/// 实现者必须自己保证「不把凭据写进日志」—— 传入的 `response` 就是口令。
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: AuthRequest) -> AuthFuture<'_>;
}

/// 没有任何后端的占位实现。
///
/// 只在「会话不通告 AUTH」时被用到（此时 `AuthVerify` 根本不会产生）。真被调用说明
/// 配置被绕过，按临时错误处理而不是放行。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableAuthenticator;

impl Authenticator for UnavailableAuthenticator {
    fn authenticate(&self, _request: AuthRequest) -> AuthFuture<'_> {
        Box::pin(async { AuthOutcome::TemporaryFailure("no authentication backend".to_string()) })
    }
}

/// 可克隆的认证后端句柄（`ServerConfig` 要 `Clone`，而 `dyn Authenticator` 不能）。
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

/// 严格 base64 校验（RFC 4648 标准字母表 + `=` 填充）。
///
/// 之所以是**安全**检查而不是顺手做的格式检查：这个字符串会被拼进 Dovecot 的
/// 制表符分隔协议行（见模块说明）。返回 `false` 时上层必须回 501 而不是转发。
pub fn is_valid_base64(value: &str) -> bool {
    if value.is_empty() || value.len() % 4 != 0 {
        return false;
    }
    let bytes = value.as_bytes();
    // 填充只允许出现在末尾，且最多两个（`====` 不是合法 base64）。
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let body = &bytes[..bytes.len() - padding];
    if body.is_empty() {
        // 全是填充：`====` 已被上面的 padding 上限拦下，这里只剩 `=`/`==` 的情形。
        return false;
    }
    body.iter()
        .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
}

/// Dovecot auth-client（协议 v1.2）客户端。
#[derive(Debug, Clone)]
pub struct DovecotAuthClient {
    socket: PathBuf,
    service: String,
    timeout: Duration,
}

impl DovecotAuthClient {
    /// 生产默认：socket 取 [`DEFAULT_AUTH_SOCKET`]，service 为 `smtp`。
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            service: "smtp".to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// 从环境变量读取 socket 路径，缺省 [`DEFAULT_AUTH_SOCKET`]。
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

    /// 一次完整交换：握手 → AUTH → 解析应答。任何 I/O 或协议问题都是 `Err`，
    /// 由 [`Authenticator::authenticate`] 统一折算成 [`AuthOutcome::TemporaryFailure`]。
    async fn exchange(&self, request: &AuthRequest) -> std::io::Result<AuthOutcome> {
        let stream = UnixStream::connect(&self.socket).await?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        // 先声明协议版本（Dovecot 2.4 / 协议 1.3 会等这一行才发横幅；2.3 则已经发了）。
        let handshake = format!("VERSION\t1\t2\nCPID\t{}\n", std::process::id());
        write_half.write_all(handshake.as_bytes()).await?;
        write_half.flush().await?;

        let mechanisms = read_handshake(&mut reader).await?;
        if !mechanisms.iter().any(|name| name == &request.mechanism) {
            // 本机通告了 AUTH，但 Dovecot 没有对应机制 —— 配置不一致，不是口令问题。
            return Ok(AuthOutcome::TemporaryFailure(format!(
                "dovecot does not offer mechanism {}",
                request.mechanism
            )));
        }

        let mut line = format!("AUTH\t1\t{}\tservice={}", request.mechanism, self.service);
        if request.secured {
            // 如实声明：会话确实在 TLS 之上（会话层已保证明文上不认证）。
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
            // 机制名来自命令解析器，理论上已被会话限制为 PLAIN；这里再挡一次，
            // 因为它同样会被拼进协议行。
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

/// 读服务端握手横幅，返回它通告的机制名。
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
                // 主版本必须一致，否则两边说的不是同一个协议。
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
            // SPID / CUID / COOKIE / CPID 等对认证判定没有影响。
            _ => {}
        }
    }
    Err(protocol_error("handshake did not finish"))
}

/// 解析 `OK` / `FAIL` / `CONT` 应答。
fn parse_auth_response(line: &str) -> std::io::Result<AuthOutcome> {
    let mut fields = line.split('\t');
    let status = fields.next().unwrap_or_default();
    // 第二个字段是请求 id；我们每次只用 id=1 连一条新连接。
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
        // PLAIN 的应答是一次性给全的，Dovecot 不应再要一轮；收到 CONT 说明双方对
        // 机制的理解不一致。
        "CONT" => Err(protocol_error(
            "unexpected CONT for a single-shot mechanism",
        )),
        _ => Err(protocol_error("unrecognised auth socket status")),
    }
}

/// 在 `key=value` 参数里取值，并按 Dovecot 的制表符转义规则还原、剔除控制字符。
fn lookup_parameter(parameters: &[&str], key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    parameters
        .iter()
        .find_map(|field| field.strip_prefix(&prefix))
        .map(|value| sanitize_identity(&unescape_tab(value)))
}

/// Dovecot 的通用制表符转义：`\001` 是转义引导，后跟 `0/1/t/r/l`。
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

/// 身份字符串只用于日志与 `AUTH=` 参数：控制字符一律剔除（否则是一个日志注入面）。
fn sanitize_identity(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

/// 机制名是否是可安全拼进协议行的 token。
fn is_safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// 读一行（含 LF）并有长度上限。返回 `None` 表示对端在读到任何字节前关闭。
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

    #[test]
    fn base64_validation_rejects_anything_that_could_inject_a_protocol_field() {
        // 这条同时是正确性与安全性要求：TAB / LF / CR 若混进应答，就会在
        // Dovecot 的制表符分隔协议行里凭空多出字段。
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
        // 未定义的转义序列按「原样输出该字符」处理（与 Dovecot 一致）。
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

        // user 里混进控制字符不得变成日志注入面。
        let outcome = parse_auth_response("OK\t1\tuser=ali\u{1}rce").expect("应能解析");
        match outcome {
            AuthOutcome::Success { user } => assert_eq!(user, "alice"),
            other => panic!("应为成功，实际 {other:?}"),
        }
    }

    #[test]
    fn an_ok_without_a_user_field_still_succeeds() {
        // 不同 passdb 返回的字段不同；缺 user 不能当成失败。
        assert_eq!(
            parse_auth_response("OK\t1").unwrap(),
            AuthOutcome::Success {
                user: "unknown".to_string()
            }
        );
    }

    #[test]
    fn a_fail_without_temp_is_a_credential_failure_but_one_with_temp_is_not() {
        // 分类错误会让客户端在 Dovecot 抖动时去改密码，或把口令错当成临时故障重试。
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
        // 应答串了号意味着双方对「哪条请求在飞」的认知已经分叉。
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
        // 用固定输入直接驱动解析器，不需要真实 socket。
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
        // 配置被绕过时宁可拒绝，也不能放行。
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
}
