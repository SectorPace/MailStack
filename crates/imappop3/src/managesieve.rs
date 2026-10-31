//! ManageSieve（RFC 5804）：脚本上传与管理协议（默认 4190，STARTTLS/隐式 TLS）。
//!
//! ## 协议面
//!
//! 支持 `CAPABILITY`、`NOOP`、`LOGOUT`、`STARTTLS`、`AUTHENTICATE PLAIN`、
//! `LISTSCRIPTS`、`GETSCRIPT`、`PUTSCRIPT`、`CHECKSCRIPT`、`SETACTIVE`、
//! `DELETESCRIPT`、`RENAMESCRIPT`、`HAVESPACE`。
//!
//! ## 安全与正确性
//!
//! * **先认证、后取存储**：认证通过后用部署层注入的 [`MailboxResolver`] 找到该用户
//!   的 Maildir；未知用户拒绝。脚本只落在本人 Maildir 的 `sieve/` 下。
//! * **上传即校验**：`PUTSCRIPT` / `CHECKSCRIPT` 用同一套 [`crate::sieve`] 编译器
//!   验证；本服务端不支持的扩展（如 `vacation`）会在这里被明确拒绝，而不是存下一个
//!   永不生效的脚本。
//! * **脚本名校验**：仅字母数字与 `._-`、≤128、不以 `.` 开头，杜绝路径穿越。
//! * 活动脚本由 `sieve/.active` 标记；LMTP 投递读取它（`sieve::load_script`）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::auth::{AuthBackend, AuthOutcome, AuthRequest};
use crate::error::{MailError, Result};
use crate::lineio::LineIo;
use crate::maildir::MailStore;
use crate::metrics::Metrics;
use crate::resolver::MailboxResolver;
use crate::sieve;

const MAX_LINE: usize = 64 * 1024;
const MAX_SCRIPT: usize = 64 * 1024;

#[derive(Clone)]
pub struct ManageSieveContext {
    pub auth: AuthBackend,
    pub resolver: Arc<dyn MailboxResolver>,
    pub read_timeout: Duration,
}

impl ManageSieveContext {
    pub fn new(auth: AuthBackend, resolver: Arc<dyn MailboxResolver>) -> Self {
        Self {
            auth,
            resolver,
            read_timeout: Duration::from_secs(5 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManageSieveServerConfig {
    pub bind: SocketAddr,
    pub implicit_tls: bool,
    pub max_connections: usize,
    pub handshake_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl Default for ManageSieveServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:4190".parse().expect("常量地址合法"),
            implicit_tls: false,
            max_connections: 128,
            handshake_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

pub enum ManageSieveExit<S> {
    Logout(S),
    StartTls(S),
    Closed(S),
}

struct Command {
    name: String,
    args: Vec<String>,
    literal: Option<Vec<u8>>,
}

enum Control {
    Continue,
    Logout,
    StartTls,
}

struct Session<'a, S> {
    io: LineIo<S>,
    ctx: &'a ManageSieveContext,
    peer: SocketAddr,
    secured: bool,
    starttls: bool,
    user: Option<String>,
    store: Option<Arc<MailStore>>,
}

/// 在一条已建立的连接上跑 ManageSieve 会话（`secured` 表示已在 TLS 上）。
pub async fn serve_connection<S>(
    stream: S,
    ctx: &ManageSieveContext,
    peer: SocketAddr,
    secured: bool,
    starttls: bool,
) -> Result<ManageSieveExit<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Session {
        io: LineIo::new(stream),
        ctx,
        peer,
        secured,
        starttls,
        user: None,
        store: None,
    }
    .run()
    .await
}

impl<S> Session<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self) -> Result<ManageSieveExit<S>> {
        self.send_capabilities().await?;
        loop {
            let read = timeout(self.ctx.read_timeout, read_command(&mut self.io)).await;
            let command = match read {
                Err(_) => {
                    let _ = self.bye("idle timeout").await;
                    let _ = self.io.flush().await;
                    return Ok(ManageSieveExit::Closed(self.io.into_inner()));
                }
                Ok(Err(error)) => {
                    let _ = self.no(&error.to_string()).await;
                    let _ = self.io.flush().await;
                    return Ok(ManageSieveExit::Closed(self.io.into_inner()));
                }
                Ok(Ok(None)) => return Ok(ManageSieveExit::Closed(self.io.into_inner())),
                Ok(Ok(Some(command))) => command,
            };
            match self.dispatch(command).await {
                Ok(Control::Continue) => self.io.flush().await?,
                Ok(Control::Logout) => {
                    self.io.flush().await?;
                    return Ok(ManageSieveExit::Logout(self.io.into_inner()));
                }
                Ok(Control::StartTls) => {
                    self.io.flush().await?;
                    return Ok(ManageSieveExit::StartTls(self.io.into_inner()));
                }
                Err(error) => {
                    let _ = self.no(&error.to_string()).await;
                    self.io.flush().await?;
                }
            }
        }
    }

    async fn dispatch(&mut self, command: Command) -> Result<Control> {
        match command.name.as_str() {
            "CAPABILITY" => self.send_capabilities().await?,
            "NOOP" => self.ok("NOOP completed").await?,
            "LOGOUT" => {
                self.ok("LOGOUT completed").await?;
                return Ok(Control::Logout);
            }
            "STARTTLS" => {
                if self.secured || !self.starttls {
                    self.no("STARTTLS is not available").await?;
                } else if self.user.is_some() {
                    self.no("STARTTLS is not allowed after authentication")
                        .await?;
                } else {
                    self.ok("begin TLS negotiation").await?;
                    return Ok(Control::StartTls);
                }
            }
            "AUTHENTICATE" => self.handle_authenticate(&command).await?,
            _ if self.store.is_none() => self.no("authenticate first").await?,
            "LISTSCRIPTS" => self.handle_listscripts().await?,
            "GETSCRIPT" => self.handle_getscript(&command).await?,
            "PUTSCRIPT" => self.handle_putscript(&command, false).await?,
            "CHECKSCRIPT" => self.handle_putscript(&command, true).await?,
            "SETACTIVE" => self.handle_setactive(&command).await?,
            "DELETESCRIPT" => self.handle_deletescript(&command).await?,
            "RENAMESCRIPT" => self.handle_renamescript(&command).await?,
            "HAVESPACE" => self.ok("space available").await?,
            _ => self.no("unknown command").await?,
        }
        Ok(Control::Continue)
    }

    async fn handle_authenticate(&mut self, command: &Command) -> Result<()> {
        if self.user.is_some() {
            return self.no("already authenticated").await;
        }
        if command.args.len() < 2 {
            return self.no("AUTHENTICATE requires a mechanism and data").await;
        }
        if !command.args[0].eq_ignore_ascii_case("PLAIN") {
            return self.no("unsupported authentication mechanism").await;
        }
        let Ok(payload) =
            base64::engine::general_purpose::STANDARD.decode(command.args[1].as_bytes())
        else {
            return self.no("invalid base64 in AUTHENTICATE").await;
        };
        let fields: Vec<&[u8]> = payload.split(|byte| *byte == 0).collect();
        let (user, password) = match fields.as_slice() {
            [_, user, password] => (*user, *password),
            [user, password] => (*user, *password),
            _ => return self.no("malformed SASL PLAIN response").await,
        };
        let request = AuthRequest {
            user: String::from_utf8_lossy(user).to_string(),
            password: String::from_utf8_lossy(password).to_string(),
            secured: self.secured,
            peer: self.peer,
            service: "sieve",
        };
        match self.ctx.auth.as_dyn().authenticate(request).await {
            AuthOutcome::Success { user } => match self.ctx.resolver.resolve(&user) {
                Some(store) => {
                    self.user = Some(user);
                    self.store = Some(store);
                    self.send_capabilities().await?;
                }
                None => self.no("no mailbox for this user").await?,
            },
            AuthOutcome::InvalidCredentials => self.no("invalid credentials").await?,
            AuthOutcome::TemporaryFailure(_) => {
                self.no("authentication backend unavailable").await?
            }
        }
        Ok(())
    }

    async fn handle_listscripts(&mut self) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        for (name, active) in sieve::list_scripts(&store)? {
            let quoted = quote(&name);
            if active {
                self.line(&format!("{quoted} ACTIVE")).await?;
            } else {
                self.line(&quoted).await?;
            }
        }
        self.ok("LISTSCRIPTS completed").await
    }

    async fn handle_getscript(&mut self, command: &Command) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        let Some(name) = command.args.first() else {
            return self.no("GETSCRIPT requires a name").await;
        };
        match sieve::get_script(&store, name)? {
            None => self.no("script not found").await,
            Some(source) => {
                self.io
                    .write_all(format!("{{{}+}}\r\n", source.len()).as_bytes())
                    .await?;
                self.io.write_all(source.as_bytes()).await?;
                self.io.write_all(b"\r\n").await?;
                self.ok("GETSCRIPT completed").await
            }
        }
    }

    async fn handle_putscript(&mut self, command: &Command, check_only: bool) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        let Some(literal) = command.literal.as_deref() else {
            return self.no("script must be sent as a literal").await;
        };
        if literal.len() > MAX_SCRIPT {
            return self.no("script exceeds 64 KiB").await;
        }
        let source = String::from_utf8_lossy(literal);
        if let Err(error) = sieve::compile(&source) {
            return self.no(&format!("script is invalid: {error}")).await;
        }
        if check_only {
            return self.ok("CHECKSCRIPT completed").await;
        }
        let Some(name) = command.args.first() else {
            return self.no("PUTSCRIPT requires a name").await;
        };
        if let Err(error) = sieve::put_script(&store, name, &source) {
            return self.no(&error.to_string()).await;
        }
        self.ok("PUTSCRIPT completed").await
    }

    async fn handle_setactive(&mut self, command: &Command) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        let name = command.args.first().cloned().unwrap_or_default();
        let active = if name.is_empty() {
            None
        } else {
            Some(name.as_str())
        };
        if let Err(error) = sieve::set_active(&store, active) {
            return self.no(&error.to_string()).await;
        }
        self.ok("SETACTIVE completed").await
    }

    async fn handle_deletescript(&mut self, command: &Command) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        let Some(name) = command.args.first() else {
            return self.no("DELETESCRIPT requires a name").await;
        };
        if let Err(error) = sieve::delete_script(&store, name) {
            return self.no(&error.to_string()).await;
        }
        self.ok("DELETESCRIPT completed").await
    }

    async fn handle_renamescript(&mut self, command: &Command) -> Result<()> {
        let Some(store) = self.store.clone() else {
            return self.no("authenticate first").await;
        };
        if command.args.len() < 2 {
            return self.no("RENAMESCRIPT requires old and new names").await;
        }
        if let Err(error) = sieve::rename_script(&store, &command.args[0], &command.args[1]) {
            return self.no(&error.to_string()).await;
        }
        self.ok("RENAMESCRIPT completed").await
    }

    async fn send_capabilities(&mut self) -> Result<()> {
        self.line("\"IMPLEMENTATION\" \"MailStack ManageSieve\"")
            .await?;
        self.line("\"VERSION\" \"1.0\"").await?;
        self.line("\"SIEVE\" \"fileinto reject body redirect vacation\"")
            .await?;
        if self.user.is_none() {
            self.line("\"SASL\" \"PLAIN\"").await?;
            if self.starttls && !self.secured {
                self.line("\"STARTTLS\"").await?;
            }
        }
        self.line("OK \"ManageSieve ready\"").await
    }

    async fn line(&mut self, text: &str) -> Result<()> {
        self.io.write_all(text.as_bytes()).await?;
        self.io.write_all(b"\r\n").await
    }

    async fn ok(&mut self, message: &str) -> Result<()> {
        self.line(&format!("OK \"{}\"", escape(message))).await
    }

    async fn no(&mut self, message: &str) -> Result<()> {
        self.line(&format!("NO \"{}\"", escape(message))).await
    }

    async fn bye(&mut self, message: &str) -> Result<()> {
        self.line(&format!("BYE \"{}\"", escape(message))).await
    }
}

async fn read_command<S>(io: &mut LineIo<S>) -> Result<Option<Command>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(line) = io.read_line(MAX_LINE).await? else {
        return Ok(None);
    };
    let line = String::from_utf8_lossy(&line).to_string();
    let mut tokens = tokenize(&line)?;
    let mut literal = None;
    if let Some(last) = tokens.last() {
        if let Some(size) = literal_marker(last) {
            tokens.pop();
            literal = Some(io.read_exact(size, MAX_SCRIPT).await?);
        }
    }
    if tokens.is_empty() {
        return Ok(None);
    }
    let name = tokens.remove(0).to_ascii_uppercase();
    Ok(Some(Command {
        name,
        args: tokens,
        literal,
    }))
}

/// 解析 `{n+}` / `{n}` 字面量标记。
fn literal_marker(token: &str) -> Option<usize> {
    let inner = token.strip_prefix('{')?.strip_suffix('}')?;
    let inner = inner.strip_suffix('+').unwrap_or(inner);
    if inner.is_empty() || !inner.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    inner.parse().ok()
}

/// 把一行拆成 token：双引号字符串（支持 `\"`、`\\` 转义）与裸 token。
fn tokenize(line: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(' ') | Some('\t')) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        if chars.peek() == Some(&'"') {
            chars.next();
            let mut value = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some(escaped @ ('"' | '\\')) => value.push(escaped),
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                        }
                        None => return Err(MailError::protocol("unterminated escape")),
                    },
                    Some(ch) => value.push(ch),
                    None => return Err(MailError::protocol("unterminated string")),
                }
            }
            tokens.push(value);
        } else {
            let mut value = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == ' ' || ch == '\t' {
                    break;
                }
                value.push(ch);
                chars.next();
            }
            tokens.push(value);
        }
    }
    Ok(tokens)
}

fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn escape(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch == '"' || ch == '\\' || ch.is_control() {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// 监听器
// ---------------------------------------------------------------------------

pub struct ManageSieveServer {
    pub context: ManageSieveContext,
    pub config: ManageSieveServerConfig,
    pub tls: Option<TlsAcceptor>,
    pub metrics: Arc<Metrics>,
}

impl ManageSieveServer {
    pub fn new(
        context: ManageSieveContext,
        config: ManageSieveServerConfig,
        tls: Option<TlsAcceptor>,
    ) -> Result<Self> {
        if config.max_connections == 0 {
            return Err(MailError::config("max_connections must be positive"));
        }
        if config.implicit_tls && tls.is_none() {
            return Err(MailError::config("implicit TLS requires a TlsAcceptor"));
        }
        Ok(Self {
            context,
            config,
            tls,
            metrics: Arc::new(Metrics::new("managesieve")),
        })
    }

    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub async fn serve(self, shutdown: watch::Receiver<bool>) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.bind).await?;
        let local = listener.local_addr()?;
        tracing::info!(addr = %local, "ManageSieve server listening");
        self.serve_on(listener, shutdown).await
    }

    pub async fn serve_on(
        self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        if *shutdown.borrow() {
            return Ok(());
        }
        let semaphore = Arc::new(Semaphore::new(self.config.max_connections));
        let context = Arc::new(self.context);
        let config = Arc::new(self.config);
        let tls = self.tls;
        let metrics = self.metrics;
        let mut tasks: JoinSet<()> = JoinSet::new();

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => pair,
                        Err(error) => {
                            tracing::warn!(%error, "ManageSieve accept failed");
                            continue;
                        }
                    };
                    let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            metrics.connection_busy();
                            let mut stream = stream;
                            let _ = stream.write_all(b"BYE \"Server busy\"\r\n").await;
                            continue;
                        }
                    };
                    metrics.connection_accepted();
                    let context = Arc::clone(&context);
                    let config = Arc::clone(&config);
                    let tls = tls.clone();
                    let metrics = Arc::clone(&metrics);
                    tasks.spawn(async move {
                        let _permit = permit;
                        handle_connection(stream, peer, context, config, tls, metrics).await;
                    });
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "ManageSieve connection task panicked");
                    }
                }
            }
        }

        let grace = config.shutdown_grace;
        if timeout(grace, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "ManageSieve connection task panicked during shutdown");
                }
            }
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            tracing::warn!("ManageSieve connections exceeded the shutdown grace; aborted");
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    context: Arc<ManageSieveContext>,
    config: Arc<ManageSieveServerConfig>,
    tls: Option<TlsAcceptor>,
    metrics: Arc<Metrics>,
) {
    let _active = Metrics::track_active(&metrics);
    if config.implicit_tls {
        let Some(acceptor) = tls else {
            return;
        };
        match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => {
                finish_session(stream, peer, &context, true, false, &metrics).await;
            }
            Ok(Err(error)) => {
                metrics.tls_handshake_failed();
                tracing::warn!(%peer, %error, "ManageSieve TLS handshake failed");
            }
            Err(_) => {
                metrics.tls_handshake_timeout();
                tracing::warn!(%peer, "ManageSieve TLS handshake timed out");
            }
        }
        return;
    }

    match serve_connection(stream, &context, peer, false, tls.is_some()).await {
        Ok(ManageSieveExit::StartTls(stream)) => {
            let Some(acceptor) = tls else {
                return;
            };
            match timeout(config.handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    finish_session(stream, peer, &context, true, false, &metrics).await;
                }
                Ok(Err(error)) => {
                    metrics.tls_handshake_failed();
                    tracing::warn!(%peer, %error, "ManageSieve STARTTLS handshake failed");
                }
                Err(_) => {
                    metrics.tls_handshake_timeout();
                    tracing::warn!(%peer, "ManageSieve STARTTLS handshake timed out");
                }
            }
        }
        Ok(ManageSieveExit::Logout(_)) | Ok(ManageSieveExit::Closed(_)) => {
            metrics.session_completed();
        }
        Err(error) => {
            if error.is_server_error() {
                metrics.session_server_error();
                tracing::warn!(%peer, %error, "ManageSieve session ended with a server error");
            } else {
                metrics.session_completed();
                tracing::debug!(%peer, %error, "ManageSieve session ended");
            }
        }
    }
}

async fn finish_session<S>(
    stream: S,
    peer: SocketAddr,
    context: &ManageSieveContext,
    secured: bool,
    starttls: bool,
    metrics: &Metrics,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match serve_connection(stream, context, peer, secured, starttls).await {
        Ok(ManageSieveExit::Logout(_)) | Ok(ManageSieveExit::Closed(_)) => {
            metrics.session_completed()
        }
        Ok(ManageSieveExit::StartTls(_)) => metrics.session_completed(),
        Err(error) => {
            if error.is_server_error() {
                metrics.session_server_error();
                tracing::warn!(%peer, %error, "ManageSieve session ended with a server error");
            } else {
                metrics.session_completed();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{MemoryDirectory, PasswordDirectory};
    use crate::maildir::SystemClock;
    use crate::resolver::MapResolver;
    use tokio::io::{AsyncBufReadExt, BufReader, DuplexStream};

    const PASSWORD: &str = "Correct-Horse-9-Battery";

    fn setup() -> (tempfile::TempDir, Arc<MailStore>, ManageSieveContext) {
        let directory = tempfile::tempdir().unwrap();
        let store =
            Arc::new(MailStore::new(directory.path().join("bob"), Arc::new(SystemClock)).unwrap());
        let mut record = mailstack_core::password::password_record("bob", PASSWORD).unwrap();
        record.username = "bob@example.com".to_string();
        let mut users = MemoryDirectory::new();
        users.insert(record);
        let auth = AuthBackend::new(Arc::new(PasswordDirectory::new(users)));
        let mut resolver = MapResolver::new();
        resolver.insert("bob@example.com", Arc::clone(&store));
        let context = ManageSieveContext::new(auth, Arc::new(resolver));
        (directory, store, context)
    }

    fn plain_b64() -> String {
        base64::engine::general_purpose::STANDARD.encode(format!("\0bob@example.com\0{PASSWORD}"))
    }

    struct Client {
        io: BufReader<DuplexStream>,
    }

    impl Client {
        fn new(io: DuplexStream) -> Self {
            Self {
                io: BufReader::new(io),
            }
        }

        async fn send(&mut self, line: &str) {
            let io = self.io.get_mut();
            io.write_all(line.as_bytes()).await.unwrap();
            io.write_all(b"\r\n").await.unwrap();
            io.flush().await.unwrap();
        }

        async fn send_literal(&mut self, prefix: &str, data: &str) {
            let io = self.io.get_mut();
            io.write_all(format!("{prefix} {{{}+}}\r\n", data.len()).as_bytes())
                .await
                .unwrap();
            io.write_all(data.as_bytes()).await.unwrap();
            io.flush().await.unwrap();
        }

        async fn line(&mut self) -> String {
            let mut line = String::new();
            let read = timeout(Duration::from_secs(5), self.io.read_line(&mut line))
                .await
                .expect("read timed out")
                .unwrap();
            assert!(read > 0, "connection closed");
            line.trim_end_matches("\r\n").to_string()
        }

        async fn until_terminal(&mut self) -> Vec<String> {
            let mut lines = Vec::new();
            loop {
                let line = self.line().await;
                let done =
                    line.starts_with("OK") || line.starts_with("NO") || line.starts_with("BYE");
                lines.push(line);
                if done {
                    return lines;
                }
            }
        }
    }

    fn spawn(
        context: ManageSieveContext,
    ) -> (
        Client,
        tokio::task::JoinHandle<Result<ManageSieveExit<DuplexStream>>>,
    ) {
        let context = Arc::new(context);
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let handle = tokio::spawn(async move {
            serve_connection(
                server_io,
                &context,
                "192.0.2.10:50000".parse().unwrap(),
                false,
                false,
            )
            .await
        });
        (Client::new(client_io), handle)
    }

    #[tokio::test]
    async fn managesieve_auth_and_script_lifecycle() {
        let (_dir, store, context) = setup();
        let (mut client, handle) = spawn(context);

        let greeting = client.until_terminal().await;
        assert!(greeting[0].contains("IMPLEMENTATION"), "{greeting:?}");
        assert!(greeting.last().unwrap().starts_with("OK"), "{greeting:?}");

        // 未认证访问脚本命令 → NO。
        client.send("LISTSCRIPTS").await;
        assert!(client.until_terminal().await[0].starts_with("NO"));

        // 错误口令 → NO。
        let bad = base64::engine::general_purpose::STANDARD.encode("\0bob@example.com\0wrong");
        client
            .send(&format!("AUTHENTICATE \"PLAIN\" \"{bad}\""))
            .await;
        assert!(client.until_terminal().await[0].starts_with("NO"));

        // 正确口令 → 能力行 + OK。
        client
            .send(&format!("AUTHENTICATE \"PLAIN\" \"{}\"", plain_b64()))
            .await;
        let authed = client.until_terminal().await;
        assert!(authed.last().unwrap().starts_with("OK"), "{authed:?}");

        // 无效脚本 → NO。
        client
            .send_literal("CHECKSCRIPT", "this is not sieve")
            .await;
        assert!(client.until_terminal().await[0].starts_with("NO"));

        // 上传有效脚本，设为活动。
        client
            .send_literal(
                "PUTSCRIPT \"filters\"",
                "require [\"fileinto\"]; fileinto \"Invoices\";",
            )
            .await;
        assert!(client.until_terminal().await[0].starts_with("OK"));
        client.send("SETACTIVE \"filters\"").await;
        assert!(client.until_terminal().await[0].starts_with("OK"));

        // 活动脚本被 LMTP 读取。
        let loaded = sieve::load_script(&store).unwrap().unwrap();
        assert!(loaded.contains("fileinto"), "{loaded}");

        // LISTSCRIPTS 标记 ACTIVE。
        client.send("LISTSCRIPTS").await;
        let listed = client.until_terminal().await;
        assert!(
            listed.iter().any(|l| l == "\"filters\" ACTIVE"),
            "{listed:?}"
        );

        // GETSCRIPT 返回字面量内容。
        client.send("GETSCRIPT \"filters\"").await;
        let header = client.line().await;
        assert!(header.starts_with('{') && header.ends_with('}'), "{header}");
        let mut content = String::new();
        let mut remaining: usize = header[1..header.len() - 1]
            .trim_end_matches('+')
            .parse()
            .unwrap();
        while remaining > 0 {
            let mut chunk = [0u8; 256];
            let n = self_read(&mut client, &mut chunk[..remaining.min(256)]).await;
            content.push_str(&String::from_utf8_lossy(&chunk[..n]));
            remaining -= n;
        }
        assert!(content.contains("fileinto"), "{content}");
        assert!(client
            .until_terminal()
            .await
            .last()
            .unwrap()
            .starts_with("OK"));

        // 重命名，活动标记跟随。
        client.send("RENAMESCRIPT \"filters\" \"main\"").await;
        assert!(client.until_terminal().await[0].starts_with("OK"));
        assert_eq!(
            sieve::active_script_name(&store).unwrap().as_deref(),
            Some("main")
        );

        // 删除活动脚本 → 活动清空。
        client.send("DELETESCRIPT \"main\"").await;
        assert!(client.until_terminal().await[0].starts_with("OK"));
        assert!(sieve::active_script_name(&store).unwrap().is_none());
        assert!(sieve::list_scripts(&store).unwrap().is_empty());

        client.send("LOGOUT").await;
        let _ = client.until_terminal().await;
        let _ = handle.await.unwrap().unwrap();
    }

    async fn self_read(client: &mut Client, buffer: &mut [u8]) -> usize {
        use tokio::io::AsyncReadExt;
        client.io.read(buffer).await.unwrap()
    }
}
