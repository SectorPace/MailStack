use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::auth::{AuthBackend, AuthOutcome, AuthRequest};
use crate::blocking;
use crate::error::{MailError, Result};
use crate::lineio::LineIo;
use crate::maildir::{FolderState, MailStore, MessageMeta};
use crate::mime;

#[derive(Debug, Clone)]
pub struct Pop3Config {
    pub server_name: String,
    pub require_tls: bool,
    pub max_auth_failures: u32,
    pub max_line: usize,
    pub read_timeout: Duration,

    pub max_message_size: u64,
}

impl Default for Pop3Config {
    fn default() -> Self {
        Self {
            server_name: "mailstack".to_string(),

            require_tls: true,
            max_auth_failures: 5,
            max_line: 1024,
            read_timeout: Duration::from_secs(10 * 60),
            max_message_size: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct Pop3SessionContext {
    pub store: Arc<MailStore>,
    pub auth: AuthBackend,
    pub config: Pop3Config,

    pub resolver: Option<Arc<dyn crate::resolver::MailboxResolver>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Pop3ConnectionOptions {
    pub secured: bool,
    pub starttls_available: bool,
    pub greet: bool,
}

pub enum Pop3Exit<S> {
    Logout(S),
    StartTls(S),
    Closed(S),
}

pub async fn serve_connection<S>(
    io: S,
    ctx: &Pop3SessionContext,
    peer: SocketAddr,
    options: Pop3ConnectionOptions,
) -> Result<Pop3Exit<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Pop3Session {
        io: LineIo::new(io),
        ctx,
        peer,
        secured: options.secured,
        starttls: options.starttls_available && !options.secured,
        state: State::Authorization { user: None },
        failures: 0,

        store: Arc::clone(&ctx.store),
    }
    .run(options.greet)
    .await
}

enum State {
    Authorization {
        user: Option<String>,
    },
    Transaction {
        _lock: File,
        uidvalidity: u32,
        messages: Vec<MessageMeta>,
        deleted: HashSet<usize>,
    },
}

enum Control {
    Continue,
    Logout,
    StartTls,
    Close,
}

struct Pop3Session<'a, S> {
    io: LineIo<S>,
    ctx: &'a Pop3SessionContext,
    peer: SocketAddr,
    secured: bool,
    starttls: bool,
    state: State,
    failures: u32,

    store: Arc<MailStore>,
}

impl<'a, S> Pop3Session<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self, greet: bool) -> Result<Pop3Exit<S>> {
        if greet {
            let greeting = format!("+OK {} POP3 ready\r\n", self.ctx.config.server_name);
            self.write_all(greeting.as_bytes()).await?;
            self.flush().await?;
        }
        loop {
            let read = tokio::time::timeout(
                self.ctx.config.read_timeout,
                self.io.read_line(self.ctx.config.max_line),
            )
            .await;
            let line = match read {
                Err(_) => {
                    self.err("idle timeout").await?;
                    return Ok(Pop3Exit::Closed(self.io.into_inner()));
                }
                Ok(Err(error)) => {
                    let _ = self.err(&format!("protocol error: {error}")).await;
                    return Ok(Pop3Exit::Closed(self.io.into_inner()));
                }
                Ok(Ok(None)) => return Ok(Pop3Exit::Closed(self.io.into_inner())),
                Ok(Ok(Some(line))) => line,
            };
            let text = String::from_utf8_lossy(&line).to_string();
            let (command, argument) = split_command(&text);
            match self.dispatch(&command, argument.as_deref()).await {
                Ok(Control::Continue) => {
                    self.flush().await?;
                }
                Ok(Control::Logout) => {
                    self.flush().await?;
                    return Ok(Pop3Exit::Logout(self.io.into_inner()));
                }
                Ok(Control::StartTls) => {
                    self.flush().await?;
                    return Ok(Pop3Exit::StartTls(self.io.into_inner()));
                }
                Ok(Control::Close) => {
                    self.flush().await?;
                    return Ok(Pop3Exit::Closed(self.io.into_inner()));
                }
                Err(error) => {
                    let message = match &error {
                        MailError::Invalid(message) | MailError::Protocol(message) => {
                            message.clone()
                        }
                        _ => {
                            tracing::warn!(peer = %self.peer, %error, "POP3 command failed");
                            "internal error".to_string()
                        }
                    };
                    self.err(&message).await?;
                    self.flush().await?;
                }
            }
        }
    }

    async fn dispatch(&mut self, command: &str, argument: Option<&str>) -> Result<Control> {
        match command {
            "CAPA" => {
                self.expect_no_argument(argument)?;
                self.capa().await?;
                Ok(Control::Continue)
            }
            "USER" => self.handle_user(argument).await,
            "PASS" => self.handle_pass(argument).await,
            "STLS" => self.handle_stls(argument).await,
            "STAT" => self.handle_stat(argument).await,
            "LIST" => self.handle_list(argument).await,
            "UIDL" => self.handle_uidl(argument).await,
            "RETR" => self.handle_retr(argument).await,
            "TOP" => self.handle_top(argument).await,
            "DELE" => self.handle_dele(argument).await,
            "RSET" => self.handle_rset(argument).await,
            "NOOP" => {
                self.expect_no_argument(argument)?;
                self.ok("").await?;
                Ok(Control::Continue)
            }
            "QUIT" => {
                self.expect_no_argument(argument)?;
                self.quit().await
            }
            "" => {
                self.err("empty command").await?;
                Ok(Control::Continue)
            }
            _ => {
                self.err("unknown command").await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn capa(&mut self) -> Result<()> {
        let mut lines = vec!["TOP", "USER", "UIDL", "IMPLEMENTATION MailStack"];
        if self.starttls {
            lines.push("STLS");
        }
        self.write_all(b"+OK Capability list follows\r\n").await?;
        for line in lines {
            self.write_all(line.as_bytes()).await?;
            self.write_all(b"\r\n").await?;
        }
        self.write_all(b".\r\n").await
    }

    async fn handle_user(&mut self, argument: Option<&str>) -> Result<Control> {
        let State::Authorization { .. } = self.state else {
            self.err("USER is not valid in TRANSACTION state").await?;
            return Ok(Control::Continue);
        };
        let Some(user) = argument else {
            self.err("USER requires a name").await?;
            return Ok(Control::Continue);
        };
        let user = user.trim();
        if user.is_empty() || user.len() > 320 {
            self.err("invalid user name").await?;
            return Ok(Control::Continue);
        }
        self.state = State::Authorization {
            user: Some(user.to_string()),
        };
        self.ok("send PASS").await?;
        Ok(Control::Continue)
    }

    async fn handle_pass(&mut self, argument: Option<&str>) -> Result<Control> {
        let user = match &self.state {
            State::Authorization { user } => match user.clone() {
                Some(user) => user,
                None => {
                    self.err("USER first").await?;
                    return Ok(Control::Continue);
                }
            },
            State::Transaction { .. } => {
                self.err("already authenticated").await?;
                return Ok(Control::Continue);
            }
        };
        let Some(password) = argument else {
            self.err("PASS requires a password").await?;
            return Ok(Control::Continue);
        };
        if self.ctx.config.require_tls && !self.secured {
            self.err("[AUTH] TLS is required before authentication")
                .await?;
            return Ok(Control::Continue);
        }

        let request = AuthRequest {
            user,
            password: password.to_string(),
            secured: self.secured,
            peer: self.peer,
            service: "pop3",
        };
        match self.ctx.auth.as_dyn().authenticate(request).await {
            AuthOutcome::Success { user } => {
                if let Some(resolver) = self.ctx.resolver.as_ref() {
                    let Some(store) = resolver.resolve(&user) else {
                        tracing::warn!(peer = %self.peer, user = %user, "pop3 login rejected: mailbox is not provisioned");
                        self.err("[SYS/TEMP] mailbox is not provisioned").await?;
                        return Ok(Control::Continue);
                    };
                    self.store = store;
                }
                self.enter_transaction().await
            }
            AuthOutcome::InvalidCredentials => {
                self.failures += 1;
                if self.failures >= self.ctx.config.max_auth_failures {
                    self.err("[AUTH] too many failed authentication attempts")
                        .await?;
                    return Ok(Control::Close);
                }
                self.err("[AUTH] invalid credentials").await?;
                Ok(Control::Continue)
            }
            AuthOutcome::TemporaryFailure(_) => {
                self.err("[SYS/TEMP] authentication backend is unavailable")
                    .await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn enter_transaction(&mut self) -> Result<Control> {
        let store = Arc::clone(&self.store);
        let lock = match blocking::maildir(&store, move |store| acquire_mailbox_lock(store.root()))
            .await
        {
            Ok(lock) => lock,
            Err(MailError::AlreadyExists(_)) => {
                self.err("[IN-USE] mailbox is in use").await?;
                return Ok(Control::Continue);
            }
            Err(error) => return Err(error),
        };
        let state = match blocking::maildir(&store, move |store| {
            store.open_folder(crate::maildir::INBOX, true)
        })
        .await
        {
            Ok(state) => state,
            Err(error) => return Err(error),
        };
        let FolderState {
            uidvalidity,
            messages,
            ..
        } = state;
        self.state = State::Transaction {
            _lock: lock,
            uidvalidity,
            messages,
            deleted: HashSet::new(),
        };
        self.ok("mailbox is ready").await?;
        Ok(Control::Continue)
    }

    async fn handle_stls(&mut self, argument: Option<&str>) -> Result<Control> {
        self.expect_no_argument(argument)?;
        if !matches!(self.state, State::Authorization { .. }) {
            self.err("STLS is only valid before authentication").await?;
            return Ok(Control::Continue);
        }
        if !self.starttls {
            self.err("STLS is not available").await?;
            return Ok(Control::Continue);
        }
        self.ok("Begin TLS negotiation now").await?;
        Ok(Control::StartTls)
    }

    async fn handle_stat(&mut self, argument: Option<&str>) -> Result<Control> {
        self.expect_no_argument(argument)?;
        let Some((count, size)) = self.statistics() else {
            self.err("no mailbox").await?;
            return Ok(Control::Continue);
        };
        self.ok(&format!("{count} {size}")).await?;
        Ok(Control::Continue)
    }

    async fn handle_list(&mut self, argument: Option<&str>) -> Result<Control> {
        match argument.map(str::trim).filter(|value| !value.is_empty()) {
            None => {
                let State::Transaction {
                    messages, deleted, ..
                } = &self.state
                else {
                    self.err("no mailbox").await?;
                    return Ok(Control::Continue);
                };
                let lines: Vec<String> = messages
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| !deleted.contains(index))
                    .map(|(index, message)| format!("{} {}", index + 1, message.size))
                    .collect();
                self.multiline("scan listing follows", &lines).await?;
                Ok(Control::Continue)
            }
            Some(_) => {
                let (index, message) = match self.lookup_message(argument) {
                    Ok(found) => found,
                    Err(message_text) => {
                        self.err(message_text).await?;
                        return Ok(Control::Continue);
                    }
                };
                self.ok(&format!("{} {}", index + 1, message.size)).await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn handle_uidl(&mut self, argument: Option<&str>) -> Result<Control> {
        match argument.map(str::trim).filter(|value| !value.is_empty()) {
            None => {
                let State::Transaction {
                    uidvalidity,
                    messages,
                    deleted,
                    ..
                } = &self.state
                else {
                    self.err("no mailbox").await?;
                    return Ok(Control::Continue);
                };
                let mut lines = Vec::new();
                for (index, message) in messages.iter().enumerate() {
                    if deleted.contains(&index) {
                        continue;
                    }
                    lines.push(format!("{} {}-{}", index + 1, uidvalidity, message.uid));
                }
                self.multiline("unique-id listing follows", &lines).await?;
                Ok(Control::Continue)
            }
            Some(_) => {
                let (index, message) = match self.lookup_message(argument) {
                    Ok(found) => found,
                    Err(message_text) => {
                        self.err(message_text).await?;
                        return Ok(Control::Continue);
                    }
                };
                let uidvalidity = match &self.state {
                    State::Transaction { uidvalidity, .. } => *uidvalidity,
                    _ => 0,
                };
                self.ok(&format!("{} {}-{}", index + 1, uidvalidity, message.uid))
                    .await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn handle_retr(&mut self, argument: Option<&str>) -> Result<Control> {
        let (_, message) = match self.lookup_message(argument) {
            Ok(found) => found,
            Err(message_text) => {
                self.err(message_text).await?;
                return Ok(Control::Continue);
            }
        };
        if message.size > self.ctx.config.max_message_size {
            self.err("message is too large to retrieve").await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&self.store);
        let meta = message.clone();
        let data = match blocking::maildir(&store, move |store| store.read(&meta)).await {
            Ok(data) => data,
            Err(error) => {
                tracing::warn!(%error, "POP3 RETR failed to read a message");
                self.err("message is unavailable").await?;
                return Ok(Control::Continue);
            }
        };
        self.write_all(format!("+OK {} octets\r\n", message.size).as_bytes())
            .await?;
        write_transfer(&mut self.io, &data, None).await?;
        self.write_all(b".\r\n").await?;
        Ok(Control::Continue)
    }

    async fn handle_top(&mut self, argument: Option<&str>) -> Result<Control> {
        let Some(argument) = argument else {
            self.err("TOP requires a message number and a line count")
                .await?;
            return Ok(Control::Continue);
        };
        let mut fields = argument.split_whitespace();
        let number = fields.next();
        let lines = fields.next();
        if fields.next().is_some() {
            self.err("TOP requires a message number and a line count")
                .await?;
            return Ok(Control::Continue);
        }
        let line_count: usize = match lines.and_then(|value| value.parse().ok()) {
            Some(value) if value <= 10_000 => value,
            _ => {
                self.err("invalid TOP line count").await?;
                return Ok(Control::Continue);
            }
        };
        let (_, message) = match self.lookup_message(number) {
            Ok(found) => found,
            Err(message_text) => {
                self.err(message_text).await?;
                return Ok(Control::Continue);
            }
        };
        if message.size > self.ctx.config.max_message_size {
            self.err("message is too large to retrieve").await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&self.store);
        let meta = message.clone();
        let data = match blocking::maildir(&store, move |store| store.read(&meta)).await {
            Ok(data) => data,
            Err(error) => {
                tracing::warn!(%error, "POP3 TOP failed to read a message");
                self.err("message is unavailable").await?;
                return Ok(Control::Continue);
            }
        };
        self.write_all(format!("+OK {} octets\r\n", message.size).as_bytes())
            .await?;
        write_transfer(&mut self.io, &data, Some(line_count)).await?;
        self.write_all(b".\r\n").await?;
        Ok(Control::Continue)
    }

    async fn handle_dele(&mut self, argument: Option<&str>) -> Result<Control> {
        let (index, _) = match self.lookup_message(argument) {
            Ok(found) => found,
            Err(message_text) => {
                self.err(message_text).await?;
                return Ok(Control::Continue);
            }
        };
        if let State::Transaction { deleted, .. } = &mut self.state {
            deleted.insert(index);
        }
        self.ok(&format!("message {} deleted", index + 1)).await?;
        Ok(Control::Continue)
    }

    async fn handle_rset(&mut self, argument: Option<&str>) -> Result<Control> {
        self.expect_no_argument(argument)?;
        match &mut self.state {
            State::Transaction { deleted, .. } => {
                deleted.clear();
                self.ok("mailbox reset").await?;
            }
            State::Authorization { user } => {
                *user = None;
                self.ok("session reset").await?;
            }
        }
        Ok(Control::Continue)
    }

    async fn quit(&mut self) -> Result<Control> {
        let uids: Vec<u32> = match &self.state {
            State::Transaction {
                messages, deleted, ..
            } => deleted
                .iter()
                .filter_map(|index| messages.get(*index).map(|message| message.uid))
                .collect(),
            State::Authorization { .. } => Vec::new(),
        };
        if !uids.is_empty() {
            let store = Arc::clone(&self.store);
            let targets = uids.clone();
            if let Err(error) = blocking::maildir(&store, move |store| {
                store.expunge(crate::maildir::INBOX, &targets)
            })
            .await
            {
                tracing::warn!(%error, "POP3 QUIT could not remove deleted messages");
                self.err("[SYS/TEMP] some deleted messages were not removed")
                    .await?;
                return Ok(Control::Continue);
            }
        }
        self.ok("bye").await?;
        Ok(Control::Logout)
    }

    fn lookup_message(
        &self,
        argument: Option<&str>,
    ) -> std::result::Result<(usize, MessageMeta), &'static str> {
        let State::Transaction {
            messages, deleted, ..
        } = &self.state
        else {
            return Err("no mailbox");
        };
        let number: usize = argument
            .and_then(|value| value.trim().parse().ok())
            .filter(|number| *number >= 1)
            .ok_or("invalid message number")?;
        let index = number - 1;
        if deleted.contains(&index) {
            return Err("message is deleted");
        }
        messages
            .get(index)
            .cloned()
            .map(|message| (index, message))
            .ok_or("no such message")
    }

    fn statistics(&self) -> Option<(usize, u64)> {
        match &self.state {
            State::Transaction {
                messages, deleted, ..
            } => {
                let mut count = 0usize;
                let mut size = 0u64;
                for (index, message) in messages.iter().enumerate() {
                    if deleted.contains(&index) {
                        continue;
                    }
                    count += 1;
                    size = size.saturating_add(message.size);
                }
                Some((count, size))
            }
            State::Authorization { .. } => None,
        }
    }

    async fn multiline(&mut self, status: &str, lines: &[String]) -> Result<()> {
        self.write_all(format!("+OK {status}\r\n").as_bytes())
            .await?;
        for line in lines {
            self.write_all(line.as_bytes()).await?;
            self.write_all(b"\r\n").await?;
        }
        self.write_all(b".\r\n").await
    }

    fn expect_no_argument(&self, argument: Option<&str>) -> Result<()> {
        if argument
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
        {
            return Err(MailError::protocol("unexpected argument"));
        }
        Ok(())
    }

    async fn ok(&mut self, text: &str) -> Result<()> {
        let line = if text.is_empty() {
            "+OK\r\n".to_string()
        } else {
            format!("+OK {}\r\n", sanitize(text))
        };
        self.write_all(line.as_bytes()).await
    }

    async fn err(&mut self, text: &str) -> Result<()> {
        let line = format!("-ERR {}\r\n", sanitize(text));
        self.write_all(line.as_bytes()).await
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.io.write_all(bytes).await
    }

    async fn flush(&mut self) -> Result<()> {
        self.io.flush().await
    }
}

fn split_command(line: &str) -> (String, Option<String>) {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    match trimmed.split_once(' ') {
        Some((command, rest)) => (command.to_ascii_uppercase(), Some(rest.to_string())),
        None => (trimmed.to_ascii_uppercase(), None),
    }
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect()
}

fn acquire_mailbox_lock(root: &Path) -> Result<File> {
    let path = root.join(".mailstack-pop3.lock");
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| MailError::io(&path, error))?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(
            MailError::already_exists("mailbox is locked by another POP3 session"),
        ),
        Err(error) => Err(MailError::io(&path, error)),
    }
}

async fn write_transfer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
    top: Option<usize>,
) -> Result<()> {
    if let Some(limit) = top {
        let (headers, body) = mime::split_headers_body(message);
        for line in headers.split_inclusive(|byte| *byte == b'\n') {
            write_wire_line(writer, strip_eol(line)).await?;
        }
        write_wire_line(writer, b"").await?;
        for (index, line) in body.split_inclusive(|byte| *byte == b'\n').enumerate() {
            if index >= limit {
                break;
            }
            write_wire_line(writer, strip_eol(line)).await?;
        }
    } else {
        for line in message.split_inclusive(|byte| *byte == b'\n') {
            write_wire_line(writer, strip_eol(line)).await?;
        }
    }
    Ok(())
}

async fn write_wire_line<W: AsyncWrite + Unpin>(writer: &mut W, line: &[u8]) -> Result<()> {
    let stream_error = |error| MailError::io(Path::new("<stream>"), error);
    if line.first() == Some(&b'.') {
        writer.write_all(b".").await.map_err(stream_error)?;
    }
    writer.write_all(line).await.map_err(stream_error)?;
    writer.write_all(b"\r\n").await.map_err(stream_error)
}

fn strip_eol(line: &[u8]) -> &[u8] {
    if line.ends_with(b"\r\n") {
        &line[..line.len() - 2]
    } else if line.ends_with(b"\n") {
        &line[..line.len() - 1]
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::{Flag, FlagSet, SystemClock};

    #[test]
    fn command_splitting_preserves_the_password_argument() {
        assert_eq!(
            split_command("user Alice"),
            ("USER".to_string(), Some("Alice".to_string()))
        );
        assert_eq!(
            split_command("PASS  a b "),
            ("PASS".to_string(), Some(" a b ".to_string()))
        );
        assert_eq!(split_command("QUIT"), ("QUIT".to_string(), None));
    }

    #[tokio::test]
    async fn transfer_dot_stuffs_and_normalises_line_endings() {
        let message = b"Subject: x\n\n.leading dot\r\nsecond\n";
        let mut out = Vec::new();
        write_transfer(&mut out, message, None).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("\r\n..leading dot\r\n"), "{text:?}");
        assert!(text.ends_with("\r\n"), "不得自行追加终止点（由调用方写）");
    }

    #[tokio::test]
    async fn top_keeps_headers_and_limits_body_lines() {
        let message = b"Subject: x\r\n\r\none\r\ntwo\r\nthree\r\n";
        let mut out = Vec::new();
        write_transfer(&mut out, message, Some(1)).await.unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("Subject: x\r\n\r\n"));
        assert!(text.contains("one\r\n"));
        assert!(!text.contains("two"));
    }

    #[test]
    fn the_exclusive_lock_is_released_with_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = MailStore::new(dir.path(), Arc::new(SystemClock)).unwrap();
        let lock = acquire_mailbox_lock(store.root()).unwrap();
        let second = acquire_mailbox_lock(store.root());
        assert!(matches!(second, Err(MailError::AlreadyExists(_))));
        drop(lock);
        assert!(acquire_mailbox_lock(store.root()).is_ok());
    }

    #[test]
    fn flags_are_not_used_but_the_type_stays_exported_for_uidl_stability() {
        let mut flags = FlagSet::new();
        flags.insert(Flag::System(crate::maildir::SystemFlag::Seen));
        assert!(flags.iter().any(|flag| flag.imap_name() == "\\Seen"));
    }
}
