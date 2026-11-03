//! IMAP4rev1 会话状态机。
//!
//! ## 三态模型
//!
//! ```text
//! NotAuthenticated ──LOGIN/AUTHENTICATE──► Authenticated ──SELECT/EXAMINE──► Selected
//!        │                                     │                              │
//!        └─STARTTLS（就地升级后回到原状态）     └─CREATE/LIST/APPEND...       └─FETCH/STORE/SEARCH...
//! ```
//!
//! 状态检查在 `dispatch` 里逐命令完成：在错误的状态调用命令返回 `BAD`，而不是
//! 静默忽略 —— 后者会让客户端以为命令生效。
//!
//! ## UID 与序号的边界
//!
//! 同一个 `FETCH` 实现被 `FETCH` 与 `UID FETCH` 共用，靠 `uid_mode` 决定集合
//! 按 UID 还是序号解析，并在应答里自动补 `UID` 项（RFC 3501 §6.4.8 要求 UID
//! 命令的 FETCH 应答包含 UID）。EXAMINE 只把所选邮箱设为只读，不影响其它邮箱的
//! APPEND/COPY。
//!
//! ## 会话内的竞态
//!
//! 其他客户端（以及投递进程）会同时改同一个 Maildir。会话不缓存「文件内容」，
//! 只缓存**元数据快照**；NOOP / IDLE / 写入类命令之后用 [`refresh_selected`]
//! 对比新旧快照并发出 `EXPUNGE` / `EXISTS` / `FETCH FLAGS`。顺序是刻意的：
//! 先按**旧序号**发 EXPUNGE（从大到小），再发 EXISTS，最后用**新序号**发标志变化。
//!
//! [`refresh_selected`]: ImapSession::refresh_selected

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::{AuthBackend, AuthOutcome, AuthRequest, ScramCredentials};
use crate::blocking;
use crate::date;
use crate::error::{MailError, Result};
use crate::imap::fetch::{self};
use crate::imap::parser::{self, Command, ParserLimits, Token};
use crate::imap::scram;
use crate::imap::search::{self, SearchContext};
use crate::imap::sort;
use crate::imap::thread::{self, ThreadAlgorithm};
use crate::lineio::LineIo;
use crate::maildir::{
    is_special_use_attr, Flag, FlagSet, FolderStamp, FolderState, MailStore, MessageMeta,
    NewMessage, SystemFlag, DELIMITER, INBOX,
};
use crate::metrics::Metrics;
use crate::render;
use crate::resolver::MailboxResolver;
use crate::seqset::SequenceSet;

/// 共享邮箱命名空间前缀：`shared/<user>/<folder>`（命名空间分隔符 `/`）。
const SHARED_PREFIX: &str = "shared/";

/// 一个解析后的邮箱目标；`owner` 为 `Some` 表示这是别人的共享邮箱。
struct ResolvedMailbox {
    store: Arc<MailStore>,
    folder: String,
    owner: Option<String>,
}

/// 共享邮箱的 ACL 授权判断：本人邮箱恒通过；共享邮箱要求目标 ACL 授予全部所需权限。
/// `read_acl` 是同步文件 I/O，放 blocking 池执行，避免卡住 async worker。
async fn check_shared_rights(
    store: &Arc<MailStore>,
    folder: &str,
    owner: Option<&str>,
    user: Option<&str>,
    required: &str,
) -> Result<()> {
    let Some(owner) = owner else {
        return Ok(());
    };
    let me = user.unwrap_or("").to_ascii_lowercase();
    if me.is_empty() {
        return Err(MailError::Invalid("authentication required".to_string()));
    }
    if me == owner {
        return Ok(());
    }
    let folder = folder.to_string();
    let acl = blocking::maildir(store, move |store| store.read_acl(&folder)).await?;
    let granted = acl
        .get(&me)
        .or_else(|| acl.get("authenticated"))
        .or_else(|| acl.get("anyone"))
        .map(|rights| rights.to_ascii_lowercase());
    match granted {
        Some(granted) if required.chars().all(|letter| granted.contains(letter)) => Ok(()),
        _ => Err(MailError::Invalid(
            "permission denied for shared mailbox".to_string(),
        )),
    }
}

#[derive(Debug, Clone)]
pub struct ImapConfig {
    /// 问候语与 `* OK` 里出现的服务器名。
    pub server_name: String,
    /// 为 `true` 时，明文连接不得 LOGIN/AUTHENTICATE（通告 `LOGINDISABLED`）。
    pub require_tls: bool,
    /// 单条连接允许的连续认证失败次数；达到后发 BYE 断开。
    pub max_auth_failures: u32,
    pub max_line: usize,
    /// APPEND literal 上限（字节）。同时是读命令的硬上限。
    pub max_literal: usize,
    /// 单封邮件读取上限（FETCH/SEARCH 用）。
    pub max_message_size: u64,
    /// 是否允许普通用户执行 SETQUOTA（配额管理通常只应由管理面执行）。
    pub allow_setquota: bool,
    /// 读命令超时。
    pub read_timeout: Duration,
    /// AUTHENTICATE 交互式应答（等待继续行）的超时，比普通命令短得多：
    /// 半途停住的认证不应占用一条连接直到全局读超时。
    pub auth_timeout: Duration,
    /// IDLE 轮询间隔（发现其他会话/投递写入的邮件）。
    pub idle_poll: Duration,
    /// 单次 IDLE 的最长时间（RFC 建议 ≤ 29 分钟）。
    pub idle_timeout: Duration,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            server_name: "mailstack".to_string(),
            // 安全默认：未显式配置 TLS 的部署不应在明文连接上接受口令。
            // 开发/内网环境必须显式设 `require_tls: false`。
            require_tls: true,
            max_auth_failures: 5,
            max_line: 8 * 1024,
            max_literal: 32 * 1024 * 1024,
            max_message_size: 64 * 1024 * 1024,
            allow_setquota: false,
            read_timeout: Duration::from_secs(30 * 60),
            auth_timeout: Duration::from_secs(60),
            idle_poll: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(29 * 60),
        }
    }
}

/// 每个监听器（143 / 993）各拿一份上下文。
///
/// `resolver` 同时承担两件事：
/// 1. `shared/<user>/<folder>` 的跨用户共享邮箱；
/// 2. **多用户装配**——认证成功后按登录名把会话切到本人 Maildir
///    （见 [`AuthOutcome::Success`] 分支）。`None` 表示单用户部署。
#[derive(Clone)]
pub struct ImapSessionContext {
    pub store: Arc<MailStore>,
    pub auth: AuthBackend,
    pub config: ImapConfig,
    /// 命令级与认证级指标。监听器可通过 `with_metrics` 与传输层指标共享同一份。
    pub metrics: Arc<Metrics>,
    /// 跨用户共享邮箱的解析器（`shared/<user>/<folder>`）。`None` 表示单用户部署。
    pub resolver: Option<Arc<dyn MailboxResolver>>,
}

/// 连接参数由监听器决定（同一份配置既服务明文也服务 TLS）。
#[derive(Debug, Clone, Copy)]
pub struct ConnectionOptions {
    pub secured: bool,
    /// 明文连接上是否通告/接受 STARTTLS。
    pub starttls_available: bool,
    /// 是否发送问候语（STARTTLS 升级后的第二次进入不发）。
    pub greet: bool,
}

pub enum ImapExit<S> {
    Logout(S),
    StartTls(S),
    Closed(S),
}

impl<S> ImapExit<S> {
    pub fn into_inner(self) -> S {
        match self {
            ImapExit::Logout(io) | ImapExit::StartTls(io) | ImapExit::Closed(io) => io,
        }
    }
}

pub async fn serve_connection<S>(
    io: S,
    ctx: &ImapSessionContext,
    peer: SocketAddr,
    options: ConnectionOptions,
) -> Result<ImapExit<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ImapSession {
        io: LineIo::new(io),
        ctx,
        peer,
        store: Arc::clone(&ctx.store),
        own_store: Arc::clone(&ctx.store),
        selected_owner: None,
        secured: options.secured,
        starttls: options.starttls_available && !options.secured,
        state: State::NotAuthenticated,
        failures: 0,
        condstore: false,
        qresync: false,
        saved_search: None,
    }
    .run(options.greet)
    .await
}

enum State {
    NotAuthenticated,
    Authenticated { user: String },
    Selected { user: String, view: View },
}

struct View {
    folder: String,
    writable: bool,
    uidvalidity: u32,
    uidnext: u32,
    highest_modseq: u64,
    messages: Vec<MessageMeta>,
    /// 上次扫描后的目录指纹；用于 NOOP/IDLE 的免扫描快速路径。
    stamp: Option<FolderStamp>,
    /// 连续跳过的扫描次数。到 10 次强制全量扫描一次，防止时间戳精度漏变化。
    skipped_stamps: u8,
}

impl View {
    fn max_uid(&self) -> u32 {
        self.messages.last().map(|message| message.uid).unwrap_or(0)
    }

    fn max_seq(&self) -> u32 {
        self.messages.len() as u32
    }

    fn unseen_sequence(&self) -> Option<u32> {
        self.messages
            .iter()
            .position(|message| !message.flags.iter().any(Flag::is_seen))
            .map(|index| index as u32 + 1)
    }

    fn message(&self, index: usize) -> Option<&MessageMeta> {
        self.messages.get(index)
    }
}

enum Control {
    Continue,
    Logout,
    StartTls,
    Close,
    /// `COMPRESS` 已被接受：先把明文 OK flush 出去，再启用 DEFLATE。
    Compress,
}

struct ImapSession<'a, S> {
    io: LineIo<S>,
    ctx: &'a ImapSessionContext,
    peer: SocketAddr,
    /// 当前生效的存储：默认是本人邮箱；SELECT 共享邮箱后指向目标用户的存储。
    store: Arc<MailStore>,
    /// 本人邮箱（不随共享邮箱选择而变），用于 `deselect_to_personal` 还原。
    own_store: Arc<MailStore>,
    /// 当前选中邮箱的所有者（`None` = 本人）。用于共享邮箱的 ACL 授权判断。
    selected_owner: Option<String>,
    secured: bool,
    starttls: bool,
    state: State,
    failures: u32,
    /// 会话是否启用了 CONDSTORE（ENABLE 或 SELECT 参数）。
    condstore: bool,
    /// 会话是否启用了 QRESYNC（隐含 CONDSTORE）。
    qresync: bool,
    /// RFC 5182：最近一次 `SEARCH RETURN (SAVE)` 保存的结果（按 UID 存，模式无关）。
    saved_search: Option<Vec<u32>>,
}

impl<'a, S> ImapSession<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn run(mut self, greet: bool) -> Result<ImapExit<S>> {
        if greet {
            let greeting = format!(
                "* OK [CAPABILITY {}] {} IMAP4rev1 ready\r\n",
                self.capabilities(),
                self.ctx.config.server_name
            );
            self.write_all(greeting.as_bytes()).await?;
            self.flush().await?;
        }

        let limits = ParserLimits {
            max_line: self.ctx.config.max_line,
            max_literal: self.ctx.config.max_literal,
            max_tokens: 1024,
            max_command: 64 * 1024,
        };

        loop {
            let read = tokio::time::timeout(
                self.ctx.config.read_timeout,
                parser::read_command(&mut self.io, limits),
            )
            .await;

            let command = match read {
                Err(_) => {
                    self.bye("idle timeout").await?;
                    return Ok(ImapExit::Closed(self.io.into_inner()));
                }
                Ok(Err(error)) => {
                    // 解析失败意味着字节流已经不可信；直接断开而不是继续猜。
                    let message = format!("* BYE [ALERT] {}", sanitize(&error.to_string()));
                    self.write_all(message.as_bytes()).await?;
                    self.write_all(b"\r\n").await?;
                    self.flush().await?;
                    return Ok(ImapExit::Closed(self.io.into_inner()));
                }
                Ok(Ok(None)) => return Ok(ImapExit::Closed(self.io.into_inner())),
                Ok(Ok(Some(command))) => command,
            };

            let tag = command.tag.clone();
            let outcome = self.dispatch(command).await;
            if outcome.is_ok() {
                self.ctx.metrics.command_completed();
            }
            match outcome {
                Ok(Control::Continue) => {
                    self.flush().await?;
                }
                Ok(Control::Logout) => {
                    self.flush().await?;
                    return Ok(ImapExit::Logout(self.io.into_inner()));
                }
                Ok(Control::StartTls) => {
                    self.flush().await?;
                    return Ok(ImapExit::StartTls(self.io.into_inner()));
                }
                Ok(Control::Compress) => {
                    // 切换应答是明文：先把它 flush 出去，之后所有字节才走 DEFLATE。
                    self.flush().await?;
                    self.io.enable_compression()?;
                }
                Ok(Control::Close) => {
                    self.flush().await?;
                    return Ok(ImapExit::Closed(self.io.into_inner()));
                }
                Err(error) => {
                    if matches!(error, MailError::Timeout) {
                        self.ctx.metrics.command_failed();
                        self.bye("idle timeout").await?;
                        self.flush().await?;
                        return Ok(ImapExit::Closed(self.io.into_inner()));
                    }
                    // 服务器故障计为失败；NO/BAD 这类协议层拒绝仍算「已处理」。
                    if error.is_server_error() {
                        self.ctx.metrics.command_failed();
                    } else {
                        self.ctx.metrics.command_completed();
                    }
                    self.send_failure(&tag, &error).await?;
                    self.flush().await?;
                }
            }
        }
    }

    async fn dispatch(&mut self, command: Command) -> Result<Control> {
        let tag = command.tag.clone();
        let name = command.name.clone();
        match name.as_str() {
            "CAPABILITY" => {
                self.expect_arity(&command, 0)?;
                let text = format!("* CAPABILITY {}", self.capabilities());
                self.line(&text).await?;
                self.ok(&tag, "CAPABILITY completed").await?;
                Ok(Control::Continue)
            }
            "COMPRESS" => {
                self.expect_arity(&command, 1)?;
                self.require_authenticated(&tag)?;
                let method = command.args[0].text().unwrap_or_default();
                if !method.eq_ignore_ascii_case("DEFLATE") {
                    return self
                        .no_code(&tag, "COMPRESSIONERROR", "unsupported compression method")
                        .await;
                }
                if self.io.compression_enabled() {
                    return self.bad(&tag, "compression is already enabled").await;
                }
                self.ok(&tag, "DEFLATE compression enabled").await?;
                Ok(Control::Compress)
            }
            "NOOP" => {
                self.expect_arity(&command, 0)?;
                if matches!(self.state, State::Selected { .. }) {
                    self.refresh_selected().await?;
                }
                self.ok(&tag, "NOOP completed").await?;
                Ok(Control::Continue)
            }
            "LOGOUT" => {
                self.expect_arity(&command, 0)?;
                self.write_all(b"* BYE MailStack IMAP4rev1 signing off\r\n")
                    .await?;
                self.ok(&tag, "LOGOUT completed").await?;
                Ok(Control::Logout)
            }
            "ID" => self.handle_id(&command).await,
            "ENABLE" => self.handle_enable(&command).await,
            "UNSELECT" => self.handle_unselect(&command).await,
            "STARTTLS" => {
                self.expect_arity(&command, 0)?;
                if !matches!(self.state, State::NotAuthenticated) {
                    return self
                        .bad(&tag, "STARTTLS is only valid before authentication")
                        .await;
                }
                if self.secured {
                    return self.bad(&tag, "TLS is already active").await;
                }
                if !self.starttls {
                    return self.bad(&tag, "STARTTLS is not available").await;
                }
                self.ok(&tag, "Begin TLS negotiation now").await?;
                Ok(Control::StartTls)
            }
            "LOGIN" => self.handle_login(&command).await,
            "AUTHENTICATE" => self.handle_authenticate(&command).await,
            "SELECT" | "EXAMINE" => self.handle_select(&command).await,
            "CREATE" => self.handle_create(&command).await,
            "DELETE" => self.handle_delete(&command).await,
            "RENAME" => self.handle_rename(&command).await,
            "SUBSCRIBE" => self.handle_subscribe(&command, true).await,
            "UNSUBSCRIBE" => self.handle_subscribe(&command, false).await,
            "LIST" | "LSUB" => self.handle_list(&command).await,
            "STATUS" => self.handle_status(&command).await,
            "GETQUOTA" => self.handle_getquota(&command).await,
            "GETQUOTAROOT" => self.handle_getquotaroot(&command).await,
            "SETQUOTA" => self.handle_setquota(&command).await,
            "APPEND" => self.handle_append(command).await,
            "CHECK" => {
                self.require_selected(&tag)?;
                self.expect_arity(&command, 0)?;
                self.ok(&tag, "CHECK completed").await?;
                Ok(Control::Continue)
            }
            "CLOSE" => self.handle_close(&command).await,
            "EXPUNGE" => self.handle_expunge(&command, None).await,
            "SEARCH" => self.handle_search(&command, false).await,
            "SORT" => self.handle_sort(&command, false).await,
            "THREAD" => self.handle_thread(&command, false).await,
            "FETCH" => self.handle_fetch(&command, false).await,
            "STORE" => self.handle_store(&command, false).await,
            "COPY" => self.handle_copy(&command, false).await,
            "MOVE" => self.handle_move(&command, false).await,
            "UID" => self.handle_uid(&command).await,
            "IDLE" => self.handle_idle(&command).await,
            "NAMESPACE" => {
                self.require_authenticated(&tag)?;
                self.expect_arity(&command, 0)?;
                let shared = if self.ctx.resolver.is_some() {
                    format!("((\"{SHARED_PREFIX}\" \"/\"))")
                } else {
                    "NIL".to_string()
                };
                self.line(&format!(
                    "* NAMESPACE ((\"\" \"{DELIMITER}\")) NIL {shared}"
                ))
                .await?;
                self.ok(&tag, "NAMESPACE completed").await?;
                Ok(Control::Continue)
            }
            "GETMETADATA" => self.handle_getmetadata(&command).await,
            "SETMETADATA" => self.handle_setmetadata(&command).await,
            "GETACL" => self.handle_getacl(&command).await,
            "SETACL" => self.handle_setacl(&command).await,
            "DELETEACL" => self.handle_deleteacl(&command).await,
            "LISTRIGHTS" => self.handle_listrights(&command).await,
            "MYRIGHTS" => self.handle_myrights(&command).await,
            _ => self.bad(&tag, "unknown command").await,
        }
    }

    // -----------------------------------------------------------------
    // 认证
    // -----------------------------------------------------------------

    async fn handle_login(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        if !matches!(self.state, State::NotAuthenticated) {
            return self.bad(&tag, "already authenticated").await;
        }
        if !self.can_authenticate() {
            return self
                .no_code(&tag, "PRIVACYREQUIRED", "TLS is required before login")
                .await;
        }
        self.expect_arity(command, 2)?;
        let user = string_arg(&command.args[0])?;
        let password = string_arg(&command.args[1])?;
        self.finish_authentication(&tag, user, password).await
    }

    async fn handle_authenticate(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        if !matches!(self.state, State::NotAuthenticated) {
            return self.bad(&tag, "already authenticated").await;
        }
        if !self.can_authenticate() {
            return self
                .no_code(
                    &tag,
                    "PRIVACYREQUIRED",
                    "TLS is required before authentication",
                )
                .await;
        }
        if command.args.is_empty() {
            return self.bad(&tag, "AUTHENTICATE requires a mechanism").await;
        }
        if command.args.len() > 2 {
            return self
                .bad(&tag, "AUTHENTICATE accepts at most one initial response")
                .await;
        }
        let mechanism = string_arg(&command.args[0])?.to_ascii_uppercase();
        // SASL-IR（RFC 4959）：第二个参数是 base64 初始应答；单独的 "=" 表示空应答。
        // 解不开的 base64 与口令错误一样计入失败次数：否则攻击者可以只发永远
        // 解不开的输入，无限尝试也不触发 max_auth_failures。
        let initial = match command.args.get(1) {
            Some(token) => {
                let text = token
                    .text()
                    .ok_or_else(|| MailError::protocol("invalid initial response"))?;
                if text == "=" {
                    Some(Vec::new())
                } else {
                    match decode_base64(text.as_bytes()) {
                        Ok(decoded) => Some(decoded),
                        Err(error) => return self.malformed_auth(&tag, &error).await,
                    }
                }
            }
            None => None,
        };
        match mechanism.as_str() {
            "PLAIN" => {
                let payload = match initial {
                    Some(payload) => payload,
                    None => match decode_base64(&self.read_continuation("").await?) {
                        Ok(payload) => payload,
                        Err(error) => return self.malformed_auth(&tag, &error).await,
                    },
                };
                let fields: Vec<&[u8]> = payload.split(|byte| *byte == 0).collect();
                if fields.len() != 3 {
                    return self
                        .malformed_auth(&tag, &MailError::protocol("invalid PLAIN response"))
                        .await;
                }
                let authzid = String::from_utf8_lossy(fields[0]).to_string();
                let authcid = String::from_utf8_lossy(fields[1]).to_string();
                let password = String::from_utf8_lossy(fields[2]).to_string();
                if authcid.is_empty() || password.is_empty() {
                    // 空凭据与口令错误走同一条失败计数路径（应答文本相同）。
                    return self.auth_failure(&tag).await;
                }
                if !authzid.is_empty() && !authzid.eq_ignore_ascii_case(&authcid) {
                    return self
                        .no_code(
                            &tag,
                            "AUTHORIZATIONFAILED",
                            "cannot authorize as another user",
                        )
                        .await;
                }
                self.finish_authentication(&tag, authcid, password).await
            }
            "LOGIN" => {
                let user = match initial {
                    Some(bytes) => match String::from_utf8(bytes) {
                        Ok(text) => text,
                        Err(_) => {
                            return self
                                .malformed_auth(
                                    &tag,
                                    &MailError::invalid("username is not valid UTF-8"),
                                )
                                .await
                        }
                    },
                    None => {
                        match decode_base64_text(&self.read_continuation("VXNlcm5hbWU6").await?) {
                            Ok(text) => text,
                            Err(error) => return self.malformed_auth(&tag, &error).await,
                        }
                    }
                };
                let password =
                    match decode_base64_text(&self.read_continuation("UGFzc3dvcmQ6").await?) {
                        Ok(text) => text,
                        Err(error) => return self.malformed_auth(&tag, &error).await,
                    };
                self.finish_authentication(&tag, user, password).await
            }
            "SCRAM-SHA-256" => self.handle_scram(&tag, initial).await,
            _ => self.bad(&tag, "unsupported SASL mechanism").await,
        }
    }

    async fn handle_scram(&mut self, tag: &str, initial: Option<Vec<u8>>) -> Result<Control> {
        let client_first_bytes = match initial {
            Some(bytes) => bytes,
            None => match decode_base64(&self.read_continuation("").await?) {
                Ok(bytes) => bytes,
                Err(error) => return self.malformed_auth(tag, &error).await,
            },
        };
        let client_first_text = match String::from_utf8(client_first_bytes) {
            Ok(text) => text,
            Err(_) => return self.auth_failure(tag).await,
        };
        let client_first = match scram::parse_client_first(&client_first_text) {
            Ok(client_first) => client_first,
            Err(_) => return self.auth_failure(tag).await,
        };
        let credentials = self
            .ctx
            .auth
            .scram_credentials(&client_first.username)
            .await
            .unwrap_or_else(|| ScramCredentials::dummy_for(&client_first.username));
        let server_nonce = scram::server_nonce();
        let server_first = scram::server_first(&client_first, &credentials, &server_nonce);
        let response = self
            .read_continuation(
                &base64::engine::general_purpose::STANDARD.encode(server_first.as_bytes()),
            )
            .await?;
        let client_final = match decode_base64_text(&response) {
            Ok(text) => text,
            Err(_) => return self.auth_failure(tag).await,
        };
        let server_signature = match scram::verify_client_final(
            &client_first,
            &server_first,
            &server_nonce,
            &client_final,
            &credentials,
        ) {
            Ok(signature) => signature,
            Err(_) => return self.auth_failure(tag).await,
        };
        let final_message = format!(
            "v={}",
            base64::engine::general_purpose::STANDARD.encode(server_signature)
        );
        self.write_all(
            format!(
                "+ {}\r\n",
                base64::engine::general_purpose::STANDARD.encode(final_message.as_bytes())
            )
            .as_bytes(),
        )
        .await?;
        self.flush().await?;
        let acknowledgement = tokio::time::timeout(
            self.ctx.config.auth_timeout,
            self.io.read_line(self.ctx.config.max_line),
        )
        .await;
        match acknowledgement {
            Err(_) => return Err(MailError::Timeout),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(None)) => return Err(MailError::protocol("connection closed during SCRAM")),
            Ok(Ok(Some(line))) => {
                if !line.is_empty() {
                    return self.auth_failure(tag).await;
                }
            }
        }
        self.failures = 0;
        let user = client_first.username.to_ascii_lowercase();
        tracing::info!(peer = %self.peer, user = %user, "imap SCRAM login succeeded");
        self.state = State::Authenticated { user };
        self.ctx.metrics.auth_success();
        self.ok(
            tag,
            &format!(
                "[CAPABILITY {}] authentication completed",
                self.capabilities()
            ),
        )
        .await?;
        Ok(Control::Continue)
    }

    async fn auth_failure(&mut self, tag: &str) -> Result<Control> {
        self.failures += 1;
        self.ctx.metrics.auth_failed();
        tracing::warn!(peer = %self.peer, failures = self.failures, "imap login failed");
        if self.failures >= self.ctx.config.max_auth_failures {
            self.bye("too many failed authentication attempts").await?;
            return Ok(Control::Close);
        }
        self.no_code(tag, "AUTHENTICATIONFAILED", "invalid credentials")
            .await?;
        Ok(Control::Continue)
    }

    /// 畸形 SASL 输入（base64 解不开、字段数量不对、凭据不是 UTF-8 等）：
    /// 失败计数与口令错误走同一条路，应答文本沿用 [`ImapSession::send_failure`]
    /// 的分类（解码错误 → NO、字段缺失 → BAD），与改动前完全一致；差别只是
    /// 同时累计 `max_auth_failures`，防止用永远解不开的输入绕过爆破保护。
    async fn malformed_auth(&mut self, tag: &str, error: &MailError) -> Result<Control> {
        self.failures += 1;
        self.ctx.metrics.auth_failed();
        tracing::warn!(peer = %self.peer, failures = self.failures, "imap login failed");
        if self.failures >= self.ctx.config.max_auth_failures {
            self.bye("too many failed authentication attempts").await?;
            return Ok(Control::Close);
        }
        self.send_failure(tag, error).await?;
        Ok(Control::Continue)
    }

    async fn handle_id(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        if command.args.len() > 1 {
            return self.bad(&tag, "ID accepts at most one argument").await;
        }
        if let Some(token) = command.args.first() {
            if !token.is_nil() && token.list().is_none() {
                return self.bad(&tag, "ID requires a list or NIL").await;
            }
        }
        self.line(&format!(
            "* ID (\"name\" \"MailStack\" \"version\" \"{}\")",
            env!("CARGO_PKG_VERSION")
        ))
        .await?;
        self.ok(&tag, "ID completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_enable(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        if command.args.is_empty() {
            return self
                .bad(&tag, "ENABLE requires at least one capability")
                .await;
        }
        let mut enabled: Vec<&str> = Vec::new();
        for arg in &command.args {
            let name = arg
                .as_atom()
                .ok_or_else(|| MailError::invalid("ENABLE requires capability atoms"))?;
            if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
                return self.bad(&tag, "invalid capability name").await;
            }
            if name.eq_ignore_ascii_case("CONDSTORE") {
                self.condstore = true;
                if !enabled.contains(&"CONDSTORE") {
                    enabled.push("CONDSTORE");
                }
            }
            if name.eq_ignore_ascii_case("QRESYNC") {
                self.qresync = true;
                self.condstore = true;
                if !enabled.contains(&"CONDSTORE") {
                    enabled.push("CONDSTORE");
                }
                if !enabled.contains(&"QRESYNC") {
                    enabled.push("QRESYNC");
                }
            }
            // 未支持的扩展（如 QRESYNC）按 RFC 5161 静默忽略。
        }
        if !enabled.is_empty() {
            self.line(&format!("* ENABLED {}", enabled.join(" ")))
                .await?;
            if let Some(highest) = self.view().map(|view| view.highest_modseq) {
                self.line(&format!("* OK [HIGHESTMODSEQ {highest}] HIGHESTMODSEQ"))
                    .await?;
            }
        }
        self.ok(&tag, "ENABLE completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_unselect(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.expect_arity(command, 0)?;
        if !matches!(self.state, State::Selected { .. }) {
            return self.bad(&tag, "UNSELECT requires a selected mailbox").await;
        }
        self.deselect_to_personal();
        self.ok(&tag, "UNSELECT completed").await?;
        Ok(Control::Continue)
    }

    async fn finish_authentication(
        &mut self,
        tag: &str,
        user: String,
        password: String,
    ) -> Result<Control> {
        let request = AuthRequest {
            user,
            password,
            secured: self.secured,
            peer: self.peer,
            service: "imap",
        };
        match self.ctx.auth.as_dyn().authenticate(request).await {
            AuthOutcome::Success { user } => {
                self.failures = 0;

                // 多用户装配：声明了 `resolver` 就按**登录名**把会话切到该用户的
                // Maildir。`ctx.store` 只是单用户部署（无 resolver）的默认值。
                //
                // 解析失败必须**拒绝登录**，不能退回 `ctx.store` —— 那等于把
                // 默认账号的邮箱交给任何一个口令正确但没开邮箱的用户。
                if let Some(resolver) = self.ctx.resolver.as_ref() {
                    let Some(store) = resolver.resolve(&user) else {
                        self.ctx.metrics.auth_failed();
                        tracing::warn!(peer = %self.peer, user = %user, "imap login rejected: mailbox is not provisioned");
                        return self
                            .no_code(tag, "UNAVAILABLE", "mailbox is not provisioned")
                            .await;
                    };
                    self.store = Arc::clone(&store);
                    // 记下本人邮箱：共享邮箱选择结束后要还原到它，而不是 `ctx.store`。
                    self.own_store = store;
                }

                self.state = State::Authenticated { user: user.clone() };
                self.ctx.metrics.auth_success();
                tracing::info!(peer = %self.peer, user = %user, "imap login succeeded");
                self.ok(
                    tag,
                    &format!(
                        "[CAPABILITY {}] authentication completed",
                        self.capabilities()
                    ),
                )
                .await?;
                Ok(Control::Continue)
            }
            AuthOutcome::InvalidCredentials => self.auth_failure(tag).await,
            AuthOutcome::TemporaryFailure(_) => {
                self.ctx.metrics.auth_failed();
                self.no_code(tag, "UNAVAILABLE", "authentication backend is unavailable")
                    .await?;
                Ok(Control::Continue)
            }
        }
    }

    fn can_authenticate(&self) -> bool {
        self.secured || !self.ctx.config.require_tls
    }

    fn capabilities(&self) -> String {
        let mut capabilities = vec![
            "IMAP4rev1",
            "SASL-IR",
            "LITERAL+",
            "UIDPLUS",
            "MULTIAPPEND",
            "NAMESPACE",
            "ID",
            "ENABLE",
            "CONDSTORE",
            "QRESYNC",
            "IDLE",
            "MOVE",
            "UNSELECT",
            "SPECIAL-USE",
            "CHILDREN",
            "ESEARCH",
            "QUOTA",
            "SORT",
            "SORT=DISPLAY",
            "THREAD=ORDEREDSUBJECT",
            "THREAD=REFERENCES",
            "METADATA",
            "ACL",
            "BINARY",
        ];
        // COMPRESS 只在认证后有效（RFC 4978 §4），所以也只在认证后才通告。
        if !matches!(self.state, State::NotAuthenticated) {
            capabilities.push("COMPRESS=DEFLATE");
        }
        if self.starttls && !self.secured {
            capabilities.push("STARTTLS");
        }
        if self.can_authenticate() {
            capabilities.push("AUTH=PLAIN");
            capabilities.push("AUTH=LOGIN");
            capabilities.push("AUTH=SCRAM-SHA-256");
        } else {
            capabilities.push("LOGINDISABLED");
        }
        capabilities.join(" ")
    }

    async fn read_continuation(&mut self, prompt: &str) -> Result<Vec<u8>> {
        let line = format!("+ {prompt}\r\n");
        self.write_all(line.as_bytes()).await?;
        self.flush().await?;
        let read = tokio::time::timeout(
            self.ctx.config.auth_timeout,
            self.io.read_line(self.ctx.config.max_line),
        )
        .await
        .map_err(|_| MailError::Timeout)??;
        read.ok_or_else(|| MailError::protocol("client closed during authentication"))
    }

    // -----------------------------------------------------------------
    // 邮箱选择与命名空间
    // -----------------------------------------------------------------

    async fn handle_select(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        if command.args.is_empty() || command.args.len() > 2 {
            return self
                .bad(
                    &tag,
                    "SELECT/EXAMINE accepts a mailbox and optional parameters",
                )
                .await;
        }
        let name = string_arg(&command.args[0])?;
        let mut qresync_request: Option<(u32, u64)> = None;
        if let Some(token) = command.args.get(1) {
            let items = token
                .list()
                .ok_or_else(|| MailError::protocol("SELECT parameters must be a list"))?;
            if items.is_empty() {
                return self.bad(&tag, "empty SELECT parameter list").await;
            }
            let mut index = 0usize;
            while index < items.len() {
                let parameter = items[index]
                    .as_atom()
                    .ok_or_else(|| MailError::protocol("SELECT parameters must be atoms"))?
                    .to_ascii_uppercase();
                match parameter.as_str() {
                    "CONDSTORE" => self.condstore = true,
                    "QRESYNC" => {
                        if !self.qresync {
                            return self.bad(&tag, "QRESYNC requires ENABLE QRESYNC").await;
                        }
                        let Some(Token::List(parameters)) = items.get(index + 1) else {
                            return self.bad(&tag, "QRESYNC requires parameters").await;
                        };
                        match parse_qresync_params(parameters) {
                            Ok(parsed) => qresync_request = Some(parsed),
                            Err(message) => return self.bad(&tag, &message.to_string()).await,
                        }
                        self.condstore = true;
                        index += 1;
                    }
                    _ => {
                        return self
                            .bad(&tag, &format!("unsupported SELECT parameter: {parameter}"))
                            .await
                    }
                }
                index += 1;
            }
        }
        let writable = command.name == "SELECT";
        // 解析目标：共享邮箱按 ACL 授权（需 l+r），个人邮箱恒通过。
        let resolved = match self.resolve_mailbox(&name) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.deselect_to_personal();
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "lr").await {
            self.deselect_to_personal();
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&resolved.store);
        let mailbox = resolved.folder.clone();
        let state =
            match blocking::maildir(&store, move |store| store.open_folder(&mailbox, true)).await {
                Ok(state) => state,
                Err(error) => {
                    // RFC 3501 §6.3.1：SELECT/EXAMINE 在尝试新邮箱之前自动 deselect；
                    // 新邮箱选择失败时应处于「无选中」状态，而不是继续指向旧邮箱。
                    self.deselect_to_personal();
                    self.send_failure(&tag, &error).await?;
                    return Ok(Control::Continue);
                }
            };
        // 选择成功：把当前存储切到目标（共享或本人）。
        self.store = Arc::clone(&resolved.store);
        self.selected_owner = resolved.owner.clone();
        // RFC 5182：邮箱切换后，上一个邮箱的 SEARCH RETURN (SAVE) 结果（按
        // UID 存）不再有意义；留在原地会让新邮箱里的 `$` 解析到旧邮箱的 UID。
        self.saved_search = None;
        let user = self.user().unwrap_or_default().to_string();
        let folder_for_stamp = state.name.clone();
        let stamp = blocking::maildir(&self.store, move |store| {
            store.folder_stamp(&folder_for_stamp)
        })
        .await
        .ok();
        let qresync_data = match qresync_request {
            Some((uidvalidity, modseq)) if uidvalidity == state.uidvalidity => {
                let store = Arc::clone(&self.store);
                let folder = state.name.clone();
                let expunged =
                    blocking::maildir(&store, move |store| store.expunged_since(&folder, modseq))
                        .await?;
                let changed: Vec<usize> = state
                    .messages
                    .iter()
                    .enumerate()
                    .filter(|(_, message)| message.modseq > modseq)
                    .map(|(index, _)| index)
                    .collect();
                Some((expunged, changed))
            }
            _ => None,
        };
        let view = View {
            folder: state.name.clone(),
            writable,
            uidvalidity: state.uidvalidity,
            uidnext: state.uidnext,
            highest_modseq: state.highest_modseq,
            messages: state.messages,
            stamp,
            skipped_stamps: 0,
        };

        if let Some((expunged, _)) = &qresync_data {
            if !expunged.is_empty() {
                self.line(&format!(
                    "* VANISHED (EARLIER) {}",
                    SequenceSet::from_values(expunged)
                ))
                .await?;
            }
        }

        let flags = format!(
            "* FLAGS ({})",
            [
                SystemFlag::Answered,
                SystemFlag::Flagged,
                SystemFlag::Deleted,
                SystemFlag::Seen,
                SystemFlag::Draft
            ]
            .iter()
            .map(|flag| flag.imap_name())
            .collect::<Vec<_>>()
            .join(" ")
        );
        self.line(&flags).await?;
        if writable {
            self.line(&format!(
                "* OK [PERMANENTFLAGS ({} \\*)] Flags permitted",
                [
                    SystemFlag::Answered,
                    SystemFlag::Flagged,
                    SystemFlag::Deleted,
                    SystemFlag::Seen,
                    SystemFlag::Draft
                ]
                .iter()
                .map(|flag| flag.imap_name())
                .collect::<Vec<_>>()
                .join(" ")
            ))
            .await?;
        } else {
            self.line("* OK [PERMANENTFLAGS ()] No permanent flags permitted")
                .await?;
        }
        self.line(&format!("* {} EXISTS", view.messages.len()))
            .await?;
        self.line(&format!(
            "* {} RECENT",
            view.messages
                .iter()
                .filter(|message| message.recent)
                .count()
        ))
        .await?;
        self.line(&format!(
            "* OK [UIDVALIDITY {}] UIDs valid",
            view.uidvalidity
        ))
        .await?;
        self.line(&format!(
            "* OK [UIDNEXT {}] Predicted next UID",
            view.uidnext
        ))
        .await?;
        if self.condstore {
            self.line(&format!(
                "* OK [HIGHESTMODSEQ {}] HIGHESTMODSEQ",
                view.highest_modseq
            ))
            .await?;
        }
        if let Some(sequence) = view.unseen_sequence() {
            self.line(&format!("* OK [UNSEEN {sequence}] First unseen message"))
                .await?;
        }
        if let Some((_, changed)) = &qresync_data {
            for &index in changed {
                let Some(message) = view.messages.get(index) else {
                    continue;
                };
                self.line(&format!(
                    "* {} FETCH (UID {} FLAGS {} MODSEQ ({}))",
                    index + 1,
                    message.uid,
                    fetch::format_flags(&message.flags),
                    message.modseq
                ))
                .await?;
            }
        }
        self.state = State::Selected { user, view };
        let code = if writable { "READ-WRITE" } else { "READ-ONLY" };
        self.ok(&tag, &format!("[{code}] {} completed", command.name))
            .await?;
        Ok(Control::Continue)
    }
    async fn handle_create(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        if command.args.is_empty() || command.args.len() > 3 {
            return self
                .bad(&tag, "CREATE requires a mailbox and optional USE list")
                .await;
        }
        let name = string_arg(&command.args[0])?;
        self.deny_shared(&name)?;
        let mut uses: Vec<String> = Vec::new();
        let use_list = match command.args.get(1) {
            None => None,
            Some(Token::Atom(keyword)) if keyword.eq_ignore_ascii_case("USE") => {
                if command.args.len() != 3 {
                    return self
                        .bad(&tag, "CREATE USE requires an attribute list")
                        .await;
                }
                command.args.get(2)
            }
            // 宽容：允许省略 USE 关键字直接跟列表。
            Some(Token::List(_)) if command.args.len() == 2 => command.args.get(1),
            Some(_) => {
                return self
                    .bad(&tag, "CREATE requires a mailbox and optional USE list")
                    .await
            }
        };
        if let Some(token) = use_list {
            let items = token
                .list()
                .ok_or_else(|| MailError::protocol("CREATE USE requires a list"))?;
            for item in items {
                let text = item
                    .text()
                    .ok_or_else(|| MailError::invalid("invalid special-use attribute"))?;
                if !is_special_use_attr(&text) {
                    return self
                        .bad(&tag, &format!("unknown special-use attribute: {text}"))
                        .await;
                }
                uses.push(text);
            }
        }
        let store = Arc::clone(&self.store);
        let folder = name.clone();
        let result = blocking::maildir(&store, move |store| {
            store.create(&folder)?;
            if !uses.is_empty() {
                store.set_special_use(&folder, &uses)?;
            }
            Ok(())
        })
        .await;
        self.relay(&tag, result, "CREATE completed").await
    }

    async fn handle_delete(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let name = string_arg(&command.args[0])?;
        self.deny_shared(&name)?;
        if let State::Selected { view, .. } = &self.state {
            if view.folder.eq_ignore_ascii_case(&name) {
                return self.bad(&tag, "cannot delete the selected mailbox").await;
            }
        }
        let store = Arc::clone(&self.store);
        let folder = name.clone();
        let result = blocking::maildir(&store, move |store| store.delete(&folder)).await;
        self.relay(&tag, result, "DELETE completed").await
    }

    async fn handle_rename(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 2)?;
        let from = string_arg(&command.args[0])?;
        let to = string_arg(&command.args[1])?;
        self.deny_shared(&from)?;
        self.deny_shared(&to)?;
        let store = Arc::clone(&self.store);
        let source = from.clone();
        let destination = to.clone();
        match blocking::maildir(&store, move |store| store.rename(&source, &destination)).await {
            Ok(()) => {
                self.ok(&tag, "RENAME completed").await?;
                // 重命名当前选中的邮箱后，视图里的文件夹名必须跟着变；
                // 否则后续 FETCH 会去找一个已经不存在的名字。
                let selected = matches!(&self.state, State::Selected { view, .. } if view.folder.eq_ignore_ascii_case(&from));
                if selected {
                    let new_name = if crate::maildir::is_inbox(&from) {
                        INBOX.to_string()
                    } else {
                        to.clone()
                    };
                    if let State::Selected { view, .. } = &mut self.state {
                        view.folder = new_name;
                    }
                    self.refresh_selected().await?;
                }
                Ok(Control::Continue)
            }
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn handle_subscribe(&mut self, command: &Command, subscribe: bool) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let name = string_arg(&command.args[0])?;
        self.deny_shared(&name)?;
        let store = Arc::clone(&self.store);
        let folder = name.clone();
        let result = blocking::maildir(&store, move |store| {
            if subscribe {
                store.subscribe(&folder)
            } else {
                store.unsubscribe(&folder)
            }
        })
        .await;
        let completed = if subscribe {
            "SUBSCRIBE completed"
        } else {
            "UNSUBSCRIBE completed"
        };
        self.relay(&tag, result, completed).await
    }

    async fn handle_list(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        let (selection, reference, pattern) = parse_list_args(command)?;
        if pattern.is_empty() && reference.is_empty() {
            // RFC 3501 §6.3.8：空模式用于探测层级分隔符，必须回一条 LIST。
            self.line(&format!(
                "* {} (\\Noselect) \"{DELIMITER}\" \"\"",
                if command.name == "LSUB" {
                    "LSUB"
                } else {
                    "LIST"
                }
            ))
            .await?;
            self.ok(&tag, &format!("{} completed", command.name))
                .await?;
            return Ok(Control::Continue);
        }
        let full_pattern = resolve_pattern(&reference, &pattern);
        if full_pattern.len() > MAX_LIST_PATTERN {
            return Err(MailError::protocol("LIST pattern is too long"));
        }

        let response_name = if command.name == "LSUB" {
            "LSUB"
        } else {
            "LIST"
        };
        let lsub = command.name == "LSUB";
        if !lsub && full_pattern.starts_with(SHARED_PREFIX) {
            for (name, attributes) in self.shared_mailbox_listing(&full_pattern).await? {
                self.line(&format!(
                    "* {response_name} ({}) \"/\" {}",
                    attributes.join(" "),
                    render::string(&name)
                ))
                .await?;
            }
            self.ok(&tag, &format!("{} completed", command.name))
                .await?;
            return Ok(Control::Continue);
        }
        let subscribed_only = lsub || selection.contains("SUBSCRIBED");
        let special_only = selection.contains("SPECIAL-USE");
        let store = Arc::clone(&self.store);
        let (folders, mut names, special_uses) = blocking::maildir(&store, move |store| {
            let folders = store.folders()?;
            let names = if subscribed_only {
                store.subscriptions()?
            } else {
                folders.clone()
            };
            let special_uses = store.special_use_map()?;
            Ok((folders, names, special_uses))
        })
        .await?;
        names.sort();
        names.dedup();

        // 一次遍历算出所有「有子文件夹」的父名：逐名字再做前缀扫描是 O(n²)。
        let mut parents: HashSet<String> = HashSet::new();
        for folder in &folders {
            let mut name = folder.as_str();
            while let Some((parent, _)) = name.rsplit_once(DELIMITER) {
                parents.insert(parent.to_string());
                name = parent;
            }
        }
        let folder_set: HashSet<&str> = folders.iter().map(String::as_str).collect();

        for name in names {
            if !matches_pattern(&full_pattern, &name) {
                continue;
            }
            let uses = special_uses.get(&name).cloned().unwrap_or_default();
            if special_only && uses.is_empty() {
                continue;
            }
            let exists = folder_set.contains(name.as_str());
            let mut attributes: Vec<String> = Vec::new();
            if !exists {
                attributes.push("\\Noselect".to_string());
            } else if parents.contains(&name) {
                attributes.push("\\HasChildren".to_string());
            } else {
                attributes.push("\\HasNoChildren".to_string());
            }
            attributes.extend(uses);
            let attributes = attributes.join(" ");
            let line = format!(
                "* {response_name} ({attributes}) \"{DELIMITER}\" {}",
                render::string(&name)
            );
            self.line(&line).await?;
        }
        self.ok(&tag, &format!("{} completed", command.name))
            .await?;
        Ok(Control::Continue)
    }

    async fn handle_status(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 2)?;
        let name = string_arg(&command.args[0])?;
        let items = command.args[1]
            .list()
            .ok_or_else(|| MailError::invalid("STATUS requires an item list"))?;
        let mut requested = Vec::new();
        for item in items {
            let item = item
                .as_atom()
                .ok_or_else(|| MailError::invalid("STATUS items must be atoms"))?
                .to_ascii_uppercase();
            if !matches!(
                item.as_str(),
                "MESSAGES" | "RECENT" | "UIDNEXT" | "UIDVALIDITY" | "UNSEEN"
            ) {
                return self.bad(&tag, "unknown STATUS item").await;
            }
            requested.push(item);
        }
        let resolved = match self.resolve_mailbox(&name) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "l").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&resolved.store);
        let folder = resolved.folder.clone();
        let status = match blocking::maildir(&store, move |store| store.status(&folder)).await {
            Ok(status) => status,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        let values: Vec<String> = requested
            .iter()
            .map(|item| match item.as_str() {
                "MESSAGES" => format!("MESSAGES {}", status.messages),
                "RECENT" => format!("RECENT {}", status.recent),
                "UIDNEXT" => format!("UIDNEXT {}", status.uidnext),
                "UIDVALIDITY" => format!("UIDVALIDITY {}", status.uidvalidity),
                _ => format!("UNSEEN {}", status.unseen),
            })
            .collect();
        self.line(&format!(
            "* STATUS {} ({})",
            render::string(&name),
            values.join(" ")
        ))
        .await?;
        self.ok(&tag, "STATUS completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_getquota(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let root = string_arg(&command.args[0])?;
        if !root.is_empty() && !root.eq_ignore_ascii_case(INBOX) {
            return self
                .no_code(&tag, "NONEXISTENT", "unknown quota root")
                .await;
        }
        let store = Arc::clone(&self.store);
        let status = blocking::maildir(&store, |store| store.quota_status()).await?;
        self.line(&format!(
            "* QUOTA {} {}",
            render::string(INBOX),
            quota_resource_list(&status)
        ))
        .await?;
        self.ok(&tag, "GETQUOTA completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_getquotaroot(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let mailbox = string_arg(&command.args[0])?;
        let store = Arc::clone(&self.store);
        let mailbox_for_check = mailbox.clone();
        let exists =
            blocking::maildir(&store, move |store| store.exists(&mailbox_for_check)).await?;
        if !exists {
            return self
                .no_code(&tag, "NONEXISTENT", "mailbox does not exist")
                .await;
        }
        let store = Arc::clone(&self.store);
        let status = blocking::maildir(&store, |store| store.quota_status()).await?;
        self.line(&format!(
            "* QUOTAROOT {} {}",
            render::string(&mailbox),
            render::string(INBOX)
        ))
        .await?;
        self.line(&format!(
            "* QUOTA {} {}",
            render::string(INBOX),
            quota_resource_list(&status)
        ))
        .await?;
        self.ok(&tag, "GETQUOTAROOT completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_setquota(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        if !self.ctx.config.allow_setquota {
            return self.no_code(&tag, "NOPERM", "SETQUOTA is disabled").await;
        }
        self.expect_arity(command, 2)?;
        let root = string_arg(&command.args[0])?;
        if !root.eq_ignore_ascii_case(INBOX) {
            return self
                .no_code(&tag, "NONEXISTENT", "unknown quota root")
                .await;
        }
        let items = command.args[1]
            .list()
            .ok_or_else(|| MailError::protocol("SETQUOTA requires a resource list"))?;
        if items.is_empty() || items.len() % 2 != 0 {
            return self
                .bad(&tag, "SETQUOTA requires resource/value pairs")
                .await;
        }
        let mut messages: Option<u32> = None;
        let mut storage: Option<u64> = None;
        let mut index = 0usize;
        while index < items.len() {
            let resource = items[index]
                .text()
                .ok_or_else(|| MailError::invalid("invalid quota resource"))?
                .to_ascii_uppercase();
            let value: u64 = items[index + 1]
                .text()
                .ok_or_else(|| MailError::invalid("invalid quota value"))?
                .parse()
                .map_err(|_| MailError::invalid("quota value out of range"))?;
            match resource.as_str() {
                "MESSAGE" => {
                    messages = (value > 0)
                        .then(|| {
                            u32::try_from(value)
                                .map_err(|_| MailError::invalid("message quota out of range"))
                        })
                        .transpose()?;
                }
                "STORAGE" => {
                    storage = (value > 0)
                        .then(|| {
                            value
                                .checked_mul(1024)
                                .ok_or_else(|| MailError::invalid("storage quota out of range"))
                        })
                        .transpose()?;
                }
                _ => {
                    return self
                        .bad(&tag, &format!("unsupported quota resource: {resource}"))
                        .await
                }
            }
            index += 2;
        }
        let store = Arc::clone(&self.store);
        blocking::maildir(&store, move |store| store.set_quota(messages, storage)).await?;
        self.ok(&tag, "SETQUOTA completed").await?;
        Ok(Control::Continue)
    }

    // -----------------------------------------------------------------
    // 写入
    // -----------------------------------------------------------------

    async fn handle_append(&mut self, command: Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        let mut args = command.args.into_iter();
        let Some(first) = args.next() else {
            return self
                .bad(&tag, "APPEND requires a mailbox and a message")
                .await;
        };
        let mailbox = string_arg(&first)?;
        if matches!(&self.state, State::Selected { view, .. } if view.folder.eq_ignore_ascii_case(&mailbox) && !view.writable)
        {
            return self
                .no_code(&tag, "READ-ONLY", "mailbox is read-only")
                .await;
        }

        // MULTIAPPEND（RFC 3502）：mailbox [flags] [date] literal ...
        // literal 直接 move 进 NewMessage，避免为 32 MiB 正文再做一次复制。
        let mut messages: Vec<NewMessage> = Vec::new();
        let mut flags = FlagSet::new();
        let mut date = None;
        for token in args {
            match token {
                Token::List(items) => flags = parse_flag_items(&items)?,
                Token::Literal(data) => {
                    messages.push(NewMessage {
                        data,
                        flags: std::mem::take(&mut flags),
                        internal_date: date.take(),
                    });
                    if messages.len() > 1000 {
                        return self.bad(&tag, "APPEND accepts at most 1000 messages").await;
                    }
                }
                Token::Atom(text) | Token::Quoted(text) => {
                    date = Some(date::parse_date_time(&text)?);
                }
            }
        }
        if messages.is_empty() {
            return self.bad(&tag, "APPEND requires a literal message").await;
        }
        if !flags.is_empty() || date.is_some() {
            return self
                .bad(&tag, "APPEND flags/date must precede a message")
                .await;
        }

        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "i").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&resolved.store);
        let target = resolved.folder.clone();
        let appended =
            blocking::maildir(&store, move |store| store.append_many(&target, &messages)).await;
        let (uidvalidity, uids) = match appended {
            Ok(result) => result,
            Err(MailError::NotFound(_)) => {
                self.no_code(&tag, "TRYCREATE", "target mailbox does not exist")
                    .await?;
                return Ok(Control::Continue);
            }
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        self.ok(
            &tag,
            &format!(
                "[APPENDUID {uidvalidity} {}] APPEND completed",
                SequenceSet::from_values(&uids)
            ),
        )
        .await?;
        if matches!(&self.state, State::Selected { view, .. } if view.folder.eq_ignore_ascii_case(&resolved.folder))
        {
            // 本地追加后必须绕过 mtime 快速路径：粗粒度时间戳可能让「刚写入」
            // 与上次扫描落在同一刻度，客户端就收不到 EXISTS。
            self.invalidate_view_stamp();
            self.refresh_selected().await?;
        }
        Ok(Control::Continue)
    }

    async fn handle_close(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.expect_arity(command, 0)?;
        let (folder, writable) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.writable),
            _ => return self.bad(&tag, "CLOSE requires a selected mailbox").await,
        };
        if writable {
            self.require_selected_rights("t").await?;
            let uids: Vec<u32> = self
                .view()
                .map(|view| {
                    view.messages
                        .iter()
                        .filter(|message| message.flags.iter().any(Flag::is_deleted))
                        .map(|message| message.uid)
                        .collect()
                })
                .unwrap_or_default();
            if !uids.is_empty() {
                let store = Arc::clone(&self.store);
                let target = folder.clone();
                blocking::maildir(&store, move |store| store.expunge(&target, &uids)).await?;
            }
        }
        self.deselect_to_personal();
        self.ok(&tag, "CLOSE completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_expunge(
        &mut self,
        command: &Command,
        restrict: Option<&SequenceSet>,
    ) -> Result<Control> {
        let tag = command.tag.clone();
        if restrict.is_some() {
            self.expect_arity(command, 1)?;
        } else {
            self.expect_arity(command, 0)?;
        }
        let (folder, writable, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.writable, view.max_uid()),
            _ => return self.bad(&tag, "EXPUNGE requires a selected mailbox").await,
        };
        if !writable {
            return self
                .no_code(&tag, "READ-ONLY", "mailbox is read-only")
                .await;
        }
        // 共享邮箱需要删除权限（t）。
        self.require_selected_rights("t").await?;

        let restrict = match restrict {
            Some(set) => set.clone(),
            None => {
                // 全量 EXPUNGE 的集合语义由「所有 \Deleted」表达。
                SequenceSet::parse("1:*").unwrap_or_default()
            }
        };
        let mut targets: Vec<(u32, u32)> = Vec::new(); // (sequence, uid)
        if let Some(view) = self.view() {
            for (index, message) in view.messages.iter().enumerate() {
                let deleted = message.flags.iter().any(Flag::is_deleted);
                if !deleted {
                    continue;
                }
                let selected_by_set = restrict.contains(message.uid, max_uid);
                if selected_by_set {
                    targets.push((index as u32 + 1, message.uid));
                }
            }
        }

        let uids: Vec<u32> = targets.iter().map(|(_, uid)| *uid).collect();
        if !uids.is_empty() {
            let store = Arc::clone(&self.store);
            let target = folder.clone();
            let expunge_uids = uids.clone();
            blocking::maildir(&store, move |store| store.expunge(&target, &expunge_uids)).await?;
        }
        let mut sequences: Vec<u32> = targets.iter().map(|(sequence, _)| *sequence).collect();
        if self.qresync {
            if !uids.is_empty() {
                self.line(&format!("* VANISHED {}", SequenceSet::from_values(&uids)))
                    .await?;
            }
        } else {
            sequences.sort_unstable_by(|a, b| b.cmp(a));
            for sequence in sequences {
                self.line(&format!("* {sequence} EXPUNGE")).await?;
            }
        }
        let removed: HashSet<u32> = uids.into_iter().collect();
        if let State::Selected { view, .. } = &mut self.state {
            view.messages
                .retain(|message| !removed.contains(&message.uid));
        }
        self.ok(&tag, "EXPUNGE completed").await?;
        Ok(Control::Continue)
    }

    // -----------------------------------------------------------------
    // 读取
    // -----------------------------------------------------------------

    async fn handle_uid(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        let Some(subcommand) = command.args.first().and_then(Token::as_atom) else {
            return self.bad(&tag, "UID requires a subcommand").await;
        };
        let subcommand = subcommand.to_ascii_uppercase();
        let mut inner = command.clone();
        inner.args = command.args[1..].to_vec();
        inner.name = subcommand.clone();
        let raw = command
            .raw_args
            .as_deref()
            .and_then(|raw| raw.trim().split_once(' '))
            .map(|(_, rest)| rest.trim().to_string());
        inner.raw_args = raw;

        match subcommand.as_str() {
            "FETCH" => self.handle_fetch(&inner, true).await,
            "STORE" => self.handle_store(&inner, true).await,
            "SEARCH" => self.handle_search(&inner, true).await,
            "SORT" => self.handle_sort(&inner, true).await,
            "THREAD" => self.handle_thread(&inner, true).await,
            "COPY" => self.handle_copy(&inner, true).await,
            "MOVE" => self.handle_move(&inner, true).await,
            "EXPUNGE" => {
                let set = match inner.args.first().and_then(Token::text) {
                    Some(text) => match self.parse_sequence_set(&text, true) {
                        Ok(set) => set,
                        Err(error) => {
                            self.send_failure(&tag, &error).await?;
                            return Ok(Control::Continue);
                        }
                    },
                    None => return self.bad(&tag, "UID EXPUNGE requires a set").await,
                };
                self.handle_expunge(&inner, Some(&set)).await
            }
            _ => self.bad(&tag, "unsupported UID subcommand").await,
        }
    }

    async fn handle_sort(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_selected(&tag)?;
        if command.args.len() < 3 {
            return self
                .bad(&tag, "SORT requires criteria, charset and search keys")
                .await;
        }
        let criteria_tokens = command.args[0]
            .list()
            .ok_or_else(|| MailError::protocol("SORT criteria must be a list"))?;
        let criteria = match sort::parse_criteria(criteria_tokens) {
            Ok(criteria) => criteria,
            Err(error) => return self.bad(&tag, &error.to_string()).await,
        };
        let charset = string_arg(&command.args[1])?;
        let normalized = charset.to_ascii_uppercase();
        if normalized != "US-ASCII" && normalized != "UTF-8" {
            self.no_code(
                &tag,
                "BADCHARSET (US-ASCII UTF-8)",
                &format!("charset {charset} is not supported"),
            )
            .await?;
            return Ok(Control::Continue);
        }
        let parsed = match search::parse(&command.args[2..]) {
            Ok(parsed) => parsed,
            Err(search::SearchError::BadCharset(charset)) => {
                self.no_code(
                    &tag,
                    "BADCHARSET (US-ASCII UTF-8)",
                    &format!("charset {charset} is not supported"),
                )
                .await?;
                return Ok(Control::Continue);
            }
            Err(search::SearchError::Invalid(message)) => {
                return self.bad(&tag, &message).await;
            }
        };
        if parsed.options.is_some() {
            return self.bad(&tag, "RETURN is not valid with SORT").await;
        }
        let needs_search_message = search::needs_message(&parsed.key);
        let needs_sort_headers = sort::needs_headers(&criteria);
        let needs_message = needs_search_message || needs_sort_headers;
        let (messages, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.messages.clone(), view.max_uid()),
            _ => return self.bad(&tag, "SORT requires a selected mailbox").await,
        };

        let mut matched: Vec<(u32, sort::SortValues)> = Vec::new();
        // 元数据预筛：只看 Meta 就能判定的条件直接出结果；其余邮件收集起来
        // 分批读正文（每批一次 blocking::maildir，取代逐封一次的 spawn 往返）。
        let mut pending: Vec<usize> = Vec::new();
        for (index, meta) in messages.iter().enumerate() {
            if needs_message && meta.size > self.ctx.config.max_message_size {
                return Err(MailError::invalid(
                    "a message is too large to sort; use a narrower search",
                ));
            }
            let context = SearchContext {
                meta,
                sequence: index as u32 + 1,
                max_sequence: messages.len() as u32,
                max_uid,
                message: &[],
            };
            match search::matches_meta(&parsed.key, &context) {
                Some(false) => {}
                // 已命中且排序值不需要邮件头：无需正文，直接取值。
                Some(true) if !needs_sort_headers => matched.push((
                    if uid_mode { meta.uid } else { index as u32 + 1 },
                    sort::values(meta, &[], &criteria),
                )),
                // 判定未定，或排序值需要邮件头 —— 统一进批读正文。
                _ => pending.push(index),
            }
        }
        for (start, end) in content_batch_ranges(&pending, &messages) {
            let batch: Vec<MessageMeta> = pending[start..end]
                .iter()
                .map(|&index| messages[index].clone())
                .collect();
            let contents = read_content_batch(&self.store, batch).await?;
            for (offset, message) in contents.iter().enumerate() {
                let index = pending[start + offset];
                let meta = &messages[index];
                let context = SearchContext {
                    meta,
                    sequence: index as u32 + 1,
                    max_sequence: messages.len() as u32,
                    max_uid,
                    message: message.as_slice(),
                };
                if search::matches(&parsed.key, &context) {
                    matched.push((
                        if uid_mode { meta.uid } else { index as u32 + 1 },
                        sort::values(meta, message, &criteria),
                    ));
                }
            }
        }
        let numbers = sort::sort(matched, &criteria);
        let mut line = String::from("* SORT");
        for number in numbers {
            line.push(' ');
            line.push_str(&number.to_string());
        }
        line.push_str("\r\n");
        self.write_all(line.as_bytes()).await?;
        self.ok(&tag, "SORT completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_thread(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_selected(&tag)?;
        if command.args.len() < 3 {
            return self
                .bad(&tag, "THREAD requires algorithm, charset and search keys")
                .await;
        }
        let algorithm_name = string_arg(&command.args[0])?;
        let Some(algorithm) = ThreadAlgorithm::parse(&algorithm_name) else {
            return self
                .bad(
                    &tag,
                    &format!("unsupported THREAD algorithm: {algorithm_name}"),
                )
                .await;
        };
        let charset = string_arg(&command.args[1])?;
        let normalized = charset.to_ascii_uppercase();
        if normalized != "US-ASCII" && normalized != "UTF-8" {
            self.no_code(
                &tag,
                "BADCHARSET (US-ASCII UTF-8)",
                &format!("charset {charset} is not supported"),
            )
            .await?;
            return Ok(Control::Continue);
        }
        let parsed = match search::parse(&command.args[2..]) {
            Ok(parsed) => parsed,
            Err(search::SearchError::BadCharset(charset)) => {
                self.no_code(
                    &tag,
                    "BADCHARSET (US-ASCII UTF-8)",
                    &format!("charset {charset} is not supported"),
                )
                .await?;
                return Ok(Control::Continue);
            }
            Err(search::SearchError::Invalid(message)) => {
                return self.bad(&tag, &message).await;
            }
        };
        if parsed.options.is_some() {
            return self.bad(&tag, "RETURN is not valid with THREAD").await;
        }
        let (messages, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.messages.clone(), view.max_uid()),
            _ => return self.bad(&tag, "THREAD requires a selected mailbox").await,
        };

        let mut threads = Vec::new();
        // THREAD 的分组值（主题 / 引用链）始终取自邮件头：预筛只排除在搜索
        // 阶段仅凭 Meta 就已确定不命中的邮件，其余的分批读正文 —— 之前是
        // 每封先读后判，不命中的邮件也付了一次磁盘 I/O。
        let mut pending: Vec<usize> = Vec::new();
        for (index, meta) in messages.iter().enumerate() {
            if meta.size > self.ctx.config.max_message_size {
                return Err(MailError::invalid(
                    "a message is too large to thread; use a narrower search",
                ));
            }
            let context = SearchContext {
                meta,
                sequence: index as u32 + 1,
                max_sequence: messages.len() as u32,
                max_uid,
                message: &[],
            };
            if search::matches_meta(&parsed.key, &context) != Some(false) {
                pending.push(index);
            }
        }
        for (start, end) in content_batch_ranges(&pending, &messages) {
            let batch: Vec<MessageMeta> = pending[start..end]
                .iter()
                .map(|&index| messages[index].clone())
                .collect();
            let contents = read_content_batch(&self.store, batch).await?;
            for (offset, message) in contents.iter().enumerate() {
                let index = pending[start + offset];
                let meta = &messages[index];
                let context = SearchContext {
                    meta,
                    sequence: index as u32 + 1,
                    max_sequence: messages.len() as u32,
                    max_uid,
                    message: message.as_slice(),
                };
                if !search::matches(&parsed.key, &context) {
                    continue;
                }
                let number = if uid_mode { meta.uid } else { index as u32 + 1 };
                threads.push(thread::from_message(number, meta, message));
            }
        }
        let rendered = thread::render(algorithm, &threads);
        let line = if rendered.is_empty() {
            "* THREAD\r\n".to_string()
        } else {
            format!("* THREAD {rendered}\r\n")
        };
        self.write_all(line.as_bytes()).await?;
        self.ok(&tag, "THREAD completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_fetch(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_selected(&tag)?;
        let raw = command
            .raw_args
            .as_deref()
            .ok_or_else(|| MailError::protocol("FETCH requires arguments"))?;
        let (set_text, items_text) = raw.trim().split_once(' ').unwrap_or((raw.trim(), ""));
        let (items_text, changed_since) = match fetch::split_changedsince(items_text) {
            Ok(parsed) => parsed,
            Err(error) => return self.bad(&tag, &error.to_string()).await,
        };
        if items_text.trim().is_empty() {
            return self.bad(&tag, "FETCH requires items").await;
        }
        if changed_since.is_some() && !self.condstore {
            return self.bad(&tag, "CHANGEDSINCE requires CONDSTORE").await;
        }
        let set = match self.parse_sequence_set(set_text, uid_mode) {
            Ok(set) => set,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        let items = match fetch::parse_items(items_text) {
            Ok(items) => items,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if items.contains(&fetch::FetchItem::ModSeq) && !self.condstore {
            return self.bad(&tag, "MODSEQ requires CONDSTORE").await;
        }
        let needs_message = fetch::needs_message(&items);
        let needs_full_message = fetch::needs_full_message(&items);
        let (folder, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.max_uid()),
            _ => return self.bad(&tag, "FETCH requires a selected mailbox").await,
        };

        let indices: Vec<usize> = self
            .view()
            .map(|view| {
                view.messages
                    .iter()
                    .enumerate()
                    .filter(|(index, message)| {
                        let selected = if uid_mode {
                            set.contains(message.uid, max_uid)
                        } else {
                            set.contains(*index as u32 + 1, view.max_seq())
                        };
                        selected && changed_since.is_none_or(|modseq| message.modseq > modseq)
                    })
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default();

        let mut seen_updates: Vec<(u32, u32, FlagSet, u64)> = Vec::new();
        for index in indices {
            let Some(meta) = self.view().and_then(|view| view.message(index)).cloned() else {
                continue;
            };
            let message = if needs_message {
                if meta.size > self.ctx.config.max_message_size {
                    return Err(MailError::invalid("message is too large to fetch"));
                }
                let store = Arc::clone(&self.store);
                let meta_for_read = meta.clone();
                let header_limit = crate::mime::MAX_HEADER_BYTES + 2;
                Some(if needs_full_message {
                    blocking::maildir(&store, move |store| store.read(&meta_for_read)).await?
                } else {
                    // 只要头部时读前缀，避免把 50 MiB 的正文也读进内存。
                    blocking::maildir(&store, move |store| {
                        store.read_prefix(&meta_for_read, header_limit)
                    })
                    .await?
                })
            } else {
                None
            };
            let (rendered, mark_seen) = fetch::render(&items, &meta, message.as_deref(), uid_mode)?;
            let sequence = index as u32 + 1;
            self.write_all(format!("* {sequence} FETCH (").as_bytes())
                .await?;
            self.write_all(&rendered).await?;
            self.write_all(b")\r\n").await?;

            if mark_seen && !meta.flags.iter().any(Flag::is_seen) {
                let mut flags = meta.flags.clone();
                flags.insert(Flag::System(SystemFlag::Seen));
                let store = Arc::clone(&self.store);
                let target = folder.clone();
                let uid = meta.uid;
                let new_flags = flags.clone();
                let updated = blocking::maildir(&store, move |store| {
                    store.set_flags(&target, uid, &new_flags)
                })
                .await?;
                self.update_view_message(uid, updated.flags.clone(), updated.modseq);
                seen_updates.push((sequence, uid, flags, updated.modseq));
            }
        }

        for (sequence, uid, flags, modseq) in seen_updates {
            let mut line = format!("* {sequence} FETCH (FLAGS {}", fetch::format_flags(&flags));
            if self.condstore {
                line.push_str(&format!(" MODSEQ ({modseq})"));
            }
            if uid_mode {
                line.push_str(&format!(" UID {uid}"));
            }
            line.push_str(")\r\n");
            self.write_all(line.as_bytes()).await?;
        }

        self.ok(&tag, "FETCH completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_store(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        let (folder, writable, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.writable, view.max_uid()),
            _ => return self.bad(&tag, "STORE requires a selected mailbox").await,
        };
        if !writable {
            return self
                .no_code(&tag, "READ-ONLY", "mailbox is read-only")
                .await;
        }
        // 共享邮箱需要写标志权限（w）。
        self.require_selected_rights("w").await?;
        if command.args.len() != 3 && command.args.len() != 4 {
            return self.bad(&tag, "STORE requires set, item, flags").await;
        }
        let set_text = string_arg(&command.args[0])?;
        let set = match self.parse_sequence_set(&set_text, uid_mode) {
            Ok(set) => set,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        let item = string_arg(&command.args[1])?.to_ascii_uppercase();
        let (mode, silent) = match item.as_str() {
            "FLAGS" => (StoreMode::Replace, false),
            "FLAGS.SILENT" => (StoreMode::Replace, true),
            "+FLAGS" => (StoreMode::Add, false),
            "+FLAGS.SILENT" => (StoreMode::Add, true),
            "-FLAGS" => (StoreMode::Remove, false),
            "-FLAGS.SILENT" => (StoreMode::Remove, true),
            _ => return self.bad(&tag, "unknown STORE item").await,
        };
        let new_flags = parse_flag_tokens(&command.args[2])?;
        let unchanged_since = match command.args.get(3) {
            None => None,
            Some(token) => {
                if !self.condstore {
                    return self.bad(&tag, "UNCHANGEDSINCE requires CONDSTORE").await;
                }
                let items = token
                    .list()
                    .ok_or_else(|| MailError::protocol("STORE modifier must be a list"))?;
                if items.len() != 2 {
                    return self.bad(&tag, "UNCHANGEDSINCE requires a modseq").await;
                }
                let keyword = items[0]
                    .as_atom()
                    .ok_or_else(|| MailError::protocol("invalid STORE modifier"))?;
                if !keyword.eq_ignore_ascii_case("UNCHANGEDSINCE") {
                    return self
                        .bad(&tag, &format!("unsupported STORE modifier: {keyword}"))
                        .await;
                }
                let value = items[1]
                    .text()
                    .ok_or_else(|| MailError::protocol("invalid UNCHANGEDSINCE value"))?;
                Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| MailError::invalid("UNCHANGEDSINCE modseq out of range"))?,
                )
            }
        };

        let targets: Vec<(usize, u32)> = self
            .view()
            .map(|view| {
                view.messages
                    .iter()
                    .enumerate()
                    .filter(|(index, message)| {
                        if uid_mode {
                            set.contains(message.uid, max_uid)
                        } else {
                            set.contains(*index as u32 + 1, view.max_seq())
                        }
                    })
                    .map(|(index, message)| (index, message.uid))
                    .collect()
            })
            .unwrap_or_default();

        let mut modified: Vec<u32> = Vec::new();
        for (index, uid) in targets {
            let Some(meta) = self.view().and_then(|view| view.message(index)).cloned() else {
                continue;
            };
            if let Some(limit) = unchanged_since {
                if meta.modseq > limit {
                    modified.push(if uid_mode { uid } else { index as u32 + 1 });
                    continue;
                }
            }
            let mut flags = meta.flags.clone();
            match mode {
                StoreMode::Replace => flags = new_flags.clone(),
                StoreMode::Add => flags.extend(new_flags.iter().cloned()),
                StoreMode::Remove => flags.retain(|flag| !new_flags.contains(flag)),
            }
            let store = Arc::clone(&self.store);
            let target = folder.clone();
            let flags_for_store = flags.clone();
            let updated = blocking::maildir(&store, move |store| {
                store.set_flags(&target, uid, &flags_for_store)
            })
            .await?;
            self.update_view_message(uid, updated.flags.clone(), updated.modseq);
            if !silent {
                let mut line = format!(
                    "* {} FETCH (FLAGS {}",
                    index + 1,
                    fetch::format_flags(&flags)
                );
                if self.condstore {
                    line.push_str(&format!(" MODSEQ ({})", updated.modseq));
                }
                if uid_mode {
                    line.push_str(&format!(" UID {uid}"));
                }
                line.push_str(")\r\n");
                self.write_all(line.as_bytes()).await?;
            }
        }
        if modified.is_empty() {
            self.ok(&tag, "STORE completed").await?;
        } else {
            self.ok(
                &tag,
                &format!(
                    "[MODIFIED {}] STORE completed",
                    SequenceSet::from_values(&modified)
                ),
            )
            .await?;
        }
        Ok(Control::Continue)
    }

    async fn handle_copy(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        let (folder, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.max_uid()),
            _ => return self.bad(&tag, "COPY requires a selected mailbox").await,
        };
        self.expect_arity(command, 2)?;
        let set = match self.parse_sequence_set(&string_arg(&command.args[0])?, uid_mode) {
            Ok(set) => set,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        let target = string_arg(&command.args[1])?;
        let destination = match self.resolve_mailbox(&target) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&destination, "i").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        if !Arc::ptr_eq(&destination.store, &self.store) {
            return self
                .no_code(&tag, "NOPERM", "cross-store COPY is not supported")
                .await;
        }
        let store = Arc::clone(&self.store);
        let target_for_check = destination.folder.clone();
        let exists =
            blocking::maildir(&store, move |store| store.exists(&target_for_check)).await?;
        if !exists {
            return self
                .no_code(&tag, "TRYCREATE", "target mailbox does not exist")
                .await;
        }
        let targets: Vec<u32> = self
            .view()
            .map(|view| {
                view.messages
                    .iter()
                    .enumerate()
                    .filter(|(index, message)| {
                        if uid_mode {
                            set.contains(message.uid, max_uid)
                        } else {
                            set.contains(*index as u32 + 1, view.max_seq())
                        }
                    })
                    .map(|(_, message)| message.uid)
                    .collect()
            })
            .unwrap_or_default();

        if targets.is_empty() {
            self.ok(&tag, "COPY completed").await?;
            return Ok(Control::Continue);
        }
        // 一次打开源邮箱、一次索引；逐封调用 `store.copy` 会为每封信重新扫描
        // 整个文件夹（k 封复制 = O(k·n)）。
        let store = Arc::clone(&self.store);
        let source_folder = folder.clone();
        let destination_folder = destination.folder.clone();
        let copy_uids = targets.clone();
        let (uidvalidity, destination_uids) = blocking::maildir(&store, move |store| {
            store.copy_many(&source_folder, &copy_uids, &destination_folder)
        })
        .await?;
        self.ok(
            &tag,
            &format!(
                "[COPYUID {uidvalidity} {} {}] COPY completed",
                SequenceSet::from_values(&targets),
                SequenceSet::from_values(&destination_uids)
            ),
        )
        .await?;
        if matches!(&self.state, State::Selected { view, .. } if view.folder.eq_ignore_ascii_case(&destination.folder))
        {
            self.invalidate_view_stamp();
            self.refresh_selected().await?;
        }
        Ok(Control::Continue)
    }

    /// RFC 6851 MOVE：复制到目标、删除源邮件，并以 untagged EXPUNGE 汇报。
    async fn handle_move(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        let (folder, writable, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.folder.clone(), view.writable, view.max_uid()),
            _ => return self.bad(&tag, "MOVE requires a selected mailbox").await,
        };
        if !writable {
            return self
                .no_code(&tag, "READ-ONLY", "mailbox is read-only")
                .await;
        }
        self.expect_arity(command, 2)?;
        let set = match self.parse_sequence_set(&string_arg(&command.args[0])?, uid_mode) {
            Ok(set) => set,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        let target = string_arg(&command.args[1])?;
        let destination = match self.resolve_mailbox(&target) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&destination, "i").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        if !Arc::ptr_eq(&destination.store, &self.store) {
            return self
                .no_code(&tag, "NOPERM", "cross-store MOVE is not supported")
                .await;
        }
        if destination.folder.eq_ignore_ascii_case(&folder) {
            return self
                .no_code(
                    &tag,
                    "CANNOT",
                    "source and destination are the same mailbox",
                )
                .await;
        }
        let store = Arc::clone(&self.store);
        let target_for_check = destination.folder.clone();
        let exists =
            blocking::maildir(&store, move |store| store.exists(&target_for_check)).await?;
        if !exists {
            return self
                .no_code(&tag, "TRYCREATE", "target mailbox does not exist")
                .await;
        }

        let targets: Vec<u32> = self
            .view()
            .map(|view| {
                view.messages
                    .iter()
                    .enumerate()
                    .filter(|(index, message)| {
                        if uid_mode {
                            set.contains(message.uid, max_uid)
                        } else {
                            set.contains(*index as u32 + 1, view.max_seq())
                        }
                    })
                    .map(|(_, message)| message.uid)
                    .collect()
            })
            .unwrap_or_default();
        if targets.is_empty() {
            self.ok(&tag, "MOVE completed").await?;
            return Ok(Control::Continue);
        }
        let sequences: Vec<u32> = self
            .view()
            .map(|view| {
                targets
                    .iter()
                    .filter_map(|uid| {
                        view.messages
                            .iter()
                            .position(|message| message.uid == *uid)
                            .map(|index| index as u32 + 1)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let store = Arc::clone(&self.store);
        let source_folder = folder.clone();
        let destination_folder = destination.folder.clone();
        let copy_uids = targets.clone();
        let (uidvalidity, destination_uids) = blocking::maildir(&store, move |store| {
            store.copy_many(&source_folder, &copy_uids, &destination_folder)
        })
        .await?;

        let store = Arc::clone(&self.store);
        let source_folder = folder.clone();
        let expunge_uids = targets.clone();
        if let Err(error) = blocking::maildir(&store, move |store| {
            store.expunge(&source_folder, &expunge_uids)
        })
        .await
        {
            // 源删除失败：尽量撤回目标副本，避免同一封邮件两份都留下。
            let store = Arc::clone(&self.store);
            let destination_folder = destination.folder.clone();
            let rollback = destination_uids.clone();
            let _ = blocking::maildir(&store, move |store| {
                store.expunge(&destination_folder, &rollback)
            })
            .await;
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }

        self.line(&format!(
            "* OK [COPYUID {uidvalidity} {} {}] MOVE completed",
            SequenceSet::from_values(&targets),
            SequenceSet::from_values(&destination_uids)
        ))
        .await?;
        let mut sequences = sequences;
        if self.qresync {
            self.line(&format!(
                "* VANISHED {}",
                SequenceSet::from_values(&targets)
            ))
            .await?;
        } else {
            sequences.sort_unstable_by(|a, b| b.cmp(a));
            for sequence in sequences {
                self.line(&format!("* {sequence} EXPUNGE")).await?;
            }
        }
        let removed: HashSet<u32> = targets.into_iter().collect();
        if let State::Selected { view, .. } = &mut self.state {
            view.messages
                .retain(|message| !removed.contains(&message.uid));
        }
        self.ok(&tag, "MOVE completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_getmetadata(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        let (mailbox, entries) = parse_metadata_args(command)?;
        if let Some(mailbox) = &mailbox {
            self.deny_shared(mailbox)?;
        }
        let (scope_folder, response_name) = self.resolve_metadata_scope(&mailbox)?;

        let mut names = Vec::with_capacity(entries.len());
        for token in &entries {
            let name = token
                .text()
                .ok_or_else(|| MailError::protocol("invalid metadata entry"))?;
            validate_metadata_entry(&name)?;
            names.push(name);
        }

        let store = Arc::clone(&self.store);
        let scope = scope_folder.clone();
        let map =
            blocking::maildir(&store, move |store| store.read_metadata(scope.as_deref())).await?;

        // 值按 literal 输出：meta 值可含任意字节，quoted 会破坏含 CR/LF 的应答。
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(
            format!("* METADATA {} (", crate::render::quoted(&response_name)).as_bytes(),
        );
        for (index, name) in names.iter().enumerate() {
            if index > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(crate::render::quoted(name).as_bytes());
            out.push(b' ');
            match map.get(name) {
                Some(value) => {
                    out.extend_from_slice(format!("{{{}}}\r\n", value.len()).as_bytes());
                    out.extend_from_slice(value);
                }
                None => out.extend_from_slice(b"NIL"),
            }
        }
        out.extend_from_slice(b")\r\n");
        self.write_all(&out).await?;
        self.ok(&tag, "GETMETADATA completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_setmetadata(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        let (mailbox, entries) = parse_metadata_args(command)?;
        if let Some(mailbox) = &mailbox {
            self.deny_shared(mailbox)?;
        }
        if entries.len() % 2 != 0 {
            return self
                .bad(&tag, "SETMETADATA expects entry/value pairs")
                .await;
        }
        let (scope_folder, _) = self.resolve_metadata_scope(&mailbox)?;

        let mut updates: Vec<(String, Option<Vec<u8>>)> = Vec::with_capacity(entries.len() / 2);
        for pair in entries.chunks(2) {
            let entry = pair[0]
                .text()
                .ok_or_else(|| MailError::protocol("invalid metadata entry"))?;
            validate_metadata_entry(&entry)?;
            let value = if pair[1].is_nil() {
                None
            } else if let Some(bytes) = pair[1].bytes() {
                Some(bytes.to_vec())
            } else {
                Some(
                    pair[1]
                        .text()
                        .ok_or_else(|| MailError::protocol("invalid metadata value"))?
                        .into_bytes(),
                )
            };
            updates.push((entry, value));
        }

        let store = Arc::clone(&self.store);
        let scope = scope_folder.clone();
        let mut map =
            blocking::maildir(&store, move |store| store.read_metadata(scope.as_deref())).await?;
        for (entry, value) in updates {
            match value {
                Some(value) => {
                    map.insert(entry, value);
                }
                None => {
                    map.remove(&entry);
                }
            }
        }
        let store = Arc::clone(&self.store);
        let scope = scope_folder.clone();
        let to_write = map;
        blocking::maildir(&store, move |store| {
            store.write_metadata(scope.as_deref(), &to_write)
        })
        .await?;
        self.ok(&tag, "SETMETADATA completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_getacl(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let mailbox = string_arg(&command.args[0])?;
        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "l").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let store = Arc::clone(&resolved.store);
        let name = resolved.folder.clone();
        let acl = blocking::maildir(&store, move |store| store.read_acl(&name)).await?;
        let owner = resolved
            .owner
            .clone()
            .unwrap_or_else(|| self.user().unwrap_or("").to_string());

        let mut line = format!(
            "* ACL {} {} {}",
            crate::render::quoted(&mailbox),
            crate::render::quoted(&owner),
            crate::acl::ALL_RIGHTS
        );
        for (identifier, rights) in &acl {
            if *identifier == owner {
                continue;
            }
            line.push(' ');
            line.push_str(&crate::render::quoted(identifier));
            line.push(' ');
            line.push_str(rights);
        }
        line.push_str("\r\n");
        self.write_all(line.as_bytes()).await?;
        self.ok(&tag, "GETACL completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_setacl(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 3)?;
        let mailbox = string_arg(&command.args[0])?;
        let identifier = string_arg(&command.args[1])?;
        let rights_raw = string_arg(&command.args[2])?;
        if !crate::acl::valid_identifier(&identifier) {
            return self.bad(&tag, "invalid ACL identifier").await;
        }
        let rights = match crate::acl::normalize_rights(&rights_raw) {
            Ok(rights) => rights,
            Err(error) => {
                return self
                    .send_failure(&tag, &error)
                    .await
                    .map(|_| Control::Continue)
            }
        };
        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "a").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let owner = resolved
            .owner
            .clone()
            .unwrap_or_else(|| self.user().unwrap_or("").to_string());
        let identifier = identifier.to_ascii_lowercase();
        if identifier == owner {
            return self
                .no_code(&tag, "ACL", "cannot change the owner's rights")
                .await;
        }
        let store = Arc::clone(&resolved.store);
        let name = resolved.folder.clone();
        let id = identifier.clone();
        blocking::maildir(&store, move |store| {
            let mut map = store.read_acl(&name)?;
            if rights.is_empty() {
                map.remove(&id);
            } else {
                map.insert(id.clone(), rights.clone());
            }
            store.write_acl(&name, &map)
        })
        .await?;
        self.ok(&tag, "SETACL completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_deleteacl(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 2)?;
        let mailbox = string_arg(&command.args[0])?;
        let identifier = string_arg(&command.args[1])?;
        if !crate::acl::valid_identifier(&identifier) {
            return self.bad(&tag, "invalid ACL identifier").await;
        }
        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "a").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        let owner = resolved
            .owner
            .clone()
            .unwrap_or_else(|| self.user().unwrap_or("").to_string());
        let identifier = identifier.to_ascii_lowercase();
        if identifier == owner {
            return self.no_code(&tag, "ACL", "cannot remove the owner").await;
        }
        let store = Arc::clone(&resolved.store);
        let name = resolved.folder.clone();
        let id = identifier.clone();
        blocking::maildir(&store, move |store| {
            let mut map = store.read_acl(&name)?;
            map.remove(&id);
            store.write_acl(&name, &map)
        })
        .await?;
        self.ok(&tag, "DELETEACL completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_listrights(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 2)?;
        let mailbox = string_arg(&command.args[0])?;
        let identifier = string_arg(&command.args[1])?;
        if !crate::acl::valid_identifier(&identifier) {
            return self.bad(&tag, "invalid ACL identifier").await;
        }
        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "l").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        // read_acl 同时做邮箱存在性检查。
        let store = Arc::clone(&resolved.store);
        let name = resolved.folder.clone();
        let _ = blocking::maildir(&store, move |store| store.read_acl(&name)).await?;

        let owner = resolved
            .owner
            .clone()
            .unwrap_or_else(|| self.user().unwrap_or("").to_string());
        let is_owner = identifier.eq_ignore_ascii_case(&owner);
        let (required, optional) = if is_owner {
            (crate::acl::ALL_RIGHTS, "")
        } else {
            ("", crate::acl::ALL_RIGHTS)
        };
        let mut line = format!(
            "* LISTRIGHTS {} {} {}",
            crate::render::quoted(&mailbox),
            crate::render::quoted(&identifier),
            crate::render::quoted(required)
        );
        for letter in optional.chars() {
            line.push(' ');
            line.push_str(&crate::render::quoted(&letter.to_string()));
        }
        line.push_str("\r\n");
        self.write_all(line.as_bytes()).await?;
        self.ok(&tag, "LISTRIGHTS completed").await?;
        Ok(Control::Continue)
    }

    async fn handle_myrights(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_authenticated(&tag)?;
        self.expect_arity(command, 1)?;
        let mailbox = string_arg(&command.args[0])?;
        let resolved = match self.resolve_mailbox(&mailbox) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.send_failure(&tag, &error).await?;
                return Ok(Control::Continue);
            }
        };
        if let Err(error) = self.require_shared_rights(&resolved, "l").await {
            self.send_failure(&tag, &error).await?;
            return Ok(Control::Continue);
        }
        // read_acl 顺带校验邮箱存在性；结果直接交给 my_rights，避免再读一次。
        let store = Arc::clone(&resolved.store);
        let name = resolved.folder.clone();
        let acl = blocking::maildir(&store, move |store| store.read_acl(&name)).await?;
        let rights = self.my_rights(&resolved, &acl);
        let line = format!(
            "* MYRIGHTS {} {}\r\n",
            crate::render::quoted(&mailbox),
            rights
        );
        self.write_all(line.as_bytes()).await?;
        self.ok(&tag, "MYRIGHTS completed").await?;
        Ok(Control::Continue)
    }

    /// 解析 METADATA 的目标：`None` 用当前选中的邮箱，`Some("")` 是服务器级。
    fn resolve_metadata_scope(&self, mailbox: &Option<String>) -> Result<(Option<String>, String)> {
        match mailbox {
            None => {
                let State::Selected { view, .. } = &self.state else {
                    return Err(MailError::protocol(
                        "METADATA requires a mailbox name or a selected mailbox",
                    ));
                };
                Ok((Some(view.folder.clone()), view.folder.clone()))
            }
            Some(name) if name.is_empty() => Ok((None, String::new())),
            Some(name) => Ok((Some(name.clone()), name.clone())),
        }
    }

    async fn handle_search(&mut self, command: &Command, uid_mode: bool) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_selected(&tag)?;
        let parsed = match search::parse(&command.args) {
            Ok(parsed) => parsed,
            Err(search::SearchError::BadCharset(charset)) => {
                self.no_code(
                    &tag,
                    "BADCHARSET (US-ASCII UTF-8)",
                    &format!("charset {charset} is not supported"),
                )
                .await?;
                return Ok(Control::Continue);
            }
            Err(search::SearchError::Invalid(message)) => {
                return self.bad(&tag, &message).await;
            }
        };
        if search::contains_modseq(&parsed.key) && !self.condstore {
            return self.bad(&tag, "MODSEQ requires CONDSTORE").await;
        }
        let needs_message = search::needs_message(&parsed.key);
        let (messages, max_uid) = match &self.state {
            State::Selected { view, .. } => (view.messages.clone(), view.max_uid()),
            _ => return self.bad(&tag, "SEARCH requires a selected mailbox").await,
        };

        let mut matched = vec![false; messages.len()];
        // 元数据预筛：只看 Meta 就能判定的条件直接出结果；需要正文的邮件
        // 分批读取（每批一次 blocking::maildir，取代逐封一次的 spawn 往返）。
        let mut pending: Vec<usize> = Vec::new();
        for (index, meta) in messages.iter().enumerate() {
            if needs_message && meta.size > self.ctx.config.max_message_size {
                // 静默跳过会让 SEARCH 给出「看起来完整、其实缺了几封」的结果。
                // 宁可明确失败，让客户端知道这次搜索不完整。
                return Err(MailError::invalid(
                    "a message is too large to search; use a narrower search",
                ));
            }
            let context = SearchContext {
                meta,
                sequence: index as u32 + 1,
                max_sequence: messages.len() as u32,
                max_uid,
                message: &[],
            };
            match search::matches_meta(&parsed.key, &context) {
                Some(false) => {}
                Some(true) => matched[index] = true,
                None => pending.push(index),
            }
        }
        for (start, end) in content_batch_ranges(&pending, &messages) {
            let batch: Vec<MessageMeta> = pending[start..end]
                .iter()
                .map(|&index| messages[index].clone())
                .collect();
            let contents = read_content_batch(&self.store, batch).await?;
            for (offset, message) in contents.iter().enumerate() {
                let index = pending[start + offset];
                let meta = &messages[index];
                let context = SearchContext {
                    meta,
                    sequence: index as u32 + 1,
                    max_sequence: messages.len() as u32,
                    max_uid,
                    message: message.as_slice(),
                };
                if search::matches(&parsed.key, &context) {
                    matched[index] = true;
                }
            }
        }

        let mut results = Vec::new();
        let mut matched_uids = Vec::new();
        for (index, hit) in matched.iter().enumerate() {
            if *hit {
                let meta = &messages[index];
                results.push(if uid_mode { meta.uid } else { index as u32 + 1 });
                matched_uids.push(meta.uid);
            }
        }

        if let Some(options) = parsed.options {
            if options.save {
                // RFC 5182：保存结果，且不回任何 untagged SEARCH/ESEARCH。
                self.saved_search = Some(matched_uids);
                self.ok(&tag, "SEARCH completed").await?;
                return Ok(Control::Continue);
            }
            // RFC 4731 ESEARCH：只回客户端请求的字段；空结果只回 COUNT 0。
            let mut response = format!("* ESEARCH (TAG \"{}\")", sanitize(&tag));
            if uid_mode {
                response.push_str(" UID");
            }
            if options.min {
                if let Some(value) = results.first() {
                    response.push_str(&format!(" MIN {value}"));
                }
            }
            if options.max {
                if let Some(value) = results.last() {
                    response.push_str(&format!(" MAX {value}"));
                }
            }
            if options.all && !results.is_empty() {
                response.push_str(&format!(" ALL {}", SequenceSet::from_values(&results)));
            }
            if options.count {
                response.push_str(&format!(" COUNT {}", results.len()));
            }
            self.line(&response).await?;
        } else {
            let mut line = String::from("* SEARCH");
            for value in results {
                line.push(' ');
                line.push_str(&value.to_string());
            }
            line.push_str("\r\n");
            self.write_all(line.as_bytes()).await?;
        }
        self.ok(&tag, "SEARCH completed").await?;
        Ok(Control::Continue)
    }

    // -----------------------------------------------------------------
    // IDLE 与刷新
    // -----------------------------------------------------------------

    async fn handle_idle(&mut self, command: &Command) -> Result<Control> {
        let tag = command.tag.clone();
        self.require_selected(&tag)?;
        self.expect_arity(command, 0)?;
        self.write_all(b"+ idling\r\n").await?;
        self.flush().await?;

        let started = Instant::now();
        loop {
            if started.elapsed() > self.ctx.config.idle_timeout {
                self.bye("IDLE timeout").await?;
                return Ok(Control::Close);
            }
            let read = tokio::time::timeout(
                self.ctx.config.idle_poll,
                self.io.read_line(self.ctx.config.max_line),
            )
            .await;
            match read {
                Err(_) => {
                    // 轮询窗口内没有 DONE：检查邮箱变化并继续。
                    self.refresh_selected().await?;
                    self.flush().await?;
                }
                Ok(Err(error)) => return Err(error),
                Ok(Ok(None)) => return Ok(Control::Close),
                Ok(Ok(Some(line))) => {
                    let text = String::from_utf8_lossy(&line).trim().to_string();
                    if text.eq_ignore_ascii_case("DONE") {
                        self.ok(&tag, "IDLE terminated").await?;
                        return Ok(Control::Continue);
                    }
                    // IDLE 期间只允许 DONE。其它命令以 tagged BAD 结束 IDLE，
                    // 而不是「回了 BAD 却继续 idling」——后者会让客户端误以为
                    // 已退出 IDLE，后续命令被当作 IDLE 内文本处理。
                    self.bad(&tag, "expected DONE").await?;
                    return Ok(Control::Continue);
                }
            }
        }
    }

    async fn refresh_selected(&mut self) -> Result<()> {
        let Some(folder) = self.view().map(|view| view.folder.clone()) else {
            return Ok(());
        };
        let store = Arc::clone(&self.store);
        let folder_for_stamp = folder.clone();
        let stamp =
            blocking::maildir(&store, move |store| store.folder_stamp(&folder_for_stamp)).await?;

        // 目录指纹未变 → 跳过整次扫描。每 10 次仍强制全量扫描，避免文件系统
        // 时间戳精度过低导致永久漏检。
        if self
            .view()
            .is_some_and(|view| view.stamp == Some(stamp) && view.skipped_stamps < 9)
        {
            if let State::Selected { view, .. } = &mut self.state {
                view.skipped_stamps += 1;
            }
            return Ok(());
        }

        let Some((old_messages, old_uidvalidity)) = self
            .view()
            .map(|view| (view.messages.clone(), view.uidvalidity))
        else {
            return Ok(());
        };
        let folder_for_open = folder.clone();
        let new_state: FolderState = blocking::maildir(&store, move |store| {
            store.open_folder(&folder_for_open, false)
        })
        .await?;

        if new_state.uidvalidity != old_uidvalidity {
            // 邮箱被重建：旧 UID 语义全部失效，只能整体重报。
            self.line(&format!(
                "* OK [UIDVALIDITY {}] UIDs valid",
                new_state.uidvalidity
            ))
            .await?;
            self.line(&format!("* {} EXISTS", new_state.messages.len()))
                .await?;
            self.line(&format!(
                "* {} RECENT",
                new_state
                    .messages
                    .iter()
                    .filter(|message| message.recent)
                    .count()
            ))
            .await?;
            if self.condstore {
                self.line(&format!(
                    "* OK [HIGHESTMODSEQ {}] HIGHESTMODSEQ",
                    new_state.highest_modseq
                ))
                .await?;
            }
        } else {
            let old_by_uid: HashMap<u32, &MessageMeta> = old_messages
                .iter()
                .map(|message| (message.uid, message))
                .collect();
            let new_uids: HashSet<u32> = new_state
                .messages
                .iter()
                .map(|message| message.uid)
                .collect();

            let expunged_messages: Vec<&MessageMeta> = old_messages
                .iter()
                .filter(|message| !new_uids.contains(&message.uid))
                .collect();
            if self.qresync {
                if !expunged_messages.is_empty() {
                    let uids: Vec<u32> = expunged_messages
                        .iter()
                        .map(|message| message.uid)
                        .collect();
                    self.line(&format!("* VANISHED {}", SequenceSet::from_values(&uids)))
                        .await?;
                }
            } else {
                let mut expunged: Vec<u32> = old_messages
                    .iter()
                    .enumerate()
                    .filter(|(_, message)| !new_uids.contains(&message.uid))
                    .map(|(index, _)| index as u32 + 1)
                    .collect();
                expunged.sort_unstable_by(|a, b| b.cmp(a));
                for sequence in expunged {
                    self.line(&format!("* {sequence} EXPUNGE")).await?;
                }
            }

            if new_state.messages.len() != old_messages.len()
                || new_state
                    .messages
                    .iter()
                    .any(|message| !old_by_uid.contains_key(&message.uid))
            {
                self.line(&format!("* {} EXISTS", new_state.messages.len()))
                    .await?;
            }

            let recent = new_state
                .messages
                .iter()
                .filter(|message| message.recent)
                .count();
            if recent > 0 {
                self.line(&format!("* {recent} RECENT")).await?;
            }

            for (index, message) in new_state.messages.iter().enumerate() {
                let Some(old) = old_by_uid.get(&message.uid) else {
                    continue;
                };
                if old.flags != message.flags {
                    let mut line = format!(
                        "* {} FETCH (FLAGS {}",
                        index + 1,
                        fetch::format_flags(&message.flags)
                    );
                    if self.condstore {
                        line.push_str(&format!(" MODSEQ ({})", message.modseq));
                    }
                    line.push_str(")\r\n");
                    self.write_all(line.as_bytes()).await?;
                }
            }
        }

        if let State::Selected { view, .. } = &mut self.state {
            view.uidvalidity = new_state.uidvalidity;
            view.uidnext = new_state.uidnext;
            view.highest_modseq = new_state.highest_modseq;
            view.messages = new_state.messages;
            view.stamp = Some(stamp);
            view.skipped_stamps = 0;
        }
        Ok(())
    }

    fn update_view_message(&mut self, uid: u32, flags: FlagSet, modseq: u64) {
        if let State::Selected { view, .. } = &mut self.state {
            if let Some(message) = view.messages.iter_mut().find(|message| message.uid == uid) {
                message.flags = flags;
                message.modseq = modseq;
            }
            if modseq > view.highest_modseq {
                view.highest_modseq = modseq;
            }
        }
    }

    /// 本地写入后清空指纹，确保下一次刷新走全量扫描。
    fn invalidate_view_stamp(&mut self) {
        if let State::Selected { view, .. } = &mut self.state {
            view.stamp = None;
        }
    }

    // -----------------------------------------------------------------
    // 应答与工具
    // -----------------------------------------------------------------

    fn view(&self) -> Option<&View> {
        match &self.state {
            State::Selected { view, .. } => Some(view),
            _ => None,
        }
    }

    fn user(&self) -> Option<&str> {
        match &self.state {
            State::NotAuthenticated => None,
            State::Authenticated { user } => Some(user),
            State::Selected { user, .. } => Some(user),
        }
    }

    fn require_authenticated(&self, _tag: &str) -> Result<()> {
        if matches!(self.state, State::NotAuthenticated) {
            return Err(MailError::Protocol(
                "command requires authentication".to_string(),
            ));
        }
        Ok(())
    }

    /// 解析序列集合。`$`（RFC 5182 SEARCHRES）先展开成已保存结果的**完整**
    /// 集合（如 `3,7:9`），而不是只取最高编号 —— 否则 SAVE 了多条结果后
    /// `$` 会静默漏掉除最大编号外的所有邮件。
    fn parse_sequence_set(&self, text: &str, uid_mode: bool) -> Result<SequenceSet> {
        let resolved = if text.contains('$') {
            let saved = self
                .saved_search
                .as_ref()
                .filter(|uids| !uids.is_empty())
                .ok_or_else(|| {
                    MailError::protocol("'$' requires a prior SEARCH with RETURN (SAVE)")
                })?;
            let view_messages: &[MessageMeta] = match &self.state {
                State::Selected { view, .. } => &view.messages,
                _ if !uid_mode => {
                    return Err(MailError::protocol("'$' requires a selected mailbox"));
                }
                _ => &[],
            };
            let numbers = saved_result_numbers(saved, uid_mode, view_messages)?;
            text.replace('$', &SequenceSet::from_values(&numbers))
        } else {
            text.to_string()
        };
        SequenceSet::parse(&resolved)
    }

    /// 解析邮箱名：`shared/<user>/<folder>` 指向目标用户存储，其余为本人存储。
    fn resolve_mailbox(&self, name: &str) -> Result<ResolvedMailbox> {
        if let Some(rest) = name.strip_prefix(SHARED_PREFIX) {
            let Some(resolver) = &self.ctx.resolver else {
                return Err(MailError::Invalid(
                    "shared mailboxes are not configured".to_string(),
                ));
            };
            let (user, folder) = match rest.split_once('/') {
                Some((user, folder)) => (user, folder),
                None => (rest, ""),
            };
            if user.is_empty() || folder.is_empty() {
                return Err(MailError::NotFound(name.to_string()));
            }
            let Some(store) = resolver.resolve(user) else {
                return Err(MailError::NotFound(name.to_string()));
            };
            Ok(ResolvedMailbox {
                store,
                folder: folder.to_string(),
                owner: Some(user.to_ascii_lowercase()),
            })
        } else {
            Ok(ResolvedMailbox {
                // 个人邮箱：用会话当前的 store（多用户装配下它已是本人邮箱，
                // 而 `ctx.store` 只是单用户部署的占位）。
                store: Arc::clone(&self.store),
                folder: name.to_string(),
                owner: None,
            })
        }
    }

    /// 回到「无选中 + 本人存储」：SELECT 失败或 CLOSE 时用。
    fn deselect_to_personal(&mut self) {
        if matches!(self.state, State::Selected { .. }) {
            let user = self.user().unwrap_or_default().to_string();
            self.state = State::Authenticated { user };
        }
        self.store = Arc::clone(&self.own_store);
        self.selected_owner = None;
    }

    /// 当前用户对目标邮箱的有效权限：本人/所有者全权；共享邮箱取 ACL 授予集。
    /// `acl` 由调用方通过 blocking 池读取（见 [`blocking::maildir`]）。
    fn my_rights(&self, resolved: &ResolvedMailbox, acl: &BTreeMap<String, String>) -> String {
        let Some(owner) = &resolved.owner else {
            return crate::acl::ALL_RIGHTS.to_string();
        };
        let me = self.user().unwrap_or("").to_ascii_lowercase();
        if me == *owner {
            return crate::acl::ALL_RIGHTS.to_string();
        }
        acl.get(&me)
            .or_else(|| acl.get("authenticated"))
            .or_else(|| acl.get("anyone"))
            .cloned()
            .unwrap_or_default()
    }

    /// 枚举共享命名空间下当前用户可见（有 `l` 权限）的邮箱。
    ///
    /// `folders()` / `read_acl()` / `list_users()` 都是同步文件 I/O，统一丢给
    /// blocking 池（[`blocking::maildir`]；resolver 用裸 `spawn_blocking`），
    /// 慢盘只会堆积 blocking 池，不会卡住 async worker。
    async fn shared_mailbox_listing(&self, pattern: &str) -> Result<Vec<(String, Vec<String>)>> {
        let Some(resolver) = &self.ctx.resolver else {
            return Ok(Vec::new());
        };
        let me = self.user().unwrap_or("").to_ascii_lowercase();
        let rest = pattern.strip_prefix(SHARED_PREFIX).unwrap_or(pattern);
        let mut out = Vec::new();
        if let Some((user_part, mailbox_pattern)) = rest.split_once('/') {
            let Some(store) = resolver.resolve(user_part) else {
                return Ok(Vec::new());
            };
            let owner = user_part.to_ascii_lowercase();
            let folders = blocking::maildir(&store, |store| store.folders()).await?;
            for folder in folders {
                if !matches_pattern(mailbox_pattern, &folder) {
                    continue;
                }
                if check_shared_rights(
                    &store,
                    &folder,
                    Some(owner.as_str()),
                    Some(me.as_str()),
                    "l",
                )
                .await
                .is_err()
                {
                    continue;
                }
                out.push((
                    format!("{SHARED_PREFIX}{user_part}/{folder}"),
                    vec!["\\HasNoChildren".to_string()],
                ));
            }
        } else {
            let users = {
                let resolver = Arc::clone(resolver);
                match tokio::task::spawn_blocking(move || resolver.list_users()).await {
                    Ok(users) => users,
                    Err(error) => {
                        // JoinError 代表 blocking 任务 panic 或 runtime 关闭；
                        // 与 blocking::maildir 的处理保持一致。
                        tracing::warn!(%error, "resolver blocking task failed");
                        return Err(MailError::storage(format!(
                            "resolver worker failed: {error}"
                        )));
                    }
                }
            };
            for user in users {
                if !matches_pattern(rest, &user) {
                    continue;
                }
                let Some(store) = resolver.resolve(&user) else {
                    continue;
                };
                let owner = user.to_ascii_lowercase();
                if check_shared_rights(&store, INBOX, Some(owner.as_str()), Some(me.as_str()), "l")
                    .await
                    .is_err()
                {
                    continue;
                }
                out.push((
                    format!("{SHARED_PREFIX}{user}"),
                    vec!["\\Noselect".to_string(), "\\HasChildren".to_string()],
                ));
            }
        }
        Ok(out)
    }

    async fn require_shared_rights(
        &self,
        resolved: &ResolvedMailbox,
        required: &str,
    ) -> Result<()> {
        check_shared_rights(
            &resolved.store,
            &resolved.folder,
            resolved.owner.as_deref(),
            self.user(),
            required,
        )
        .await
    }

    /// 对「当前选中邮箱」做权限检查（个人邮箱恒通过）。
    async fn require_selected_rights(&self, required: &str) -> Result<()> {
        let State::Selected { view, .. } = &self.state else {
            return Err(MailError::protocol("no selected mailbox"));
        };
        check_shared_rights(
            &self.store,
            &view.folder,
            self.selected_owner.as_deref(),
            self.user(),
            required,
        )
        .await
    }

    /// 共享邮箱上的结构性操作（建/删/改名/订阅）暂不支持。
    fn deny_shared(&self, name: &str) -> Result<()> {
        if name.starts_with(SHARED_PREFIX) {
            Err(MailError::Invalid(
                "this operation is not supported on shared mailboxes".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn require_selected(&self, _tag: &str) -> Result<()> {
        if !matches!(self.state, State::Selected { .. }) {
            return Err(MailError::Protocol(
                "command requires a selected mailbox".to_string(),
            ));
        }
        Ok(())
    }

    fn expect_arity(&self, command: &Command, expected: usize) -> Result<()> {
        if command.args.len() != expected {
            return Err(MailError::protocol(format!(
                "{} expects {expected} argument(s)",
                command.name
            )));
        }
        Ok(())
    }

    async fn relay(&mut self, tag: &str, result: Result<()>, completed: &str) -> Result<Control> {
        match result {
            Ok(()) => {
                self.ok(tag, completed).await?;
                Ok(Control::Continue)
            }
            Err(error) => {
                self.send_failure(tag, &error).await?;
                Ok(Control::Continue)
            }
        }
    }

    async fn ok(&mut self, tag: &str, text: &str) -> Result<()> {
        let line = format!("{tag} OK {}\r\n", sanitize(text));
        self.write_all(line.as_bytes()).await
    }

    async fn bad(&mut self, tag: &str, text: &str) -> Result<Control> {
        let line = format!("{tag} BAD {}\r\n", sanitize(text));
        self.write_all(line.as_bytes()).await?;
        Ok(Control::Continue)
    }

    async fn no_code(&mut self, tag: &str, code: &str, text: &str) -> Result<Control> {
        let line = format!("{tag} NO [{code}] {}\r\n", sanitize(text));
        self.write_all(line.as_bytes()).await?;
        Ok(Control::Continue)
    }

    async fn send_failure(&mut self, tag: &str, error: &MailError) -> Result<()> {
        let line = match error {
            MailError::NotFound(message) => {
                format!("{tag} NO [NONEXISTENT] {}\r\n", sanitize(message))
            }
            MailError::AlreadyExists(message) => {
                format!("{tag} NO [ALREADYEXISTS] {}\r\n", sanitize(message))
            }
            MailError::Invalid(message) => format!("{tag} NO {}\r\n", sanitize(message)),
            MailError::QuotaExceeded(message) => {
                format!("{tag} NO [OVERQUOTA] {}\r\n", sanitize(message))
            }
            MailError::Protocol(message) => format!("{tag} BAD {}\r\n", sanitize(message)),
            MailError::Storage(_) | MailError::Auth(_) | MailError::Io { .. } => {
                tracing::warn!(error = %error, "imap command failed");
                format!("{tag} NO [SERVERBUG] internal server error\r\n")
            }
            MailError::Config(_) => format!("{tag} NO [SERVERBUG] server misconfigured\r\n"),
            MailError::Timeout => format!("{tag} NO [UNAVAILABLE] timeout\r\n"),
        };
        self.write_all(line.as_bytes()).await
    }

    async fn bye(&mut self, reason: &str) -> Result<()> {
        let line = format!("* BYE {}\r\n", sanitize(reason));
        self.write_all(line.as_bytes()).await?;
        self.flush().await
    }

    async fn line(&mut self, text: &str) -> Result<()> {
        self.write_all(text.as_bytes()).await?;
        self.write_all(b"\r\n").await
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.io.write_all(bytes).await
    }

    async fn flush(&mut self) -> Result<()> {
        self.io.flush().await
    }
}

#[derive(Clone, Copy)]
enum StoreMode {
    Replace,
    Add,
    Remove,
}

fn string_arg(token: &Token) -> Result<String> {
    token
        .text()
        .ok_or_else(|| MailError::protocol("expected a string argument"))
}

/// 解析 GETMETADATA/SETMETADATA 的 `[mailbox] (entries)`：首参是列表即无邮箱名。
fn parse_metadata_args(command: &Command) -> Result<(Option<String>, Vec<Token>)> {
    match command.args.first().and_then(|token| token.list()) {
        Some(entries) => Ok((None, entries.to_vec())),
        None => {
            let mailbox = command
                .args
                .first()
                .and_then(|token| token.text())
                .ok_or_else(|| MailError::protocol("expected a mailbox name or entry list"))?;
            let entries = command
                .args
                .get(1)
                .and_then(|token| token.list())
                .ok_or_else(|| MailError::protocol("expected an entry list"))?
                .to_vec();
            Ok((Some(mailbox), entries))
        }
    }
}

/// RFC 5464 条目名：`/private/<name>` 或 `/shared/<name>`，可见 ASCII、≤512 字节。
fn validate_metadata_entry(entry: &str) -> Result<()> {
    if entry.len() > 512 || !entry.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(MailError::invalid("invalid metadata entry name"));
    }
    match entry
        .strip_prefix("/private/")
        .or_else(|| entry.strip_prefix("/shared/"))
    {
        Some(tail) if !tail.is_empty() => Ok(()),
        _ => Err(MailError::invalid(
            "metadata entry must start with /private/ or /shared/",
        )),
    }
}

fn parse_flag_tokens(token: &Token) -> Result<FlagSet> {
    let mut flags = FlagSet::new();
    let mut parse = |item: &Token| -> Result<()> {
        let text = item
            .text()
            .ok_or_else(|| MailError::invalid("invalid flag"))?;
        if text.eq_ignore_ascii_case("\\Recent") {
            return Ok(());
        }
        let flag = Flag::parse_imap(&text)
            .ok_or_else(|| MailError::invalid(format!("invalid flag: {text}")))?;
        flags.insert(flag);
        Ok(())
    };
    match token {
        Token::List(items) => {
            for item in items {
                parse(item)?;
            }
        }
        other => parse(other)?,
    }
    Ok(flags)
}

fn parse_flag_items(items: &[Token]) -> Result<FlagSet> {
    let mut flags = FlagSet::new();
    for item in items {
        let text = item
            .text()
            .ok_or_else(|| MailError::invalid("invalid flag"))?;
        if text.eq_ignore_ascii_case("\\Recent") {
            continue;
        }
        let flag = Flag::parse_imap(&text)
            .ok_or_else(|| MailError::invalid(format!("invalid flag: {text}")))?;
        flags.insert(flag);
    }
    Ok(flags)
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect()
}

/// 解析 `QRESYNC (uidvalidity modseq [known-uids [(known-seqs known-uids)]])`。
///
/// 只使用前两个参数做增量同步；已知 UID 列表用于裁剪 VANISHED 范围，属于
/// 优化项，当前忽略。
fn parse_qresync_params(items: &[Token]) -> Result<(u32, u64)> {
    if items.len() < 2 || items.len() > 4 {
        return Err(MailError::invalid(
            "QRESYNC requires uidvalidity and modseq",
        ));
    }
    let uidvalidity = items[0]
        .text()
        .ok_or_else(|| MailError::invalid("invalid QRESYNC uidvalidity"))?
        .parse::<u32>()
        .map_err(|_| MailError::invalid("invalid QRESYNC uidvalidity"))?;
    if uidvalidity == 0 {
        return Err(MailError::invalid("invalid QRESYNC uidvalidity"));
    }
    let modseq = items[1]
        .text()
        .ok_or_else(|| MailError::invalid("invalid QRESYNC modseq"))?
        .parse::<u64>()
        .map_err(|_| MailError::invalid("invalid QRESYNC modseq"))?;
    Ok((uidvalidity, modseq))
}

fn resolve_pattern(reference: &str, pattern: &str) -> String {
    if pattern.is_empty() {
        return reference.to_string();
    }
    if reference.is_empty() {
        return pattern.to_string();
    }
    if pattern.starts_with(DELIMITER) {
        return format!("{reference}{pattern}");
    }
    if reference.ends_with(DELIMITER) {
        format!("{reference}{pattern}")
    } else {
        format!("{reference}{DELIMITER}{pattern}")
    }
}

/// RFC 5182：把已保存的 UID 结果展开成编号列表。uid 模式直接用 UID；序号
/// 模式把 UID 映射成当前视图里的序号。结果已排序去重（`SequenceSet::
/// from_values` 会做区间压缩）。已保存的 UID 在当前邮箱里一封都对不上时
/// 明确报错，绝不静默当作空集。
fn saved_result_numbers(
    saved: &[u32],
    uid_mode: bool,
    messages: &[MessageMeta],
) -> Result<Vec<u32>> {
    if uid_mode {
        let mut uids = saved.to_vec();
        uids.sort_unstable();
        uids.dedup();
        if uids.is_empty() {
            return Err(MailError::protocol("'$' has no saved result"));
        }
        return Ok(uids);
    }
    let mut sequences: Vec<u32> = messages
        .iter()
        .enumerate()
        .filter(|(_, message)| saved.contains(&message.uid))
        .map(|(index, _)| index as u32 + 1)
        .collect();
    if sequences.is_empty() {
        return Err(MailError::protocol(
            "the saved SEARCH result no longer refers to a message",
        ));
    }
    sequences.sort_unstable();
    sequences.dedup();
    Ok(sequences)
}

fn quota_resource_list(status: &crate::maildir::QuotaStatus) -> String {
    let mut resources = Vec::new();
    if let Some(limit) = status.limits.storage_bytes {
        resources.push(format!(
            "STORAGE {} {}",
            status.bytes.div_ceil(1024),
            limit.div_ceil(1024)
        ));
    }
    if let Some(limit) = status.limits.messages {
        resources.push(format!("MESSAGE {} {limit}", status.messages));
    }
    format!("({})", resources.join(" "))
}

/// 解析 LIST/LSUB 的 `(selection-options) reference pattern [(return-options)]`
/// （RFC 5258 的常用子集：CHILDREN / SPECIAL-USE / SUBSCRIBED）。
fn parse_list_args(command: &Command) -> Result<(HashSet<String>, String, String)> {
    let mut index = 0usize;
    let mut selection: HashSet<String> = HashSet::new();
    if let Some(Token::List(items)) = command.args.first() {
        if items.is_empty() {
            return Err(MailError::protocol("LIST selection list is empty"));
        }
        for item in items {
            let name = item
                .as_atom()
                .ok_or_else(|| MailError::protocol("LIST options must be atoms"))?
                .to_ascii_uppercase();
            match name.as_str() {
                "CHILDREN" | "SPECIAL-USE" | "SUBSCRIBED" => {
                    selection.insert(name);
                }
                _ => {
                    return Err(MailError::protocol(format!(
                        "unsupported LIST selection option: {name}"
                    )))
                }
            }
        }
        index = 1;
    }
    let reference = command
        .args
        .get(index)
        .ok_or_else(|| MailError::protocol("LIST requires a reference"))?;
    let pattern = command
        .args
        .get(index + 1)
        .ok_or_else(|| MailError::protocol("LIST requires a pattern"))?;
    match command.args.get(index + 2) {
        None => {}
        Some(Token::List(items)) => {
            for item in items {
                let name = item
                    .as_atom()
                    .ok_or_else(|| MailError::protocol("LIST return options must be atoms"))?
                    .to_ascii_uppercase();
                if !matches!(name.as_str(), "CHILDREN" | "SPECIAL-USE") {
                    return Err(MailError::protocol(format!(
                        "unsupported LIST return option: {name}"
                    )));
                }
            }
        }
        Some(_) => return Err(MailError::protocol("LIST return options must be a list")),
    }
    if command.args.len() > index + 3 {
        return Err(MailError::protocol("too many LIST arguments"));
    }
    Ok((selection, string_arg(reference)?, string_arg(pattern)?))
}

/// LIST 模式的长度上限。模式来自客户端（literal 语法能传到 max_literal），
/// 而匹配耗时随模式长度增长；超长模式直接回 BAD，不做匹配。
const MAX_LIST_PATTERN: usize = 512;

/// IMAP LIST 通配符匹配：`*` 跨层级，`%` 不跨层级（RFC 3501 §6.3.8）。
///
/// 经典的双指针回溯：记录最近一个 `*` 与最近一个 `%`（含它开始消耗的名字
/// 位置），失配时优先让 `%` 多吞一个字符（不能是层级分隔符），吞不动再回退
/// 到更早的 `*`。时间 O(模式×名字)、空间 O(1) —— 之前的 O(模式×名字) DP 表
/// 会为 32 MiB 的 literal 模式一次性分配数 GB 内存。按字节比较即可：模式与
/// 名字都是合法 UTF-8，通配符吞半个多字节字符不可能匹配上任何字面量。
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if !pattern.contains(['*', '%']) {
        return if name == INBOX {
            pattern.eq_ignore_ascii_case(INBOX)
        } else {
            pattern == name
        };
    }
    let pattern_bytes = pattern.as_bytes();
    let name_bytes = name.as_bytes();
    let delimiter = DELIMITER as u8;
    // (模式里的下标, 它开始消耗的名字位置)。回溯 = 多吞一个字符并重试其后缀。
    let mut star: Option<(usize, usize)> = None;
    let mut percent: Option<(usize, usize)> = None;
    let mut i = 0usize;
    let mut j = 0usize;
    while j < name_bytes.len() {
        if i < pattern_bytes.len() && (pattern_bytes[i] == b'*' || pattern_bytes[i] == b'%') {
            if pattern_bytes[i] == b'*' {
                // 新的 '*' 支配它之前的所有回溯点。
                star = Some((i, j));
                percent = None;
            } else {
                percent = Some((i, j));
            }
            i += 1;
        } else if i < pattern_bytes.len() && pattern_bytes[i] == name_bytes[j] {
            i += 1;
            j += 1;
        } else if let Some((percent_index, percent_mark)) = percent {
            if percent_mark < name_bytes.len() && name_bytes[percent_mark] != delimiter {
                // 让这个 % 多消耗一个字符，重新匹配它后面的部分。
                percent = Some((percent_index, percent_mark + 1));
                i = percent_index + 1;
                j = percent_mark + 1;
            } else {
                // '%' 不能跨层级：这个回溯点作废，下一轮退到更早的 '*'。
                percent = None;
            }
        } else if let Some((star_index, star_mark)) = star {
            if star_mark < name_bytes.len() {
                star = Some((star_index, star_mark + 1));
                percent = None;
                i = star_index + 1;
                j = star_mark + 1;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    // 名字耗尽后，模式尾部只剩通配符才能匹配（它们都可以匹配空）。
    while i < pattern_bytes.len() && (pattern_bytes[i] == b'*' || pattern_bytes[i] == b'%') {
        i += 1;
    }
    i == pattern_bytes.len()
}

fn decode_base64(payload: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| MailError::invalid("SASL response is not valid base64"))?
        .trim();
    if text.len() > 16 * 1024 {
        return Err(MailError::invalid("SASL response is too long"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .map_err(|_| MailError::invalid("SASL response is not valid base64"))
}

fn decode_base64_text(payload: &[u8]) -> Result<String> {
    let bytes = decode_base64(payload)?;
    String::from_utf8(bytes).map_err(|_| MailError::invalid("credential is not valid UTF-8"))
}

// ---------------------------------------------------------------------------
// SORT / THREAD / SEARCH 共用的正文批量读取
// ---------------------------------------------------------------------------

/// 正文批量读取的批次上限。批大小同时受封数与累计字节约束：数量上限防小
/// 邮件海把单批返回值撑爆，字节上限防大邮件占过多内存；一封超过字节上限的
/// 邮件自成一批（否则它永远进不了任何批次）。
const CONTENT_BATCH_MESSAGES: usize = 16;
const CONTENT_BATCH_BYTES: u64 = 32 * 1024 * 1024;

/// 按（封数、累计字节）双上限把待读正文的消息切批，返回每批在 `pending`
/// 里的 `[start, end)` 区间。批内首封无条件入批，超大邮件因此能自成一批。
fn content_batch_ranges(pending: &[usize], messages: &[MessageMeta]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < pending.len() {
        let mut bytes = 0u64;
        let mut end = start;
        while end < pending.len() {
            let size = messages[pending[end]].size;
            if end > start && bytes + size > CONTENT_BATCH_BYTES {
                break;
            }
            bytes += size;
            end += 1;
            if end - start == CONTENT_BATCH_MESSAGES {
                break;
            }
        }
        ranges.push((start, end));
        start = end;
    }
    ranges
}

/// 一次 blocking::maildir 读出一批正文。批内任何一封失败就返回该错误 ——
/// 与逐封读取一致：正文读不出来时整条命令失败，绝不静默返回残缺结果。
async fn read_content_batch(
    store: &Arc<MailStore>,
    batch: Vec<MessageMeta>,
) -> Result<Vec<Vec<u8>>> {
    blocking::maildir(store, move |store| {
        batch
            .iter()
            .map(|meta| store.read(meta))
            .collect::<Result<Vec<_>>>()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{MemoryDirectory, PasswordDirectory};
    use crate::maildir::SystemClock;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn wildcard_matching_respects_the_hierarchy_delimiter() {
        assert!(matches_pattern("*", "INBOX"));
        assert!(matches_pattern("*", "Sent.2026"));
        assert!(matches_pattern("%", "Sent"));
        assert!(!matches_pattern("%", "Sent.2026"), "% 不跨层级");
        assert!(matches_pattern("Sent.%", "Sent.2026"));
        assert!(matches_pattern("Sent.*", "Sent.2026.Deep"));
        assert!(matches_pattern("inbox", "INBOX"));
        assert!(!matches_pattern("sent", "Sent"), "非 INBOX 区分大小写");
        assert!(matches_pattern("*.2026", "Sent.2026"));
        // 双指针回溯覆盖的混合通配符场景（与原 DP 语义一致）。
        assert!(matches_pattern("Sent.*", "Sent."));
        assert!(matches_pattern("*%", "anything"));
        assert!(matches_pattern("*a%", "xa"));
        assert!(!matches_pattern("*a%", "a.b"), "% 在结尾也吞不掉分隔符");
        assert!(!matches_pattern("a%b", "a.b"));
        assert!(matches_pattern("a%*b", "acb"));
        assert!(matches_pattern("a%*b", "a.b"));
        assert!(matches_pattern("%*%b", "a.bZb"));
        assert!(!matches_pattern("%b", "a.b"));
        assert!(matches_pattern("*%b", "a.b"));
    }

    fn meta_with_uid(uid: u32) -> MessageMeta {
        MessageMeta {
            uid,
            base: String::new(),
            filename: String::new(),
            path: std::path::PathBuf::new(),
            size: 0,
            internal_date: 0,
            modseq: 0,
            flags: FlagSet::new(),
            recent: false,
        }
    }

    #[test]
    fn dollar_placeholder_expands_to_every_saved_uid() {
        let messages: Vec<MessageMeta> = [3u32, 7, 9].into_iter().map(meta_with_uid).collect();
        // uid 模式：展开为全部已保存 UID（排序去重），不只是最大值。
        assert_eq!(
            saved_result_numbers(&[9, 3, 7], true, &messages).unwrap(),
            vec![3, 7, 9]
        );
        // 序号模式：UID 映射成当前视图里的序号（uid 7 → 序号 2）。
        assert_eq!(
            saved_result_numbers(&[7], false, &messages).unwrap(),
            vec![2]
        );
        assert_eq!(
            saved_result_numbers(&[3, 9], false, &messages).unwrap(),
            vec![1, 3]
        );
        // 已保存的 UID 一封都对不上 → 明确报错，绝不静默当作空集。
        assert!(saved_result_numbers(&[99], false, &messages).is_err());
    }

    #[test]
    fn reference_join_follows_common_client_usage() {
        assert_eq!(resolve_pattern("", "*"), "*");
        assert_eq!(resolve_pattern("Sent", "*"), "Sent.*");
        assert_eq!(resolve_pattern("Sent.", "*"), "Sent.*");
        assert_eq!(resolve_pattern("", "INBOX"), "INBOX");
    }

    #[test]
    fn response_injection_is_neutralised() {
        assert_eq!(sanitize("a\r\nb"), "a  b");
        assert!(!sanitize("x\n* OK injected").contains('\n'));
    }

    #[test]
    fn base64_decoding_accepts_padded_and_unpadded() {
        assert_eq!(decode_base64(b"AGJvYg==").unwrap(), b"\0bob");
        assert_eq!(decode_base64(b"AGJvYg").unwrap(), b"\0bob");
        assert!(decode_base64(b"not base64!").is_err());
    }

    #[test]
    fn flag_tokens_reject_recent_and_unknown_system_flags() {
        let token = Token::List(vec![
            Token::Atom("\\Seen".into()),
            Token::Atom("$Junk".into()),
        ]);
        let flags = parse_flag_tokens(&token).unwrap();
        assert_eq!(flags.len(), 2);
        assert!(parse_flag_tokens(&Token::Atom("\\Recent".into()))
            .unwrap()
            .is_empty());
        assert!(parse_flag_tokens(&Token::Atom("\\Nope".into())).is_err());
    }

    #[test]
    fn content_batch_ranges_respect_count_and_byte_bounds() {
        let meta = |size| MessageMeta {
            uid: 1,
            base: String::new(),
            filename: String::new(),
            path: std::path::PathBuf::new(),
            size,
            internal_date: 0,
            modseq: 0,
            flags: FlagSet::new(),
            recent: false,
        };
        // 40 封 1 KiB：只受封数上限约束 → 16 + 16 + 8。
        let pending: Vec<usize> = (0..40).collect();
        let messages: Vec<MessageMeta> = (0..40).map(|_| meta(1024)).collect();
        assert_eq!(
            content_batch_ranges(&pending, &messages),
            vec![(0, 16), (16, 32), (32, 40)]
        );
        // 10 封 8 MiB：字节上限先到 → 4 + 4 + 2。
        let pending: Vec<usize> = (0..10).collect();
        let messages: Vec<MessageMeta> = (0..10).map(|_| meta(8 << 20)).collect();
        assert_eq!(
            content_batch_ranges(&pending, &messages),
            vec![(0, 4), (4, 8), (8, 10)]
        );
        // 单封超过字节上限：自成一批，不与相邻邮件混批。
        let pending: Vec<usize> = (0..3).collect();
        let messages: Vec<MessageMeta> = [1024u64, 64 << 20, 2048]
            .iter()
            .map(|&size| meta(size))
            .collect();
        assert_eq!(
            content_batch_ranges(&pending, &messages),
            vec![(0, 1), (1, 2), (2, 3)]
        );
        // 空邮箱：无批次。
        assert_eq!(content_batch_ranges(&[], &[]), Vec::new());
    }

    // -----------------------------------------------------------------
    // SORT / THREAD / SEARCH：分批读取与逐封读取的等价性
    // -----------------------------------------------------------------

    const BATCH_TEST_PASSWORD: &str = "Correct-Horse-9-Battery";
    /// 夹具邮件数：超过 [`CONTENT_BATCH_MESSAGES`]，SORT/THREAD/SEARCH 的
    /// 正文路径都会跨多个读取批次（16 + 16 + 8）。
    const BATCH_TEST_MESSAGES: u32 = 40;

    struct BatchFixture {
        _directory: tempfile::TempDir,
        store: Arc<MailStore>,
        auth: AuthBackend,
    }

    fn batch_fixture() -> BatchFixture {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(MailStore::new(directory.path(), Arc::new(SystemClock)).unwrap());
        // 与 tests/e2e.rs 同构：用户名带域，登录名即用户名。
        let mut record =
            mailstack_core::password::password_record("bob", BATCH_TEST_PASSWORD).unwrap();
        record.username = "bob@example.com".to_string();
        let mut users = MemoryDirectory::new();
        users.insert(record);
        BatchFixture {
            _directory: directory,
            store,
            auth: AuthBackend::new(Arc::new(PasswordDirectory::new(users))),
        }
    }

    fn batch_context(fixture: &BatchFixture) -> ImapSessionContext {
        ImapSessionContext {
            store: Arc::clone(&fixture.store),
            auth: fixture.auth.clone(),
            config: ImapConfig {
                server_name: "mail.test".to_string(),
                require_tls: false,
                read_timeout: Duration::from_secs(10),
                ..ImapConfig::default()
            },
            metrics: Arc::new(Metrics::new("imap")),
            resolver: None,
        }
    }

    /// 写入 [`BATCH_TEST_MESSAGES`] 封确定性邮件（与旧的逐封读取产出完全相同
    /// 的结果集，便于用常量断言）：
    ///
    /// * 奇数主题 `thread`，偶数 `Re: thread` 且 `In-Reply-To` 第 1 封 ——
    ///   ORDEREDSUBJECT / REFERENCES 的分组可手工推导；
    /// * 填充行长度逐封递减 100 字节，SIZE 严格递减（排序无并列）；
    /// * 内部日期逐封 +1 天（ARRIVAL 严格递增）；
    /// * 第 5i 封带 `\Seen`（SEEN / UNSEEN 路径）；
    /// * 正文 `body-{i}`（BODY / TEXT 路径，且互不为对方的子串）。
    ///
    /// 追加顺序即序号：第 i 封 = 序号 i = UID i。
    fn append_batch_fixture(store: &MailStore) {
        for i in 1..=BATCH_TEST_MESSAGES {
            let mut flags = FlagSet::new();
            if i % 5 == 0 {
                flags.insert(Flag::System(SystemFlag::Seen));
            }
            let subject = if i % 2 == 0 { "Re: thread" } else { "thread" };
            let mut message = format!("Subject: {subject}\r\nMessage-ID: <m{i}@example>\r\n");
            if i % 2 == 0 {
                message.push_str("In-Reply-To: <m1@example>\r\n");
            }
            let padding = "x".repeat((41 - i as usize) * 100);
            message.push_str(&format!("\r\nbody-{i}\r\n{padding}\r\n"));
            store
                .append(
                    INBOX,
                    message.as_bytes(),
                    &flags,
                    Some(1_760_000_000 + i as i64 * 86_400),
                )
                .unwrap();
        }
    }

    struct BatchClient {
        io: BufReader<tokio::io::DuplexStream>,
    }

    impl BatchClient {
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                io: BufReader::new(stream),
            }
        }

        async fn send(&mut self, line: &str) {
            let io = self.io.get_mut();
            io.write_all(line.as_bytes()).await.unwrap();
            io.write_all(b"\r\n").await.unwrap();
            io.flush().await.unwrap();
        }

        async fn line(&mut self) -> String {
            let mut line = String::new();
            let read = tokio::time::timeout(Duration::from_secs(15), self.io.read_line(&mut line))
                .await
                .expect("读取超时")
                .unwrap();
            assert!(read > 0, "连接被对端关闭");
            line
        }

        async fn until_tag(&mut self, tag: &str) -> Vec<String> {
            let mut lines = Vec::new();
            loop {
                let line = self.line().await;
                let done = line.starts_with(&format!("{tag} "));
                lines.push(line);
                if done {
                    return lines;
                }
            }
        }
    }

    fn spawn_batch_session(
        context: ImapSessionContext,
    ) -> (
        BatchClient,
        tokio::task::JoinHandle<crate::Result<ImapExit<tokio::io::DuplexStream>>>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let context = Arc::new(context);
        let handle = tokio::spawn(async move {
            serve_connection(
                server_io,
                &context,
                "192.0.2.10:50000".parse().unwrap(),
                ConnectionOptions {
                    secured: false,
                    starttls_available: false,
                    greet: true,
                },
            )
            .await
        });
        (BatchClient::new(client_io), handle)
    }

    /// 登录并选中 INBOX。
    async fn login_and_select_inbox(client: &mut BatchClient) {
        let _ = client.line().await; // 问候语
        client
            .send(&format!("f1 LOGIN bob@example.com {BATCH_TEST_PASSWORD}"))
            .await;
        let _ = client.until_tag("f1").await;
        client.send("f2 SELECT INBOX").await;
        let _ = client.until_tag("f2").await;
    }

    fn joined_lines(lines: Vec<String>) -> String {
        lines.join("\n")
    }

    #[tokio::test]
    async fn search_batched_reads_match_the_per_message_flow() {
        let fixture = batch_fixture();
        append_batch_fixture(&fixture.store);
        let (mut client, handle) = spawn_batch_session(batch_context(&fixture));
        login_and_select_inbox(&mut client).await;

        // 纯 Meta 条件：预筛后无需读任何正文。
        client.send("s1 SEARCH ALL").await;
        let lines = joined_lines(client.until_tag("s1").await);
        assert!(
            lines.contains("* SEARCH 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40"),
            "{lines}"
        );

        client.send("s2 SEARCH UNSEEN").await;
        let lines = joined_lines(client.until_tag("s2").await);
        assert!(
            lines.contains("* SEARCH 1 2 3 4 6 7 8 9 11 12 13 14 16 17 18 19 21 22 23 24 26 27 28 29 31 32 33 34 36 37 38 39"),
            "{lines}"
        );

        // 正文条件：所有邮件进批读正文，逐封判定。
        client.send("s3 SEARCH BODY \"body-7\"").await;
        let lines = joined_lines(client.until_tag("s3").await);
        assert!(lines.contains("* SEARCH 7"), "{lines}");

        // OR 混合：SEEN 侧靠 Meta 直接命中（跳过正文读取），其余邮件才进批。
        client.send("s4 SEARCH OR BODY \"body-7\" SEEN").await;
        let lines = joined_lines(client.until_tag("s4").await);
        assert!(
            lines.contains("* SEARCH 5 7 10 15 20 25 30 35 40"),
            "{lines}"
        );

        // 头部条件 + UID 模式。
        client
            .send("s5 UID SEARCH HEADER SUBJECT \"Re: thread\"")
            .await;
        let lines = joined_lines(client.until_tag("s5").await);
        assert!(
            lines.contains("* SEARCH 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40"),
            "{lines}"
        );

        client.send("s6 LOGOUT").await;
        let _ = client.until_tag("s6").await;
        let _ = handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sort_batched_reads_match_the_per_message_flow() {
        let fixture = batch_fixture();
        append_batch_fixture(&fixture.store);
        let (mut client, handle) = spawn_batch_session(batch_context(&fixture));
        login_and_select_inbox(&mut client).await;

        // 纯 Meta 排序 + 纯 Meta 搜索：全程不读正文；SIZE 严格递减，
        // REVERSE SIZE 即 1..=40。
        client.send("o1 SORT (REVERSE SIZE) UTF-8 ALL").await;
        let lines = joined_lines(client.until_tag("o1").await);
        assert!(
            lines.contains("* SORT 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40"),
            "{lines}"
        );

        // 头部排序：命中的邮件都要读正文取主题；"re: thread" < "thread"，
        // 偶数组在前，组内按序号稳定。
        client.send("o2 SORT (SUBJECT) UTF-8 ALL").await;
        let lines = joined_lines(client.until_tag("o2").await);
        assert!(
            lines.contains("* SORT 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40 1 3 5 7 9 11 13 15 17 19 21 23 25 27 29 31 33 35 37 39"),
            "{lines}"
        );

        // 正文搜索 + 头部排序：只有命中的邮件参与排序值计算。
        client.send("o3 SORT (SUBJECT) UTF-8 BODY \"body-7\"").await;
        let lines = joined_lines(client.until_tag("o3").await);
        assert!(lines.contains("* SORT 7"), "{lines}");

        // UID 模式 + 纯 Meta 搜索（ARRIVAL = 内部日期，逐封递增）。
        client
            .send("o4 UID SORT (ARRIVAL) UTF-8 UNSEEN LARGER 100")
            .await;
        let lines = joined_lines(client.until_tag("o4").await);
        assert!(
            lines.contains("* SORT 1 2 3 4 6 7 8 9 11 12 13 14 16 17 18 19 21 22 23 24 26 27 28 29 31 32 33 34 36 37 38 39"),
            "{lines}"
        );

        client.send("o5 LOGOUT").await;
        let _ = client.until_tag("o5").await;
        let _ = handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn thread_batched_reads_match_the_per_message_flow() {
        let fixture = batch_fixture();
        append_batch_fixture(&fixture.store);
        let (mut client, handle) = spawn_batch_session(batch_context(&fixture));
        login_and_select_inbox(&mut client).await;

        // 全量 ORDEREDSUBJECT：夹具偶数主题是 "Re: thread"，基主题归一化会
        // 剥掉 "Re:" —— 40 封共享同一基主题，按日期序构成**一个**组
        //（RFC 5256 §7：分组键是 base subject，不是原始 Subject 字段）。
        client.send("d1 THREAD ORDEREDSUBJECT UTF-8 ALL").await;
        let lines = joined_lines(client.until_tag("d1").await);
        assert!(
            lines.contains("* THREAD (1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40)"),
            "{lines}"
        );

        client.send("d2 THREAD REFERENCES UTF-8 ALL").await;
        let lines = joined_lines(client.until_tag("d2").await);
        assert!(
            lines.contains("* THREAD (1 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40)(3)(5)(7)(9)(11)(13)(15)(17)(19)(21)(23)(25)(27)(29)(31)(33)(35)(37)(39)"),
            "{lines}"
        );

        // Meta 搜索：预筛直接排除未命中的邮件，只读命中部分。
        // SEEN = 5/10/15/20/25/30/35/40，基主题同上全部相同 → 单组、日期序。
        client.send("d3 THREAD ORDEREDSUBJECT UTF-8 SEEN").await;
        let lines = joined_lines(client.until_tag("d3").await);
        assert!(
            lines.contains("* THREAD (5 10 15 20 25 30 35 40)"),
            "{lines}"
        );

        // UID 模式：序号 = UID，输出与 d2 相同。
        client
            .send("d4 UID THREAD REFERENCES UTF-8 SUBJECT \"thread\"")
            .await;
        let lines = joined_lines(client.until_tag("d4").await);
        assert!(
            lines.contains("* THREAD (1 2 4 6 8 10 12 14 16 18 20 22 24 26 28 30 32 34 36 38 40)(3)(5)(7)(9)(11)(13)(15)(17)(19)(21)(23)(25)(27)(29)(31)(33)(35)(37)(39)"),
            "{lines}"
        );

        client.send("d5 LOGOUT").await;
        let _ = client.until_tag("d5").await;
        let _ = handle.await.unwrap().unwrap();
    }
}
