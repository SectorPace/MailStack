//! Sieve（RFC 5228）安全子集：LMTP 投递前的服务端过滤。
//!
//! ## 支持的语法
//!
//! * 控制流：`if` / `elsif` / `else`、`true` / `false`、`not`、`allof`、`anyof`；
//! * 测试：`exists`、`header`（`:is` / `:contains` / `:matches`）、`address`
//!   （匹配类型同上 + `:all` / `:localpart` / `:domain`）、`size`（`:over` / `:under`）、
//!   `body`（`:is` / `:contains` / `:matches`，`:text` 默认 / `:raw`）；
//! * 动作：`keep`、`discard`、`stop`、`fileinto [:create] "folder"`、`reject "reason"`、
//!   `redirect "address"`、`vacation [":days" n] [":subject" s] "body"`；
//! * `require`：接受 `fileinto`、`reject`、`body`、`redirect`、`vacation`。
//!
//! `redirect` 与 `vacation` 的外发经 [`crate::outbound::OutboundSink`]（生产环境是
//! `mailstack-queue` 外发队列）；`vacation` 会按天数对同一发件人去重，且不回复
//! 自动/群发邮件。外发失败只记日志，本地投递照常进行。
//!
//! ## 明确不支持（编译期报错 → 整份脚本被忽略并回退 INBOX）
//!
//! `envelope`、`include`、`imap4flags`、`copy`、`editheader` 等需要额外扩展或
//! 外部能力的命令。**拒绝**而不是
//! 静默降级，是因为「以为设置了过滤其实没生效」比「脚本被忽略、邮件仍在 INBOX」更危险。
//!
//! ## 安全默认（绝不因脚本问题丢信）
//!
//! * 没有 `.sieve` 文件 → 完全按原行为投递 INBOX；
//! * 脚本编译失败 → 记日志并投递 INBOX；
//! * 求值有步数/递归深度/动作数上限，防止脚本耗尽 CPU；
//! * 动作没有产生任何投递且没有 `discard` 时，执行**隐式 keep**（RFC 5228 §2.10.2）。
//!
//! 脚本从 `<maildir>/.sieve` 读取（UTF-8，≤64 KiB）。

use crate::error::{MailError, Result};
use crate::maildir::{FlagSet, MailStore, NewMessage, INBOX};
use crate::mime;
use crate::outbound::OutboundSink;

const SCRIPT_FILE: &str = ".sieve";
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const VACATION_STATE: &str = ".mailstack-vacation";
const MAX_STEPS: usize = 20_000;
const MAX_DEPTH: usize = 32;
const MAX_ACTIONS: usize = 256;

/// 一个已求值的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Keep,
    Discard,
    FileInto {
        folder: String,
        create: bool,
    },
    Reject(String),
    /// 转发一份到指定地址（不改动本地投递）。
    Redirect(String),
    /// 自动回复（按 `days` 天对同一发件人去重）。
    Vacation {
        days: u32,
        subject: Option<String>,
        body: String,
    },
}

/// 投递计划：`reject` 为 `Some` 时不投递；否则按 `folders` 顺序各投一份。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeliveryPlan {
    pub folders: Vec<String>,
    pub reject: Option<String>,
}

/// 一封邮件在某个收件人下的 Sieve 投递结果。
#[derive(Debug)]
pub enum Delivery {
    Rejected(String),
    Delivered {
        folders: Vec<String>,
        uids: Vec<u32>,
    },
}

#[derive(Debug, Clone)]
pub struct Script {
    commands: Vec<Command>,
}

/// 读取生效中的脚本：优先 ManageSieve 管理的活动脚本（`sieve/.active`），否则
/// 回退到 `<maildir>/.sieve`。缺失返回 `Ok(None)`；超过 64 KiB 视为错误。
pub fn load_script(store: &MailStore) -> Result<Option<String>> {
    if let Some(name) = active_script_name(store)? {
        if let Some(source) = get_script(store, &name)? {
            return Ok(Some(source));
        }
        tracing::warn!(script = %name, "active Sieve script is missing; falling back to .sieve");
    }
    let path = store.root().join(SCRIPT_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            if bytes.len() > MAX_SCRIPT_BYTES {
                return Err(MailError::invalid("Sieve script exceeds 64 KiB"));
            }
            Ok(Some(String::from_utf8_lossy(&bytes).to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(MailError::io(&path, error)),
    }
}

// ---------------------------------------------------------------------------
// 脚本存储（ManageSieve 用）
// ---------------------------------------------------------------------------

const SCRIPTS_DIR: &str = "sieve";
const ACTIVE_FILE: &str = ".active";

fn scripts_dir(store: &MailStore) -> std::path::PathBuf {
    store.root().join(SCRIPTS_DIR)
}

/// 脚本名：≤128，仅字母数字与 `._-`，不得以 `.` 开头（防路径穿越/隐藏文件）。
pub fn validate_script_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(MailError::invalid("invalid script name"))
    }
}

pub fn active_script_name(store: &MailStore) -> Result<Option<String>> {
    let path = scripts_dir(store).join(ACTIVE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let name = content.trim().to_string();
            Ok(if name.is_empty() { None } else { Some(name) })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(MailError::io(&path, error)),
    }
}

/// 列出脚本及其是否活动，按名称排序。
pub fn list_scripts(store: &MailStore) -> Result<Vec<(String, bool)>> {
    let dir = scripts_dir(store);
    let active = active_script_name(store)?;
    let mut scripts = Vec::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|error| MailError::io(&dir, error))?;
                if !entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if validate_script_name(&name).is_err() {
                    continue;
                }
                let is_active = active.as_deref() == Some(name.as_str());
                scripts.push((name, is_active));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(MailError::io(&dir, error)),
    }
    scripts.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(scripts)
}

pub fn get_script(store: &MailStore, name: &str) -> Result<Option<String>> {
    validate_script_name(name)?;
    let path = scripts_dir(store).join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(MailError::io(&path, error)),
    }
}

/// 原子写入脚本（临时文件 + rename）。
pub fn put_script(store: &MailStore, name: &str, source: &str) -> Result<()> {
    validate_script_name(name)?;
    if source.len() > MAX_SCRIPT_BYTES {
        return Err(MailError::invalid("Sieve script exceeds 64 KiB"));
    }
    let dir = scripts_dir(store);
    std::fs::create_dir_all(&dir).map_err(|error| MailError::io(&dir, error))?;
    let path = dir.join(name);
    let temp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    std::fs::write(&temp, source.as_bytes()).map_err(|error| MailError::io(&temp, error))?;
    std::fs::rename(&temp, &path).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        MailError::io(&path, error)
    })
}

/// 设置（`Some`）或清除（`None`）活动脚本。
pub fn set_active(store: &MailStore, name: Option<&str>) -> Result<()> {
    let dir = scripts_dir(store);
    std::fs::create_dir_all(&dir).map_err(|error| MailError::io(&dir, error))?;
    let path = dir.join(ACTIVE_FILE);
    match name {
        Some(name) => {
            validate_script_name(name)?;
            if !dir.join(name).is_file() {
                return Err(MailError::not_found(name));
            }
            std::fs::write(&path, name).map_err(|error| MailError::io(&path, error))
        }
        None => match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(MailError::io(&path, error)),
        },
    }
}

/// 删除脚本；若删的是活动脚本，同时清除活动标记。
pub fn delete_script(store: &MailStore, name: &str) -> Result<()> {
    validate_script_name(name)?;
    let dir = scripts_dir(store);
    let path = dir.join(name);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(MailError::not_found(name))
        }
        Err(error) => return Err(MailError::io(&path, error)),
    }
    if active_script_name(store)?.as_deref() == Some(name) {
        let _ = std::fs::remove_file(dir.join(ACTIVE_FILE));
    }
    Ok(())
}

pub fn rename_script(store: &MailStore, from: &str, to: &str) -> Result<()> {
    validate_script_name(from)?;
    validate_script_name(to)?;
    let dir = scripts_dir(store);
    let source = dir.join(from);
    let target = dir.join(to);
    if !source.is_file() {
        return Err(MailError::not_found(from));
    }
    if target.exists() {
        return Err(MailError::already_exists(to));
    }
    std::fs::rename(&source, &target).map_err(|error| MailError::io(&target, error))?;
    if active_script_name(store)?.as_deref() == Some(from) {
        std::fs::write(dir.join(ACTIVE_FILE), to)
            .map_err(|error| MailError::io(dir.join(ACTIVE_FILE), error))?;
    }
    Ok(())
}

/// 编译脚本。语法错误、未知命令或不受支持的 `require` 都会返回错误。
pub fn compile(source: &str) -> Result<Script> {
    let tokens = Lexer::new(source).tokenize()?;
    let commands = Parser { tokens, pos: 0 }.parse()?;
    validate_requires(&commands)?;
    Ok(Script { commands })
}

/// 求值脚本，返回按顺序执行到的动作（已被 `stop` 截断）。
pub fn actions(script: &Script, message: &[u8]) -> Vec<Action> {
    let mut eval = Eval {
        headers: mime::parse_headers(message),
        message,
        steps: 0,
        actions: Vec::new(),
        stopped: false,
    };
    eval.run(&script.commands, 0);
    eval.actions
}

/// 把动作落成投递计划。`ensure(folder, create)` 负责确认（或按需创建）目标邮箱，
/// 返回 `false` 时该 `fileinto` 回退为投递 INBOX（keep），绝不丢信。
pub fn delivery_plan(
    actions: &[Action],
    mut ensure: impl FnMut(&str, bool) -> bool,
) -> DeliveryPlan {
    let mut folders: Vec<String> = Vec::new();
    let mut discarded = false;
    let mut reject = None;
    for action in actions {
        match action {
            Action::Keep => push_unique(&mut folders, INBOX),
            Action::FileInto { folder, create } => {
                if ensure(folder, *create) {
                    push_unique(&mut folders, folder);
                } else {
                    push_unique(&mut folders, INBOX);
                }
            }
            Action::Discard => discarded = true,
            Action::Reject(reason) => reject = Some(reason.clone()),
            // 转发/自动回复是外发副作用，不影响本地投递计划。
            Action::Redirect(_) | Action::Vacation { .. } => {}
        }
    }
    if reject.is_some() {
        return DeliveryPlan {
            folders: Vec::new(),
            reject,
        };
    }
    // 隐式 keep：没有任何投递动作、也没显式 discard。
    if folders.is_empty() && !discarded {
        folders.push(INBOX.to_string());
    }
    DeliveryPlan {
        folders,
        reject: None,
    }
}

/// 完整的「Sieve + 投递」：读脚本、求值、落盘。脚本问题一律回退 INBOX。
///
/// 不带信封信息与外发出口，供测试/单机使用；生产 LMTP 用 [`deliver_envelope`]。
pub fn deliver_with_sieve(store: &MailStore, message: &[u8]) -> Result<Delivery> {
    deliver_envelope(store, message, "", "", None)
}

/// 带信封发件人/收件人与外发出口的投递：
///
/// * `redirect` 转发一份到目标地址（不改变本地投递）；
/// * `vacation` 按天数去重后自动回复（null envelope sender）；
/// * 外发失败只记日志，**不影响本地投递**（绝不因为转发失败而丢信）。
pub fn deliver_envelope(
    store: &MailStore,
    message: &[u8],
    from: &str,
    to: &str,
    outbound: Option<&dyn OutboundSink>,
) -> Result<Delivery> {
    let evaluated = match load_script(store)? {
        Some(source) => match compile(&source) {
            Ok(script) => actions(&script, message),
            Err(error) => {
                tracing::warn!(error = %error, "Sieve script failed to compile; delivering to INBOX");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    let wants_outbound = evaluated
        .iter()
        .any(|action| matches!(action, Action::Redirect(_) | Action::Vacation { .. }));
    if wants_outbound {
        match outbound {
            Some(sink) => {
                for action in &evaluated {
                    match action {
                        Action::Redirect(address) => {
                            if let Err(error) = sink.submit(from, address, message) {
                                tracing::warn!(%error, to = %address, "Sieve redirect failed");
                            }
                        }
                        Action::Vacation {
                            days,
                            subject,
                            body,
                        } => submit_vacation(
                            store,
                            message,
                            from,
                            to,
                            *days,
                            subject.as_deref(),
                            body,
                            sink,
                        ),
                        _ => {}
                    }
                }
            }
            None => tracing::warn!(
                "Sieve redirect/vacation requested but no outbound sink is configured"
            ),
        }
    }

    let plan = delivery_plan(&evaluated, |folder, create| {
        if store.exists(folder).unwrap_or(false) {
            true
        } else if create {
            store.create(folder).is_ok()
        } else {
            false
        }
    });
    if let Some(reason) = plan.reject {
        return Ok(Delivery::Rejected(reason));
    }
    let mut folders = Vec::new();
    let mut uids = Vec::new();
    for folder in plan.folders {
        let (_, appended) = store.append_many(
            &folder,
            &[NewMessage {
                data: message.to_vec(),
                flags: FlagSet::new(),
                internal_date: None,
            }],
        )?;
        uids.extend(appended);
        folders.push(folder);
    }
    Ok(Delivery::Delivered { folders, uids })
}

#[allow(clippy::too_many_arguments)]
fn submit_vacation(
    store: &MailStore,
    message: &[u8],
    from: &str,
    to: &str,
    days: u32,
    subject: Option<&str>,
    body: &str,
    sink: &dyn OutboundSink,
) {
    if from.is_empty() || from.eq_ignore_ascii_case(to) {
        return;
    }
    let headers = mime::parse_headers(message);
    if is_automated(&headers) {
        return;
    }
    let now = store.clock().now_secs();
    let window = i64::from(days.max(1)) * 86_400;
    let mut replies = read_vacation_state(store);
    let key = from.to_ascii_lowercase();
    if let Some(last) = replies.get(&key) {
        if now.saturating_sub(*last) < window {
            return;
        }
    }
    let reply = build_vacation_reply(&headers, to, from, subject, body);
    if let Err(error) = sink.submit("", from, reply.as_bytes()) {
        tracing::warn!(%error, to = %from, "Sieve vacation send failed");
        return;
    }
    replies.insert(key, now);
    if let Err(error) = write_vacation_state(store, &replies, now) {
        tracing::warn!(%error, "failed to persist vacation state");
    }
}

/// 自动/群发邮件：自动回复不应回这类邮件（防回环、防打扰）。
fn is_automated(headers: &mime::Headers) -> bool {
    if let Some(value) = headers.get("auto-submitted") {
        if !value.trim().eq_ignore_ascii_case("no") {
            return true;
        }
    }
    if headers.get("list-id").is_some() {
        return true;
    }
    if let Some(precedence) = headers.get("precedence") {
        if matches!(
            precedence.trim().to_ascii_lowercase().as_str(),
            "bulk" | "list" | "junk"
        ) {
            return true;
        }
    }
    false
}

fn build_vacation_reply(
    original: &mime::Headers,
    to: &str,
    from: &str,
    subject: Option<&str>,
    body: &str,
) -> String {
    let subject = match subject {
        Some(subject) => subject.to_string(),
        None => match original
            .get("subject")
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(original_subject) => format!("Auto-Reply: {original_subject}"),
            None => "Auto-Reply".to_string(),
        },
    };
    let mut out = String::new();
    out.push_str(&format!("From: {}\r\n", sanitize_header(to)));
    out.push_str(&format!("To: {}\r\n", sanitize_header(from)));
    out.push_str(&format!("Subject: {}\r\n", sanitize_header(&subject)));
    out.push_str("Auto-Submitted: auto-replied\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    if let Some(message_id) = original.get("message-id") {
        let message_id = sanitize_header(message_id.trim());
        if !message_id.is_empty() {
            out.push_str(&format!("In-Reply-To: {message_id}\r\n"));
            out.push_str(&format!("References: {message_id}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.push_str(body);
    out.push_str("\r\n");
    out
}

fn sanitize_header(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

fn vacation_state_path(store: &MailStore) -> std::path::PathBuf {
    store.root().join(VACATION_STATE)
}

fn read_vacation_state(store: &MailStore) -> std::collections::HashMap<String, i64> {
    let mut map = std::collections::HashMap::new();
    let Ok(contents) = std::fs::read_to_string(vacation_state_path(store)) else {
        return map;
    };
    for line in contents.lines() {
        if let Some((sender, timestamp)) = line.split_once(' ') {
            if let Ok(timestamp) = timestamp.parse::<i64>() {
                map.insert(sender.to_string(), timestamp);
            }
        }
    }
    map
}

fn write_vacation_state(
    store: &MailStore,
    replies: &std::collections::HashMap<String, i64>,
    now: i64,
) -> Result<()> {
    // 只保留最近 30 天、最多 1000 条，避免状态文件无限增长。
    let cutoff = now.saturating_sub(30 * 86_400);
    let mut entries: Vec<(&String, &i64)> = replies
        .iter()
        .filter(|(_, timestamp)| **timestamp >= cutoff)
        .collect();
    entries.sort_by(|a, b| b.1.cmp(a.1));
    entries.truncate(1000);
    let mut buffer = String::new();
    for (sender, timestamp) in entries {
        buffer.push_str(sender);
        buffer.push(' ');
        buffer.push_str(&timestamp.to_string());
        buffer.push('\n');
    }
    let path = vacation_state_path(store);
    std::fs::write(&path, buffer).map_err(|error| MailError::io(&path, error))
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|item| item == value) {
        list.push(value.to_string());
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Command {
    Require(Vec<String>),
    If {
        branches: Vec<(Test, Vec<Command>)>,
        otherwise: Option<Vec<Command>>,
    },
    Keep,
    Discard,
    Stop,
    FileInto {
        folder: String,
        create: bool,
    },
    Reject(String),
    Redirect(String),
    Vacation {
        days: u32,
        subject: Option<String>,
        body: String,
    },
}

#[derive(Debug, Clone)]
enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists(Vec<String>),
    Header {
        match_type: MatchType,
        header: String,
        key: String,
    },
    Address {
        match_type: MatchType,
        part: AddressPart,
        header: String,
        key: String,
    },
    Size {
        over: bool,
        limit: usize,
    },
    /// RFC 5173：正文匹配。`text` 为真表示 `:text`（默认，解码后的文本部件），
    /// 否则为 `:raw`（原始正文）。
    Body {
        match_type: MatchType,
        text: bool,
        key: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchType {
    Is,
    Contains,
    Matches,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressPart {
    All,
    LocalPart,
    Domain,
}

fn validate_requires(commands: &[Command]) -> Result<()> {
    for command in commands {
        match command {
            Command::Require(list) => {
                for extension in list {
                    match extension.to_ascii_lowercase().as_str() {
                        "fileinto" | "reject" | "body" | "redirect" | "vacation" => {}
                        other => {
                            return Err(MailError::invalid(format!(
                                "unsupported Sieve extension: {other}"
                            )))
                        }
                    }
                }
            }
            Command::If {
                branches,
                otherwise,
            } => {
                for (_, block) in branches {
                    validate_requires(block)?;
                }
                if let Some(block) = otherwise {
                    validate_requires(block)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 词法
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Number(u64),
    Str(String),
    Tag(String),
    LBracket,
    RBracket,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semicolon,
}

struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            bytes: source.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn tokenize(mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b'#' => {
                    while let Some(byte) = self.peek() {
                        if byte == b'\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                b'"' => tokens.push(Token::Str(self.string()?)),
                b'[' => {
                    self.pos += 1;
                    tokens.push(Token::LBracket);
                }
                b']' => {
                    self.pos += 1;
                    tokens.push(Token::RBracket);
                }
                b'(' => {
                    self.pos += 1;
                    tokens.push(Token::LParen);
                }
                b')' => {
                    self.pos += 1;
                    tokens.push(Token::RParen);
                }
                b'{' => {
                    self.pos += 1;
                    tokens.push(Token::LBrace);
                }
                b'}' => {
                    self.pos += 1;
                    tokens.push(Token::RBrace);
                }
                b',' => {
                    self.pos += 1;
                    tokens.push(Token::Comma);
                }
                b';' => {
                    self.pos += 1;
                    tokens.push(Token::Semicolon);
                }
                b':' => {
                    self.pos += 1;
                    tokens.push(Token::Tag(self.identifier()?));
                }
                b'0'..=b'9' => tokens.push(Token::Number(self.number()?)),
                _ if byte.is_ascii_alphabetic() || byte == b'_' => {
                    tokens.push(Token::Ident(self.identifier()?))
                }
                _ => return Err(MailError::invalid("unexpected character in Sieve script")),
            }
        }
        Ok(tokens)
    }

    fn identifier(&mut self) -> Result<String> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(MailError::invalid("expected an identifier in Sieve script"));
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.pos]).to_string())
    }

    fn number(&mut self) -> Result<u64> {
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&self.bytes[start..self.pos])
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| MailError::invalid("invalid number in Sieve script"))
    }

    fn string(&mut self) -> Result<String> {
        self.pos += 1; // 开引号
        let mut out = Vec::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(MailError::invalid("unterminated string in Sieve script"));
            };
            self.pos += 1;
            match byte {
                b'"' => return Ok(String::from_utf8_lossy(&out).to_string()),
                b'\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(MailError::invalid("unterminated escape in Sieve script"));
                    };
                    self.pos += 1;
                    match escaped {
                        b'"' | b'\\' => out.push(escaped),
                        _ => return Err(MailError::invalid("invalid escape in Sieve string")),
                    }
                }
                other => out.push(other),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 语法
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn parse(mut self) -> Result<Vec<Command>> {
        let mut commands = Vec::new();
        while self.pos < self.tokens.len() {
            commands.push(self.command()?);
        }
        Ok(commands)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        match self.next() {
            Some(token) if &token == expected => Ok(()),
            _ => Err(MailError::invalid("unexpected token in Sieve script")),
        }
    }

    fn command(&mut self) -> Result<Command> {
        let name = match self.next() {
            Some(Token::Ident(name)) => name.to_ascii_lowercase(),
            _ => return Err(MailError::invalid("expected a Sieve command")),
        };
        match name.as_str() {
            "require" => {
                let list = self.string_list()?;
                self.expect(&Token::Semicolon)?;
                Ok(Command::Require(list))
            }
            "if" => {
                let mut branches = vec![(self.test()?, self.block()?)];
                let mut otherwise = None;
                loop {
                    match self.peek() {
                        Some(Token::Ident(word)) if word.eq_ignore_ascii_case("elsif") => {
                            self.pos += 1;
                            branches.push((self.test()?, self.block()?));
                        }
                        Some(Token::Ident(word)) if word.eq_ignore_ascii_case("else") => {
                            self.pos += 1;
                            otherwise = Some(self.block()?);
                            break;
                        }
                        _ => break,
                    }
                }
                Ok(Command::If {
                    branches,
                    otherwise,
                })
            }
            "keep" => {
                self.expect(&Token::Semicolon)?;
                Ok(Command::Keep)
            }
            "discard" => {
                self.expect(&Token::Semicolon)?;
                Ok(Command::Discard)
            }
            "stop" => {
                self.expect(&Token::Semicolon)?;
                Ok(Command::Stop)
            }
            "fileinto" => {
                let mut create = false;
                while let Some(Token::Tag(tag)) = self.peek() {
                    let tag = tag.to_ascii_lowercase();
                    self.pos += 1;
                    match tag.as_str() {
                        "create" => create = true,
                        other => {
                            return Err(MailError::invalid(format!(
                                "unsupported fileinto tag: :{other}"
                            )))
                        }
                    }
                }
                let folder = self.string()?;
                self.expect(&Token::Semicolon)?;
                Ok(Command::FileInto { folder, create })
            }
            "reject" => {
                let reason = self.string()?;
                self.expect(&Token::Semicolon)?;
                Ok(Command::Reject(reason))
            }
            "redirect" => {
                if let Some(Token::Tag(_)) = self.peek() {
                    return Err(MailError::invalid("redirect tags are not supported"));
                }
                let address = self.string()?;
                self.expect(&Token::Semicolon)?;
                Ok(Command::Redirect(address))
            }
            "vacation" => {
                let mut days = 7u32;
                let mut subject = None;
                while let Some(Token::Tag(tag)) = self.peek() {
                    let tag = tag.to_ascii_lowercase();
                    self.pos += 1;
                    match tag.as_str() {
                        "days" => match self.next() {
                            Some(Token::Number(value)) => days = value as u32,
                            _ => {
                                return Err(MailError::invalid("vacation :days requires a number"))
                            }
                        },
                        "subject" => subject = Some(self.string()?),
                        other => {
                            return Err(MailError::invalid(format!(
                                "unsupported vacation tag: :{other}"
                            )))
                        }
                    }
                }
                let body = self.string()?;
                self.expect(&Token::Semicolon)?;
                Ok(Command::Vacation {
                    days,
                    subject,
                    body,
                })
            }
            other => Err(MailError::invalid(format!(
                "unsupported Sieve command: {other}"
            ))),
        }
    }

    fn string(&mut self) -> Result<String> {
        match self.next() {
            Some(Token::Str(value)) => Ok(value),
            _ => Err(MailError::invalid("expected a string in Sieve script")),
        }
    }

    fn string_list(&mut self) -> Result<Vec<String>> {
        match self.next() {
            Some(Token::Str(value)) => Ok(vec![value]),
            Some(Token::LBracket) => {
                let mut items = Vec::new();
                loop {
                    match self.peek() {
                        Some(Token::RBracket) => {
                            self.pos += 1;
                            break;
                        }
                        Some(Token::Str(_)) => items.push(self.string()?),
                        _ => return Err(MailError::invalid("expected a string list")),
                    }
                    match self.next() {
                        Some(Token::Comma) => continue,
                        Some(Token::RBracket) => break,
                        _ => return Err(MailError::invalid("expected ',' or ']'")),
                    }
                }
                Ok(items)
            }
            _ => Err(MailError::invalid("expected a string or string list")),
        }
    }

    fn block(&mut self) -> Result<Vec<Command>> {
        self.expect(&Token::LBrace)?;
        let mut commands = Vec::new();
        loop {
            match self.peek() {
                Some(Token::RBrace) => {
                    self.pos += 1;
                    return Ok(commands);
                }
                None => return Err(MailError::invalid("unterminated Sieve block")),
                _ => commands.push(self.command()?),
            }
        }
    }

    fn test(&mut self) -> Result<Test> {
        let name = match self.next() {
            Some(Token::Ident(name)) => name.to_ascii_lowercase(),
            _ => return Err(MailError::invalid("expected a Sieve test")),
        };
        match name.as_str() {
            "true" => Ok(Test::True),
            "false" => Ok(Test::False),
            "not" => Ok(Test::Not(Box::new(self.test()?))),
            "allof" => Ok(Test::AllOf(self.test_list()?)),
            "anyof" => Ok(Test::AnyOf(self.test_list()?)),
            "exists" => Ok(Test::Exists(self.string_list()?)),
            "header" => {
                let match_type = self.match_tags()?;
                let header = self.string()?;
                let key = self.string()?;
                Ok(Test::Header {
                    match_type,
                    header,
                    key,
                })
            }
            "address" => {
                let (match_type, part) = self.address_tags()?;
                let header = self.string()?;
                let key = self.string()?;
                Ok(Test::Address {
                    match_type,
                    part,
                    header,
                    key,
                })
            }
            "size" => {
                let over = match self.next() {
                    Some(Token::Tag(tag)) if tag.eq_ignore_ascii_case("over") => true,
                    Some(Token::Tag(tag)) if tag.eq_ignore_ascii_case("under") => false,
                    _ => return Err(MailError::invalid("size requires :over or :under")),
                };
                let limit = match self.next() {
                    Some(Token::Number(value)) => value as usize,
                    _ => return Err(MailError::invalid("size requires a number")),
                };
                Ok(Test::Size { over, limit })
            }
            "body" => {
                let mut match_type = MatchType::Is;
                let mut text = true;
                while let Some(Token::Tag(tag)) = self.peek() {
                    let tag = tag.to_ascii_lowercase();
                    self.pos += 1;
                    match tag.as_str() {
                        "is" => match_type = MatchType::Is,
                        "contains" => match_type = MatchType::Contains,
                        "matches" => match_type = MatchType::Matches,
                        "text" => text = true,
                        "raw" => text = false,
                        other => {
                            return Err(MailError::invalid(format!(
                                "unsupported body tag: :{other}"
                            )))
                        }
                    }
                }
                let key = self.string()?;
                Ok(Test::Body {
                    match_type,
                    text,
                    key,
                })
            }
            other => Err(MailError::invalid(format!(
                "unsupported Sieve test: {other}"
            ))),
        }
    }

    fn test_list(&mut self) -> Result<Vec<Test>> {
        self.expect(&Token::LParen)?;
        let mut tests = Vec::new();
        loop {
            tests.push(self.test()?);
            match self.next() {
                Some(Token::Comma) => continue,
                Some(Token::RParen) => return Ok(tests),
                _ => return Err(MailError::invalid("expected ',' or ')'")),
            }
        }
    }

    fn match_tags(&mut self) -> Result<MatchType> {
        let mut kind = MatchType::Is;
        while let Some(Token::Tag(tag)) = self.peek() {
            let tag = tag.to_ascii_lowercase();
            self.pos += 1;
            kind = match tag.as_str() {
                "is" => MatchType::Is,
                "contains" => MatchType::Contains,
                "matches" => MatchType::Matches,
                other => {
                    return Err(MailError::invalid(format!(
                        "unsupported match tag: :{other}"
                    )))
                }
            };
        }
        Ok(kind)
    }

    fn address_tags(&mut self) -> Result<(MatchType, AddressPart)> {
        let mut kind = MatchType::Is;
        let mut part = AddressPart::All;
        while let Some(Token::Tag(tag)) = self.peek() {
            let tag = tag.to_ascii_lowercase();
            self.pos += 1;
            match tag.as_str() {
                "is" => kind = MatchType::Is,
                "contains" => kind = MatchType::Contains,
                "matches" => kind = MatchType::Matches,
                "all" => part = AddressPart::All,
                "localpart" => part = AddressPart::LocalPart,
                "domain" => part = AddressPart::Domain,
                other => {
                    return Err(MailError::invalid(format!(
                        "unsupported address tag: :{other}"
                    )))
                }
            }
        }
        Ok((kind, part))
    }
}

// ---------------------------------------------------------------------------
// 求值
// ---------------------------------------------------------------------------

struct Eval<'a> {
    headers: mime::Headers,
    message: &'a [u8],
    steps: usize,
    actions: Vec<Action>,
    stopped: bool,
}

impl Eval<'_> {
    fn run(&mut self, commands: &[Command], depth: usize) {
        if depth > MAX_DEPTH {
            self.stopped = true;
            return;
        }
        for command in commands {
            if self.stopped {
                return;
            }
            self.steps += 1;
            if self.steps > MAX_STEPS {
                self.stopped = true;
                return;
            }
            match command {
                Command::Require(_) => {}
                Command::If {
                    branches,
                    otherwise,
                } => {
                    let mut matched = false;
                    for (test, block) in branches {
                        if self.matches(test, depth) {
                            self.run(block, depth + 1);
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        if let Some(block) = otherwise {
                            self.run(block, depth + 1);
                        }
                    }
                }
                Command::Keep => self.push(Action::Keep),
                Command::Discard => self.push(Action::Discard),
                Command::Stop => {
                    self.stopped = true;
                    return;
                }
                Command::FileInto { folder, create } => self.push(Action::FileInto {
                    folder: folder.clone(),
                    create: *create,
                }),
                Command::Reject(reason) => self.push(Action::Reject(reason.clone())),
                Command::Redirect(address) => self.push(Action::Redirect(address.clone())),
                Command::Vacation {
                    days,
                    subject,
                    body,
                } => self.push(Action::Vacation {
                    days: *days,
                    subject: subject.clone(),
                    body: body.clone(),
                }),
            }
        }
    }

    fn push(&mut self, action: Action) {
        if self.actions.len() < MAX_ACTIONS {
            self.actions.push(action);
        }
    }

    fn matches(&mut self, test: &Test, depth: usize) -> bool {
        self.steps += 1;
        if self.steps > MAX_STEPS || depth > MAX_DEPTH {
            self.stopped = true;
            return false;
        }
        match test {
            Test::True => true,
            Test::False => false,
            Test::Not(inner) => !self.matches(inner, depth + 1),
            Test::AllOf(tests) => tests.iter().all(|test| self.matches(test, depth + 1)),
            Test::AnyOf(tests) => tests.iter().any(|test| self.matches(test, depth + 1)),
            Test::Exists(names) => names.iter().all(|name| self.headers.get(name).is_some()),
            Test::Header {
                match_type,
                header,
                key,
            } => self
                .headers
                .get_all(header)
                .any(|value| match_value(*match_type, value, key)),
            Test::Address {
                match_type,
                part,
                header,
                key,
            } => self.headers.get_all(header).any(|value| {
                address_specs(value).iter().any(|spec| {
                    let field = match part {
                        AddressPart::All => spec.as_str(),
                        AddressPart::LocalPart => spec.split('@').next().unwrap_or(""),
                        AddressPart::Domain => {
                            spec.split_once('@').map(|(_, domain)| domain).unwrap_or("")
                        }
                    };
                    match_value(*match_type, field, key)
                })
            }),
            Test::Size { over, limit } => {
                if *over {
                    self.message.len() > *limit
                } else {
                    self.message.len() < *limit
                }
            }
            Test::Body {
                match_type,
                text,
                key,
            } => {
                let body = if *text {
                    let mut out = Vec::new();
                    collect_text(self.message, &mut out);
                    out
                } else {
                    let (_, body) = mime::split_headers_body(self.message);
                    body.to_vec()
                };
                match_value(*match_type, &String::from_utf8_lossy(&body), key)
            }
        }
    }
}

/// 递归收集解码后的文本部件（RFC 5173 `:text`）。深度受限，防嵌套攻击。
fn collect_text(message: &[u8], out: &mut Vec<u8>) {
    collect_text_at(message, out, 0);
}

fn collect_text_at(message: &[u8], out: &mut Vec<u8>, depth: usize) {
    if depth > 16 {
        return;
    }
    let headers = mime::parse_headers(message);
    let content = mime::content_type(&headers);
    let (_, body) = mime::split_headers_body(message);
    if content.is_multipart() {
        if let Some(boundary) = content.param("boundary") {
            for part in mime::multipart_parts(body, boundary) {
                collect_text_at(part, out, depth + 1);
            }
        }
    } else if content.is_text() {
        let encoding = headers
            .get("content-transfer-encoding")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        out.extend_from_slice(&mime::decode_transfer_encoding(body, &encoding));
    }
}

fn match_value(kind: MatchType, haystack: &str, needle: &str) -> bool {
    match kind {
        MatchType::Is => haystack.eq_ignore_ascii_case(needle),
        MatchType::Contains => haystack
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        MatchType::Matches => glob_match(
            haystack.to_ascii_lowercase().as_bytes(),
            needle.to_ascii_lowercase().as_bytes(),
        ),
    }
}

/// `*` 任意长度、`?` 单个字符。经典双指针 + 回溯，避免正则式灾难。
fn glob_match(text: &[u8], pattern: &[u8]) -> bool {
    let (mut t, mut p) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            t += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// 从地址头里提取 addr-spec（`local@domain`）：`Name <a@b>` / `a@b` / 逗号分隔。
fn address_specs(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|token| {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            if let (Some(open), Some(close)) = (token.rfind('<'), token.rfind('>')) {
                if close > open {
                    return Some(token[open + 1..close].trim().to_string());
                }
            }
            Some(token.split_whitespace().last().unwrap_or(token).to_string())
        })
        .filter(|spec| !spec.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maildir::SystemClock;
    use std::sync::Arc;

    fn run(script: &str, message: &[u8]) -> Vec<Action> {
        let compiled = compile(script).expect("script must compile");
        actions(&compiled, message)
    }

    fn message(subject: &str, from: &str) -> Vec<u8> {
        format!("From: {from}\r\nSubject: {subject}\r\n\r\nbody\r\n").into_bytes()
    }

    #[test]
    fn header_contains_fileinto_and_else_keep() {
        let script = r#"
            require ["fileinto"];
            if header :contains "subject" "invoice" {
                fileinto "Invoices";
            } else {
                keep;
            }
        "#;
        let actions = run(script, &message("Your Invoice 7", "billing@shop.test"));
        assert_eq!(
            actions,
            vec![Action::FileInto {
                folder: "Invoices".to_string(),
                create: false
            }]
        );
        let actions = run(script, &message("hello", "friend@test"));
        assert_eq!(actions, vec![Action::Keep]);
    }

    #[test]
    fn allof_anyof_not_address_and_size() {
        let script = r#"
            require ["fileinto"];
            if allof(not exists "x-spam", address :domain :is "from" "spam.test", size :over 10) {
                discard;
            }
        "#;
        let actions = run(script, &message("hi", "bad@spam.test"));
        assert_eq!(actions, vec![Action::Discard]);

        // 域名不匹配 → 无动作（隐式 keep 由 delivery_plan 决定）。
        let actions = run(script, &message("hi", "ok@good.test"));
        assert!(actions.is_empty());
    }

    #[test]
    fn matches_glob_and_reject() {
        let script = r#"
            require ["reject"];
            if header :matches "subject" "*spam*" {
                reject "no thanks";
            }
        "#;
        let actions = run(script, &message("totally SPAM here", "x@test"));
        assert_eq!(actions, vec![Action::Reject("no thanks".to_string())]);
    }

    #[test]
    fn body_text_and_raw_match_decoded_content() {
        // multipart/alternative，文本部件是 base64 编码的 "hello world"。
        let message = b"Content-Type: multipart/alternative; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQ=\r\n--B--\r\n";

        let script = r#"require ["body"]; if body :contains "hello world" { discard; }"#;
        assert_eq!(run(script, message), vec![Action::Discard]);

        // :raw 只看原始正文（base64 文本），不应命中解码后的内容。
        let script = r#"require ["body"]; if body :raw :contains "hello world" { discard; }"#;
        assert!(run(script, message).is_empty());
    }

    #[test]
    fn stop_halts_and_discard_cancels_implicit_keep() {
        let script = r#"
            if true { discard; stop; }
            keep;
        "#;
        let actions = run(script, &message("hi", "x@test"));
        assert_eq!(actions, vec![Action::Discard]);
        let plan = delivery_plan(&actions, |_, _| true);
        assert!(plan.folders.is_empty(), "discard 不得再隐式 keep");
        assert!(plan.reject.is_none());
    }

    #[test]
    fn implicit_keep_when_script_takes_no_action() {
        let script =
            r#"require ["fileinto"]; if header :is "from" "boss@corp.test" { fileinto "Boss"; }"#;
        let actions = run(script, &message("hi", "someone@else.test"));
        assert!(actions.is_empty());
        let plan = delivery_plan(&actions, |_, _| true);
        assert_eq!(plan.folders, vec![INBOX.to_string()]);
    }

    #[test]
    fn fileinto_falls_back_to_inbox_when_folder_is_unusable() {
        let actions = vec![Action::FileInto {
            folder: "Missing".to_string(),
            create: false,
        }];
        let plan = delivery_plan(&actions, |_, _| false);
        assert_eq!(plan.folders, vec![INBOX.to_string()]);
    }

    #[test]
    fn unsupported_extension_and_command_are_compile_errors() {
        assert!(compile(r#"require ["include"];"#).is_err());
        assert!(compile("bogus;").is_err());
        assert!(compile("if true { keep").is_err());
        assert!(compile(r#"require ["fileinto"]; fileinto "X";"#).is_ok());
        assert!(compile(r#"require ["redirect"]; redirect "a@b";"#).is_ok());
        assert!(compile(r#"require ["vacation"]; vacation "away";"#).is_ok());
    }

    #[test]
    fn deliver_with_sieve_creates_folder_and_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = MailStore::new(dir.path(), Arc::new(SystemClock)).unwrap();

        // 无脚本 → 投递 INBOX。
        let delivery = deliver_with_sieve(&store, b"Subject: hi\r\n\r\nbody").unwrap();
        match delivery {
            Delivery::Delivered { folders, .. } => assert_eq!(folders, vec![INBOX.to_string()]),
            other => panic!("unexpected {other:?}"),
        }

        // fileinto :create "Archive" → 自动创建并投递到 Archive。
        std::fs::write(
            store.root().join(".sieve"),
            r#"require ["fileinto"]; fileinto :create "Archive";"#,
        )
        .unwrap();
        let delivery = deliver_with_sieve(&store, b"Subject: hi\r\n\r\nbody").unwrap();
        match delivery {
            Delivery::Delivered { folders, .. } => assert_eq!(folders, vec!["Archive".to_string()]),
            other => panic!("unexpected {other:?}"),
        }
        let archive = store.open_folder("Archive", false).unwrap();
        assert_eq!(archive.messages.len(), 1);

        // 编译失败 → 回退 INBOX（不丢信）。
        std::fs::write(store.root().join(".sieve"), "this is not sieve").unwrap();
        let delivery = deliver_with_sieve(&store, b"Subject: hi\r\n\r\nbody").unwrap();
        match delivery {
            Delivery::Delivered { folders, .. } => assert_eq!(folders, vec![INBOX.to_string()]),
            other => panic!("unexpected {other:?}"),
        }

        // reject → 拒绝。
        std::fs::write(
            store.root().join(".sieve"),
            r#"require ["reject"]; reject "go away";"#,
        )
        .unwrap();
        match deliver_with_sieve(&store, b"Subject: hi\r\n\r\nbody").unwrap() {
            Delivery::Rejected(reason) => assert_eq!(reason, "go away"),
            other => panic!("unexpected {other:?}"),
        }
    }

    struct CaptureSink {
        sent: std::sync::Mutex<Vec<(String, String, String)>>,
    }

    impl OutboundSink for CaptureSink {
        fn submit(&self, from: &str, to: &str, data: &[u8]) -> Result<()> {
            self.sent.lock().unwrap().push((
                from.to_string(),
                to.to_string(),
                String::from_utf8_lossy(data).to_string(),
            ));
            Ok(())
        }
    }

    #[test]
    fn redirect_and_vacation_submit_through_the_sink() {
        let dir = tempfile::tempdir().unwrap();
        let store = MailStore::new(dir.path(), Arc::new(SystemClock)).unwrap();
        let sink = CaptureSink {
            sent: std::sync::Mutex::new(Vec::new()),
        };
        let message = b"From: sender@example.com\r\nSubject: hi\r\nMessage-ID: <id1@x>\r\n\r\nbody";

        // redirect：保留原信封发件人，转发到目标地址。
        std::fs::write(
            store.root().join(".sieve"),
            r#"require ["redirect"]; redirect "target@example.com";"#,
        )
        .unwrap();
        let delivery = deliver_envelope(
            &store,
            message,
            "sender@example.com",
            "user@example.com",
            Some(&sink),
        )
        .unwrap();
        assert!(matches!(delivery, Delivery::Delivered { .. }));
        {
            let sent = sink.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, "sender@example.com");
            assert_eq!(sent[0].1, "target@example.com");
            assert!(sent[0].2.contains("Subject: hi"));
        }

        // vacation：null envelope sender；同一发件人在窗口内只回一次。
        sink.sent.lock().unwrap().clear();
        std::fs::write(
            store.root().join(".sieve"),
            r#"require ["vacation"]; vacation :days 7 :subject "Away" "I am away";"#,
        )
        .unwrap();
        deliver_envelope(
            &store,
            message,
            "sender@example.com",
            "user@example.com",
            Some(&sink),
        )
        .unwrap();
        deliver_envelope(
            &store,
            message,
            "sender@example.com",
            "user@example.com",
            Some(&sink),
        )
        .unwrap();
        {
            let sent = sink.sent.lock().unwrap();
            assert_eq!(sent.len(), 1, "vacation 应在窗口内去重");
            assert_eq!(sent[0].0, "", "vacation 用 null envelope sender");
            assert_eq!(sent[0].1, "sender@example.com");
            assert!(sent[0].2.contains("Auto-Submitted: auto-replied"));
            assert!(sent[0].2.contains("Subject: Away"));
        }
    }
}
