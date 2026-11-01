//! 系统账号邮箱管理（`users.*`）。
//!
//! 从 `backend/mailstackctl/mail.py` 等价移植。这里回答了本项目一直悬而未决的
//! 「vmail 布局 / Dovecot 口令方案」问题：
//!
//! * **不用 `/var/vmail` 布局**：基线用**系统账号**。`useradd -m` 建家目录
//!   `/home/<u>`，Maildir 就是 `~/Maildir`（`cur`/`new`/`tmp`）。
//! * **不写 Dovecot passwd-file**：口令走 **PAM / 系统口令**，用 `chpasswd`
//!   （stdin `user:password\n`，失败退回 `passwd user` 并两次喂口令）；锁定/解锁用
//!   `passwd -l` / `passwd -u`；锁定状态看 `passwd -S <u>` 的第 2 个字段。
//!
//! ## 三份注册表
//!
//! | 文件 | 内容 | 权限 |
//! |---|---|---|
//! | `/etc/mailstack/managed-users.json` | unix 用户名数组（排序） | 0640 root:mailstack-admin |
//! | `/var/lib/mailstack/managed-mailboxes.json` | `{email, unixUser, displayName}` 数组 | 0640 root:mailstack-webmail |
//! | `/var/lib/mailstack/webmail-session-epoch.json` | `{用户名: unix秒}` | 0640 root:mailstack-webmail |
//!
//! ## 顺序纪律
//!
//! `user_add` 的**全部校验必须发生在任何副作用之前**：被拒的请求不得留下半个
//! 已建账号、不得碰注册表。副作用里唯一的例外是建 Maildir —— 它失败在基线里
//! **只告警不中止**（账号已经建好了，此时回滚反而更糟）。
//!
//! ## 可测试性
//!
//! 系统账号查询（`pwd.getpwnam` / `grp.getgrall`）与程序探测（`shutil.which`）
//! 都必须可注入：单测绝不能真的跑 `useradd` / `chpasswd`，也绝不能读写真实的
//! `/etc`。`/etc/passwd` 与 `/etc/group` 用**纯 Rust 解析**，不引入 libc/nix。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_core::atomic;
use mailstack_core::error::CoreResult;
use mailstack_core::exec::CommandRunner;
use mailstack_core::mailbox_passwords::MailboxPasswords;
use mailstack_core::password::validate_mailbox_password;
use mailstack_core::paths::Paths;
use mailstack_core::validate::{ADDRESS_RE, USER_RE};
use serde_json::{json, Value};

use crate::handlers::HandlerError;
use crate::readers::Clock;

/// 绝不允许被 `users.delete` / `users.password` 触碰的账号。
pub const PROTECTED_USERS: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "mail",
    "postfix",
    "dovecot",
    "nobody",
    "mailstack-admin",
    "mailstack-web",
];

/// 注册表与纪元文件的权限位。
pub const REGISTRY_MODE: u32 = 0o640;

/// webmail 进程所属组：`managed-mailboxes.json` 与 epoch 文件都归它。
pub const WEBMAIL_GROUP: &str = "mailstack-webmail";

/// 创建 Maildir 时用户家目录 / Maildir 目录 / 文件的权限位。
const HOME_MODE: u32 = 0o750;
const MAILDIR_DIR_MODE: u32 = 0o770;
const MAILDIR_FILE_MODE: u32 = 0o660;

/// 程序与路径探测。
///
/// 抽成 trait 是为了让 `useradd` / `adduser` / `chpasswd` / `userdel` / `deluser`
/// 的可用性在测试里可控。基线的 `shutil.which` 只查 `PATH`；生产实现走
/// [`mailstack_core::exec::resolve_program`]（`PATH` + 常见 sbin），因为特权助手
/// 的 `PATH` 通常不含 `/usr/sbin`，那正是 `useradd` 的家。
pub trait ProgramEnv: Send + Sync {
    /// 等价 `shutil.which(program)`：命中返回解析后的完整路径。
    fn which(&self, program: &str) -> Option<PathBuf>;

    /// 等价 `os.path.exists`（`nologin` 候选路径判定用）。
    fn path_exists(&self, path: &Path) -> bool;
}

/// 生产探测：真实 `PATH` / sbin 目录与文件系统。
#[derive(Debug, Default)]
pub struct SystemProgramEnv;

impl ProgramEnv for SystemProgramEnv {
    fn which(&self, program: &str) -> Option<PathBuf> {
        // `resolve_program` 找不到时原样返回入参，据此判断「是否真的命中」。
        let resolved = mailstack_core::exec::resolve_program(program);
        (resolved != program).then(|| PathBuf::from(resolved))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// `users.*` 的运行环境。
#[derive(Clone)]
pub struct UsersEnv {
    /// 系统账号文件的根：生产 `/etc`，测试给临时目录。
    pub passwd_root: PathBuf,
    /// 需要 `webmail` 可读的文件属组。生产 `mailstack-webmail`；
    /// 测试可设 `None` 跳过 chown（chown 到不存在的组只会在每次调用时告警）。
    ///
    /// 名字沿用 epoch 语义，但 `managed-mailboxes.json` 与 epoch 文件在基线里
    /// 同属 `root:mailstack-webmail`，故两处共用同一字段。
    pub session_epoch_owner: Option<String>,
    /// 程序探测。
    pub programs: Arc<dyn ProgramEnv>,
}

impl std::fmt::Debug for UsersEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsersEnv")
            .field("passwd_root", &self.passwd_root)
            .field("session_epoch_owner", &self.session_epoch_owner)
            .finish_non_exhaustive()
    }
}

impl Default for UsersEnv {
    fn default() -> Self {
        Self {
            passwd_root: PathBuf::from("/etc"),
            session_epoch_owner: Some(WEBMAIL_GROUP.to_string()),
            programs: Arc::new(SystemProgramEnv),
        }
    }
}

/// `/etc/passwd` 里的一行（只保留我们用得到的列）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
}

/// 系统账号邮箱动作的执行体。
pub struct Users {
    paths: Paths,
    env: UsersEnv,
    runner: Arc<dyn CommandRunner>,
    /// 注入时钟（Unix 秒）：epoch bump 必须用注入时间，测试才能断言具体值。
    clock: Clock,
}

impl Users {
    pub fn new(paths: Paths, env: UsersEnv, runner: Arc<dyn CommandRunner>, clock: Clock) -> Self {
        Self {
            paths,
            env,
            runner,
            clock,
        }
    }

    /// 生产构造。
    pub fn system(paths: Paths) -> Self {
        Self::new(
            paths,
            UsersEnv::default(),
            Arc::new(mailstack_core::exec::SystemCommandRunner),
            Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
        )
    }

    /// 覆盖运行环境（测试用）。
    pub fn with_env(mut self, env: UsersEnv) -> Self {
        self.env = env;
        self
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    // ───────────────────────── 系统账号文件解析 ─────────────────────────

    /// 解析 `<passwd_root>/passwd`。字段顺序：`name:passwd:uid:gid:gecos:home:shell`。
    ///
    /// 用纯 Rust 解析而非 `pwd.getpwnam`：单测需要一个可注入的假 `/etc`，
    /// 而 NSS 查询无法重定向到临时目录。
    fn parse_passwd(&self) -> Vec<PasswdEntry> {
        let Ok(text) = std::fs::read_to_string(self.env.passwd_root.join("passwd")) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() != 7 {
                    return None;
                }
                Some(PasswdEntry {
                    name: fields[0].to_string(),
                    uid: fields[2].parse().ok()?,
                    gid: fields[3].parse().ok()?,
                    home: PathBuf::from(fields[5]),
                })
            })
            .collect()
    }

    fn lookup_user(&self, name: &str) -> Option<PasswdEntry> {
        self.parse_passwd().into_iter().find(|e| e.name == name)
    }

    /// 「`mail` 组是否存在」。
    ///
    /// 这是对基线 `'mail' in [g.gr_name for g in grp.getgrall()]` 的**等价替换**：
    /// `grp` 走 NSS，无法指向测试的假根；这里直接解析 `<passwd_root>/group`，
    /// 语义相同（只看第一列组名）且完全可注入。
    fn group_exists(&self, name: &str) -> bool {
        let Ok(text) = std::fs::read_to_string(self.env.passwd_root.join("group")) else {
            return false;
        };
        text.lines().any(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#') && line.split(':').next() == Some(name)
        })
    }

    /// 账号是否被锁定：`passwd -S <u>` 的第 2 个字段是 `L` 或 `LK`。
    ///
    /// 命令不可用/无输出时返回 `false`（「没证据说明被锁」），与基线的
    /// `len(fields) > 1 and ...` 一致 —— 不会把查询失败误报成「已锁定」。
    fn account_locked(&self, name: &str) -> bool {
        match self.runner.run("passwd", &["-S", name]) {
            Ok(output) => output
                .stdout
                .split_whitespace()
                .nth(1)
                .map(|field| field == "L" || field == "LK")
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// 一次性读 `<passwd_root>/shadow`，按用户名给出「是否被锁定」。
    ///
    /// `users.list` 此前对**每个邮箱** fork 一次 `passwd -S`；受管邮箱一多，
    /// 一次列表动作就是几十上百个子进程。daemon 以 root 运行（规格书 §2.3），
    /// shadow 可读，一次读入即可。字段 2 与 `passwd -S` 第 2 字段的对应：
    ///
    /// * `!` 前缀（`!`、`!!`、`!$6$...`）= 锁定（`passwd -S` 的 `L`/`LK`）；
    /// * 空 / `*` = NP（无口令），**不**视为锁定 —— 与 [`Self::account_locked`]
    ///   「没证据说明被锁」的口径一致；
    /// * 其余 = P（口令已设）。
    ///
    /// 读失败（权限、坏 UTF-8）返回 `None`，调用方回退到旧的逐行 `passwd -S`
    /// 路径 —— 状态判定不能因为一次读失败而整体变错。shadow 里没有的账号
    /// 视为未锁定（`passwd -S` 对不存在的账号同样不报「已锁」）。
    fn locked_map_from_shadow(&self) -> Option<BTreeMap<String, bool>> {
        let text = std::fs::read_to_string(self.env.passwd_root.join("shadow")).ok()?;
        let mut locked: BTreeMap<String, bool> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(':');
            let name = fields.next()?;
            let hash = fields.next().unwrap_or("");
            locked.insert(name.to_string(), hash.starts_with('!'));
        }
        Some(locked)
    }

    /// nologin shell：`which(nologin)` → `/usr/sbin/nologin` → `/sbin/nologin` → `/bin/false`。
    fn nologin_shell(&self) -> String {
        if let Some(found) = self.env.programs.which("nologin") {
            return found.display().to_string();
        }
        for candidate in ["/usr/sbin/nologin", "/sbin/nologin"] {
            if self.env.programs.path_exists(Path::new(candidate)) {
                return candidate.to_string();
            }
        }
        "/bin/false".to_string()
    }

    // ───────────────────────── 注册表读写 ─────────────────────────

    /// 读 `managed-users.json` 的**如实报错**版本（5.13：读不出来 ≠ 没有）。
    ///
    /// 文件缺失是合法状态（还没有任何受管用户）；读失败（EACCES / IO 错）与
    /// 损坏（不是 JSON 数组）必须报错 —— 若把错误静默成空集合，`users.add` /
    /// `users.delete` 的「读出 → 修改 → 写回」会把整份注册表清成只剩这一条，
    /// 那是数据毁灭。
    fn try_read_managed_users(&self) -> Result<BTreeSet<String>, HandlerError> {
        let text = match std::fs::read_to_string(&self.paths.managed_users) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(e) => {
                return Err(HandlerError::new(format!(
                    "managed user registry is unreadable ({}): {e}",
                    self.paths.managed_users.display()
                )))
            }
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(items)) => Ok(items
                .into_iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()),
            _ => Err(HandlerError::new(format!(
                "managed user registry is corrupt ({}): expected a JSON array of user names",
                self.paths.managed_users.display()
            ))),
        }
    }

    /// 宽松版本：**只读**路径（受管与否的守卫判断）在读失败时退回空集合。
    ///
    /// 守卫的语义是 fail-closed：读不到 ⇒ 视为「不受管」⇒ 拒绝操作，不会发生
    /// 写回，因此不构成 5.13 的清空风险。**凡是要把读出的东西写回去的地方，
    /// 必须用 [`Self::try_read_managed_users`]。**
    fn read_managed_users(&self) -> BTreeSet<String> {
        self.try_read_managed_users().unwrap_or_default()
    }

    /// [`Self::try_read_managed_users`] 对应的 `managed-mailboxes.json` 版本。
    fn try_read_mailboxes(&self) -> Result<Vec<Value>, HandlerError> {
        let text = match std::fs::read_to_string(&self.paths.managed_mailboxes) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(HandlerError::new(format!(
                    "managed mailbox registry is unreadable ({}): {e}",
                    self.paths.managed_mailboxes.display()
                )))
            }
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(items)) => Ok(items),
            _ => Err(HandlerError::new(format!(
                "managed mailbox registry is corrupt ({}): expected a JSON array",
                self.paths.managed_mailboxes.display()
            ))),
        }
    }

    /// [`Self::try_read_mailboxes`] 的宽松版本：只读列表/反查用（见上）。
    fn read_mailboxes(&self) -> Vec<Value> {
        self.try_read_mailboxes().unwrap_or_default()
    }

    /// 原子写 `managed-users.json`：`sorted()` + `indent=2` + 末尾换行，0640。
    fn save_managed_users(&self, users: &BTreeSet<String>) -> Result<(), HandlerError> {
        // BTreeSet 天然有序，等价基线的 `sorted(items)`。
        let list: Vec<&String> = users.iter().collect();
        let text = format!("{}\n", serde_json::to_string_pretty(&list)?);
        atomic::atomic(&self.paths.managed_users, text.as_bytes(), REGISTRY_MODE)?;
        Ok(())
    }

    /// 写 `managed-mailboxes.json`：0640，并 chown 到 `mailstack-webmail`。
    ///
    /// 用 [`atomic::atomic_as`]（跳过默认的 `mailstack-admin` chown）后**显式**改属组，
    /// 因为 baseline 是先 `atomic` 再 `os.chown(..., 0, mailstack-webmail)` ——
    /// 最终属组以 webmail 为准。
    fn save_mailboxes(&self, boxes: &[Value]) -> Result<(), HandlerError> {
        let text = format!("{}\n", serde_json::to_string_pretty(boxes)?);
        atomic::atomic_as(
            &self.paths.managed_mailboxes,
            text.as_bytes(),
            REGISTRY_MODE,
            None,
        )?;
        self.chown_to_webmail(&self.paths.managed_mailboxes);
        Ok(())
    }

    /// 尽力把文件属组改为 webmail 组；失败仅告警（基线同样只 `warn`）。
    fn chown_to_webmail(&self, path: &Path) {
        let Some(group) = self.env.session_epoch_owner.as_deref() else {
            return; // 测试：显式跳过 chown。
        };
        chown_group_best_effort(path, group);
    }

    // ───────────────────────── 账号与 Maildir ─────────────────────────

    /// `useradd` 的降级链（基线顺序，**不改变尝试顺序**）。
    fn create_account(&self, user: &str, group: &str, nologin: &str) -> Result<(), HandlerError> {
        if let Some(useradd) = self.env.programs.which("useradd") {
            let useradd = useradd.display().to_string();
            let mut result = self
                .runner
                .run(&useradd, &["-m", "-N", "-g", group, "-s", nologin, user])?;
            if !result.success() {
                result = self.runner.run(&useradd, &["-m", "-s", nologin, user])?;
            }
            if !result.success() {
                return Err(HandlerError::new(format!(
                    "useradd failed to create mailbox user: {}",
                    command_detail(&result)
                )));
            }
            return Ok(());
        }

        if let Some(adduser) = self.env.programs.which("adduser") {
            let adduser = adduser.display().to_string();
            let mut result = self
                .runner
                .run(&adduser, &["-D", "-s", nologin, "-G", group, user])?;
            if !result.success() {
                result = self.runner.run(&adduser, &["-D", "-s", nologin, user])?;
            }
            if !result.success() {
                return Err(HandlerError::new(format!(
                    "adduser failed to create mailbox user: {}",
                    command_detail(&result)
                )));
            }
            return Ok(());
        }

        Err(HandlerError::new(
            "Neither useradd nor adduser command found",
        ))
    }

    /// 设置系统口令：`chpasswd`（stdin `user:password\n`），否则 `passwd`（两次）。
    fn set_password(&self, user: &str, password: &str) -> Result<(), HandlerError> {
        if let Some(chpasswd) = self.env.programs.which("chpasswd") {
            let chpasswd = chpasswd.display().to_string();
            let stdin = format!("{user}:{password}\n");
            let result = self.runner.run_with_input(&chpasswd, &[], &stdin)?;
            if !result.success() {
                return Err(HandlerError::new(format!(
                    "password change failed: {}",
                    command_detail(&result)
                )));
            }
        } else {
            // 退回交互式 `passwd`：stdin 里喂两遍（提示两次输入）。
            let stdin = format!("{password}\n{password}\n");
            let result = self.runner.run_with_input("passwd", &[user], &stdin)?;
            if !result.success() {
                return Err(HandlerError::new(format!(
                    "password change failed: {}",
                    command_detail(&result)
                )));
            }
        }
        Ok(())
    }

    /// 建 `~/Maildir/{cur,new,tmp}` 并调整属主/权限。
    ///
    /// **失败只告警不中止**：账号与口令都已生效，此时把一个成功了一半的操作
    /// 报成失败，只会让调用方以为账号没建出来。
    fn ensure_maildir(&self, entry: &PasswdEntry, user: &str) {
        let result = self.apply_maildir(entry);
        if let Err(error) = result {
            mailstack_core::warn::warn_with_detail(
                &format!("set Maildir ownership for {user}"),
                &error.to_string(),
            );
        }
    }

    fn apply_maildir(&self, entry: &PasswdEntry) -> std::io::Result<()> {
        let maildir = entry.home.join("Maildir");
        for sub in ["cur", "new", "tmp"] {
            std::fs::create_dir_all(maildir.join(sub))?;
        }
        set_mode(&entry.home, HOME_MODE)?;
        self.apply_maildir_ownership(&maildir, entry.uid, entry.gid)
    }

    /// 递归把 Maildir 的目录置 0770、文件置 0660，并尽量改成该用户的属主/属组。
    fn apply_maildir_ownership(&self, maildir: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        let mut stack = vec![maildir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            set_mode(&dir, MAILDIR_DIR_MODE)?;
            chown_best_effort(&dir, uid, gid);
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    stack.push(path);
                } else {
                    set_mode(&path, MAILDIR_FILE_MODE)?;
                    chown_best_effort(&path, uid, gid);
                }
            }
        }
        Ok(())
    }

    /// 失效某个用户的所有 webmail 在线会话。
    ///
    /// 改密与锁定/解锁都必须踢掉**已经在线**的会话，而不只是影响后续登录：
    /// webmail 进程轮询这张 epoch 表，凡是早于该用户 epoch 的会话一律丢弃。
    /// 失败非致命（会话 TTL 仍然兜底），但必须上报。
    ///
    /// epoch 表同样是 read-modify-write：与注册表同一理由，临界区必须持锁
    /// （10），否则并发的 users.password 会互相丢 epoch。
    fn bump_session_epoch(&self, user: &str) {
        let result = atomic::locked_with(&self.paths.webmail_session_epoch, || -> CoreResult<()> {
            let mut epochs: BTreeMap<String, i64> =
                std::fs::read_to_string(&self.paths.webmail_session_epoch)
                    .ok()
                    .and_then(|text| serde_json::from_str(&text).ok())
                    .unwrap_or_default();
            epochs.insert(user.to_string(), self.now());
            let text = format!("{}\n", serde_json::to_string_pretty(&epochs)?);
            atomic::atomic_as(
                &self.paths.webmail_session_epoch,
                text.as_bytes(),
                REGISTRY_MODE,
                None,
            )?;
            Ok(())
        });
        if let Err(error) = result {
            mailstack_core::warn::warn_with_detail(
                "bump webmail session epoch",
                &error.to_string(),
            );
            return;
        }
        self.chown_to_webmail(&self.paths.webmail_session_epoch);
    }

    // ───────────────────────── 对外动作 ─────────────────────────

    /// `users()`：受管邮箱列表。
    ///
    /// 系统里已不存在的账号**跳过该条**（不是报错）：注册表可能残留已手工删除的
    /// 账号，把它当成错误会让整个列表不可用。
    ///
    /// 锁定状态优先用一次 [`Self::locked_map_from_shadow`]；读不到 shadow 时
    /// 才退回逐行 `passwd -S`。输出形状两种路径完全一致。
    pub fn list(&self) -> Vec<Value> {
        let passwd = self.parse_passwd();
        let locked = self.locked_map_from_shadow();
        self.read_mailboxes()
            .into_iter()
            .filter_map(|item| {
                let name = mailbox_str(&item, "unixUser");
                if passwd.iter().all(|entry| entry.name != name) {
                    return None;
                }
                let email = mailbox_str(&item, "email");
                let domain = email
                    .split_once('@')
                    .map(|(_, domain)| domain.to_string())
                    .unwrap_or_default();
                let display = {
                    let raw = mailbox_str(&item, "displayName");
                    if raw.is_empty() {
                        name.clone()
                    } else {
                        raw
                    }
                };
                let is_locked = match &locked {
                    Some(map) => map.get(&name).copied().unwrap_or(false),
                    None => self.account_locked(&name),
                };
                let status = if is_locked { "disabled" } else { "enabled" };
                Some(json!({
                    "id": name,
                    "username": name,
                    "displayName": display,
                    "email": email,
                    "domain": domain,
                    "aliasesCount": 0,
                    "quotaUsedGb": 0,
                    "quotaMaxGb": 0,
                    "lastLoginTime": "",
                    "lastLoginIp": "",
                    "status": status,
                    "role": "mailbox",
                }))
            })
            .collect()
    }

    /// `username` 与 `email` 是否正好对应注册表里的同一个受管邮箱。
    ///
    /// 供 `setup.mail.test` 恢复基线的「sender 必须对应一个受管邮箱」检查。
    ///
    /// 比较是**区分大小写**的精确相等（等价基线
    /// `item.get('unixUser') == username and item.get('email') == sender`）：
    /// 注册表里存的是规范化后的小写值，调用方传进来的大小写若不符，应当判为
    /// 「不是同一个邮箱」并拒绝，而不是被悄悄归一化后放行。
    pub fn managed_mailbox_matches(&self, username: &str, email: &str) -> bool {
        self.read_mailboxes().iter().any(|item| {
            mailbox_str(item, "unixUser") == username && mailbox_str(item, "email") == email
        })
    }

    /// 账号是否被锁定（`passwd -S` 的第 2 个字段为 `L`/`LK`）。
    ///
    /// 包一层 [`Users::account_locked`]，供 `setup.mail.test` 的「邮箱被禁用」检查使用。
    pub fn is_locked(&self, username: &str) -> bool {
        self.account_locked(username)
    }

    /// 写 IMAP/POP3 的口令记录（`mailbox-passwords.json`，INV-37）。
    ///
    /// 为什么必须与系统口令**并写**：系统口令给 PAM/Postfix 用，协议面
    /// （`mailstack-imap`）用 PBKDF2 记录。只写一边的结果是「webmail 能登、
    /// 客户端说密码错」，或被反过来；两种都属最难排障的故障。
    ///
    /// 记录键优先用**邮箱地址**（客户端登录名），拿不到地址时退回 unix 账号名。
    fn save_mailbox_password(&self, identity: &str, password: &str) -> Result<(), HandlerError> {
        let record = if identity.contains('@') {
            mailstack_core::password::mailbox_password_record(identity, password)
        } else {
            mailstack_core::password::password_record(identity, password)
        }
        .map_err(|error| HandlerError::new(format!("mailbox password record rejected: {error}")))?;
        MailboxPasswords::at(&self.paths)
            .upsert(&record)
            .map_err(|error| {
                HandlerError::new(format!("cannot persist mailbox password record: {error}"))
            })
    }

    /// 按 unix 账号名找它的邮箱地址（`managed-mailboxes.json` 的反查）。
    fn address_of(&self, user: &str) -> Option<String> {
        self.read_mailboxes()
            .iter()
            .find(|item| mailbox_str(item, "unixUser") == user)
            .map(|item| mailbox_str(item, "email"))
            .filter(|email| !email.is_empty())
    }

    /// 删掉某个账号的口令记录；返回是否真的删掉了。
    fn drop_mailbox_password(&self, user: &str, address: Option<&str>) {
        let store = MailboxPasswords::at(&self.paths);
        if let Some(address) = address {
            let _ = store.remove(address);
        }
        let _ = store.remove(user);
    }

    /// `users.add`：建系统账号、设口令、建 Maildir、登记两份注册表。
    pub fn add(&self, data: &Value) -> Result<Value, HandlerError> {
        // `address` 是管理前端的字段名，`email` 是基线与控制台的字段名。
        let email = str_field_any(data, &["email", "address"])
            .trim()
            .to_lowercase();
        let username_field = str_field(data, "username").trim().to_lowercase();
        // 基线：`data.get('username') or email.split('@')[0]`，空串视为缺失。
        let user = if username_field.is_empty() {
            email
                .split_once('@')
                .map(|(local, _)| local.to_string())
                .unwrap_or_default()
        } else {
            username_field
        };

        if is_protected(&user) {
            return Err(HandlerError::new("mailbox username is protected"));
        }
        if !USER_RE.is_match(&user) || !ADDRESS_RE.is_match(&email) {
            return Err(HandlerError::new("invalid mailbox identity"));
        }

        // 上下文 = 用户名与完整地址：口令里出现两者任一即拒绝。
        let password = str_field(data, "password");
        validate_mailbox_password(password, [user.as_str(), email.as_str()])
            .map_err(|error| HandlerError::new(error.to_string()))?;

        let domain = email
            .split_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("");
        let managed_domains: BTreeSet<String> = atomic::try_rows(&self.paths.domains)
            .map_err(|error| {
                // 5.13：读不出来 ≠ 没有受管域名。原先这里退化成空集合，
                // 结果是「表读不了」被报成「这个域名不受管」—— 运维会去查域名配置，
                // 而真正的问题在权限或磁盘上。
                HandlerError::new(format!("managed domain table is unreadable: {error}"))
            })?
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect();
        if !managed_domains.contains(domain) {
            return Err(HandlerError::new("mailbox domain is not managed"));
        }

        // 5.13：这一步只是**快速预检**（省一次 useradd），权威的查重与登记在
        // 下面锁内的临界区里再做一遍。注册表读不出来 ≠ 没有 —— 静默成空集合
        // 会让后面的「读出 → 修改 → 写回」把整份注册表清空。
        if self
            .try_read_mailboxes()?
            .iter()
            .any(|item| mailbox_str(item, "email").to_lowercase() == email)
        {
            return Err(HandlerError::new("mailbox already exists"));
        }

        // ── 以下开始产生副作用 ──
        let group = if self.group_exists("mail") {
            "mail"
        } else {
            "users"
        };
        let nologin = self.nologin_shell();
        self.create_account(&user, group, &nologin)?;
        // 从这里起任何一步失败都要尽力回滚刚建的系统账号：不回滚的话，
        // 「set_password 失败」会留下一个没口令、没人管的孤儿系统账号。
        if let Err(error) = self.set_password(&user, password) {
            self.rollback_created_account(&user);
            return Err(error);
        }
        // 并写 IMAP/POP3 口令记录：协议面不读 /etc/shadow（见 INV-37）。
        if let Err(error) = self.save_mailbox_password(&email, password) {
            self.rollback_created_account(&user);
            return Err(error);
        }

        match self.lookup_user(&user) {
            Some(entry) => self.ensure_maildir(&entry, &user),
            None => mailstack_core::warn::warn_with_detail(
                &format!("set Maildir ownership for {user}"),
                "account is not present in the passwd database",
            ),
        }

        // 两份注册表的登记是 read-modify-write，必须在 core 的排他锁内完成
        // （10）：并发的 users.add / users.delete 不加锁会互相丢更新。
        // add 与 delete 的临界区取**同一把**锁（managed-users 的 sidecar），
        // 两份注册表才不会交错写。锁与 atomic 写的 sidecar 不同名，可安全嵌套
        // （INV-31）。锁内失败同样要回滚刚建的账号。
        //
        // `name` 是管理前端的字段名（它把展示名直接叫 `name`）。
        let display_name: String = str_field_any(data, &["displayName", "name"])
            .chars()
            .take(80)
            .collect();
        let registration = atomic::locked_with(&self.paths.managed_users, || {
            let mut boxes = self.try_read_mailboxes()?;
            if boxes
                .iter()
                .any(|item| mailbox_str(item, "email").to_lowercase() == email)
            {
                return Err(HandlerError::new("mailbox already exists"));
            }
            let mut managed = self.try_read_managed_users()?;
            managed.insert(user.clone());
            self.save_managed_users(&managed)?;
            boxes.push(json!({
                "email": email,
                "unixUser": user,
                "displayName": display_name,
            }));
            self.save_mailboxes(&boxes)?;
            Ok(())
        });
        if let Err(error) = registration {
            self.rollback_created_account(&user);
            return Err(error);
        }

        Ok(Value::Array(self.list()))
    }

    /// `users.delete`：删除系统账号并从两份注册表移除。
    pub fn delete(&self, data: &Value) -> Result<Value, HandlerError> {
        let user = user_ident(data);
        if !USER_RE.is_match(user)
            || is_protected(user)
            || !self.read_managed_users().contains(user)
        {
            return Err(HandlerError::new(
                "user is protected or not managed by MailStack",
            ));
        }

        if let Some(entry) = self.lookup_user(user) {
            if entry.uid < 1000 {
                return Err(HandlerError::new("system account deletion is forbidden"));
            }
        }

        // 降级链见 [`Self::remove_account`]。
        self.remove_account(user)?;

        // 地址要在从注册表里删掉**之前**取，否则只能按 unix 账号名删记录，
        // 而记录通常是以邮箱地址为键的 —— 会留下一份谁也删不掉的僵尸口令。
        let address = self.address_of(user);
        // 注册表更新与 users.add 取**同一把**锁（10）：不加锁时并发的
        // add/delete 会互相丢更新。锁内读失败必须报错（5.13）——此时账号已删，
        // 但绝不能把「读不到」当成「空注册表」写回去。
        atomic::locked_with(&self.paths.managed_users, || -> Result<(), HandlerError> {
            let mut managed = self.try_read_managed_users()?;
            managed.remove(user);
            self.save_managed_users(&managed)?;

            let boxes: Vec<Value> = self
                .try_read_mailboxes()?
                .into_iter()
                .filter(|item| mailbox_str(item, "unixUser") != user)
                .collect();
            self.save_mailboxes(&boxes)?;
            Ok(())
        })?;
        self.drop_mailbox_password(user, address.as_deref());

        Ok(Value::Array(self.list()))
    }

    /// 删除系统账号的降级链：`userdel -r` → `userdel` →
    /// `deluser --remove-home` → `deluser`。
    ///
    /// 两个程序都不存在时基线**静默什么都不做**（不是错误），这里保持等价
    /// （返回 `Err` 由调用方决定：`users.delete` 会报错，回滚路径只告警）。
    fn remove_account(&self, user: &str) -> Result<(), HandlerError> {
        if let Some(userdel) = self.env.programs.which("userdel") {
            let userdel = userdel.display().to_string();
            let result = self.runner.run(&userdel, &["-r", user])?;
            if !result.success() {
                let fallback = self.runner.run(&userdel, &[user])?;
                if !fallback.success() {
                    return Err(HandlerError::new(format!(
                        "user deletion failed: {}",
                        command_detail(&fallback)
                    )));
                }
            }
        } else if let Some(deluser) = self.env.programs.which("deluser") {
            let deluser = deluser.display().to_string();
            let result = self.runner.run(&deluser, &["--remove-home", user])?;
            if !result.success() {
                let fallback = self.runner.run(&deluser, &[user])?;
                if !fallback.success() {
                    return Err(HandlerError::new(format!(
                        "user deletion failed: {}",
                        command_detail(&fallback)
                    )));
                }
            }
        } else {
            return Err(HandlerError::new(
                "Neither userdel nor deluser command found",
            ));
        }
        Ok(())
    }

    /// 建号中途失败的回滚：尽力删掉刚建的系统账号（连家目录），结果只告警。
    ///
    /// 顺序纪律（模块头）：失败的请求不得留下半个账号 —— 不回滚的话，
    /// 「set_password 失败」会留下一个没口令、不受任何注册表管辖的孤儿账号。
    fn rollback_created_account(&self, user: &str) {
        match self.remove_account(user) {
            Ok(()) => mailstack_core::warn::warn(&format!(
                "rolled back partially created mailbox user {user}"
            )),
            Err(error) => mailstack_core::warn::warn_with_detail(
                &format!("roll back partially created mailbox user {user}"),
                &error.to_string(),
            ),
        }
    }

    /// `users.status`：锁定 / 解锁账号，并 bump 会话 epoch。
    pub fn status(&self, data: &Value) -> Result<Value, HandlerError> {
        let user = user_ident(data);
        // `active` 是管理前端的字段名（它就是「账号是否启用」）。
        let enabled = data
            .get("enabled")
            .or_else(|| data.get("active"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if is_protected(user) || !self.read_managed_users().contains(user) {
            return Err(HandlerError::new(
                "user is protected or not managed by MailStack",
            ));
        }

        let verb = if enabled { "-u" } else { "-l" };
        let result = self.runner.run("passwd", &[verb, user])?;
        if !result.success() {
            return Err(HandlerError::new(format!(
                "account status change failed: {}",
                command_detail(&result)
            )));
        }
        self.bump_session_epoch(user);
        Ok(Value::Array(self.list()))
    }

    /// `users.password`：重设系统口令，并 bump 会话 epoch。
    pub fn password(&self, data: &Value) -> Result<Value, HandlerError> {
        let user = user_ident(data);
        if is_protected(user) || !self.read_managed_users().contains(user) {
            return Err(HandlerError::new(
                "mailbox is protected or not managed by MailStack",
            ));
        }
        // 注意：基线这里 context 是**单个**用户名字符串，不是元组。
        let password = str_field(data, "password");
        validate_mailbox_password(password, [user])
            .map_err(|error| HandlerError::new(error.to_string()))?;

        self.set_password(user, password)?;
        // 并写 IMAP/POP3 口令记录 —— 只改系统口令会让客户端继续用旧口令。
        let identity = self.address_of(user).unwrap_or_else(|| user.to_string());
        self.save_mailbox_password(&identity, password)?;
        self.bump_session_epoch(user);
        Ok(json!({ "updated": true }))
    }
}

fn is_protected(user: &str) -> bool {
    PROTECTED_USERS.contains(&user)
}

/// 取字符串字段；缺失或非字符串返回空串（基线的 `str(data.get(k, ''))` 语义近似）。
fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(Value::as_str).unwrap_or("")
}

/// 按候选顺序取第一个**非空**字符串字段。
///
/// 为什么要多个候选名：管理前端用 `address` 称呼邮箱地址，而基线与控制台用
/// `email` / `id`。两者指向同一个东西，但必须**显式列出**而不是靠猜 —— 例如
/// `users.delete` 若只认 `id`，前端传 `address` 时会得到「不是受管用户」，
/// 看上去像权限问题，实际只是字段名没对上，排查成本很高。
fn str_field_any<'a>(data: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .map(|key| str_field(data, key))
        .find(|value| !value.is_empty())
        .unwrap_or("")
}

/// 解析「用户标识」：优先 `id` / `username`，否则从前端传来的 `address` / `email`
/// 取 `@` 之前的本地部分。
///
/// 为什么可以取本地部分：本产品的建号规则就是
/// `username = email.split('@')[0]`（见 [`Users::add`]），两者由同一条规则绑定，
/// 不是猜测。若前端传完整邮箱而这里只认 `id`，用户会看到「不是受管用户」，
/// 情形和字段名没对上一样令人困惑。
fn user_ident(data: &Value) -> &str {
    let direct = str_field_any(data, &["id", "username"]);
    if !direct.is_empty() {
        return direct;
    }
    let address = str_field_any(data, &["address", "email"]);
    address
        .split_once('@')
        .map(|(local, _)| local)
        .unwrap_or(address)
}

fn mailbox_str(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// `stderr or stdout` —— 与基线给运维看的诊断文本一致。
fn command_detail(output: &mailstack_core::exec::CommandOutput) -> String {
    if output.stderr.trim().is_empty() {
        output.stdout.trim().to_string()
    } else {
        output.stderr.trim().to_string()
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// 尽力 chown；失败不中断（Maildir 的属主调整本来就可能因权限/uid 不存在而失败）。
#[cfg(unix)]
fn chown_best_effort(path: &Path, uid: u32, gid: u32) {
    if let Err(error) = std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
        mailstack_core::warn::warn_with_detail(
            &format!("chown {}", path.display()),
            &error.to_string(),
        );
    }
}

#[cfg(not(unix))]
fn chown_best_effort(_path: &Path, _uid: u32, _gid: u32) {}

#[cfg(unix)]
fn chown_group_best_effort(path: &Path, group: &str) {
    let Some(gid) = atomic::gid_by_name(group) else {
        mailstack_core::warn::warn(&format!("resolve group {group}"));
        return;
    };
    if let Err(error) = std::os::unix::fs::chown(path, Some(0), Some(gid)) {
        mailstack_core::warn::warn_with_detail(
            &format!("chown {} to group {group}", path.display()),
            &error.to_string(),
        );
    }
}

#[cfg(not(unix))]
fn chown_group_best_effort(_path: &Path, _group: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::Mutex;

    /// 固定时钟：2026-01-01T00:00:00Z。
    const NOW: i64 = 1_767_225_600;
    const GOOD_PASSWORD: &str = "Zx7Qm2Vt9Kp4";

    /// 记下每一次调用（含 stdin）的假运行器。
    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Call>>,
        /// `useradd` 按顺序返回的状态码；用尽后一律 0。
        useradd_statuses: Mutex<VecDeque<i32>>,
        command_statuses: Mutex<BTreeMap<String, VecDeque<i32>>>,
    }

    #[derive(Clone)]
    struct Call {
        program: String,
        args: Vec<String>,
        stdin: Option<String>,
    }

    impl FakeRunner {
        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn programs(&self) -> Vec<String> {
            self.calls().into_iter().map(|c| c.program).collect()
        }

        fn push_status(&self, program: &str, status: i32) {
            self.command_statuses
                .lock()
                .unwrap()
                .entry(program.to_string())
                .or_default()
                .push_back(status);
        }

        /// 调用过某程序（按文件名后缀匹配）时收到的 stdin。
        fn input_for(&self, suffix: &str) -> Option<String> {
            self.calls()
                .into_iter()
                .find(|c| c.program.ends_with(suffix) && c.stdin.is_some())
                .and_then(|c| c.stdin)
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            self.calls.lock().unwrap().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin: None,
            });
            let status = if program.ends_with("useradd") {
                self.useradd_statuses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(0)
            } else {
                self.command_statuses
                    .lock()
                    .unwrap()
                    .get_mut(program)
                    .and_then(VecDeque::pop_front)
                    .unwrap_or(0)
            };
            Ok(mailstack_core::exec::CommandOutput {
                status,
                stdout: String::new(),
                stderr: if status == 0 {
                    String::new()
                } else {
                    format!("{program} failed")
                },
            })
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            stdin: &str,
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            self.calls.lock().unwrap().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin: Some(stdin.to_string()),
            });
            let status = self
                .command_statuses
                .lock()
                .unwrap()
                .get_mut(program)
                .and_then(VecDeque::pop_front)
                .unwrap_or(0);
            Ok(mailstack_core::exec::CommandOutput {
                status,
                stdout: String::new(),
                stderr: if status == 0 {
                    String::new()
                } else {
                    format!("{program} failed")
                },
            })
        }
    }

    /// 可编排的程序探测。
    #[derive(Clone, Default)]
    struct FakePrograms {
        which: BTreeMap<String, PathBuf>,
        paths: BTreeSet<PathBuf>,
    }

    impl FakePrograms {
        fn listing(programs: &[(&str, &str)]) -> Self {
            let mut which = BTreeMap::new();
            for (name, path) in programs {
                which.insert((*name).to_string(), PathBuf::from(path));
            }
            Self {
                which,
                paths: BTreeSet::new(),
            }
        }
    }

    impl ProgramEnv for FakePrograms {
        fn which(&self, program: &str) -> Option<PathBuf> {
            self.which.get(program).cloned()
        }

        fn path_exists(&self, path: &Path) -> bool {
            self.paths.contains(path)
        }
    }

    struct Fixture {
        root: PathBuf,
        paths: Paths,
        passwd_root: PathBuf,
        home: PathBuf,
        runner: Arc<FakeRunner>,
        programs: FakePrograms,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-users-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            let passwd_root = root.join("etcfs");
            fs::create_dir_all(&passwd_root).unwrap();
            let home = root.join("home").join("alice");
            fs::create_dir_all(&home).unwrap();

            // 受管域名表：`mailbox domain is not managed` 之外的用例都用得上。
            fs::create_dir_all(&paths.postfix).unwrap();
            fs::write(&paths.domains, "example.com OK\n").unwrap();

            Self {
                root,
                paths,
                passwd_root,
                home,
                runner: Arc::new(FakeRunner::default()),
                // 默认「装了 useradd / chpasswd / nologin」。
                programs: FakePrograms::listing(&[
                    ("useradd", "/usr/sbin/useradd"),
                    ("chpasswd", "/usr/sbin/chpasswd"),
                    ("nologin", "/usr/sbin/nologin"),
                    ("userdel", "/usr/sbin/userdel"),
                ]),
            }
        }

        fn add_passwd(&self, name: &str, uid: u32, home: &Path) {
            let line = format!(
                "{name}:x:{uid}:{uid}::{home}:/usr/sbin/nologin\n",
                home = home.display()
            );
            let mut existing =
                fs::read_to_string(self.passwd_root.join("passwd")).unwrap_or_default();
            existing.push_str(&line);
            fs::write(self.passwd_root.join("passwd"), existing).unwrap();
        }

        fn write_managed_users(&self, users: &[&str]) {
            let values: Vec<&str> = users.to_vec();
            fs::create_dir_all(self.paths.managed_users.parent().unwrap()).unwrap();
            fs::write(
                &self.paths.managed_users,
                format!("{}\n", serde_json::to_string_pretty(&values).unwrap()),
            )
            .unwrap();
        }

        fn write_mailboxes(&self, boxes: &[(&str, &str)]) {
            let values: Vec<Value> = boxes
                .iter()
                .map(|(email, user)| json!({ "email": email, "unixUser": user, "displayName": "" }))
                .collect();
            fs::create_dir_all(self.paths.managed_mailboxes.parent().unwrap()).unwrap();
            fs::write(
                &self.paths.managed_mailboxes,
                format!("{}\n", serde_json::to_string_pretty(&values).unwrap()),
            )
            .unwrap();
        }

        fn users(&self) -> Users {
            Users::new(
                self.paths.clone(),
                UsersEnv {
                    passwd_root: self.passwd_root.clone(),
                    session_epoch_owner: None,
                    programs: Arc::new(self.programs.clone()),
                },
                self.runner.clone(),
                Arc::new(|| NOW),
            )
        }

        fn epoch_of(&self, user: &str) -> Option<i64> {
            let text = fs::read_to_string(&self.paths.webmail_session_epoch).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            value.get(user).and_then(Value::as_i64)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn add_payload(email: &str, username: &str) -> Value {
        json!({ "email": email, "username": username, "password": GOOD_PASSWORD })
    }

    #[test]
    fn unmanaged_domain_is_rejected_before_any_side_effect() {
        // 副作用必须发生在全部校验之后：被拒的请求不得留下半个账号或注册表。
        let f = Fixture::new("unmanaged");
        let err = f
            .users()
            .add(&add_payload("alice@unmanaged.test", "alice"))
            .unwrap_err();
        assert_eq!(err.to_string(), "mailbox domain is not managed");
        assert!(f.runner.calls().is_empty(), "不得调用任何外部命令");
        assert!(!f.paths.managed_users.exists(), "不得写 managed-users");
        assert!(
            !f.paths.managed_mailboxes.exists(),
            "不得写 managed-mailboxes"
        );
    }

    #[test]
    fn duplicate_mailbox_is_rejected() {
        let f = Fixture::new("duplicate");
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        let err = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap_err();
        assert_eq!(err.to_string(), "mailbox already exists");
        assert!(f.runner.calls().is_empty(), "不得调用 useradd");
    }

    #[test]
    fn password_is_checked_against_the_username_and_email_context() {
        let f = Fixture::new("passwordctx");
        // 含用户名的口令被拒。
        let err = f
            .users()
            .add(&json!({
                "email": "alice@example.com",
                "username": "alice",
                "password": "Alice1Secret9",
            }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "password must not contain the account name or email address"
        );
        // 含完整地址域名的口令同样被拒。
        let err = f
            .users()
            .add(&json!({
                "email": "alice@example.com",
                "username": "alice",
                "password": "MyExample.com9",
            }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "password must not contain the account name or email address"
        );
        assert!(f.runner.calls().is_empty(), "校验失败不得产生副作用");
    }

    #[test]
    fn useradd_falls_back_and_chpasswd_receives_the_secret_on_stdin() {
        let f = Fixture::new("useraddchain");
        f.add_passwd("alice", 1001, &f.home);
        // 第一次 useradd 失败，第二次（去掉 -N -g）成功。
        f.runner.useradd_statuses.lock().unwrap().push_back(1);

        let out = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap();

        let useradd_calls: Vec<Call> = f
            .runner
            .calls()
            .into_iter()
            .filter(|c| c.program.ends_with("useradd"))
            .collect();
        assert_eq!(useradd_calls.len(), 2, "必须尝试两次");
        assert_eq!(useradd_calls[0].args[0], "-m");
        assert!(useradd_calls[0].args.contains(&"-N".to_string()));
        assert_eq!(
            useradd_calls[1].args,
            vec!["-m", "-s", "/usr/sbin/nologin", "alice"]
        );

        // 口令经 stdin，绝不进 argv。
        assert_eq!(
            f.runner.input_for("chpasswd").as_deref(),
            Some("alice:Zx7Qm2Vt9Kp4\n")
        );
        assert!(
            f.runner
                .calls()
                .iter()
                .all(|c| !c.args.iter().any(|a| a.contains(GOOD_PASSWORD))),
            "口令不得出现在任何 argv 里"
        );

        let listed = out.as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["id"], "alice");
        assert_eq!(listed[0]["status"], "enabled");
    }

    #[test]
    fn add_rejects_protected_service_users_before_running_commands() {
        let f = Fixture::new("protectedadd");
        let error = f
            .users()
            .add(&add_payload("web@example.com", "mailstack-web"))
            .unwrap_err();

        assert_eq!(error.to_string(), "mailbox username is protected");
        assert!(f.runner.calls().is_empty());
        assert!(!f.paths.managed_users.exists());
        assert!(!f.paths.managed_mailboxes.exists());
    }

    #[test]
    fn failed_chpasswd_does_not_report_mailbox_creation_as_success() {
        let f = Fixture::new("chpasswdfail");
        f.runner.push_status("/usr/sbin/chpasswd", 1);

        let error = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap_err();

        assert!(error.to_string().contains("password change failed"));
        assert!(!f.paths.managed_users.exists());
        assert!(!f.paths.managed_mailboxes.exists());
    }

    #[test]
    fn failed_passwd_status_does_not_bump_session_epoch() {
        let f = Fixture::new("statusfail");
        f.write_managed_users(&["alice"]);
        f.runner.push_status("passwd", 1);

        let error = f
            .users()
            .status(&json!({ "id": "alice", "enabled": false }))
            .unwrap_err();

        assert!(error.to_string().contains("account status change failed"));
        assert_eq!(f.epoch_of("alice"), None);
    }

    #[test]
    fn failed_userdel_fallback_preserves_both_managed_registries() {
        let f = Fixture::new("deletefail");
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        f.runner.push_status("/usr/sbin/userdel", 1);
        f.runner.push_status("/usr/sbin/userdel", 1);

        let error = f.users().delete(&json!({ "id": "alice" })).unwrap_err();

        assert!(error.to_string().contains("user deletion failed"));
        assert!(f.users().read_managed_users().contains("alice"));
        assert_eq!(f.users().read_mailboxes().len(), 1);
        assert_eq!(
            f.runner
                .calls()
                .iter()
                .filter(|call| call.program.ends_with("userdel"))
                .count(),
            2
        );
    }

    #[test]
    fn delete_fails_closed_when_no_system_account_removal_program_exists() {
        let f = Fixture::new("deletemissingprogram");
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        let users = Users::new(
            f.paths.clone(),
            UsersEnv {
                passwd_root: f.passwd_root.clone(),
                session_epoch_owner: None,
                programs: Arc::new(FakePrograms::listing(&[])),
            },
            f.runner.clone(),
            Arc::new(|| NOW),
        );

        let error = users.delete(&json!({ "id": "alice" })).unwrap_err();

        assert!(error.to_string().contains("Neither userdel nor deluser"));
        assert!(users.read_managed_users().contains("alice"));
        assert_eq!(users.read_mailboxes().len(), 1);
    }

    #[test]
    fn maildir_directories_and_modes_are_created() {
        let f = Fixture::new("maildir");
        f.add_passwd("alice", 1001, &f.home);
        f.users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap();

        let maildir = f.home.join("Maildir");
        for sub in ["cur", "new", "tmp"] {
            assert!(maildir.join(sub).is_dir(), "Maildir/{sub} 必须存在");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&f.home), HOME_MODE, "家目录应为 0750");
            assert_eq!(mode(&maildir), MAILDIR_DIR_MODE, "Maildir 应为 0770");
            assert_eq!(mode(&maildir.join("new")), MAILDIR_DIR_MODE);
        }
    }

    #[test]
    fn registries_are_written_atomically_with_0640_and_sorted() {
        let f = Fixture::new("registries");
        let bob_home = f.root.join("home").join("bob");
        fs::create_dir_all(&bob_home).unwrap();
        f.add_passwd("alice", 1001, &f.home);
        f.add_passwd("bob", 1002, &bob_home);

        let users = f.users();
        users
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap();
        users.add(&add_payload("bob@example.com", "bob")).unwrap();

        let managed: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.managed_users).unwrap()).unwrap();
        assert_eq!(managed, json!(["alice", "bob"]), "必须排序后写入");

        let boxes: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.managed_mailboxes).unwrap()).unwrap();
        assert_eq!(boxes.as_array().unwrap().len(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&f.paths.managed_users), REGISTRY_MODE);
            assert_eq!(mode(&f.paths.managed_mailboxes), REGISTRY_MODE);
        }
    }

    #[test]
    fn delete_rejects_protected_and_system_accounts_but_removes_managed_ones() {
        let f = Fixture::new("delete");
        // protected：即使被误写进注册表也必须拒绝。
        f.write_managed_users(&["root", "sysacct", "alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        f.add_passwd("sysacct", 500, &f.root.join("home/sysacct"));
        f.add_passwd("alice", 1001, &f.home);

        let users = f.users();
        assert_eq!(
            users
                .delete(&json!({ "id": "root" }))
                .unwrap_err()
                .to_string(),
            "user is protected or not managed by MailStack"
        );
        assert_eq!(
            users
                .delete(&json!({ "id": "sysacct" }))
                .unwrap_err()
                .to_string(),
            "system account deletion is forbidden"
        );

        let out = users.delete(&json!({ "id": "alice" })).unwrap();
        assert!(f.runner.programs().iter().any(|p| p.ends_with("userdel")));
        let userdel = f
            .runner
            .calls()
            .into_iter()
            .find(|c| c.program.ends_with("userdel"))
            .unwrap();
        assert_eq!(userdel.args, vec!["-r", "alice"]);

        let managed: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.managed_users).unwrap()).unwrap();
        assert!(!managed.as_array().unwrap().iter().any(|v| v == "alice"));
        let boxes: Value =
            serde_json::from_str(&fs::read_to_string(&f.paths.managed_mailboxes).unwrap()).unwrap();
        assert!(boxes.as_array().unwrap().is_empty());
        assert!(out.as_array().unwrap().is_empty());
    }

    #[test]
    fn status_toggles_lock_and_bumps_the_session_epoch() {
        let f = Fixture::new("status");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        let users = f.users();

        users
            .status(&json!({ "id": "alice", "enabled": true }))
            .unwrap();
        assert!(
            f.runner
                .calls()
                .iter()
                .any(|c| c.program == "passwd" && c.args == vec!["-u", "alice"]),
            "enabled=true 必须执行 passwd -u"
        );
        assert_eq!(f.epoch_of("alice"), Some(NOW), "解锁也要 bump epoch");

        users
            .status(&json!({ "id": "alice", "enabled": false }))
            .unwrap();
        assert!(
            f.runner
                .calls()
                .iter()
                .any(|c| c.program == "passwd" && c.args == vec!["-l", "alice"]),
            "enabled=false 必须执行 passwd -l"
        );
    }

    #[test]
    fn the_frontend_field_names_address_and_name_are_understood() {
        // 管理前端用 `address` 称呼邮箱、用 `name` 称呼展示名、用 `active` 称呼启用位。
        // 不认这些名字的后果不是「报错」而是「看起来像权限问题」：
        // users.delete 只认 `id` 时会回「不是受管用户」，让人以为是授权出错。
        let f = Fixture::new("frontendnames");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        let users = f.users();

        // status：`address` + `active` 等价于 `id` + `enabled`。
        users
            .status(&json!({ "address": "alice@example.com", "active": true }))
            .unwrap();
        assert!(
            f.runner
                .calls()
                .iter()
                .any(|c| c.program == "passwd" && c.args == vec!["-u", "alice"]),
            "active=true 必须被当成 enabled=true → passwd -u"
        );

        // password：`address` 也要能定位到 unix 用户名（本地部分）。
        users
            .password(&json!({ "address": "alice@example.com", "password": GOOD_PASSWORD }))
            .unwrap();
        assert_eq!(
            f.runner.input_for("chpasswd").as_deref(),
            Some("alice:Zx7Qm2Vt9Kp4\n")
        );
    }

    #[test]
    fn add_accepts_the_frontend_address_field() {
        let f = Fixture::new("frontendadd");
        let users = f.users();

        let out = users
            .add(&json!({ "address": "alice@example.com", "name": "Alice", "password": GOOD_PASSWORD }))
            .unwrap();
        // 用户名按建号规则从地址本地部分推出，展示名取 `name`。
        assert!(out.is_array());
        let boxes = users.read_mailboxes();
        assert_eq!(mailbox_str(&boxes[0], "email"), "alice@example.com");
        assert_eq!(mailbox_str(&boxes[0], "unixUser"), "alice");
        assert_eq!(mailbox_str(&boxes[0], "displayName"), "Alice");
    }

    #[test]
    fn status_rejects_protected_or_unmanaged_users() {
        let f = Fixture::new("statusbad");
        f.write_managed_users(&["alice"]);
        let users = f.users();
        for user in ["root", "ghost"] {
            assert_eq!(
                users
                    .status(&json!({ "id": user, "enabled": false }))
                    .unwrap_err()
                    .to_string(),
                "user is protected or not managed by MailStack"
            );
        }
    }

    #[test]
    fn password_change_uses_chpasswd_bumps_the_epoch_and_reports_updated() {
        let f = Fixture::new("password");
        f.write_managed_users(&["alice"]);
        let users = f.users();

        let out = users
            .password(&json!({ "id": "alice", "password": GOOD_PASSWORD }))
            .unwrap();
        assert_eq!(out, json!({ "updated": true }));
        assert_eq!(
            f.runner.input_for("chpasswd").as_deref(),
            Some("alice:Zx7Qm2Vt9Kp4\n")
        );
        assert_eq!(f.epoch_of("alice"), Some(NOW), "改密必须 bump epoch");

        // protected / 未托管一律拒绝。
        for user in ["root", "ghost"] {
            assert_eq!(
                users
                    .password(&json!({ "id": user, "password": GOOD_PASSWORD }))
                    .unwrap_err()
                    .to_string(),
                "mailbox is protected or not managed by MailStack"
            );
        }
    }

    #[test]
    fn list_skips_accounts_that_no_longer_exist_on_the_system() {
        let f = Fixture::new("skipghost");
        f.write_mailboxes(&[
            ("alice@example.com", "alice"),
            ("ghost@example.com", "ghost"),
        ]);
        f.add_passwd("alice", 1001, &f.home);

        let listed = f.users().list();
        assert_eq!(listed.len(), 1, "不存在的账号必须被跳过而不是报错");
        assert_eq!(listed[0]["id"], "alice");
        assert_eq!(listed[0]["domain"], "example.com");
        assert_eq!(listed[0]["role"], "mailbox");
    }

    // ─────────── IMAP/POP3 口令记录（mailbox-passwords.json）───────────

    /// 建号必须**同时**写系统口令与 IMAP 口令记录。
    ///
    /// 只写系统的后果：客户端（走协议面）永远登不上；只写记录的后果：
    /// PAM/Postfix 侧认不出。两边都要有，且键是**邮箱地址**。
    #[test]
    fn add_also_writes_the_imap_password_record_keyed_by_address() {
        let f = Fixture::new("imaprecord");
        f.add_passwd("alice", 1001, &f.home);
        f.users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap();

        let record = MailboxPasswords::at(&f.paths)
            .get("alice@example.com")
            .unwrap()
            .expect("必须写入以邮箱地址为键的口令记录");
        assert!(
            mailstack_core::password::verify_password(&record, GOOD_PASSWORD),
            "记录里的哈希必须能验过建号时给的口令"
        );
        assert_eq!(record.username, "alice@example.com");
    }

    /// 改密必须同时更新协议面的记录，否则客户端会继续用旧口令。
    #[test]
    fn password_change_updates_the_imap_record_too() {
        let f = Fixture::new("imaprecordpw");
        f.add_passwd("alice", 1001, &f.home);
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);

        f.users()
            .password(&json!({ "id": "alice", "password": "Battery-Staple-7" }))
            .unwrap();

        let record = MailboxPasswords::at(&f.paths)
            .get("alice@example.com")
            .unwrap()
            .expect("改密后必须仍有记录");
        assert!(
            mailstack_core::password::verify_password(&record, "Battery-Staple-7"),
            "协议面必须认新口令"
        );
        assert!(
            !mailstack_core::password::verify_password(&record, GOOD_PASSWORD),
            "旧口令不得仍然有效"
        );
    }

    /// 删号必须把记录一起删掉；否则那个地址会留一份「谁也管不到」的口令。
    #[test]
    fn delete_drops_the_imap_record() {
        let f = Fixture::new("imaprecorddel");
        f.add_passwd("alice", 1001, &f.home);
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        MailboxPasswords::at(&f.paths)
            .upsert(
                &mailstack_core::password::mailbox_password_record(
                    "alice@example.com",
                    GOOD_PASSWORD,
                )
                .unwrap(),
            )
            .unwrap();

        f.users().delete(&json!({ "id": "alice" })).unwrap();

        assert!(
            MailboxPasswords::at(&f.paths)
                .get("alice@example.com")
                .unwrap()
                .is_none(),
            "删号后不得残留口令记录"
        );
    }

    /// 反例：记录写不进去时必须**报错**，不能"系统口令改成了、协议面还是旧口令"。
    #[test]
    fn a_failed_imap_record_write_is_reported_instead_of_silently_half_done() {
        let f = Fixture::new("imaprecordfail");
        f.add_passwd("alice", 1001, &f.home);
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        // 把记录文件的位置变成一个目录 → 原子写必然失败。
        fs::create_dir_all(&f.paths.mailbox_passwords).unwrap();

        let error = f
            .users()
            .password(&json!({ "id": "alice", "password": "Battery-Staple-7" }))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot persist mailbox password record"),
            "必须明确指出口令记录写失败：{error}"
        );
        // 系统口令那边已经改过了 —— 这正是「不能静默半成功」的理由：
        // 报错让上层知道要回滚/重试，而不是以为改成功。
    }

    // ─────────── 5.13 / 10 / 11：注册表如实读、持锁写、中途回滚 ───────────

    #[test]
    fn a_corrupt_mailbox_registry_fails_add_before_any_side_effect() {
        // 5.13：注册表损坏时 users.add 必须报错，而不是把「读到的空集合」
        // 写回去 —— 那会把整份 managed-mailboxes.json 清掉。
        let f = Fixture::new("registrycorrupt");
        fs::create_dir_all(f.paths.managed_mailboxes.parent().unwrap()).unwrap();
        fs::write(&f.paths.managed_mailboxes, "{not json").unwrap();

        let error = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("managed mailbox registry is corrupt"),
            "实际: {error}"
        );
        assert!(f.runner.calls().is_empty(), "查重在副作用之前，不得跑命令");
        assert_eq!(
            fs::read_to_string(&f.paths.managed_mailboxes).unwrap(),
            "{not json",
            "不得覆盖损坏的注册表"
        );
    }

    #[test]
    fn a_corrupt_managed_users_registry_rolls_the_add_back() {
        // 注册表在**中途**读失败（账号已建、口令已设）：必须回滚刚建的账号，
        // 且绝不能把损坏的注册表当成空集合覆盖掉。
        let f = Fixture::new("userscorrupt");
        f.write_mailboxes(&[("bob@example.com", "bob")]);
        fs::create_dir_all(f.paths.managed_users.parent().unwrap()).unwrap();
        fs::write(&f.paths.managed_users, "not-a-json-array").unwrap();
        f.add_passwd("alice", 1001, &f.home);

        let error = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap_err();

        assert!(
            error.to_string().contains("managed user registry"),
            "实际: {error}"
        );
        let userdel = f
            .runner
            .calls()
            .into_iter()
            .find(|call| call.program.ends_with("userdel"))
            .expect("中途失败必须回滚刚建的账号");
        assert_eq!(userdel.args, vec!["-r", "alice"]);
        assert_eq!(
            fs::read_to_string(&f.paths.managed_users).unwrap(),
            "not-a-json-array",
            "不得覆盖损坏的注册表"
        );
        assert_eq!(f.users().read_mailboxes().len(), 1, "既有邮箱不得被动过");
    }

    #[test]
    fn a_failed_midway_step_rolls_back_the_created_account() {
        // 11：set_password 之后的失败（此处：协议面口令记录写不进去）必须
        // 尽力 userdel -r 刚建的账号 —— 不能留下一个没口令、不受注册表管辖
        // 的孤儿系统账号。
        let f = Fixture::new("addrollback");
        f.add_passwd("alice", 1001, &f.home);
        // 把记录文件的位置变成一个目录 → 原子写必然失败。
        fs::create_dir_all(&f.paths.mailbox_passwords).unwrap();

        let error = f
            .users()
            .add(&add_payload("alice@example.com", "alice"))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot persist mailbox password record"),
            "实际: {error}"
        );
        let userdel = f
            .runner
            .calls()
            .into_iter()
            .find(|call| call.program.ends_with("userdel"))
            .expect("中途失败必须回滚刚建的账号");
        assert_eq!(userdel.args, vec!["-r", "alice"]);
        assert!(!f.paths.managed_users.exists(), "注册表不得留下痕迹");
        assert!(!f.paths.managed_mailboxes.exists(), "注册表不得留下痕迹");
    }

    #[test]
    fn list_derives_lock_status_from_a_single_shadow_read() {
        // 12：逐行 fork `passwd -S` 换成一次 shadow 读取。`!` 前缀 = 锁定，
        // 正常哈希 = 启用；输出形状与旧路径一致。
        let f = Fixture::new("shadowlocks");
        f.write_mailboxes(&[
            ("alice@example.com", "alice"),
            ("bob@example.com", "bob"),
        ]);
        f.add_passwd("alice", 1001, &f.home);
        f.add_passwd("bob", 1002, &f.root.join("home/bob"));
        fs::write(
            f.passwd_root.join("shadow"),
            "alice:!$6$rounds=100000$locked:19000:0:99999:7:::\n\
             bob:$6$salt$hashvalue:19000:0:99999:7:::\n",
        )
        .unwrap();

        let listed = f.users().list();
        let status_of = |name: &str| {
            listed
                .iter()
                .find(|user| user["id"] == name)
                .map(|user| user["status"].clone())
                .unwrap()
        };
        assert_eq!(status_of("alice"), "disabled", "`!` 前缀 = 锁定");
        assert_eq!(status_of("bob"), "enabled", "正常哈希 = 启用");
        assert!(
            f.runner
                .calls()
                .iter()
                .all(|call| !call.program.ends_with("passwd")),
            "shadow 命中时不得再逐行 fork passwd -S"
        );
    }

    #[test]
    fn list_falls_back_to_passwd_s_when_shadow_is_unreadable() {
        // shadow 读不到（缺文件 / 权限）时退回旧的逐行 `passwd -S` 路径，
        // 状态判定不能因为一次读失败而整体变错。FakeRunner 的 stdout 恒为空 →
        // `passwd -S` 无第 2 字段 → 未锁定（「没证据说明被锁」口径）。
        let f = Fixture::new("shadowfallback");
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        f.add_passwd("alice", 1001, &f.home);

        let listed = f.users().list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["status"], "enabled");
        // 回退路径必须真的被走到：列表动作里出现了 `passwd -S`。
        assert!(
            f.runner
                .calls()
                .iter()
                .any(|call| call.program == "passwd" && call.args == vec!["-S", "alice"]),
            "shadow 不可用时应逐行回退到 passwd -S"
        );
    }
}
