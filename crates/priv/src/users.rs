use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mailstack_core::atomic;
use mailstack_core::error::{CoreError, CoreResult};
use mailstack_core::exec::CommandRunner;
use mailstack_core::mailbox_passwords::MailboxPasswords;
use mailstack_core::password::validate_mailbox_password;
use mailstack_core::paths::Paths;
use mailstack_core::validate::{ADDRESS_RE, USER_RE};
use serde_json::{json, Value};

use crate::handlers::HandlerError;
use crate::readers::Clock;

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

pub const REGISTRY_MODE: u32 = 0o640;

pub const WEBMAIL_GROUP: &str = "mailstack-webmail";

const HOME_MODE: u32 = 0o750;
const MAILDIR_DIR_MODE: u32 = 0o770;
const MAILDIR_FILE_MODE: u32 = 0o660;

pub trait ProgramEnv: Send + Sync {
    fn which(&self, program: &str) -> Option<PathBuf>;

    fn path_exists(&self, path: &Path) -> bool;
}

#[derive(Debug, Default)]
pub struct SystemProgramEnv;

impl ProgramEnv for SystemProgramEnv {
    fn which(&self, program: &str) -> Option<PathBuf> {
        let resolved = mailstack_core::exec::resolve_program(program);
        (resolved != program).then(|| PathBuf::from(resolved))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

#[derive(Clone)]
pub struct UsersEnv {
    pub passwd_root: PathBuf,

    pub session_epoch_owner: Option<String>,

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
}

pub struct Users {
    paths: Paths,
    env: UsersEnv,
    runner: Arc<dyn CommandRunner>,

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

    pub fn system(paths: Paths) -> Self {
        Self::new(
            paths,
            UsersEnv::default(),
            Arc::new(mailstack_core::exec::SystemCommandRunner),
            Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
        )
    }

    pub fn with_env(mut self, env: UsersEnv) -> Self {
        self.env = env;
        self
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

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

    fn group_exists(&self, name: &str) -> bool {
        let Ok(text) = std::fs::read_to_string(self.env.passwd_root.join("group")) else {
            return false;
        };
        text.lines().any(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#') && line.split(':').next() == Some(name)
        })
    }

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

    fn read_managed_users(&self) -> BTreeSet<String> {
        self.try_read_managed_users().unwrap_or_default()
    }

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

    fn read_mailboxes(&self) -> Vec<Value> {
        self.try_read_mailboxes().unwrap_or_default()
    }

    pub fn managed_accounts(&self) -> Result<BTreeSet<String>, HandlerError> {
        let mut accounts = self.try_read_managed_users()?;
        for item in self.try_read_mailboxes()? {
            let user = mailbox_str(&item, "unixUser");
            if !user.is_empty() {
                accounts.insert(user);
            }
        }
        Ok(accounts)
    }

    pub fn managed_maildirs(&self) -> Result<(Vec<PathBuf>, Vec<String>), HandlerError> {
        let passwd = self.parse_passwd();
        let mut maildirs = Vec::new();
        let mut warnings = Vec::new();
        for account in self.managed_accounts()? {
            match passwd.iter().find(|entry| entry.name == account) {
                Some(entry) => {
                    let maildir = entry.home.join(mailstack_core::backup::MAIL_DIR_NAME);
                    if maildir.is_dir() {
                        maildirs.push(maildir);
                    } else {
                        warnings.push(format!(
                            "{account}: {} is missing, this mailbox will not be backed up",
                            maildir.display()
                        ));
                    }
                }
                None => warnings.push(format!(
                    "{account}: no passwd entry, the home directory (and Maildir) is unknown"
                )),
            }
        }
        Ok((maildirs, warnings))
    }

    fn save_managed_users(&self, users: &BTreeSet<String>) -> Result<(), HandlerError> {
        let list: Vec<&String> = users.iter().collect();
        let text = format!("{}\n", serde_json::to_string_pretty(&list)?);
        atomic::atomic(&self.paths.managed_users, text.as_bytes(), REGISTRY_MODE)?;
        Ok(())
    }

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

    fn chown_to_webmail(&self, path: &Path) {
        let Some(group) = self.env.session_epoch_owner.as_deref() else {
            return;
        };
        chown_group_best_effort(path, group);
    }

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

    fn set_password(&self, user: &str, password: &str) -> Result<(), HandlerError> {
        let chpasswd = self.env.programs.which("chpasswd").ok_or_else(|| {
            HandlerError::new(
                "chpasswd is not available; refusing to fall back to the interactive passwd path",
            )
        })?;
        let chpasswd = chpasswd.display().to_string();
        let stdin = format!("{user}:{password}\n");
        let result = self.runner.run_with_input(&chpasswd, &[], &stdin)?;
        if !result.success() {
            return Err(HandlerError::new(format!(
                "password change failed: {}",
                command_detail(&result)
            )));
        }
        Ok(())
    }

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

    fn bump_session_epoch(&self, user: &str) -> Result<(), HandlerError> {
        let path = &self.paths.webmail_session_epoch;
        let result = atomic::locked_with(path, || -> CoreResult<()> {
            let mut epochs: BTreeMap<String, i64> = match std::fs::read_to_string(path) {
                Ok(text) => serde_json::from_str(&text).map_err(|error| {
                    CoreError::invalid(format!(
                        "webmail session epoch table is corrupt ({}): {error}",
                        path.display()
                    ))
                })?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(error) => return Err(CoreError::io(path, error)),
            };
            epochs.insert(user.to_string(), self.now());
            let text = format!("{}\n", serde_json::to_string_pretty(&epochs)?);
            atomic::atomic_as(path, text.as_bytes(), REGISTRY_MODE, None)?;
            Ok(())
        });
        match result {
            Ok(()) => {
                self.chown_to_webmail(path);
                Ok(())
            }
            Err(error) => Err(HandlerError::new(format!(
                "webmail sessions could not be invalidated: {error}"
            ))),
        }
    }

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

    pub fn managed_mailbox_matches(&self, username: &str, email: &str) -> bool {
        self.read_mailboxes().iter().any(|item| {
            mailbox_str(item, "unixUser") == username && mailbox_str(item, "email") == email
        })
    }

    pub fn is_locked(&self, username: &str) -> bool {
        self.account_locked(username)
    }

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

    fn address_of(&self, user: &str) -> Option<String> {
        self.read_mailboxes()
            .iter()
            .find(|item| mailbox_str(item, "unixUser") == user)
            .map(|item| mailbox_str(item, "email"))
            .filter(|email| !email.is_empty())
    }

    fn drop_mailbox_password(&self, user: &str, address: Option<&str>) {
        let store = MailboxPasswords::at(&self.paths);
        if let Some(address) = address {
            let _ = store.remove(address);
        }
        let _ = store.remove(user);
    }

    pub fn add(&self, data: &Value) -> Result<Value, HandlerError> {
        let email = str_field_any(data, &["email", "address"])
            .trim()
            .to_lowercase();
        let username_field = str_field(data, "username").trim().to_lowercase();

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

        let password = str_field(data, "password");
        validate_mailbox_password(password, [user.as_str(), email.as_str()])
            .map_err(|error| HandlerError::new(error.to_string()))?;

        let domain = email
            .split_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("");
        let managed_domains: BTreeSet<String> = atomic::try_rows(&self.paths.domains)
            .map_err(|error| {
                HandlerError::new(format!("managed domain table is unreadable: {error}"))
            })?
            .into_iter()
            .filter_map(|row| row.into_iter().next())
            .collect();
        if !managed_domains.contains(domain) {
            return Err(HandlerError::new("mailbox domain is not managed"));
        }

        if self
            .try_read_mailboxes()?
            .iter()
            .any(|item| mailbox_str(item, "email").to_lowercase() == email)
        {
            return Err(HandlerError::new("mailbox already exists"));
        }

        let group = if self.group_exists("mail") {
            "mail"
        } else {
            "users"
        };
        let nologin = self.nologin_shell();
        self.create_account(&user, group, &nologin)?;

        if let Err(error) = self.set_password(&user, password) {
            self.rollback_created_account(&user, Some(&email));
            return Err(error);
        }

        if let Err(error) = self.save_mailbox_password(&email, password) {
            self.rollback_created_account(&user, Some(&email));
            return Err(error);
        }

        match self.lookup_user(&user) {
            Some(entry) => self.ensure_maildir(&entry, &user),
            None => mailstack_core::warn::warn_with_detail(
                &format!("set Maildir ownership for {user}"),
                "account is not present in the passwd database",
            ),
        }

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
            self.rollback_created_account(&user, Some(&email));
            return Err(error);
        }

        Ok(Value::Array(self.list()))
    }

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

        self.remove_account(user)?;

        let address = self.address_of(user);

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

    fn rollback_created_account(&self, user: &str, address: Option<&str>) {
        self.drop_mailbox_password(user, address);
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

    pub fn status(&self, data: &Value) -> Result<Value, HandlerError> {
        let user = user_ident(data);
        if is_protected(user) || !self.read_managed_users().contains(user) {
            return Err(HandlerError::new(
                "user is protected or not managed by MailStack",
            ));
        }

        let enabled = match data.get("enabled").or_else(|| data.get("active")) {
            Some(Value::Bool(value)) => *value,
            Some(other) => {
                return Err(HandlerError::new(format!(
                    "enabled (or active) must be a boolean, got {other}"
                )))
            }
            None => {
                return Err(HandlerError::new(
                    "missing required field (enabled or active)",
                ))
            }
        };

        let verb = if enabled { "-u" } else { "-l" };
        let result = self.runner.run("passwd", &[verb, user])?;
        if !result.success() {
            return Err(HandlerError::new(format!(
                "account status change failed: {}",
                command_detail(&result)
            )));
        }

        self.bump_session_epoch(user).map_err(|error| {
            HandlerError::new(format!("account status was changed but {error}"))
        })?;
        Ok(Value::Array(self.list()))
    }

    pub fn password(&self, data: &Value) -> Result<Value, HandlerError> {
        let user = user_ident(data);
        if is_protected(user) || !self.read_managed_users().contains(user) {
            return Err(HandlerError::new(
                "mailbox is protected or not managed by MailStack",
            ));
        }

        let password = str_field(data, "password");
        validate_mailbox_password(password, [user])
            .map_err(|error| HandlerError::new(error.to_string()))?;

        let identity = self.address_of(user).unwrap_or_else(|| user.to_string());
        let store = MailboxPasswords::at(&self.paths);

        let previous = store.get(&identity).map_err(|error| {
            HandlerError::new(format!(
                "cannot read the current mailbox password record: {error}"
            ))
        })?;

        self.save_mailbox_password(&identity, password)?;

        if let Err(error) = self.set_password(user, password) {
            if let Err(rollback) = self.restore_mailbox_password(&identity, previous.as_ref()) {
                let _ = self.bump_session_epoch(user);
                return Err(HandlerError::new(format!(
                    "{error}; the IMAP/POP3 password record could not be rolled back either ({rollback}), so the protocol password now differs from the system password"
                )));
            }
            return Err(error);
        }

        self.bump_session_epoch(user)
            .map_err(|error| HandlerError::new(format!("password was updated but {error}")))?;
        Ok(json!({ "updated": true }))
    }

    fn restore_mailbox_password(
        &self,
        identity: &str,
        previous: Option<&mailstack_core::password::PasswordRecord>,
    ) -> Result<(), HandlerError> {
        let store = MailboxPasswords::at(&self.paths);
        match previous {
            Some(record) => store.upsert(record).map_err(|error| {
                HandlerError::new(format!(
                    "cannot restore the previous mailbox password record: {error}"
                ))
            }),
            None => store.remove(identity).map(|_| ()).map_err(|error| {
                HandlerError::new(format!(
                    "cannot remove the mailbox password record written by this attempt: {error}"
                ))
            }),
        }
    }
}

fn is_protected(user: &str) -> bool {
    PROTECTED_USERS.contains(&user)
}

fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(Value::as_str).unwrap_or("")
}

fn str_field_any<'a>(data: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .map(|key| str_field(data, key))
        .find(|value| !value.is_empty())
        .unwrap_or("")
}

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

    const NOW: i64 = 1_767_225_600;
    const GOOD_PASSWORD: &str = "Zx7Qm2Vt9Kp4";

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<Call>>,

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

            fs::create_dir_all(&paths.postfix).unwrap();
            fs::write(&paths.domains, "example.com OK\n").unwrap();

            Self {
                root,
                paths,
                passwd_root,
                home,
                runner: Arc::new(FakeRunner::default()),

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
        let f = Fixture::new("frontendnames");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        let users = f.users();

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

    #[test]
    fn an_unreadable_imap_record_store_is_reported_instead_of_silently_half_done() {
        let f = Fixture::new("imaprecordfail");
        f.add_passwd("alice", 1001, &f.home);
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);

        fs::create_dir_all(&f.paths.mailbox_passwords).unwrap();

        let error = f
            .users()
            .password(&json!({ "id": "alice", "password": "Battery-Staple-7" }))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot read the current mailbox password record"),
            "必须明确指出协议面口令库读不出来：{error}"
        );

        assert!(
            !f.runner.programs().iter().any(|p| p.ends_with("chpasswd")),
            "协议面记录写不了时不得先改系统口令"
        );
        assert_eq!(f.epoch_of("alice"), None, "什么都没成功，不得 bump epoch");
    }

    #[test]
    fn a_failed_imap_record_write_never_touches_the_system_password() {
        let f = Fixture::new("imaprecordwrite");
        f.add_passwd("alice", 1001, &f.home);
        f.write_managed_users(&["alice"]);
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        fs::create_dir_all(f.paths.mailbox_passwords.parent().unwrap()).unwrap();
        fs::write(&f.paths.mailbox_passwords, "{\"version\":1,\"records\":{}}").unwrap();
        let mut lock = f.paths.mailbox_passwords.clone().into_os_string();
        lock.push(".lock");
        fs::create_dir_all(PathBuf::from(lock)).unwrap();

        let error = f
            .users()
            .password(&json!({ "id": "alice", "password": "Battery-Staple-7" }))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot persist mailbox password record"),
            "实际: {error}"
        );
        assert!(
            !f.runner.programs().iter().any(|p| p.ends_with("chpasswd")),
            "写入失败必须发生在改系统口令之前"
        );
        assert_eq!(f.epoch_of("alice"), None);
    }

    #[test]
    fn a_failed_system_password_change_restores_the_previous_imap_record() {
        let f = Fixture::new("imaprecordrollback");
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
        f.runner.push_status("/usr/sbin/chpasswd", 1);

        let error = f
            .users()
            .password(&json!({ "id": "alice", "password": "Battery-Staple-7" }))
            .unwrap_err();

        assert!(
            error.to_string().contains("password change failed"),
            "{error}"
        );
        let record = MailboxPasswords::at(&f.paths)
            .get("alice@example.com")
            .unwrap()
            .expect("旧记录必须还在");
        assert!(
            mailstack_core::password::verify_password(&record, GOOD_PASSWORD),
            "失败路径必须把协议面记录还原成旧口令，不能留下「协议面新、系统旧」的半成功"
        );
        assert!(!mailstack_core::password::verify_password(
            &record,
            "Battery-Staple-7"
        ));
        assert_eq!(
            f.epoch_of("alice"),
            None,
            "没有任何一边改成功，不得 bump epoch"
        );
    }

    #[test]
    fn a_rolled_back_add_leaves_no_imap_password_record() {
        let f = Fixture::new("imaprecordrollbackadd");
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
            "{error}"
        );
        assert!(
            MailboxPasswords::at(&f.paths)
                .get("alice@example.com")
                .unwrap()
                .is_none(),
            "回滚必须删掉刚写的口令记录，否则留下一个删不掉的僵尸凭据"
        );
    }

    #[test]
    fn a_corrupt_session_epoch_table_is_reported_instead_of_overwritten() {
        let f = Fixture::new("epochcorrupt");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        fs::create_dir_all(f.paths.webmail_session_epoch.parent().unwrap()).unwrap();
        fs::write(&f.paths.webmail_session_epoch, "{not-json").unwrap();

        let error = f
            .users()
            .status(&json!({ "id": "alice", "enabled": true }))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("webmail sessions could not be invalidated"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(&f.paths.webmail_session_epoch).unwrap(),
            "{not-json",
            "损坏的 epoch 表不得被整表覆盖（那会抹掉其他用户的水位）"
        );
    }

    #[test]
    fn bumping_one_user_preserves_other_session_watermarks() {
        let f = Fixture::new("epochmerge");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        fs::create_dir_all(f.paths.webmail_session_epoch.parent().unwrap()).unwrap();
        fs::write(&f.paths.webmail_session_epoch, "{\"bob\": 123}").unwrap();

        f.users()
            .status(&json!({ "id": "alice", "enabled": true }))
            .unwrap();

        let text = fs::read_to_string(&f.paths.webmail_session_epoch).unwrap();
        let table: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(table["bob"], 123, "其他用户的水位不得丢失：{text}");
        assert_eq!(table["alice"], NOW);
    }

    #[test]
    fn status_requires_an_explicit_enabled_flag_instead_of_locking_by_default() {
        let f = Fixture::new("statusmissing");
        f.write_managed_users(&["alice"]);
        f.add_passwd("alice", 1001, &f.home);
        let users = f.users();

        let error = users.status(&json!({ "id": "alice" })).unwrap_err();
        assert_eq!(
            error.to_string(),
            "missing required field (enabled or active)"
        );
        assert!(f.runner.calls().is_empty(), "缺字段时不得调用 passwd");

        let error = users
            .status(&json!({ "id": "alice", "active": "true" }))
            .unwrap_err();
        assert!(error.to_string().contains("must be a boolean"), "{error}");
        assert!(f.runner.calls().is_empty(), "类型错误时不得调用 passwd");
    }

    #[test]
    fn a_missing_chpasswd_fails_closed_instead_of_using_interactive_passwd() {
        let f = Fixture::new("nochpasswd");
        f.write_managed_users(&["alice"]);
        let users = Users::new(
            f.paths.clone(),
            UsersEnv {
                passwd_root: f.passwd_root.clone(),
                session_epoch_owner: None,
                programs: Arc::new(FakePrograms::listing(&[("useradd", "/usr/sbin/useradd")])),
            },
            f.runner.clone(),
            Arc::new(|| NOW),
        );

        let error = users
            .password(&json!({ "id": "alice", "password": GOOD_PASSWORD }))
            .unwrap_err();

        assert!(
            error.to_string().contains("chpasswd is not available"),
            "{error}"
        );
        assert!(
            !f.runner.programs().iter().any(|p| p.ends_with("passwd")),
            "不得退回交互式 passwd（会等 /dev/tty，而 run_with_input 没有超时）"
        );
    }

    #[test]
    fn a_corrupt_mailbox_registry_fails_add_before_any_side_effect() {
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
        let f = Fixture::new("addrollback");
        f.add_passwd("alice", 1001, &f.home);

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
        let f = Fixture::new("shadowlocks");
        f.write_mailboxes(&[("alice@example.com", "alice"), ("bob@example.com", "bob")]);
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
        let f = Fixture::new("shadowfallback");
        f.write_mailboxes(&[("alice@example.com", "alice")]);
        f.add_passwd("alice", 1001, &f.home);

        let listed = f.users().list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["status"], "enabled");

        assert!(
            f.runner
                .calls()
                .iter()
                .any(|call| call.program == "passwd" && call.args == vec!["-S", "alice"]),
            "shadow 不可用时应逐行回退到 passwd -S"
        );
    }
}
