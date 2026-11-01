//! 动作处理器注册表。
//!
//! 本模块只承载**已经在 Phase 1 落地**的动作实现；其余动作在注册表里显式登记为
//! 「未实现」，并返回结构化错误，而不是静默返回空数据。
//!
//! 这个区分很重要：一个静默返回 `{}` 的 `domains.list` 会被界面渲染成
//! 「没有域名」，而真相是「该动作尚未移植」——前者是数据错误，后者是事实。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use mailstack_core::paths::Paths;
use serde_json::{json, Value};

/// 处理器签名：接收 `data` 载荷，返回 JSON 结果或错误消息。
pub type Handler = Arc<dyn Fn(&Value) -> Result<Value, HandlerError> + Send + Sync>;

/// 异步处理器签名（出站探测、DNS 查询这类必须 `await` 的动作）。
pub type AsyncHandler = Arc<
    dyn Fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send>>
        + Send
        + Sync,
>;

/// 处理器错误。
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct HandlerError(pub String);

impl HandlerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// 处理器注册表里的一项。
///
/// 两种形态放在**同一张表**里而不是分成两张：分表意味着「某动作属于哪张表」
/// 需要由第二处逻辑判定，两处一旦漂移，动作就会静默落到 `NOT_IMPLEMENTED`。
enum Entry {
    Sync(Handler),
    Async(AsyncHandler),
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Entry::Sync(_) => f.write_str("Entry::Sync"),
            Entry::Async(_) => f.write_str("Entry::Async"),
        }
    }
}

/// 动作注册表。
pub struct Registry {
    handlers: HashMap<&'static str, Entry>,
    paths: Paths,
}

impl Registry {
    /// 新建注册表。**不**注册任何业务动作——由 [`Registry::with_core_actions`] 装配。
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            paths: Paths::production(),
        }
    }

    /// 装配内置动作：只读面 + 已经落地的写面。
    ///
    /// 尚未移植的动作**不注册**，由 [`Registry::dispatch`] 回 `NOT_IMPLEMENTED` ——
    /// 显式失败好过静默返回空数据（一个空的 `domains.list` 会被界面渲染成
    /// 「没有域名」，而真相是「该动作还没实现」）。
    pub fn with_core_actions(paths: Paths) -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
            paths: paths.clone(),
        };

        // ── 配置读取类：纯本地、无副作用 ──
        let p = paths.clone();
        registry.register("settings.get", move |_data| {
            Ok(serde_json::to_value(
                mailstack_core::config::read_settings(&p),
            )?)
        });

        let p = paths.clone();
        registry.register("admin.get", move |_data| {
            // INV-1：绝不返回 secret 字段。
            Ok(serde_json::to_value(mailstack_core::config::admin_public(
                &p,
            ))?)
        });

        let p = paths.clone();
        registry.register("setup.status", move |_data| {
            setup_status_json(&p)
        });

        // 向导收尾：置位 `setup.json` 的 `wizardCompleted` 并回同一份状态形状。
        // 幂等（重复调用是成功的空操作）；身份未配置时由 core 侧拒绝 ——
        // 「完成的向导」必须长在真实身份之上。
        let p = paths.clone();
        registry.register("setup.wizard.complete", move |_data| {
            mailstack_core::config::mark_setup_wizard_complete(&p)?;
            setup_status_json(&p)
        });

        let p = paths.clone();
        registry.register("ai.config.get", move |_data| {
            // 与 `ai.config.set` 返回**同一份**公开配置（`crate::ai::ai_public_config`）。
            Ok(crate::ai::ai_public_config(
                &p,
                crate::ai::private_network_enabled(),
            ))
        });

        // ── 2FA（§5.5）：secret 的信封与恢复码都只存在于助手侧 ──
        //
        // 全部经 RW 通道下发：begin/enable/disable 写信封，verify 在恢复码路径上
        // 会重新封装 admin.json（有写副作用），consume_recovery 直接消费恢复码。
        let p = paths.clone();
        registry.register("admin.totp.begin", move |_data| {
            let account = mailstack_core::config::read_admin_config(&p)
                .map(|c| c.username)
                .unwrap_or_default();
            let enrollment = mailstack_core::totp::begin(&p, &account)?;
            Ok(json!({
                "ok": true,
                "secret": enrollment.secret,
                "otpauthUrl": enrollment.otpauth_url,
                "issuer": enrollment.issuer,
                "account": enrollment.account,
                "algorithm": "SHA1",
                "digits": mailstack_core::totp::TOTP_DIGITS,
                "period": mailstack_core::totp::TOTP_PERIOD_SECS,
            }))
        });

        let p = paths.clone();
        registry.register("admin.totp.enable", move |data| {
            let code = required_str(data, "code")?;
            let codes = mailstack_core::totp::enable(&p, code, mailstack_core::totp::now_unix())?;
            Ok(json!({ "ok": true, "recoveryCodes": codes }))
        });

        // 拆 2FA 必须过第二因子，且与登录走**同一条** `verify` 路径 ——
        // 顺带继承动态码的重放记账与恢复码的一次性消费。
        //
        // 错误文案与基线 `totp_disable` 逐字一致（"invalid TOTP or recovery code"），
        // 前端已有的「验证码不正确」提示因此不需要分支；更重要的是它**不区分**
        // 「码不对」与「这个码曾经有效过」—— 那种区分会把 6 位空间的搜索效率
        // 提高一个量级。只有 `Invalid`（判定不通过）才这么报，IO/JSON 故障按原样
        // 上抛：把「磁盘写失败」说成「验证码错误」会让运维查错方向。
        let p = paths.clone();
        registry.register("admin.totp.disable", move |data| {
            // **刻意容忍缺失的 code**：`disable` 在「2FA 本就没启用」时不要求码
            // （没有第二个因子可交，见 core 侧说明），若在这里因为字段缺失就
            // 报错，会把一个本该成功的幂等调用变成失败。
            let code = ["code", "verificationCode"]
                .iter()
                .find_map(|key| optional_str(data, key))
                .unwrap_or("");
            let was_enabled =
                mailstack_core::totp::disable(&p, code, mailstack_core::totp::now_unix()).map_err(
                    |e| {
                        if e.is_client_error() {
                            HandlerError::new("invalid TOTP or recovery code")
                        } else {
                            HandlerError::from(e)
                        }
                    },
                )?;
            Ok(json!({ "ok": true, "wasEnabled": was_enabled }))
        });

        let p = paths.clone();
        registry.register("admin.totp.consume_recovery", move |data| {
            let code = required_str(data, "code")?;
            let consumed = mailstack_core::totp::consume_recovery(&p, code)?;
            Ok(json!({ "ok": true, "consumed": consumed }))
        });

        // 登录路径依赖它。**「码不对」是结论（valid: false）而不是错误** ——
        // 若在这里抛错，登录侧会把「口令或验证码错」误报成 503 基础设施故障。
        let p = paths.clone();
        registry.register("admin.totp.verify", move |data| {
            let code = required_str(data, "code")?;
            let outcome = mailstack_core::totp::verify(&p, code, mailstack_core::totp::now_unix())?;
            Ok(json!({
                "valid": outcome.valid,
                "method": outcome.method.map(|m| m.as_str()),
            }))
        });

        // ── 表文件读取类 ──
        let p = paths.clone();
        registry.register("domains.list", move |_data| {
            Ok(json!({ "domains": read_domain_table(&p)? }))
        });

        // ── 管理员凭证（§5.4；INV-30） ──
        //
        // 改名与改密都走同一个入口；`admin_set` 内部保证**既有 2FA 块不被覆盖** ——
        // 旧实现曾让每次普通改密静默关闭 2FA。
        let p = paths.clone();
        registry.register("admin.set", move |data| {
            let current = mailstack_core::config::read_admin_config(&p);
            let username = optional_str(data, "username")
                .map(str::to_string)
                .or_else(|| current.as_ref().map(|c| c.username.clone()))
                .unwrap_or_else(|| "admin".to_string());
            // 空口令 = 「只改名」这一既有语义，必须原样保留。
            let password = optional_str(data, "password").unwrap_or("");
            let public = mailstack_core::config::admin_set(&p, &username, password)?;
            Ok(serde_json::to_value(public)?)
        });

        // ── 设置写入（INV-43） ──
        //
        // 白名单之外的键**丢弃**（不是报错）：契约是「不得演变成任意键写入」，
        // 而报错会让带额外字段的旧客户端整体失败。
        let p = paths.clone();
        registry.register("settings.set", move |data| {
            let patch = data
                .as_object()
                .ok_or_else(|| HandlerError::new("settings patch must be a JSON object"))?;
            let mut settings = mailstack_core::config::read_settings(&p);
            let applied = mailstack_core::config::apply_settings_patch(&mut settings, patch);
            mailstack_core::config::write_settings(&p, &settings)?;
            Ok(json!({ "ok": true, "applied": applied, "settings": settings }))
        });

        // ── 域名表（§2.5） ──
        //
        // 写表 → `postmap` 编译 hash → 重载，序列与基线逐条一致（见 `TableStore`）。
        let p = paths.clone();
        registry.register("domains.add", move |data| {
            let name = first_str(data, &["name", "domain"])?;
            let domains = mailstack_store::TableStore::new(p.clone()).add_domain(name)?;
            Ok(json!({ "ok": true, "domains": domains }))
        });

        let p = paths.clone();
        registry.register("domains.delete", move |data| {
            // 路由契约里这条是 `DELETE /api/domains/:id`，路径参数名为 `id`；
            // 兼容性与列表元素同名的 `name`（同一语义的两种来源）。
            let name = first_str(data, &["id", "name", "domain"])?;
            let domains = mailstack_store::TableStore::new(p.clone()).delete_domain(name)?;
            Ok(json!({ "ok": true, "domains": domains }))
        });

        // ── 别名表（§2.5） ──
        let p = paths.clone();
        registry.register("aliases.add", move |data| {
            let source = first_str(data, &["source", "id", "alias"])?;
            let destinations = alias_destinations(data)?;
            let aliases =
                mailstack_store::TableStore::new(p.clone()).add_alias(source, &destinations)?;
            Ok(json!({ "ok": true, "aliases": aliases }))
        });

        let p = paths.clone();
        registry.register("aliases.delete", move |data| {
            let source = first_str(data, &["id", "source", "alias"])?;
            let aliases = mailstack_store::TableStore::new(p.clone()).delete_alias(source)?;
            Ok(json!({ "ok": true, "aliases": aliases }))
        });

        // ── DKIM 轮换（§5.8；替代 opendkim-genkey） ──
        //
        // 落在助手侧是刻意的：私钥必须以 `0640 root:opendkim` 落盘，Web 进程做不到。
        let p = paths.clone();
        registry.register("dkim.rotate", move |data| {
            let domain = first_str(data, &["domain", "name"])?;
            let selector = optional_str(data, "selector");
            let rotation = mailstack_auth::keys::rotate(&p, domain, selector)?;
            Ok(json!({
                "ok": true,
                "status": rotation.status,
                "domain": rotation.domain,
                "selector": rotation.selector,
                "record": rotation.record,
            }))
        });

        registry
    }

    /// 在 [`Registry::with_core_actions`] 之上再装配只读聚合面
    /// （`snapshot` / `logs.list` / `metrics.realtime` / `certs.list` /
    /// `network.check_port` / `system.doctor`）。
    ///
    /// 单独一个入口是为了让测试能注入替身运行器、假 `/proc` 与固定时钟 ——
    /// 那些动作默认会去读真实 `/proc`、跑真实 `journalctl`。
    pub fn with_readers(mut self, readers: std::sync::Arc<crate::readers::Readers>) -> Self {
        crate::readers::register(&mut self, readers);
        self
    }

    /// 注册一个同步处理器。
    pub fn register(
        &mut self,
        action: &'static str,
        handler: impl Fn(&Value) -> Result<Value, HandlerError> + Send + Sync + 'static,
    ) {
        self.handlers.insert(action, Entry::Sync(Arc::new(handler)));
    }

    /// 注册一个需要 `await` 的处理器。
    pub fn register_async(
        &mut self,
        action: &'static str,
        handler: impl Fn(&Value) -> Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send>>
            + Send
            + Sync
            + 'static,
    ) {
        self.handlers
            .insert(action, Entry::Async(Arc::new(handler)));
    }

    /// 该动作是否已实现。
    pub fn is_implemented(&self, action: &str) -> bool {
        self.handlers.contains_key(action)
    }

    /// 已实现的动作清单（供契约与测试比对）。
    pub fn implemented_actions(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.handlers.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// 分派动作。
    ///
    /// 注意：**白名单与通道判定不在这里**——那由 [`crate::dispatch::ActionGate`]
    /// 在调用本方法之前完成。本方法只负责「已放行的动作如何执行」。
    ///
    /// 同步处理器**绝不内联执行**：`backup.create/restore`、`certs.renew`
    /// （acme.sh 子进程可达 300s）、`users.*`（fork/exec）、`metrics.system`
    /// （内部 sleep）都会把调用方所在的 tokio worker 钉死。这里统一挪进
    /// blocking 线程池 —— `Handler` 是 `Send + Sync + 'static`，clone Arc 并
    /// clone 载荷后整体 move 进闭包即可。
    pub async fn dispatch(&self, action: &str, data: &Value) -> Result<Value, HandlerError> {
        match self.handlers.get(action) {
            Some(Entry::Sync(handler)) => {
                let handler = Arc::clone(handler);
                let payload = data.clone();
                match tokio::task::spawn_blocking(move || handler(&payload)).await {
                    Ok(result) => result,
                    Err(error) => Err(HandlerError::new(format!(
                        "privileged handler task for {action} failed: {error}"
                    ))),
                }
            }
            Some(Entry::Async(handler)) => handler(data).await,
            None => Err(HandlerError::new(format!(
                "NOT_IMPLEMENTED: action {action} is registered in the allowlist but has no Rust implementation yet"
            ))),
        }
    }
}

#[cfg(test)]
impl Registry {
    /// 测试用的同步分派。
    ///
    /// 生产的 `dispatch` 是 `async`（出站探测等动作必须 await）。单元测试大量断言的是
    /// **同步**动作，为它们逐个套上 `#[tokio::test]` 只会增加噪音；这里用一个一次性
    /// 的单线程运行时把同一份 `dispatch` 跑起来 —— 走的是同一条代码路径，
    /// 不是另写一个「测试专用分支」。
    fn dispatch_blocking(&self, action: &str, data: &Value) -> Result<Value, HandlerError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("测试运行时")
            .block_on(self.dispatch(action, data))
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl From<serde_json::Error> for HandlerError {
    fn from(e: serde_json::Error) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_core::CoreError> for HandlerError {
    fn from(e: mailstack_core::CoreError) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_store::StoreError> for HandlerError {
    fn from(e: mailstack_store::StoreError) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_auth::AuthError> for HandlerError {
    fn from(e: mailstack_auth::AuthError) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_queue::QueueError> for HandlerError {
    fn from(e: mailstack_queue::QueueError) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_core::backup::BackupError> for HandlerError {
    fn from(e: mailstack_core::backup::BackupError) -> Self {
        HandlerError::new(e.to_string())
    }
}

impl From<mailstack_smtp::SmtpError> for HandlerError {
    fn from(e: mailstack_smtp::SmtpError) -> Self {
        HandlerError::new(e.to_string())
    }
}

/// `setup.status` 的响应体；`setup.wizard.complete` 回**同一份**形状。
///
/// `completed` 是向导是否真正走完（`setup.json` 的 `wizardCompleted`，旧文件
/// 回落 `false`）—— 与 `identityConfigured`（第一步完成即为真）刻意区分：
/// 界面靠它判断「向导弃了一半」还是「已经收尾」。
fn setup_status_json(paths: &Paths) -> Result<Value, HandlerError> {
    let setup = mailstack_core::config::read_setup_config(paths);
    let completed = setup
        .as_ref()
        .map(|config| config.wizard_completed)
        .unwrap_or(false);
    let admin = mailstack_core::config::admin_public(paths);
    Ok(json!({
        "identityConfigured": setup.is_some(),
        "identity": setup,
        "passwordConfigured": admin.password_configured,
        "twoFactorEnabled": admin.two_factor_enabled,
        "completed": completed,
    }))
}

/// 取一个**可选**字符串字段；存在但不是字符串时同样视为缺失。
///
/// `pub(crate)`：`readers` 里的动作处理器与这里共用同一套载荷解析规则，
/// 免得两处对「字段缺失」的处理出现分歧。
pub(crate) fn optional_str<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

/// 按候选顺序取第一个存在的字符串字段。
///
/// 契约冻结的是**路径与方法**，载荷里的字段名在基线里并不统一（域名既可能叫
/// `domain` 也可能与列表元素同名 `name`）。逐个候选取第一个命中的，
/// 好过挑一个然后让另一种调用方无声地失败。
pub(crate) fn first_str<'a>(data: &'a Value, keys: &[&str]) -> Result<&'a str, HandlerError> {
    keys.iter()
        .find_map(|key| optional_str(data, key))
        .ok_or_else(|| HandlerError::new(format!("missing required field (one of {keys:?})")))
}

/// 解析别名目标列表。
///
/// **只接受字符串或字符串数组**：基线里把目标当裸字符串逐字符迭代，导致 `"ab"`
/// 静默变成两个目标 `a`、`b`。这里单值走「一个元素的列表」，绝不逐字符展开。
fn alias_destinations(data: &Value) -> Result<Vec<String>, HandlerError> {
    if let Some(array) = data.get("destinations").and_then(Value::as_array) {
        let parsed: Vec<String> = array
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        if parsed.len() != array.len() {
            return Err(HandlerError::new(
                "every alias destination must be a string",
            ));
        }
        return Ok(parsed);
    }
    if let Some(single) = optional_str(data, "target") {
        return Ok(vec![single.to_string()]);
    }
    Err(HandlerError::new(
        "missing required field (destinations or target)",
    ))
}

/// 取一个**必填**字符串字段。
///
/// 缺失时返回错误而不是回落空串：空的验证码会被 TOTP 校验当成「形状不对」而
/// 静默拒绝，调用方拿到的是一个说不清原因的失败。
fn required_str<'a>(data: &'a Value, key: &str) -> Result<&'a str, HandlerError> {
    data.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| HandlerError::new(format!("missing required field `{key}`")))
}

/// 读取域名表，返回结构化数组。
///
/// 表文件格式沿用 postfix 风格：每行 `<domain> <target>`，`#` 为注释。
/// 跳过空行与注释由 [`mailstack_core::atomic::try_rows`] 保证。
///
/// 5.13：用 `try_rows` 而不是 `rows` —— 读失败（EACCES / IO 错 / 坏 UTF-8）
/// 必须作为错误上报，否则「读不到」会被说成「一个域名都没有」，
/// 管理员会以为域名全丢了。
fn read_domain_table(paths: &Paths) -> Result<Vec<Value>, HandlerError> {
    Ok(mailstack_core::atomic::try_rows(&paths.domains)
        .map_err(|error| HandlerError::new(format!("domain table is unreadable: {error}")))?
        .into_iter()
        .filter_map(|row| {
            let name = row.first()?.clone();
            let target = row.get(1).cloned().unwrap_or_default();
            Some(json!({ "name": name, "target": target }))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        root: std::path::PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-reg-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let paths = Paths::rooted(&root);
            Self { root, paths }
        }

        fn registry(&self) -> Registry {
            Registry::with_core_actions(self.paths.clone())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn empty_registry_reports_actions_as_not_implemented() {
        let registry = Registry::new();
        let err = registry
            .dispatch_blocking("domains.list", &json!({}))
            .unwrap_err();
        assert!(
            err.to_string().starts_with("NOT_IMPLEMENTED"),
            "实际: {err}"
        );
    }

    #[test]
    fn core_registry_implements_the_phase_one_read_only_actions() {
        let f = Fixture::new("core");
        let registry = f.registry();
        for action in [
            "settings.get",
            "admin.get",
            "setup.status",
            "ai.config.get",
            "domains.list",
        ] {
            assert!(registry.is_implemented(action), "{action} 应已实现");
        }
    }

    #[test]
    fn admin_get_never_leaks_secret_material() {
        let f = Fixture::new("adminsecret");
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        let registry = f.registry();
        let out = registry.dispatch_blocking("admin.get", &json!({})).unwrap();
        let text = serde_json::to_string(&out).unwrap();

        assert!(!text.contains("salt"), "不得暴露 salt: {text}");
        assert!(!text.contains("hash"), "不得暴露 hash: {text}");
        assert!(!text.contains("Tr0ubadour9x"), "不得暴露口令: {text}");
        assert_eq!(out["username"], "admin");
        assert_eq!(out["passwordConfigured"], true);
    }

    #[test]
    fn settings_get_returns_defaults_when_unconfigured() {
        let f = Fixture::new("settingsdefault");
        let registry = f.registry();
        let out = registry
            .dispatch_blocking("settings.get", &json!({}))
            .unwrap();
        assert_eq!(out["transparency"], 70);
        assert_eq!(out["relayConcurrency"], 20);
        assert_eq!(out["colorTheme"], "blue");
    }

    #[test]
    fn domains_list_reads_the_table_and_skips_comments() {
        let f = Fixture::new("domains");
        fs::create_dir_all(&f.paths.postfix).unwrap();
        fs::write(
            &f.paths.domains,
            "# managed domains\nexample.com\tok\n   \nfoo.test ok\n",
        )
        .unwrap();

        let registry = f.registry();
        let out = registry
            .dispatch_blocking("domains.list", &json!({}))
            .unwrap();
        let domains = out["domains"].as_array().unwrap();
        assert_eq!(domains.len(), 2, "注释与空行必须被跳过");
        assert_eq!(domains[0]["name"], "example.com");
        assert_eq!(domains[1]["name"], "foo.test");
    }

    #[test]
    fn domains_list_on_missing_table_is_empty_not_error() {
        let f = Fixture::new("domainmissing");
        let registry = f.registry();
        let out = registry
            .dispatch_blocking("domains.list", &json!({}))
            .unwrap();
        assert_eq!(out["domains"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn ai_config_get_never_leaks_api_key() {
        let f = Fixture::new("aikey");
        fs::create_dir_all(&f.paths.etc).unwrap();
        fs::write(
            &f.paths.ai_config,
            r#"{
                "provider": "deepseek",
                "baseUrl": "https://api.deepseek.com",
                "model": "deepseek-chat",
                "apiKey": "sk-super-secret-value"
            }"#,
        )
        .unwrap();

        let registry = f.registry();
        let out = registry
            .dispatch_blocking("ai.config.get", &json!({}))
            .unwrap();
        let text = serde_json::to_string(&out).unwrap();

        assert!(
            !text.contains("sk-super-secret-value"),
            "apiKey 绝不得透传: {text}"
        );
        assert!(!text.contains("apiKey"));
        assert_eq!(out["provider"], "deepseek");
        assert_eq!(out["configured"], true);
    }

    #[test]
    fn ai_config_get_reports_unconfigured_when_file_missing() {
        let f = Fixture::new("aimissing");
        let registry = f.registry();
        let out = registry
            .dispatch_blocking("ai.config.get", &json!({}))
            .unwrap();
        assert_eq!(out["configured"], false);
    }

    #[test]
    fn ai_config_get_survives_corrupt_file() {
        let f = Fixture::new("aicorrupt");
        fs::create_dir_all(&f.paths.etc).unwrap();
        fs::write(&f.paths.ai_config, "{not json").unwrap();
        let registry = f.registry();
        let out = registry
            .dispatch_blocking("ai.config.get", &json!({}))
            .unwrap();
        assert_eq!(out["configured"], false);
    }

    #[test]
    fn setup_status_reflects_configured_identity() {
        let f = Fixture::new("setupstatus");
        let config = mailstack_core::config::SetupConfig {
            domain: "example.com".into(),
            mail_host: "mail.example.com".into(),
            server_ip: "203.0.113.10".into(),
            dkim_selector: "mail".into(),
            expected_spf: None,
            wizard_completed: false,
            updated_at: mailstack_core::now_iso8601_utc(),
        };
        mailstack_core::config::write_setup_config(&f.paths, &config).unwrap();

        let registry = f.registry();
        let out = registry
            .dispatch_blocking("setup.status", &json!({}))
            .unwrap();
        assert_eq!(out["identityConfigured"], true);
        assert_eq!(out["identity"]["domain"], "example.com");
        assert_eq!(
            out["completed"], false,
            "向导未收尾时 completed 必须是 false（identityConfigured 仍为真）"
        );
    }

    #[test]
    fn setup_wizard_complete_marks_the_flag_and_reports_the_status_shape() {
        let f = Fixture::new("wizardcomplete");
        mailstack_core::config::write_setup_config(
            &f.paths,
            &mailstack_core::config::SetupConfig {
                domain: "example.com".into(),
                mail_host: "mail.example.com".into(),
                server_ip: "203.0.113.10".into(),
                dkim_selector: "mail".into(),
                expected_spf: None,
                wizard_completed: false,
                updated_at: mailstack_core::now_iso8601_utc(),
            },
        )
        .unwrap();
        let registry = f.registry();

        // 完成前：identityConfigured 为真、completed 为假 —— 界面据此知道向导弃了一半。
        let before = registry
            .dispatch_blocking("setup.status", &json!({}))
            .unwrap();
        assert_eq!(before["identityConfigured"], true);
        assert_eq!(before["completed"], false);

        let out = registry
            .dispatch_blocking("setup.wizard.complete", &json!({}))
            .unwrap();
        assert_eq!(out["completed"], true);
        assert_eq!(out["identityConfigured"], true);
        assert_eq!(
            out["identity"]["domain"], "example.com",
            "响应必须是完整的 status 形状"
        );
        assert_eq!(out["passwordConfigured"], false);

        // 磁盘上真的置位了。
        assert!(
            mailstack_core::config::read_setup_config(&f.paths)
                .unwrap()
                .wizard_completed
        );

        // 幂等：重复完成仍是成功，completed 保持真。
        let again = registry
            .dispatch_blocking("setup.wizard.complete", &json!({}))
            .unwrap();
        assert_eq!(again["completed"], true);
    }

    #[test]
    fn setup_wizard_complete_is_refused_without_an_identity() {
        let f = Fixture::new("wizardnoid");
        let registry = f.registry();
        let err = registry
            .dispatch_blocking("setup.wizard.complete", &json!({}))
            .unwrap_err();
        assert!(
            err.to_string().contains("not configured"),
            "身份未配置必须拒绝：{err}"
        );
        // 状态里 completed 维持 false（没有 identity 也就没有 completed 可言）。
        let status = registry
            .dispatch_blocking("setup.status", &json!({}))
            .unwrap();
        assert_eq!(status["identityConfigured"], false);
        assert_eq!(status["completed"], false);
    }

    // ── 2FA 动作（§5.5） ──

    /// 2FA 只能长在已有管理员凭证之上，故这些用例需要先落一份 `admin.json`。
    fn with_admin(tag: &str) -> Fixture {
        let f = Fixture::new(tag);
        mailstack_core::config::admin_set(&f.paths, "admin", "Tr0ubadour9x").unwrap();
        f
    }

    /// 从 `admin.json` 里解出当前 secret —— 只有测试能这么做：
    /// 助手的对外接口从不提供「读回 secret」的动作。
    fn decrypt_current_secret(f: &Fixture) -> Vec<u8> {
        let config: Value =
            serde_json::from_str(&std::fs::read_to_string(&f.paths.admin_config).unwrap()).unwrap();
        let block = &config["totp"];
        let envelope = mailstack_core::totp::Envelope {
            enc: block["enc"].as_str().unwrap().to_string(),
            nonce: block["nonce"].as_str().unwrap().to_string(),
            tag: block["tag"].as_str().unwrap().to_string(),
        };
        let key = mailstack_core::totp::load_master_key(&f.paths).unwrap();
        mailstack_core::totp::open(&key, &envelope).unwrap()
    }

    #[test]
    fn totp_actions_are_all_registered() {
        let f = with_admin("totpactions");
        let registry = f.registry();
        for action in [
            "admin.totp.begin",
            "admin.totp.enable",
            "admin.totp.disable",
            "admin.totp.verify",
            "admin.totp.consume_recovery",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[test]
    fn totp_begin_returns_everything_the_enrolment_ui_needs() {
        let f = with_admin("totpbegin");
        let registry = f.registry();
        let out = registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();

        assert_eq!(out["ok"], true);
        assert_eq!(out["issuer"], "MailStack");
        assert_eq!(out["account"], "admin", "账号名取自配置，不得由请求体指定");
        assert_eq!(out["digits"], 6);
        assert_eq!(out["period"], 30);
        assert_eq!(out["algorithm"], "SHA1");
        let secret = out["secret"].as_str().unwrap();
        assert!(
            !secret.is_empty() && secret.len() % 8 == 0,
            "base32: {secret}"
        );
        assert!(out["otpauthUrl"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/MailStack:admin?"));

        // INV-5：磁盘上只留信封。
        let raw = std::fs::read_to_string(&f.paths.admin_config).unwrap();
        assert!(!raw.contains(secret), "明文 secret 不得落盘");
    }

    #[test]
    fn totp_enable_then_verify_round_trips_through_the_registry() {
        let f = with_admin("totpenable");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();

        let out = registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();
        let codes = out["recoveryCodes"].as_array().unwrap();
        assert_eq!(codes.len(), mailstack_core::totp::RECOVERY_CODE_COUNT);

        let ok = registry
            .dispatch_blocking(
                "admin.totp.verify",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();
        assert_eq!(ok["valid"], true);
        assert_eq!(ok["method"], "totp");

        let backup = registry
            .dispatch_blocking(
                "admin.totp.verify",
                &json!({ "code": codes[0].as_str().unwrap() }),
            )
            .unwrap();
        assert_eq!(backup["valid"], true);
        assert_eq!(backup["method"], "recovery");
    }

    #[test]
    fn totp_verify_reports_a_wrong_code_as_a_conclusion_not_an_error() {
        // 登录侧依赖这条：若这里返回 Err，Web 会把「验证码错」报成 503。
        let f = with_admin("totpwrong");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();
        registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();

        let bad = registry
            .dispatch_blocking("admin.totp.verify", &json!({ "code": "000000" }))
            .unwrap();
        assert_eq!(bad["valid"], false, "错码必须是结论而不是错误");
        assert!(bad["method"].is_null());

        // 而**缺失** code 字段是真错误：调用方写错了请求。
        let missing = registry
            .dispatch_blocking("admin.totp.verify", &json!({}))
            .unwrap_err();
        assert!(missing
            .to_string()
            .contains("missing required field `code`"));
    }

    // ── 写面（Phase 4） ──

    #[test]
    fn totp_disable_clears_the_block() {
        let f = with_admin("totpdisable");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();
        registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();

        // `enable` 本身不记重放账（见 core 的说明），所以这里用 enable 时的
        // 那个码即可关掉 2FA。
        let out = registry
            .dispatch_blocking(
                "admin.totp.disable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();
        assert_eq!(out["wasEnabled"], true);

        let public = registry.dispatch_blocking("admin.get", &json!({})).unwrap();
        assert_eq!(public["twoFactorEnabled"], false);
        assert_eq!(public["recoveryCodesRemaining"], 0);
    }

    #[test]
    fn totp_disable_refuses_without_a_valid_second_factor() {
        // 反例守卫：拆 2FA 曾是零验证动作 —— 拿到会话的攻击者可以直接静默
        // 拆掉 2FA。这条断言把「必须带码」钉在助手的对外行为上。
        let f = with_admin("totpdisableauth");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();
        registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();

        for bad in [
            json!({}),
            json!({ "code": "" }),
            json!({ "code": "000000" }),
            json!({ "code": "nope" }),
            json!({ "code": "already-spent" }),
        ] {
            let err = registry
                .dispatch_blocking("admin.totp.disable", &bad)
                .unwrap_err();
            assert!(
                err.to_string().contains("invalid TOTP or recovery code"),
                "{bad:?} 实际: {err}"
            );
        }

        // 拒绝必须**没有副作用**：2FA 块还在，恢复码一张没少。
        let public = registry.dispatch_blocking("admin.get", &json!({})).unwrap();
        assert_eq!(
            public["twoFactorEnabled"], true,
            "失败的 disable 不得拆掉 2FA"
        );
        assert_eq!(
            public["recoveryCodesRemaining"],
            mailstack_core::totp::RECOVERY_CODE_COUNT,
            "失败的 disable 不得消耗恢复码"
        );
    }

    #[test]
    fn totp_disable_accepts_an_unused_recovery_code() {
        // 与基线一致：关 2FA 也接受一张**未用过**的恢复码，且用掉它。
        let f = with_admin("totpdisablerecovery");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();
        let enabled = registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();
        let code = enabled["recoveryCodes"][0].as_str().unwrap().to_string();

        let out = registry
            .dispatch_blocking("admin.totp.disable", &json!({ "code": &code }))
            .unwrap();
        assert_eq!(out["wasEnabled"], true);
        assert_eq!(
            registry.dispatch_blocking("admin.get", &json!({})).unwrap()["twoFactorEnabled"],
            false
        );

        // 整块已被移除，所以这张码也不再是任何凭据。
        let again = registry
            .dispatch_blocking("admin.totp.disable", &json!({ "code": &code }))
            .unwrap();
        assert_eq!(again["wasEnabled"], false, "重复 disable 幂等且不假装成功");
    }

    #[test]
    fn write_actions_are_registered() {
        let f = Fixture::new("writeactions");
        let registry = f.registry();
        for action in [
            "admin.set",
            "settings.set",
            "domains.add",
            "domains.delete",
            "aliases.add",
            "aliases.delete",
            "dkim.rotate",
            "setup.wizard.complete",
        ] {
            assert!(registry.is_implemented(action), "{action} 必须已接线");
        }
    }

    #[test]
    fn settings_set_applies_only_the_whitelisted_keys() {
        // INV-43 的对外落点。
        let f = Fixture::new("settingsset");
        let registry = f.registry();
        let out = registry
            .dispatch_blocking(
                "settings.set",
                &json!({
                    "transparency": 33,
                    "colorTheme": "green",
                    "version": "9.9.9",
                    "evilKey": true,
                }),
            )
            .unwrap();

        assert_eq!(out["settings"]["transparency"], 33);
        assert_eq!(out["settings"]["colorTheme"], "green");
        assert_eq!(
            out["settings"]["version"],
            mailstack_core::VERSION,
            "version 不在白名单内，不得被改"
        );
        let applied = out["applied"].as_array().unwrap();
        assert!(!applied.iter().any(|v| v == "version"));
        assert!(!applied.iter().any(|v| v == "evilKey"));

        // 必须真的落盘，而不只是回显。
        let on_disk = mailstack_core::config::read_settings(&f.paths);
        assert_eq!(on_disk.transparency, 33);
        assert_eq!(on_disk.color_theme, "green");
    }

    #[test]
    fn settings_set_refuses_a_patch_that_is_not_an_object() {
        let f = Fixture::new("settingsbad");
        let registry = f.registry();
        for bad in [json!([1, 2, 3]), json!("nope"), json!(null)] {
            assert!(
                registry.dispatch_blocking("settings.set", &bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn domain_and_alias_writes_round_trip_through_the_registry() {
        let f = Fixture::new("tables");
        let registry = f.registry();

        registry
            .dispatch_blocking("domains.add", &json!({ "name": "example.com" }))
            .unwrap();
        registry
            .dispatch_blocking(
                "aliases.add",
                &json!({
                    "source": "team@example.com",
                    "destinations": ["a@example.com", "b@example.com"],
                }),
            )
            .unwrap();

        let listed = registry
            .dispatch_blocking("domains.list", &json!({}))
            .unwrap();
        assert!(listed["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["name"] == "example.com"));

        // 删域名必须连带清掉该域下的别名，否则会留下指向已删除域的孤儿路由。
        registry
            .dispatch_blocking("domains.delete", &json!({ "id": "example.com" }))
            .unwrap();
        let aliases = std::fs::read_to_string(&f.paths.aliases).unwrap_or_default();
        assert!(
            !aliases.contains("team@example.com"),
            "孤儿别名必须被一并删除: {aliases}"
        );
    }

    #[test]
    fn a_single_string_destination_is_never_expanded_into_characters() {
        // 基线里把裸字符串逐字符迭代，`"xy"` 会静默变成两个目标 `x`、`y`。
        let f = Fixture::new("aliaschars");
        let registry = f.registry();
        registry
            .dispatch_blocking(
                "aliases.add",
                &json!({ "source": "a@example.com", "target": "xy" }),
            )
            .unwrap();

        let aliases = std::fs::read_to_string(&f.paths.aliases).unwrap();
        let row = aliases
            .lines()
            .find(|l| l.starts_with("a@example.com"))
            .unwrap_or_else(|| panic!("未写入别名行: {aliases}"));
        assert_eq!(
            row.split_whitespace().collect::<Vec<_>>(),
            vec!["a@example.com", "xy"],
            "目标必须原样保留为一项"
        );
    }

    #[test]
    fn alias_add_rejects_a_non_string_destination() {
        let f = Fixture::new("aliasbad");
        let registry = f.registry();
        let err = registry
            .dispatch_blocking(
                "aliases.add",
                &json!({ "source": "a@example.com", "destinations": ["ok@example.com", 7] }),
            )
            .unwrap_err();
        assert!(err.to_string().contains("must be a string"), "实际: {err}");
    }

    #[test]
    fn write_actions_report_missing_fields_instead_of_guessing() {
        let f = Fixture::new("missingfields");
        let registry = f.registry();
        for (action, data) in [
            ("domains.add", json!({})),
            ("domains.delete", json!({})),
            ("aliases.add", json!({ "source": "a@example.com" })),
            ("aliases.delete", json!({})),
            ("dkim.rotate", json!({})),
        ] {
            let err = registry.dispatch_blocking(action, &data).unwrap_err();
            assert!(
                err.to_string().contains("missing required field"),
                "{action} 实际: {err}"
            );
        }
    }

    #[test]
    fn dkim_rotate_validates_before_generating_anything() {
        let f = Fixture::new("dkimbad");
        let registry = f.registry();
        let err = registry
            .dispatch_blocking("dkim.rotate", &json!({ "domain": "not a domain" }))
            .unwrap_err();
        assert!(err.to_string().contains("invalid"), "实际: {err}");
        // 拒绝必须不产生任何副作用。
        assert!(!f.paths.opendkim.exists(), "校验失败不得留下密钥目录");
    }

    #[test]
    fn admin_set_preserves_two_factor_through_the_registry() {
        // INV-30 的对外落点：普通改密不得静默关掉 2FA。
        let f = with_admin("adminset");
        let registry = f.registry();
        registry
            .dispatch_blocking("admin.totp.begin", &json!({}))
            .unwrap();
        let secret = decrypt_current_secret(&f);
        let now = mailstack_core::totp::now_unix();
        registry
            .dispatch_blocking(
                "admin.totp.enable",
                &json!({ "code": mailstack_core::totp::code_at(&secret, now) }),
            )
            .unwrap();

        registry
            .dispatch_blocking("admin.set", &json!({ "password": "An0therGood1" }))
            .unwrap();

        let public = registry.dispatch_blocking("admin.get", &json!({})).unwrap();
        assert_eq!(public["twoFactorEnabled"], true);
        assert_eq!(
            public["recoveryCodesRemaining"],
            mailstack_core::totp::RECOVERY_CODE_COUNT
        );
    }
}
