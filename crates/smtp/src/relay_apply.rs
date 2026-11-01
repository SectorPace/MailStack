//! 中继配置落地（规格书 §5.9.5；INV-16、INV-20）。
//!
//! 必须保持**「先测后写、写完回读、失败回滚」**的严格顺序：
//!
//! 1. 校验参数 → 执行完整测试（**测试不通过则不落任何配置**）
//! 2. 拼装 `relayhost` 形式为 `[<host>]:<port>`（方括号语法表示不做 MX 解析）
//! 3. 原子写入凭证文件（`atomic()` + `0600`）：`<relayhost> <user>:<password>\n`
//! 4. 回滚保障：执行前保存快照；异常时恢复
//! 5. 写入各配置键、重载服务
//! 6. **回读校验**：读回 `relayhost`，与期望不符则报错
//! 7. 返回 `{ applied, relayhost: <observed>, test }`
//!
//! 第 6 步不可省略：规格书明确要求「不得写完即认为成功」。
//!
//! ## 关于配置载体
//!
//! 迁移期配置写在 Postfix（`postconf` 键 + `sasl_passwd`）；Phase 5 移除 Postfix 后
//! 改由本进程自己持有。为了不把这套「测试-回滚-回读」逻辑绑死在 Postfix 上，
//! 这里抽象出 [`RelayConfigStore`]，两种载体各自实现；测试用内存实现，
//! 从而在没有 Postfix 的机器上也能验证回滚与回读语义。

use std::sync::{LazyLock, Mutex};

use serde_json::{json, Value};

use crate::error::SmtpError;
use crate::stages::RelayTestResult;
use crate::validate::RelayEndpoint;

/// `postconf` 键名（迁移期契约，不得改动）。
pub const KEY_RELAYHOST: &str = "relayhost";
pub const KEY_SASL_AUTH_ENABLE: &str = "smtp_sasl_auth_enable";
pub const KEY_SASL_PASSWORD_MAPS: &str = "smtp_sasl_password_maps";
pub const KEY_SASL_SECURITY_OPTIONS: &str = "smtp_sasl_security_options";
pub const KEY_TLS_SECURITY_LEVEL: &str = "smtp_tls_security_level";
/// INV-20：465 / SSL-TLS 必须写入该键，否则会以明文连 465、投递卡在队列。
pub const KEY_TLS_WRAPPERMODE: &str = "smtp_tls_wrappermode";

/// 凭证文件路径（迁移期；Phase 5 后改 `/etc/mailstack/relay.json`）。
pub const SASL_PASSWORD_PATH: &str = "/etc/postfix/sasl_passwd";

/// 回读校验失败的文案（对外契约，规格书 §5.9.5 原文）。
pub const ERR_RELAYHOST_VERIFY_FAILED: &str = "Postfix relayhost verification failed";

/// 进程级落地互斥（与 INV-32「并发丢更新」同一考量）。
///
/// `apply_relay` 的「快照 → 写入 → 回读 →（失败）回滚」是一组必须**整体原子**的
/// 操作：两次并发 apply 时，A 的快照可能落在 B 已写到一半的状态上，A 回滚时会把
/// B 的新配置当成「旧值」写回去 —— 两次本应各自完整的落地互相踩踏，最终配置
/// 既不是 A 的也不是 B 的。这条路径是低频管理操作（设置向导），整把串行锁没有
/// 任何吞吐代价。
///
/// 刻意用 `std::sync::Mutex` 而不是 `tokio::sync::Mutex`：`apply_relay` 是同步
/// 函数，而生产调用点（`priv::readers::setup_relay_apply`）在 async 上下文里
/// **直接**调它 —— `tokio::sync::Mutex::blocking_lock` 在运行时线程上会 panic。
/// 函数体内没有任何 `.await`，锁的持有期就是这个同步段，用 std 的锁在任何调用
/// 环境下都安全。
static APPLY_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// 落地计划：由已校验的端点推导。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    /// 期望的 `relayhost` 值，形如 `[host]:port`。
    pub relayhost: String,
    /// 需要写入的配置键（顺序即写入顺序）。
    pub keys: Vec<(String, String)>,
    /// 凭证文件内容；无凭证时为 `None`（此时不写文件）。
    pub credentials: Option<String>,
    /// 是否需要隐式 TLS 包装（INV-20）。
    pub wrappermode: bool,
}

impl RelayPlan {
    /// 取某个键的计划值。
    pub fn key(&self, name: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// 由端点推导落地计划。
pub fn plan_relay_apply(endpoint: &RelayEndpoint) -> RelayPlan {
    let relayhost = endpoint.relayhost();
    let wrappermode = endpoint.requires_wrappermode();
    let has_credentials = endpoint.has_credentials();

    let mut keys = vec![
        (KEY_RELAYHOST.to_string(), relayhost.clone()),
        (
            KEY_SASL_AUTH_ENABLE.to_string(),
            if has_credentials { "yes" } else { "no" }.to_string(),
        ),
        (
            KEY_SASL_PASSWORD_MAPS.to_string(),
            if has_credentials {
                format!("hash:{SASL_PASSWORD_PATH}")
            } else {
                String::new()
            },
        ),
        (
            KEY_SASL_SECURITY_OPTIONS.to_string(),
            "noanonymous".to_string(),
        ),
        (KEY_TLS_SECURITY_LEVEL.to_string(), "encrypt".to_string()),
    ];

    // INV-20：465 或 SSL/TLS 时必须写入 wrappermode。
    // 现状缺陷正是「测试通过但从未写这个键」，且无从界面看出。
    if wrappermode {
        keys.push((KEY_TLS_WRAPPERMODE.to_string(), "yes".to_string()));
    }

    let credentials = if has_credentials {
        // 格式契约：`<relayhost> <user>:<password>`，读侧在**第一个**冒号处切分
        // （`relay_store::parse_sasl_passwd`，等价于 `splitn(2, ':')`）——
        // 口令里再出现冒号是安全的，两侧往返一致。空白会破坏这个空白分隔的
        // 载体（读回时被静默截断），已由 `validate_relay` 在入口硬拒；
        // 用户名里应避免冒号（读回时冒号之后的部分会被当成口令）。
        Some(format!(
            "{relayhost} {}:{}\n",
            endpoint.username, endpoint.password
        ))
    } else {
        None
    };

    RelayPlan {
        relayhost,
        keys,
        credentials,
        wrappermode,
    }
}

/// 配置载体的快照（用于回滚）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    /// 本次将要改动的键及其原值（`None` 表示原本没有该键）。
    pub keys: Vec<(String, Option<String>)>,
    /// 凭证文件的**原内容**；`None` 表示原本不存在。
    pub credentials: Option<String>,
}

/// 配置载体抽象。
///
/// 迁移期的实现走 `postconf` + `sasl_passwd`；Phase 5 后的实现走本进程自己的配置。
/// 抽象出这一层是为了让「先测后写、回写校验、失败回滚」这套顺序逻辑
/// 能在没有 Postfix 的机器上被完整测试。
pub trait RelayConfigStore {
    /// 读取单个键**显式配置**的值；未显式设置时返回 `None`。
    ///
    /// 实现方必须区分「未设置」与「设置为空」—— 这个区别在回滚时是安全相关的：
    /// 对 `smtp_sasl_security_options` 而言，「未设置」意味着沿用默认的
    /// `noplaintext, noanonymous`，而「设置为空」会把这条保护**抹掉**。
    fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError>;

    /// **原子**写入单个键。
    fn write_key(&mut self, key: &str, value: &str) -> Result<(), SmtpError>;

    /// 移除单个键，使其回到「未设置」状态（沿用默认值）。
    ///
    /// 回滚时必须用它来还原「原本不存在」的键；用 `write_key(key, "")` 代替
    /// 会改变运行语义（见本 trait 的 `read_key` 说明）。
    fn remove_key(&mut self, key: &str) -> Result<(), SmtpError>;

    /// 读取凭证文件的当前内容。
    fn read_credentials(&mut self) -> Result<Option<String>, SmtpError>;

    /// 写入凭证文件（实现方必须用原子写 + `0600`）。
    fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError>;

    /// 删除凭证文件。
    fn remove_credentials(&mut self) -> Result<(), SmtpError>;

    /// 重载配置。
    fn reload(&mut self) -> Result<(), SmtpError>;
}

/// 落地结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayApplyResult {
    pub applied: bool,
    /// **回读得到**的 relayhost（不是我们打算写入的值）。
    pub relayhost: String,
    pub wrappermode: bool,
}

impl RelayApplyResult {
    pub fn to_json(&self, test: &RelayTestResult) -> Value {
        json!({
            "applied": self.applied,
            "relayhost": self.relayhost,
            "wrappermode": self.wrappermode,
            "test": test.to_json(),
        })
    }
}

/// 落地失败。
#[derive(Debug)]
pub struct RelayApplyFailure {
    pub error: SmtpError,
    /// 是否已回滚。
    pub rolled_back: bool,
}

impl RelayApplyFailure {
    pub fn to_json(&self) -> Value {
        json!({
            "applied": false,
            "rolledBack": self.rolled_back,
            "error": { "code": self.error.kind(), "message": self.error.to_string() },
        })
    }
}

/// 执行落地。
///
/// `test` 是**已经跑完**的中继测试结果。测试未连通时**直接拒绝且不写任何配置** ——
/// 这是「先测后写」的字面含义，也是规格书第 1 步的硬要求。
pub fn apply_relay(
    store: &mut dyn RelayConfigStore,
    endpoint: &RelayEndpoint,
    test: &RelayTestResult,
) -> Result<RelayApplyResult, RelayApplyFailure> {
    // 全程串行：锁必须覆盖「测试判定 → 快照 → 写入 → 回读 → 回滚」整段。
    // 中毒只可能来自本函数内某次 panic；锁里没有会被破坏的共享不变量
    // （载荷就是 `()`），恢复锁继续走比让此后所有 apply 永久失败更合理。
    let _apply_guard = APPLY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // ── 1) 测试不通过则不落任何配置 ──
    if !test.connected {
        return Err(RelayApplyFailure {
            error: SmtpError::Rejected(
                "relay test did not complete successfully; refusing to write any configuration"
                    .to_string(),
            ),
            rolled_back: false,
        });
    }

    let plan = plan_relay_apply(endpoint);

    // ── 4) 先取快照，供失败回滚 ──
    let snapshot = match take_snapshot(store, &plan) {
        Ok(s) => s,
        Err(e) => {
            return Err(RelayApplyFailure {
                error: e,
                rolled_back: false,
            })
        }
    };

    // ── 2)+3)+5) 写入 ──
    if let Err(e) = write_all(store, &plan) {
        let rolled_back = rollback(store, &snapshot);
        return Err(RelayApplyFailure {
            error: e,
            rolled_back,
        });
    }

    // ── 6) 回读校验：不得写完即认为成功 ──
    let observed = match store.read_key(KEY_RELAYHOST) {
        Ok(Some(v)) => v,
        Ok(None) => {
            let rolled_back = rollback(store, &snapshot);
            return Err(RelayApplyFailure {
                error: SmtpError::Rejected(format!(
                    "{ERR_RELAYHOST_VERIFY_FAILED}: relayhost is not set after write"
                )),
                rolled_back,
            });
        }
        Err(e) => {
            let rolled_back = rollback(store, &snapshot);
            return Err(RelayApplyFailure {
                error: e,
                rolled_back,
            });
        }
    };

    if observed.trim() != plan.relayhost {
        let rolled_back = rollback(store, &snapshot);
        return Err(RelayApplyFailure {
            error: SmtpError::Rejected(format!(
                "{ERR_RELAYHOST_VERIFY_FAILED}: expected {}, observed {}",
                plan.relayhost,
                observed.trim()
            )),
            rolled_back,
        });
    }

    Ok(RelayApplyResult {
        applied: true,
        relayhost: observed.trim().to_string(),
        wrappermode: plan.wrappermode,
    })
}

/// `apply_relay` 可能写入的全部键 —— 清除（direct 模式）的逆向范围以这份列表为准。
///
/// 与 [`plan_relay_apply`] 保持同源：`plan` 依端点动态增减 `wrappermode`，
/// 清除时无从知道「上次 apply 用的是哪种端点」，因此对全集逐键移除 ——
/// `remove_key` 对从未设置的键是幂等空操作。
const APPLY_WRITTEN_KEYS: &[&str] = &[
    KEY_RELAYHOST,
    KEY_SASL_AUTH_ENABLE,
    KEY_SASL_PASSWORD_MAPS,
    KEY_SASL_SECURITY_OPTIONS,
    KEY_TLS_SECURITY_LEVEL,
    KEY_TLS_WRAPPERMODE,
];

/// 清除中继配置，回到「未配置中继（直投）」状态 —— [`apply_relay`] 的逆向。
///
/// * 键用 `remove_key` 回到**未设置**，而不是写空串 —— 理由与回滚相同：
///   对部分键写空串会抹掉 Postfix 的默认安全项（见 `rollback` 的注释）。
/// * 凭证文件一并删除；`reload` 让 Postfix 载体立即生效（原生载体是空操作）。
/// * 与 [`apply_relay`] 共用同一把进程级互斥：clear 与 apply 并发时不得交错。
/// * 幂等：重复调用、或清除一个从未配置过的载体，都是成功。
pub fn clear_relay(store: &mut dyn RelayConfigStore) -> Result<(), SmtpError> {
    let _apply_guard = APPLY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for key in APPLY_WRITTEN_KEYS {
        store.remove_key(key)?;
    }
    store.remove_credentials()?;
    store.reload()
}

fn take_snapshot(
    store: &mut dyn RelayConfigStore,
    plan: &RelayPlan,
) -> Result<ConfigSnapshot, SmtpError> {
    let mut keys = Vec::with_capacity(plan.keys.len());
    for (name, _) in &plan.keys {
        keys.push((name.clone(), store.read_key(name)?));
    }
    // 凭证文件的原内容也要快照：原本存在则回滚写回内容，原本不存在则回滚删除。
    let credentials = store.read_credentials()?;
    Ok(ConfigSnapshot { keys, credentials })
}

fn write_all(store: &mut dyn RelayConfigStore, plan: &RelayPlan) -> Result<(), SmtpError> {
    // 凭证先落盘（0600），再写配置键 —— 顺序与原文一致。
    // 无凭证的计划必须**移除**已存凭证：`load_relay` 按 host:port 匹配重挂
    // 凭证，留着旧凭证会让「不带凭证的 apply」实际仍拿旧账号去认证 ——
    // 已吊销的凭证会以莫名 AUTH 失败的形式出现，明文密钥也一直留在盘上。
    match &plan.credentials {
        Some(content) => store.write_credentials(content)?,
        None => store.remove_credentials()?,
    }
    for (key, value) in &plan.keys {
        store.write_key(key, value)?;
    }
    store.reload()
}

/// 回滚到快照。返回是否**全部**恢复成功。
///
/// 对外暴露（`pub`）是为了让配置载体的实现方能在自己的测试里直接验证
/// 「原本不存在的键必须被移除」这一安全性质。
pub fn rollback_snapshot(store: &mut dyn RelayConfigStore, snapshot: &ConfigSnapshot) -> bool {
    rollback(store, snapshot)
}

/// 回滚到快照。返回是否**全部**恢复成功。
fn rollback(store: &mut dyn RelayConfigStore, snapshot: &ConfigSnapshot) -> bool {
    let mut ok = true;

    // 凭证先恢复：它是最敏感的部分，且不该留在半写状态。
    let credentials_result = match &snapshot.credentials {
        Some(content) => store.write_credentials(content),
        None => store.remove_credentials(),
    };
    if credentials_result.is_err() {
        ok = false;
    }

    for (key, previous) in &snapshot.keys {
        // **关键**：原本不存在的键必须**移除**，不能写空串。
        //
        // 实测（Postfix 3.8.6）：把 `smtp_sasl_security_options` 设为空后
        // `postconf -h` 返回空 —— 即默认的 `noplaintext, noanonymous` 保护被抹掉；
        // 而 `postconf -X` 移除该键后 `-h` 恢复返回默认值。
        // 所以「写空串」不是还原，而是一次静默的安全策略弱化。
        let result = match previous {
            Some(value) => store.write_key(key, value),
            None => store.remove_key(key),
        };
        if result.is_err() {
            ok = false;
        }
    }

    if store.reload().is_err() {
        ok = false;
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::{RelayStage, StageOutcome};
    use std::collections::HashMap;

    // ───────────────── 测试替身：内存配置载体 ─────────────────

    #[derive(Default)]
    struct InMemoryRelayStore {
        keys: HashMap<String, String>,
        credentials: Option<String>,
        /// **一次性**故障点：命中后即消费掉（模拟瞬时故障，回滚得以成功）。
        fail_once_on: Vec<&'static str>,
        /// **持续性**故障点：每次都失败（模拟存储已损坏，回滚也无法完成）。
        fail_always_on: Vec<&'static str>,
        reloads: usize,
    }

    impl InMemoryRelayStore {
        fn new() -> Self {
            Self::default()
        }

        /// 注入一次性故障。
        fn failing_once_on(mut self, what: &'static str) -> Self {
            self.fail_once_on.push(what);
            self
        }

        /// 注入持续性故障。
        fn failing_always_on(mut self, what: &'static str) -> Self {
            self.fail_always_on.push(what);
            self
        }

        /// 判定并消费故障点。
        fn take_failure(&mut self, what: &str) -> bool {
            if self.fail_always_on.contains(&what) {
                return true;
            }
            if let Some(idx) = self.fail_once_on.iter().position(|w| *w == what) {
                self.fail_once_on.remove(idx);
                return true;
            }
            false
        }

        /// 全局前缀匹配（如 `write_key` 命中任意键）。同样消费一次性条目。
        fn take_failure_prefixed(&mut self, what: &str) -> bool {
            if self.fail_always_on.contains(&what) {
                return true;
            }
            if let Some(idx) = self.fail_once_on.iter().position(|w| *w == what) {
                self.fail_once_on.remove(idx);
                return true;
            }
            false
        }

        fn should_fail_key(&mut self, key: &str) -> bool {
            let specific = format!("write_key:{key}");
            if self.take_failure(&specific) {
                return true;
            }
            self.take_failure_prefixed("write_key")
        }
    }

    impl RelayConfigStore for InMemoryRelayStore {
        fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
            Ok(self.keys.get(key).cloned())
        }

        fn read_credentials(&mut self) -> Result<Option<String>, SmtpError> {
            Ok(self.credentials.clone())
        }

        fn write_key(&mut self, key: &str, value: &str) -> Result<(), SmtpError> {
            if self.should_fail_key(key) {
                return Err(SmtpError::Io(std::io::Error::other(
                    "injected write failure",
                )));
            }
            self.keys.insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn remove_key(&mut self, key: &str) -> Result<(), SmtpError> {
            if self.take_failure_prefixed("remove_key") {
                return Err(SmtpError::Io(std::io::Error::other(
                    "injected remove failure",
                )));
            }
            self.keys.remove(key);
            Ok(())
        }

        fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError> {
            if self.take_failure("write_credentials") {
                return Err(SmtpError::Io(std::io::Error::other(
                    "injected credentials write failure",
                )));
            }
            self.credentials = Some(content.to_string());
            Ok(())
        }

        fn remove_credentials(&mut self) -> Result<(), SmtpError> {
            self.credentials = None;
            Ok(())
        }

        fn reload(&mut self) -> Result<(), SmtpError> {
            self.reloads += 1;
            if self.take_failure("reload") {
                return Err(SmtpError::Io(std::io::Error::other(
                    "injected reload failure",
                )));
            }
            Ok(())
        }
    }

    // ───────────────── 夹具 ─────────────────

    fn endpoint(port: u16, tls: &str, user: &str, pass: &str) -> RelayEndpoint {
        crate::validate::validate_relay(
            &crate::validate::RelayValidationRequest {
                host: "smtp.sendgrid.net".to_string(),
                port,
                tls_mode: tls.to_string(),
                username: user.to_string(),
                password: pass.to_string(),
                allow_private_network: false,
            },
            false,
        )
        .unwrap()
    }

    fn passed_test() -> RelayTestResult {
        RelayTestResult {
            connected: true,
            stage: RelayStage::Auth,
            latency_ms: 10,
            stages: vec![StageOutcome::new(
                RelayStage::Auth,
                true,
                json!({ "skipped": true }),
            )],
        }
    }

    fn failed_test() -> RelayTestResult {
        RelayTestResult {
            connected: false,
            stage: RelayStage::Failed,
            latency_ms: 3,
            stages: vec![],
        }
    }

    // ───────────────── 计划推导 ─────────────────

    #[test]
    fn plan_uses_bracket_relayhost_syntax() {
        let plan = plan_relay_apply(&endpoint(587, "STARTTLS", "apikey", "secret"));
        assert_eq!(plan.relayhost, "[smtp.sendgrid.net]:587");
        assert_eq!(plan.key(KEY_RELAYHOST), Some("[smtp.sendgrid.net]:587"));
    }

    #[test]
    fn plan_sets_sasl_keys_when_credentials_are_present() {
        let plan = plan_relay_apply(&endpoint(587, "STARTTLS", "apikey", "secret"));
        assert_eq!(plan.key(KEY_SASL_AUTH_ENABLE), Some("yes"));
        assert_eq!(
            plan.key(KEY_SASL_PASSWORD_MAPS),
            Some("hash:/etc/postfix/sasl_passwd")
        );
        assert_eq!(plan.key(KEY_SASL_SECURITY_OPTIONS), Some("noanonymous"));
        assert_eq!(plan.key(KEY_TLS_SECURITY_LEVEL), Some("encrypt"));

        let creds = plan.credentials.unwrap();
        assert_eq!(
            creds, "[smtp.sendgrid.net]:587 apikey:secret\n",
            "凭证格式是 <relayhost> <user>:<password>"
        );
    }

    #[test]
    fn plan_disables_sasl_without_credentials() {
        let plan = plan_relay_apply(&endpoint(587, "STARTTLS", "", ""));
        assert_eq!(plan.key(KEY_SASL_AUTH_ENABLE), Some("no"));
        assert_eq!(plan.key(KEY_SASL_PASSWORD_MAPS), Some(""));
        assert!(plan.credentials.is_none(), "无凭证时不得写凭证文件");
    }

    #[test]
    fn plan_adds_wrappermode_for_465() {
        // INV-20：这正是现状已确认的缺陷 —— 测试通过但从未写这个键。
        let plan = plan_relay_apply(&endpoint(465, "SSL/TLS", "apikey", "secret"));
        assert_eq!(plan.key(KEY_TLS_WRAPPERMODE), Some("yes"));
        assert!(plan.wrappermode);
    }

    #[test]
    fn plan_omits_wrappermode_for_587_starttls() {
        let plan = plan_relay_apply(&endpoint(587, "STARTTLS", "apikey", "secret"));
        assert_eq!(plan.key(KEY_TLS_WRAPPERMODE), None);
        assert!(!plan.wrappermode);
    }

    #[test]
    fn plan_always_forces_encrypted_transport() {
        for (port, tls) in [(587u16, "STARTTLS"), (465, "SSL/TLS"), (2525, "STARTTLS")] {
            let plan = plan_relay_apply(&endpoint(port, tls, "", ""));
            assert_eq!(
                plan.key(KEY_TLS_SECURITY_LEVEL),
                Some("encrypt"),
                "{port} 必须强制加密"
            );
        }
    }

    // ───────────────── 落地与回滚 ─────────────────

    #[test]
    fn refuses_to_write_anything_when_the_test_did_not_pass() {
        // 规格书第 1 步：测试不通过则不落任何配置。
        let mut store = InMemoryRelayStore::new();
        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &failed_test(),
        )
        .unwrap_err();

        assert!(!failure.rolled_back, "什么都没写，自然无需回滚");
        assert!(
            store.keys.is_empty(),
            "测试未通过时不得写入任何配置键，实际: {:?}",
            store.keys
        );
        assert!(store.credentials.is_none(), "不得写入凭证");
        assert_eq!(store.reloads, 0, "不得重载服务");
    }

    #[test]
    fn successful_apply_writes_all_keys_and_credentials() {
        let mut store = InMemoryRelayStore::new();
        let result = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();

        assert!(result.applied);
        assert_eq!(result.relayhost, "[smtp.sendgrid.net]:587");
        assert_eq!(store.keys[KEY_RELAYHOST], "[smtp.sendgrid.net]:587");
        assert_eq!(store.keys[KEY_SASL_AUTH_ENABLE], "yes");
        assert_eq!(store.keys[KEY_TLS_SECURITY_LEVEL], "encrypt");
        assert!(store.credentials.is_some());
        assert!(store.reloads >= 1, "应重载服务");
    }

    #[test]
    fn apply_result_relayhost_is_what_was_read_back() {
        // 返回的是**回读值**，不是打算写入的值 —— 否则回读校验就没有意义。
        let mut store = InMemoryRelayStore::new();
        let result = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(result.relayhost, store.keys[KEY_RELAYHOST]);
    }

    #[test]
    fn readback_mismatch_is_reported_and_rolled_back() {
        // 模拟「写进去了但读回来不是这个值」。
        //
        // 注意：这个替身**只在写入之后**才开始说谎。若它在快照阶段就说谎，
        // 快照本身会被污染，回滚会把谎言写回去 —— 那样测试看着通过，
        // 实际什么都没验证到（第一版就踩了这个坑）。
        struct LyingStore {
            inner: InMemoryRelayStore,
            writes_done: bool,
        }

        impl RelayConfigStore for LyingStore {
            fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
                if key == KEY_RELAYHOST && self.writes_done {
                    // 只在回读阶段报一个不同的值。
                    return Ok(Some("[wrong.example.com]:25".to_string()));
                }
                self.inner.read_key(key)
            }
            fn read_credentials(&mut self) -> Result<Option<String>, SmtpError> {
                self.inner.read_credentials()
            }
            fn write_key(&mut self, k: &str, v: &str) -> Result<(), SmtpError> {
                self.writes_done = true;
                self.inner.write_key(k, v)
            }
            fn remove_key(&mut self, k: &str) -> Result<(), SmtpError> {
                self.inner.remove_key(k)
            }
            fn write_credentials(&mut self, c: &str) -> Result<(), SmtpError> {
                self.inner.write_credentials(c)
            }
            fn remove_credentials(&mut self) -> Result<(), SmtpError> {
                self.inner.remove_credentials()
            }
            fn reload(&mut self) -> Result<(), SmtpError> {
                self.inner.reload()
            }
        }

        // 预置一份真实的旧配置，供快照捕获。
        let mut inner = InMemoryRelayStore::new();
        inner.keys.insert(
            KEY_RELAYHOST.to_string(),
            "[old.example.com]:25".to_string(),
        );

        let mut store = LyingStore {
            inner,
            writes_done: false,
        };

        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap_err();

        assert!(
            failure
                .error
                .to_string()
                .contains(ERR_RELAYHOST_VERIFY_FAILED),
            "实际错误: {}",
            failure.error
        );
        assert!(failure.rolled_back, "回读不一致必须回滚");
        assert_eq!(
            store.inner.keys[KEY_RELAYHOST], "[old.example.com]:25",
            "回滚必须把 relayhost 还原为快照里的真值"
        );
        assert!(
            store.inner.credentials.is_none(),
            "回滚应删除本次写入的凭证（原本不存在）"
        );
    }

    #[test]
    fn write_failure_triggers_rollback_to_previous_values() {
        // 瞬时故障：写入某个键失败一次 → 必须回滚到旧值，且回滚本身成功。
        let mut store = InMemoryRelayStore::new();
        store.keys.insert(
            KEY_RELAYHOST.to_string(),
            "[old.example.com]:25".to_string(),
        );
        store
            .keys
            .insert(KEY_TLS_SECURITY_LEVEL.to_string(), "may".to_string());
        store.credentials = Some("[old.example.com]:25 u:p\n".to_string());

        let mut store = store.failing_once_on("write_key:smtp_tls_security_level");

        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap_err();

        assert!(failure.rolled_back, "回滚应当成功");
        assert_eq!(
            store.keys[KEY_RELAYHOST], "[old.example.com]:25",
            "relayhost 必须回滚为旧值"
        );
        assert_eq!(store.keys[KEY_TLS_SECURITY_LEVEL], "may");
        assert_eq!(
            store.credentials.as_deref(),
            Some("[old.example.com]:25 u:p\n"),
            "原凭证内容必须原样恢复"
        );
    }

    #[test]
    fn credentials_write_failure_triggers_rollback() {
        let mut store = InMemoryRelayStore::new();
        store.keys.insert(
            KEY_RELAYHOST.to_string(),
            "[old.example.com]:25".to_string(),
        );

        let mut store = store.failing_once_on("write_credentials");
        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap_err();

        assert!(failure.rolled_back);
        assert_eq!(store.keys[KEY_RELAYHOST], "[old.example.com]:25");
        assert!(
            store.credentials.is_none(),
            "原本没有凭证文件，回滚后也应没有"
        );
    }

    #[test]
    fn reload_failure_triggers_rollback() {
        let mut store = InMemoryRelayStore::new();
        store.keys.insert(
            KEY_RELAYHOST.to_string(),
            "[old.example.com]:25".to_string(),
        );

        let mut store = store.failing_once_on("reload");
        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap_err();

        assert!(failure.rolled_back, "重载失败也必须回滚配置");
        assert_eq!(store.keys[KEY_RELAYHOST], "[old.example.com]:25");
    }

    #[test]
    fn persistent_storage_failure_reports_rollback_as_incomplete() {
        // 存储持续不可用时，回滚也完不成 —— 此时必须诚实报 `rolled_back: false`。
        // 报 true 会让运维以为配置已经安全还原，而实际处于半写状态。
        let mut store = InMemoryRelayStore::new();
        store.keys.insert(
            KEY_RELAYHOST.to_string(),
            "[old.example.com]:25".to_string(),
        );

        let mut store = store.failing_always_on("write_key");
        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap_err();

        assert!(
            !failure.rolled_back,
            "回滚未能完成时必须报 false，而不是谎报成功"
        );
        assert_eq!(failure.to_json()["rolledBack"], false);
    }

    #[test]
    fn wrappermode_is_written_for_465_during_apply() {
        // INV-20 在落地路径上的断言：不只是计划里要有，真的要写进去。
        let mut store = InMemoryRelayStore::new();
        apply_relay(
            &mut store,
            &endpoint(465, "SSL/TLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(
            store.keys[KEY_TLS_WRAPPERMODE], "yes",
            "465 落地时必须写 smtp_tls_wrappermode=yes"
        );
    }

    #[test]
    fn apply_result_serialises_the_documented_shape() {
        let mut store = InMemoryRelayStore::new();
        let result = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();

        let value = result.to_json(&passed_test());
        assert_eq!(value["applied"], true);
        assert_eq!(value["relayhost"], "[smtp.sendgrid.net]:587");
        assert_eq!(value["wrappermode"], false);
        assert!(value["test"]["connected"].as_bool().unwrap());
    }

    #[test]
    fn failure_serialises_the_documented_shape() {
        let mut store = InMemoryRelayStore::new();
        let failure = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &failed_test(),
        )
        .unwrap_err();

        let value = failure.to_json();
        assert_eq!(value["applied"], false);
        assert_eq!(value["rolledBack"], false);
        assert!(value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("refusing"));
    }

    // ───────────────── 清除（direct 模式）：apply 的逆向 ─────────────────

    #[test]
    fn clear_relay_removes_every_key_apply_writes_and_is_idempotent() {
        // 先落一份完整 apply（含 465 的 wrappermode），再清除。
        let mut store = InMemoryRelayStore::new();
        apply_relay(
            &mut store,
            &endpoint(465, "SSL/TLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(store.keys.len(), 6, "apply 应已写入 6 个键（含 wrappermode）");
        assert!(store.credentials.is_some());

        let reloads_before = store.reloads;
        clear_relay(&mut store).unwrap();
        assert!(
            store.keys.is_empty(),
            "全部键必须被清除，实际: {:?}",
            store.keys
        );
        assert!(
            store.credentials.is_none(),
            "凭证文件必须随 clear 一并删除"
        );
        assert!(
            store.reloads > reloads_before,
            "清除后应重载（Postfix 载体靠它生效）"
        );

        // 幂等：对已清空的载体再 clear 一次仍是成功。
        clear_relay(&mut store).unwrap();
        assert!(store.keys.is_empty());
    }

    #[test]
    fn clear_relay_on_an_unconfigured_store_is_a_successful_no_op() {
        let mut store = InMemoryRelayStore::new();
        clear_relay(&mut store).unwrap();
        assert!(store.keys.is_empty());
        assert!(store.credentials.is_none());
    }
}
