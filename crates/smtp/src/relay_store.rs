//! `RelayConfigStore` 的真实落盘实现（规格书 §5.9.5、§5.9.6）。
//!
//! 两种配置载体：
//!
//! | 实现 | 载体 | 适用阶段 |
//! |---|---|---|
//! | [`PostfixRelayStore`] | `postconf` 键 + `/etc/postfix/sasl_passwd` | 迁移期（Postfix 仍在） |
//! | [`NativeRelayStore`] | `/etc/mailstack/relay.json`（0600） | Phase 5 之后（Postfix 已移除） |
//!
//! 迁移期必须能**读取**旧的 `sasl_passwd`（格式 `<relayhost> <user>:<password>`），
//! 见 [`parse_sasl_passwd`]；`postmap` 生成的 `.db` 视为可忽略。
//!
//! ## 关于同步 IO
//!
//! [`crate::relay_apply::apply_relay`] 是同步函数，故本模块也用同步 IO。
//! 这条路径由特权助手进程执行、且是低频的管理操作，阻塞是可接受的；
//! 若在异步运行时内调用，请包一层 `tokio::task::spawn_blocking`。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use mailstack_core::Paths;

use crate::error::SmtpError;
use crate::relay_apply::{RelayConfigStore, SASL_PASSWORD_PATH};

// 外部命令执行原语统一由 `mailstack-core` 提供（`postmap` 序列被 store 的表文件
// 与这里的中继凭证共用，不能各写一份）。此处**重新导出**以保持本 crate 既有的
// 公开 API 不变（`mailstack_smtp::SystemCommandRunner` 等）。
pub use mailstack_core::exec::{
    resolve_program, CommandOutput, CommandRunner, SystemCommandRunner,
};

// ───────────────────────── Postfix 载体（迁移期） ─────────────────────────

/// 迁移期载体：`postconf` 键 + `sasl_passwd`。
pub struct PostfixRelayStore {
    runner: Arc<dyn CommandRunner>,
    /// 凭证文件路径（默认 `/etc/postfix/sasl_passwd`）。
    pub sasl_passwd: PathBuf,
    postconf: String,
    postmap: String,
    postfix: String,
}

impl PostfixRelayStore {
    /// 生产实例：真实运行命令、使用默认路径。
    pub fn production() -> Self {
        Self {
            runner: Arc::new(SystemCommandRunner),
            sasl_passwd: PathBuf::from(SASL_PASSWORD_PATH),
            postconf: "postconf".to_string(),
            postmap: "postmap".to_string(),
            postfix: "postfix".to_string(),
        }
    }

    /// 注入运行器与路径（测试用）。
    pub fn with_runner(runner: Arc<dyn CommandRunner>, sasl_passwd: PathBuf) -> Self {
        Self {
            runner,
            sasl_passwd,
            postconf: "postconf".to_string(),
            postmap: "postmap".to_string(),
            postfix: "postfix".to_string(),
        }
    }

    fn postconf_get(&self, key: &str) -> Result<Option<String>, SmtpError> {
        let out = self.runner.run(&self.postconf, &["-h", key])?;
        if !out.success() {
            return Err(SmtpError::Config(out.diagnostic(&self.postconf)));
        }
        let value = out.stdout.trim().to_string();
        // `postconf -h` 对未设置的键输出空行 —— 视为“未设置”。
        Ok(if value.is_empty() { None } else { Some(value) })
    }

    /// 读取**有效值**（含默认）。仅用于诊断/展示，**不要**用于快照与回滚 ——
    /// 那需要 [`RelayConfigStore::read_key`] 的「显式配置」语义。
    pub fn effective_value(&self, key: &str) -> Result<Option<String>, SmtpError> {
        self.postconf_get(key)
    }

    fn postconf_set(&self, key: &str, value: &str) -> Result<(), SmtpError> {
        let assignment = format!("{key}={value}");
        let out = self.runner.run(&self.postconf, &["-e", &assignment])?;
        if !out.success() {
            return Err(SmtpError::Config(out.diagnostic(&self.postconf)));
        }
        Ok(())
    }
}

impl RelayConfigStore for PostfixRelayStore {
    /// 读取**显式配置**的值。
    ///
    /// 必须用 `postconf -n`（仅非默认项）而不是 `-h`（有效值含默认）：
    /// 后者无法区分「未设置」与「显式设为默认值」。实测差异：
    ///
    /// | 键 | `-h`（有效值） | `-n`（显式） |
    /// |---|---|---|
    /// | `smtp_tls_wrappermode`（未设置） | `no` | *（空）* |
    /// | `relayhost`（设空） | *（空）* | `relayhost =` |
    ///
    /// 若用 `-h`，快照会把从未设置过的键记成「已设置」，回滚时便无法正确移除它们。
    fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
        let out = self.runner.run(&self.postconf, &["-n", key])?;
        if !out.success() {
            return Err(SmtpError::Config(out.diagnostic(&self.postconf)));
        }
        Ok(parse_postconf_n(&out.stdout, key))
    }

    fn write_key(&mut self, key: &str, value: &str) -> Result<(), SmtpError> {
        self.postconf_set(key, value)
    }

    /// `postconf -X` 移除该参数，使其回到「未设置」状态。
    fn remove_key(&mut self, key: &str) -> Result<(), SmtpError> {
        let out = self.runner.run(&self.postconf, &["-X", key])?;
        if !out.success() {
            return Err(SmtpError::Config(out.diagnostic(&self.postconf)));
        }
        Ok(())
    }

    fn read_credentials(&mut self) -> Result<Option<String>, SmtpError> {
        match std::fs::read_to_string(&self.sasl_passwd) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SmtpError::Config(format!(
                "read {}: {e}",
                self.sasl_passwd.display()
            ))),
        }
    }

    /// 原子写入凭证文件，权限 `0600`。
    ///
    /// 权限不是可选项：`telemetry.key_permission_scan` 会检查该文件必须是 `0600`，
    /// 不合规时报 FAIL。凭证含明文口令，绝不能以进程 umask 落盘。
    fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError> {
        mailstack_core::atomic::atomic_as(&self.sasl_passwd, content.as_bytes(), 0o600, None)?;

        // 紧接着 postmap 重建 hash 表（§5.9.6 的顺序：写凭证 → postmap → postconf → check → reload）。
        let out = self
            .runner
            .run(&self.postmap, &[&self.sasl_passwd.to_string_lossy()])?;
        if !out.success() {
            return Err(SmtpError::Config(out.diagnostic(&self.postmap)));
        }
        Ok(())
    }

    fn remove_credentials(&mut self) -> Result<(), SmtpError> {
        for path in [self.sasl_passwd.clone(), hash_db_path(&self.sasl_passwd)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(SmtpError::Config(format!("remove {}: {e}", path.display()))),
            }
        }
        Ok(())
    }

    /// `postfix check` + 重载服务。
    fn reload(&mut self) -> Result<(), SmtpError> {
        let check = self.runner.run(&self.postfix, &["check"])?;
        if !check.success() {
            return Err(SmtpError::Config(check.diagnostic(&self.postfix)));
        }
        let reload = self.runner.run(&self.postfix, &["reload"])?;
        if !reload.success() {
            return Err(SmtpError::Config(reload.diagnostic(&self.postfix)));
        }
        Ok(())
    }
}

/// 解析 `postconf -n <key>` 的输出。
///
/// 输出格式为 `key = value`（**注意带空格**，与 `-h` 的裸值不同）。
/// 键未显式设置时输出为空 → 返回 `None`。
///
/// 只认以该键开头的那一行，其余行（例如 stderr 混入的 warning）一律忽略，
/// 避免把警告文本当成配置值。
pub fn parse_postconf_n(stdout: &str, key: &str) -> Option<String> {
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// `postmap` 生成的 hash 表路径（`sasl_passwd` → `sasl_passwd.db`）。
pub use mailstack_core::exec::hash_db_path;

/// 解析旧 `sasl_passwd` 的内容，用于迁移。
///
/// 每行格式 `<relayhost> <user>:<password>`；跳过空行与 `#` 注释；
/// 不符合格式的行被忽略（不报错——迁移不应因一行脏数据而中断）。
///
/// ## 两点格式边界（与 `relay_apply::plan_relay_apply` 的写侧拼装互为镜像）
///
/// * `user:password` 在**第一个**冒号处切分（`split_once`，等价于
///   `splitn(2, ':')`）：口令里允许再有冒号，写侧也是这个语义，两侧往返一致。
///   反向注意：**用户名**里的冒号无法往返（读回时其后部分会被当成口令），
///   配置时应避免。
/// * 凭证中的空格/Tab 无法在此格式中表示（字段按空白切分，含空白的凭证读回时
///   被静默截断）。新配置已由 `validate_relay` 在入口硬拒空白；本函数只负责
///   如实读旧文件，不做修正。
pub fn parse_sasl_passwd(content: &str) -> Vec<SaslEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let relayhost = parts.next()?.to_string();
            let credentials = parts.next().unwrap_or("");
            let (username, password) = match credentials.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                // 只有用户名没有口令：保留用户名，口令为空。
                None => (credentials.to_string(), String::new()),
            };
            Some(SaslEntry {
                relayhost,
                username,
                password,
            })
        })
        .collect()
}

/// 旧 `sasl_passwd` 的一条记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslEntry {
    pub relayhost: String,
    pub username: String,
    pub password: String,
}

// ───────────────────────── 原生载体（Phase 5 目标） ─────────────────────────

/// Phase 5 之后的载体：`/etc/mailstack/relay.json`（`0600`）。
///
/// 与 Postfix 载体的区别：不再调用任何外部命令，读写都在本进程内完成。
/// 这也让它在没有 Postfix 的机器上**可以被端到端测试**。
pub struct NativeRelayStore {
    pub config_path: PathBuf,
}

impl NativeRelayStore {
    pub fn production(paths: &Paths) -> Self {
        Self {
            config_path: paths.relay_config.clone(),
        }
    }

    pub fn at(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }

    fn load(&self) -> Result<BTreeMap<String, String>, SmtpError> {
        let text = match std::fs::read_to_string(&self.config_path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => {
                return Err(SmtpError::Config(format!(
                    "read {}: {e}",
                    self.config_path.display()
                )))
            }
        };
        // 文件损坏时**不**静默当作空配置 —— 那会让人以为中继没配过。
        serde_json::from_str(&text)
            .map_err(|e| SmtpError::Config(format!("parse {}: {e}", self.config_path.display())))
    }

    fn store(&self, doc: &BTreeMap<String, String>) -> Result<(), SmtpError> {
        // 凭证与配置同文件，故整体 0600（§5.9.6：relay.json 属机密文件）。
        let data = format!("{}\n", serde_json::to_string_pretty(doc)?);
        mailstack_core::atomic::atomic_as(&self.config_path, data.as_bytes(), 0o600, None)?;
        Ok(())
    }

    /// 整体持锁的读-改-写，避免并发丢更新（与 INV-32 同一考量）。
    fn update<F>(&self, mutate: F) -> Result<(), SmtpError>
    where
        F: FnOnce(&mut BTreeMap<String, String>),
    {
        let path = self.config_path.clone();
        // `locked()` 的签名要求 `CoreResult`，故在闭包内做一次错误类型转换。
        // 只转换外层类型、保留原始消息，调用方看到的诊断信息不变。
        mailstack_core::atomic::locked(&path, || {
            let mut doc = self.load().map_err(to_core_error)?;
            mutate(&mut doc);
            self.store(&doc).map_err(to_core_error)
        })?;
        Ok(())
    }
}

/// 把 SMTP 侧错误适配为 core 的错误类型（供 `locked()` 这类核心原语复用）。
fn to_core_error(e: SmtpError) -> mailstack_core::CoreError {
    mailstack_core::CoreError::Invalid(e.to_string())
}

impl RelayConfigStore for NativeRelayStore {
    fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
        Ok(self.load()?.get(key).cloned())
    }

    fn write_key(&mut self, key: &str, value: &str) -> Result<(), SmtpError> {
        self.update(|doc| {
            doc.insert(key.to_string(), value.to_string());
        })
    }

    fn remove_key(&mut self, key: &str) -> Result<(), SmtpError> {
        self.update(|doc| {
            doc.remove(key);
        })
    }

    fn read_credentials(&mut self) -> Result<Option<String>, SmtpError> {
        Ok(self.load()?.get(CREDENTIALS_KEY).cloned())
    }

    fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError> {
        self.update(|doc| {
            doc.insert(CREDENTIALS_KEY.to_string(), content.to_string());
        })
    }

    fn remove_credentials(&mut self) -> Result<(), SmtpError> {
        self.update(|doc| {
            doc.remove(CREDENTIALS_KEY);
        })
    }

    /// 原生载体没有外部守护进程需要重载 —— 配置在下次读取时生效。
    ///
    /// 保留空实现而不是删掉该方法：`apply_relay` 的顺序里「写入后重载」是
    /// 语义的一部分，且未来若引入配置缓存/世代号，这里就是挂载点。
    fn reload(&mut self) -> Result<(), SmtpError> {
        Ok(())
    }
}

/// 原生载体中保存凭证内容的键名。
pub const CREDENTIALS_KEY: &str = "saslPasswd";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_apply::{
        apply_relay, rollback_snapshot, ConfigSnapshot, KEY_RELAYHOST, KEY_SASL_AUTH_ENABLE,
        KEY_SASL_SECURITY_OPTIONS, KEY_TLS_SECURITY_LEVEL, KEY_TLS_WRAPPERMODE,
    };
    use crate::stages::{RelayStage, RelayTestResult, StageOutcome};
    use crate::validate::{validate_relay, RelayValidationRequest};
    use std::path::Path;
    use std::sync::Mutex;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mailstack-relaystore-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn endpoint(port: u16, tls: &str) -> crate::validate::RelayEndpoint {
        validate_relay(
            &RelayValidationRequest {
                host: "smtp.sendgrid.net".to_string(),
                port,
                tls_mode: tls.to_string(),
                username: "apikey".to_string(),
                password: "SG.secret".to_string(),
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
            latency_ms: 5,
            stages: vec![StageOutcome::new(
                RelayStage::Auth,
                true,
                serde_json::json!({}),
            )],
        }
    }

    // ───────────────── 原生载体：真实磁盘 IO ─────────────────

    #[test]
    fn native_store_round_trips_keys_on_disk() {
        let dir = temp_dir("native");
        let mut store = NativeRelayStore::at(dir.join("relay.json"));

        assert_eq!(store.read_key(KEY_RELAYHOST).unwrap(), None);
        store
            .write_key(KEY_RELAYHOST, "[smtp.sendgrid.net]:587")
            .unwrap();
        assert_eq!(
            store.read_key(KEY_RELAYHOST).unwrap().as_deref(),
            Some("[smtp.sendgrid.net]:587")
        );

        // 再写一个键不得覆盖前一个（读-改-写正确）。
        store.write_key(KEY_SASL_AUTH_ENABLE, "yes").unwrap();
        assert_eq!(
            store.read_key(KEY_RELAYHOST).unwrap().as_deref(),
            Some("[smtp.sendgrid.net]:587")
        );
        assert_eq!(
            store.read_key(KEY_SASL_AUTH_ENABLE).unwrap().as_deref(),
            Some("yes")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn native_store_writes_0600_because_it_holds_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("nativemode");
        let path = dir.join("relay.json");
        let mut store = NativeRelayStore::at(&path);
        store.write_credentials("[h]:587 u:p\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "relay.json 含明文口令，必须是 0600");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_leaves_no_temp_files() {
        let dir = temp_dir("nativetmp");
        let path = dir.join("relay.json");
        let mut store = NativeRelayStore::at(&path);
        store.write_key(KEY_RELAYHOST, "[h]:587").unwrap();
        store.write_credentials("creds").unwrap();

        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不得残留临时文件: {leftovers:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_reports_corrupt_file_instead_of_treating_it_as_empty() {
        let dir = temp_dir("nativecorrupt");
        let path = dir.join("relay.json");
        std::fs::write(&path, "{not json").unwrap();
        let mut store = NativeRelayStore::at(&path);

        let err = store.read_key(KEY_RELAYHOST).unwrap_err();
        assert!(
            err.to_string().contains("parse"),
            "损坏文件必须报错，不能静默当成未配置: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_end_to_end_apply_and_readback() {
        // INV-16 的**真实落盘**路径：不只是内存替身。
        let dir = temp_dir("nativee2e");
        let path = dir.join("relay.json");
        let mut store = NativeRelayStore::at(&path);

        let result = apply_relay(&mut store, &endpoint(587, "STARTTLS"), &passed_test()).unwrap();

        assert!(result.applied);
        assert_eq!(result.relayhost, "[smtp.sendgrid.net]:587");

        // 文件真的落在磁盘上，且内容可被独立读回。
        let raw = std::fs::read_to_string(&path).unwrap();
        let doc: BTreeMap<String, String> = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc[KEY_RELAYHOST], "[smtp.sendgrid.net]:587");
        assert_eq!(doc[KEY_SASL_AUTH_ENABLE], "yes");
        assert_eq!(doc[KEY_TLS_SECURITY_LEVEL], "encrypt");
        assert_eq!(doc[KEY_SASL_SECURITY_OPTIONS], "noanonymous");
        assert!(doc[CREDENTIALS_KEY].contains("apikey:"));
        // R3-004：这个键**恒写**，587 + STARTTLS 时显式落 `no`。
        // 原实现「需要才写」，导致 465 → 587 切换后旧的 `yes` 留在盘上。
        assert_eq!(
            doc[KEY_TLS_WRAPPERMODE], "no",
            "587 + STARTTLS 必须显式写 no（而不是留空/不写）"
        );
        assert!(!result.wrappermode, "回读值必须为 false");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_end_to_end_writes_wrappermode_for_465() {
        // INV-20 的真实落盘断言。
        let dir = temp_dir("native465");
        let path = dir.join("relay.json");
        let mut store = NativeRelayStore::at(&path);

        apply_relay(&mut store, &endpoint(465, "SSL/TLS"), &passed_test()).unwrap();

        let doc: BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            doc[KEY_TLS_WRAPPERMODE], "yes",
            "465 必须在磁盘上写出 smtp_tls_wrappermode=yes"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_rollback_restores_the_file_on_disk() {
        // 真实回滚：磁盘上的旧配置必须被还原。
        //
        // 替身**只在写入之后**才开始说谎。若在快照阶段就说谎，快照会被污染，
        // 回滚会把谎言写回磁盘 —— 测试会「通过」但什么都没验证到。
        struct LyingNative {
            inner: NativeRelayStore,
            writes_done: bool,
        }

        impl RelayConfigStore for LyingNative {
            fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
                if key == KEY_RELAYHOST && self.writes_done {
                    return Ok(Some("[wrong.example.com]:25".to_string()));
                }
                self.inner.read_key(key)
            }
            fn write_key(&mut self, k: &str, v: &str) -> Result<(), SmtpError> {
                self.writes_done = true;
                self.inner.write_key(k, v)
            }
            fn remove_key(&mut self, k: &str) -> Result<(), SmtpError> {
                self.inner.remove_key(k)
            }
            fn read_credentials(&mut self) -> Result<Option<String>, SmtpError> {
                self.inner.read_credentials()
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

        let dir = temp_dir("nativerollback");
        let path = dir.join("relay.json");

        // 先建立一份「旧配置」，用真实实现写盘。
        NativeRelayStore::at(&path)
            .write_key(KEY_RELAYHOST, "[old.example.com]:25")
            .unwrap();

        let mut lying = LyingNative {
            inner: NativeRelayStore::at(&path),
            writes_done: false,
        };
        let failure =
            apply_relay(&mut lying, &endpoint(587, "STARTTLS"), &passed_test()).unwrap_err();
        assert!(failure.rolled_back, "回滚应成功");

        // 用**独立读者**（不复用替身）确认磁盘已还原。
        let doc: BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            doc[KEY_RELAYHOST], "[old.example.com]:25",
            "磁盘上的 relayhost 必须还原为旧值"
        );
        assert!(
            !doc.contains_key(CREDENTIALS_KEY),
            "原本没有凭证，回滚后也不该有"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_remove_credentials_is_idempotent() {
        let dir = temp_dir("nativeremove");
        let mut store = NativeRelayStore::at(dir.join("relay.json"));
        store.remove_credentials().unwrap();
        assert!(store.read_credentials().unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ───────────────── Postfix 载体：用注入运行器验证命令序列 ─────────────────

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        /// 预置的 postconf 读值。
        values: Mutex<BTreeMap<String, String>>,
        /// 会失败的命令前缀。
        fail_on: Mutex<Vec<String>>,
        /// 忽略写入、始终返回预置值（模拟回读不一致）。
        ignore_writes: bool,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self::default()
        }

        fn failing_on(mut self, program: &str) -> Self {
            self.fail_on.get_mut().unwrap().push(program.to_string());
            self
        }

        fn with_ignored_writes(mut self) -> Self {
            self.ignore_writes = true;
            self
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn programs(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .map(|(program, _)| program)
                .collect()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> mailstack_core::CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));

            if self.fail_on.lock().unwrap().iter().any(|p| p == program) {
                return Ok(CommandOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: format!("{program}: injected failure"),
                });
            }

            // postconf 各变体的语义（与真实 Postfix 3.8.6 实测一致）：
            //   -h <key>  → 有效值（含默认），裸值
            //   -n <key>  → 仅显式设置的值，格式 `key = value`；未设置则输出为空
            //   -e k=v    → 设置
            //   -X <key>  → 移除
            if program == "postconf" {
                let mut values = self.values.lock().unwrap();
                match args.first().copied() {
                    Some("-h") => {
                        let key = args.get(1).copied().unwrap_or("");
                        return Ok(CommandOutput {
                            status: 0,
                            stdout: values.get(key).cloned().unwrap_or_default(),
                            stderr: String::new(),
                        });
                    }
                    Some("-n") => {
                        let key = args.get(1).copied().unwrap_or("");
                        let stdout = values
                            .get(key)
                            .map(|v| format!("{key} = {v}\n"))
                            .unwrap_or_default();
                        return Ok(CommandOutput {
                            status: 0,
                            stdout,
                            stderr: String::new(),
                        });
                    }
                    Some("-e") => {
                        if !self.ignore_writes {
                            if let Some(assignment) = args.get(1) {
                                if let Some((k, v)) = assignment.split_once('=') {
                                    values.insert(k.to_string(), v.to_string());
                                }
                            }
                        }
                        return Ok(CommandOutput {
                            status: 0,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }
                    Some("-X") => {
                        if let Some(key) = args.get(1) {
                            values.remove(*key);
                        }
                        return Ok(CommandOutput {
                            status: 0,
                            stdout: String::new(),
                            stderr: String::new(),
                        });
                    }
                    _ => {}
                }
            }

            Ok(CommandOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn postfix_store(runner: Arc<dyn CommandRunner>, dir: &Path) -> PostfixRelayStore {
        PostfixRelayStore::with_runner(runner, dir.join("sasl_passwd"))
    }

    #[test]
    fn rollback_removes_keys_that_were_originally_absent() {
        // 安全回归测试（依据 Postfix 3.8.6 实测）：
        //
        // 若回滚用「写空串」代替「移除」，`smtp_sasl_security_options` 的默认值
        // `noplaintext, noanonymous` 会被抹掉 —— 一次静默的安全策略弱化。
        // 本测试固定「回滚必须移除原本不存在的键」。
        let dir = temp_dir("pfrollbackremove");
        let runner = Arc::new(RecordingRunner::new());
        let mut store = postfix_store(runner.clone(), &dir);

        // 从未设置过任何键 → 快照里全是 None。
        let snapshot = ConfigSnapshot {
            keys: vec![
                (KEY_RELAYHOST.to_string(), None),
                (KEY_SASL_SECURITY_OPTIONS.to_string(), None),
            ],
            credentials: None,
        };

        // 模拟「写入后回读不一致」触发回滚：直接调用回滚逻辑。
        assert!(rollback_snapshot(&mut store, &snapshot), "回滚应成功");

        // 必须调用 postconf -X 移除，而不是写空串。
        let calls = runner.calls();
        let removed: Vec<String> = calls
            .iter()
            .filter(|(p, a)| p == "postconf" && a.first().map(String::as_str) == Some("-X"))
            .filter_map(|(_, a)| a.get(1).cloned())
            .collect();
        assert!(
            removed.contains(&KEY_SASL_SECURITY_OPTIONS.to_string()),
            "必须用 postconf -X 移除原本未设置的 smtp_sasl_security_options，实际移除: {removed:?}"
        );
        assert!(
            removed.contains(&KEY_RELAYHOST.to_string()),
            "必须用 postconf -X 移除原本未设置的 relayhost"
        );

        // 且**不得**对这两个键写空串。
        let wrote_empty: Vec<String> = calls
            .iter()
            .filter(|(p, a)| p == "postconf" && a.first().map(String::as_str) == Some("-e"))
            .filter_map(|(_, a)| a.get(1).cloned())
            .filter(|assignment| assignment.ends_with('='))
            .collect();
        assert!(
            wrote_empty.is_empty(),
            "回滚不得用「写空串」代替移除 —— 那会抹掉 Postfix 的默认安全项，实际: {wrote_empty:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_reads_and_writes_through_postconf() {
        let dir = temp_dir("pfconf");
        let mut store = postfix_store(Arc::new(RecordingRunner::new()), &dir);

        assert_eq!(store.read_key(KEY_RELAYHOST).unwrap(), None);
        store.write_key(KEY_RELAYHOST, "[h]:587").unwrap();
        assert_eq!(
            store.read_key(KEY_RELAYHOST).unwrap().as_deref(),
            Some("[h]:587")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_reports_postconf_failure() {
        let dir = temp_dir("pffail");
        let mut store = postfix_store(
            Arc::new(RecordingRunner::new().failing_on("postconf")),
            &dir,
        );

        let err = store.read_key(KEY_RELAYHOST).unwrap_err();
        assert!(
            err.to_string().contains("postconf"),
            "应报出是 postconf 失败: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_writes_credentials_atomically_then_runs_postmap() {
        let dir = temp_dir("pfmap");
        let runner = Arc::new(RecordingRunner::new());
        let mut store = postfix_store(runner.clone(), &dir);

        store.write_credentials("[h]:587 apikey:secret\n").unwrap();

        // 文件已落盘且内容正确。
        assert_eq!(
            std::fs::read_to_string(dir.join("sasl_passwd")).unwrap(),
            "[h]:587 apikey:secret\n"
        );
        // 紧接着必须 postmap（§5.9.6 顺序）。
        let programs = runner.programs();
        assert_eq!(
            programs,
            vec!["postmap".to_string()],
            "写凭证后必须立即 postmap，实际: {programs:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn postfix_store_writes_credentials_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("pfmode");
        let mut store = postfix_store(Arc::new(RecordingRunner::new()), &dir);
        store.write_credentials("[h]:587 apikey:secret\n").unwrap();

        let mode = std::fs::metadata(dir.join("sasl_passwd"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "sasl_passwd 含明文口令且 key_permission_scan 要求 0600"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_reload_runs_check_then_reload() {
        let dir = temp_dir("pfreload");
        let runner = Arc::new(RecordingRunner::new());
        let mut store = postfix_store(runner.clone(), &dir);

        store.reload().unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 2, "应为 postfix check + postfix reload");
        assert_eq!(calls[0].0, "postfix");
        assert_eq!(calls[0].1, vec!["check".to_string()]);
        assert_eq!(calls[1].0, "postfix");
        assert_eq!(calls[1].1, vec!["reload".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_reload_failure_is_reported() {
        let dir = temp_dir("pfreloadfail");
        let mut store = postfix_store(Arc::new(RecordingRunner::new().failing_on("postfix")), &dir);
        assert!(store.reload().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_remove_credentials_clears_file_and_hash_db() {
        let dir = temp_dir("pfremove");
        let mut store = postfix_store(Arc::new(RecordingRunner::new()), &dir);
        store.write_credentials("creds\n").unwrap();
        std::fs::write(dir.join("sasl_passwd.db"), b"db").unwrap();

        store.remove_credentials().unwrap();

        assert!(!dir.join("sasl_passwd").exists());
        assert!(
            !dir.join("sasl_passwd.db").exists(),
            "postmap 生成的 .db 也必须清除"
        );
        // 幂等。
        store.remove_credentials().unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_full_apply_sequence_is_correct() {
        // 顺序断言：快照（postconf -h）→ 写凭证 + postmap → postconf -e → postfix check/reload → 回读。
        let dir = temp_dir("pfseq");
        let runner = Arc::new(RecordingRunner::new());
        let mut store = postfix_store(runner.clone(), &dir);

        let result = apply_relay(&mut store, &endpoint(587, "STARTTLS"), &passed_test()).unwrap();
        assert!(result.applied);
        assert_eq!(result.relayhost, "[smtp.sendgrid.net]:587");

        let calls = runner.calls();
        let index_of = |predicate: &dyn Fn(&str, &Vec<String>) -> bool| -> Option<usize> {
            calls.iter().position(|(p, a)| predicate(p, a))
        };

        let postmap = index_of(&|p, _| p == "postmap").expect("必须调用 postmap");
        let first_postconf_set =
            index_of(&|p, a| p == "postconf" && a.first().map(String::as_str) == Some("-e"))
                .expect("必须调用 postconf -e");
        let postfix_check =
            index_of(&|p, a| p == "postfix" && a.first().map(String::as_str) == Some("check"))
                .expect("必须调用 postfix check");

        // 快照读取必须用 `-n`（显式配置）而不是 `-h`（有效值含默认）。
        // 用 `-h` 会把从未设置过的键记成「已设置」，回滚时便无法正确移除它们 ——
        // 实测：对 `smtp_sasl_security_options` 写空串会抹掉默认的 noplaintext 保护。
        assert!(
            index_of(&|p, a| p == "postconf" && a.first().map(String::as_str) == Some("-n"))
                .is_some(),
            "必须用 postconf -n 取快照（显式配置语义）"
        );
        assert!(
            index_of(&|p, a| p == "postconf" && a.first().map(String::as_str) == Some("-h"))
                .is_none(),
            "快照与回读不得使用 postconf -h —— 它无法区分「未设置」与「设为默认值」"
        );

        assert!(
            postmap < first_postconf_set,
            "写凭证后的 postmap 必须早于 postconf -e（实际 postmap@{postmap} set@{first_postconf_set}）"
        );
        assert!(
            first_postconf_set < postfix_check,
            "postconf -e 必须早于 postfix check"
        );

        // 磁盘上的凭证文件必须存在，且 postmap 确实指向它。
        assert!(dir.join("sasl_passwd").exists());
        let postmap_args = &calls[postmap].1;
        assert_eq!(
            postmap_args.first().map(String::as_str),
            Some(dir.join("sasl_passwd").to_string_lossy().as_ref())
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_readback_mismatch_triggers_rollback() {
        // 运行器忽略写入 → 回读与期望不符 → 必须回滚。
        let dir = temp_dir("pflies");
        let runner = Arc::new(RecordingRunner::new().with_ignored_writes());
        let mut store = postfix_store(runner, &dir);

        let failure =
            apply_relay(&mut store, &endpoint(587, "STARTTLS"), &passed_test()).unwrap_err();

        assert!(
            failure
                .error
                .to_string()
                .contains(crate::relay_apply::ERR_RELAYHOST_VERIFY_FAILED),
            "实际错误: {}",
            failure.error
        );
        // 回滚应删掉本次写入的凭证。
        assert!(!dir.join("sasl_passwd").exists(), "回滚应移除凭证文件");

        std::fs::remove_dir_all(&dir).ok();
    }

    // ───────────────── 旧 sasl_passwd 解析（迁移用） ─────────────────

    #[test]
    fn parses_layman_sasl_passwd_lines() {
        let entries = parse_sasl_passwd(
            "[smtp.sendgrid.net]:587 apikey:SG.abc123\n\
             [smtp.example.com]:465 user@example.com:p@ss:with:colons\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].relayhost, "[smtp.sendgrid.net]:587");
        assert_eq!(entries[0].username, "apikey");
        assert_eq!(entries[0].password, "SG.abc123");
        // 口令里的冒号必须保留。
        assert_eq!(entries[1].password, "p@ss:with:colons");
    }

    #[test]
    fn sasl_parsing_skips_comments_and_blanks() {
        let entries = parse_sasl_passwd("# comment\n\n   \n[h]:25 u:p\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relayhost, "[h]:25");
    }

    #[test]
    fn sasl_parsing_tolerates_lines_without_credentials() {
        let entries = parse_sasl_passwd("[h]:25\n[smtp.x]:587 onlyuser\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].username, "");
        assert_eq!(entries[0].password, "");
        assert_eq!(entries[1].username, "onlyuser");
        assert_eq!(entries[1].password, "");
    }

    #[test]
    fn sasl_parsing_never_panics_on_odd_input() {
        for weird in ["", "   ", "\t", "#", "::::", "\u{0}"] {
            let _ = parse_sasl_passwd(weird);
        }
    }

    #[test]
    fn hash_db_path_appends_db_suffix() {
        assert_eq!(
            hash_db_path(Path::new("/etc/postfix/sasl_passwd")),
            PathBuf::from("/etc/postfix/sasl_passwd.db")
        );
    }

    #[test]
    fn resolve_program_passes_through_absolute_paths() {
        assert_eq!(resolve_program("/usr/sbin/postconf"), "/usr/sbin/postconf");
    }
}
