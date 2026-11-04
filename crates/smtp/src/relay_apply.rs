use std::sync::{LazyLock, Mutex};

use serde_json::{json, Value};

use crate::error::SmtpError;
use crate::stages::RelayTestResult;
use crate::validate::RelayEndpoint;

pub const KEY_RELAYHOST: &str = "relayhost";
pub const KEY_SASL_AUTH_ENABLE: &str = "smtp_sasl_auth_enable";
pub const KEY_SASL_PASSWORD_MAPS: &str = "smtp_sasl_password_maps";
pub const KEY_SASL_SECURITY_OPTIONS: &str = "smtp_sasl_security_options";
pub const KEY_TLS_SECURITY_LEVEL: &str = "smtp_tls_security_level";

pub const KEY_TLS_WRAPPERMODE: &str = "smtp_tls_wrappermode";

pub const SASL_PASSWORD_PATH: &str = "/etc/postfix/sasl_passwd";

pub const ERR_RELAYHOST_VERIFY_FAILED: &str = "Postfix relayhost verification failed";

static APPLY_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    pub relayhost: String,

    pub keys: Vec<(String, String)>,

    pub credentials: Option<String>,

    pub wrappermode: bool,
}

impl RelayPlan {
    pub fn key(&self, name: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn plan_relay_apply(endpoint: &RelayEndpoint) -> RelayPlan {
    let relayhost = endpoint.relayhost();
    let wrappermode = endpoint.requires_wrappermode();
    let has_credentials = endpoint.has_credentials();

    let keys = vec![
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
        (
            KEY_TLS_WRAPPERMODE.to_string(),
            if wrappermode { "yes" } else { "no" }.to_string(),
        ),
    ];

    let credentials = if has_credentials {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub keys: Vec<(String, Option<String>)>,

    pub credentials: Option<String>,
}

pub trait RelayConfigStore {
    fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError>;

    fn write_key(&mut self, key: &str, value: &str) -> Result<(), SmtpError>;

    fn remove_key(&mut self, key: &str) -> Result<(), SmtpError>;

    fn read_credentials(&mut self) -> Result<Option<String>, SmtpError>;

    fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError>;

    fn remove_credentials(&mut self) -> Result<(), SmtpError>;

    fn reload(&mut self) -> Result<(), SmtpError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayApplyResult {
    pub applied: bool,

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

#[derive(Debug)]
pub struct RelayApplyFailure {
    pub error: SmtpError,

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

pub fn apply_relay(
    store: &mut dyn RelayConfigStore,
    endpoint: &RelayEndpoint,
    test: &RelayTestResult,
) -> Result<RelayApplyResult, RelayApplyFailure> {
    let _apply_guard = APPLY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

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

    let snapshot = match take_snapshot(store, &plan) {
        Ok(s) => s,
        Err(e) => {
            return Err(RelayApplyFailure {
                error: e,
                rolled_back: false,
            })
        }
    };

    if let Err(e) = write_all(store, &plan) {
        let rolled_back = rollback(store, &snapshot);
        return Err(RelayApplyFailure {
            error: e,
            rolled_back,
        });
    }

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

    let observed_wrappermode = match store.read_key(KEY_TLS_WRAPPERMODE) {
        Ok(value) => value
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| value.eq_ignore_ascii_case("yes")),
        Err(error) => {
            let rolled_back = rollback(store, &snapshot);
            return Err(RelayApplyFailure { error, rolled_back });
        }
    };
    if observed_wrappermode != plan.wrappermode {
        let rolled_back = rollback(store, &snapshot);
        return Err(RelayApplyFailure {
            error: SmtpError::Rejected(format!(
                "{ERR_RELAYHOST_VERIFY_FAILED}: wrappermode expected {} but observed {}",
                plan.wrappermode, observed_wrappermode
            )),
            rolled_back,
        });
    }

    Ok(RelayApplyResult {
        applied: true,
        relayhost: observed.trim().to_string(),
        wrappermode: observed_wrappermode,
    })
}

const APPLY_WRITTEN_KEYS: &[&str] = &[
    KEY_RELAYHOST,
    KEY_SASL_AUTH_ENABLE,
    KEY_SASL_PASSWORD_MAPS,
    KEY_SASL_SECURITY_OPTIONS,
    KEY_TLS_SECURITY_LEVEL,
    KEY_TLS_WRAPPERMODE,
];

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

    let credentials = store.read_credentials()?;
    Ok(ConfigSnapshot { keys, credentials })
}

fn write_all(store: &mut dyn RelayConfigStore, plan: &RelayPlan) -> Result<(), SmtpError> {
    match &plan.credentials {
        Some(content) => store.write_credentials(content)?,
        None => store.remove_credentials()?,
    }
    for (key, value) in &plan.keys {
        store.write_key(key, value)?;
    }
    store.reload()
}

pub fn rollback_snapshot(store: &mut dyn RelayConfigStore, snapshot: &ConfigSnapshot) -> bool {
    rollback(store, snapshot)
}

fn rollback(store: &mut dyn RelayConfigStore, snapshot: &ConfigSnapshot) -> bool {
    let mut ok = true;

    let credentials_result = match &snapshot.credentials {
        Some(content) => store.write_credentials(content),
        None => store.remove_credentials(),
    };
    if credentials_result.is_err() {
        ok = false;
    }

    for (key, previous) in &snapshot.keys {
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

    #[derive(Default)]
    struct InMemoryRelayStore {
        keys: HashMap<String, String>,
        credentials: Option<String>,

        fail_once_on: Vec<&'static str>,

        fail_always_on: Vec<&'static str>,
        reloads: usize,
    }

    impl InMemoryRelayStore {
        fn new() -> Self {
            Self::default()
        }

        fn failing_once_on(mut self, what: &'static str) -> Self {
            self.fail_once_on.push(what);
            self
        }

        fn failing_always_on(mut self, what: &'static str) -> Self {
            self.fail_always_on.push(what);
            self
        }

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
        let plan = plan_relay_apply(&endpoint(465, "SSL/TLS", "apikey", "secret"));
        assert_eq!(plan.key(KEY_TLS_WRAPPERMODE), Some("yes"));
        assert!(plan.wrappermode);
    }

    #[test]
    fn plan_writes_wrappermode_explicitly_for_587_starttls() {
        let plan = plan_relay_apply(&endpoint(587, "STARTTLS", "apikey", "secret"));
        assert_eq!(plan.key(KEY_TLS_WRAPPERMODE), Some("no"));
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

    #[test]
    fn refuses_to_write_anything_when_the_test_did_not_pass() {
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
        struct LyingStore {
            inner: InMemoryRelayStore,
            writes_done: bool,
        }

        impl RelayConfigStore for LyingStore {
            fn read_key(&mut self, key: &str) -> Result<Option<String>, SmtpError> {
                if key == KEY_RELAYHOST && self.writes_done {
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
    fn switching_from_465_to_587_removes_the_stale_wrappermode() {
        let mut store = InMemoryRelayStore::new();
        apply_relay(
            &mut store,
            &endpoint(465, "SSL/TLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(store.keys[KEY_TLS_WRAPPERMODE], "yes");

        let result = apply_relay(
            &mut store,
            &endpoint(587, "STARTTLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(
            store.keys[KEY_TLS_WRAPPERMODE], "no",
            "切到 STARTTLS 后必须显式写 no，不得残留 yes"
        );
        assert!(!result.wrappermode, "落地结果应反映回读值");
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

    #[test]
    fn clear_relay_removes_every_key_apply_writes_and_is_idempotent() {
        let mut store = InMemoryRelayStore::new();
        apply_relay(
            &mut store,
            &endpoint(465, "SSL/TLS", "apikey", "secret"),
            &passed_test(),
        )
        .unwrap();
        assert_eq!(
            store.keys.len(),
            6,
            "apply 应已写入 6 个键（含 wrappermode）"
        );
        assert!(store.credentials.is_some());

        let reloads_before = store.reloads;
        clear_relay(&mut store).unwrap();
        assert!(
            store.keys.is_empty(),
            "全部键必须被清除，实际: {:?}",
            store.keys
        );
        assert!(store.credentials.is_none(), "凭证文件必须随 clear 一并删除");
        assert!(
            store.reloads > reloads_before,
            "清除后应重载（Postfix 载体靠它生效）"
        );

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
