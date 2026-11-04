use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use mailstack_core::Paths;

use crate::error::SmtpError;
use crate::relay_apply::{RelayConfigStore, SASL_PASSWORD_PATH};

pub use mailstack_core::exec::{
    resolve_program, CommandOutput, CommandRunner, SystemCommandRunner,
};

pub struct PostfixRelayStore {
    runner: Arc<dyn CommandRunner>,

    pub sasl_passwd: PathBuf,
    postconf: String,
    postmap: String,
    postfix: String,
}

impl PostfixRelayStore {
    pub fn production() -> Self {
        Self {
            runner: Arc::new(SystemCommandRunner),
            sasl_passwd: PathBuf::from(SASL_PASSWORD_PATH),
            postconf: "postconf".to_string(),
            postmap: "postmap".to_string(),
            postfix: "postfix".to_string(),
        }
    }

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

        Ok(if value.is_empty() { None } else { Some(value) })
    }

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

    fn write_credentials(&mut self, content: &str) -> Result<(), SmtpError> {
        mailstack_core::atomic::atomic_as(&self.sasl_passwd, content.as_bytes(), 0o600, None)?;

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

pub use mailstack_core::exec::hash_db_path;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslEntry {
    pub relayhost: String,
    pub username: String,
    pub password: String,
}

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

        serde_json::from_str(&text)
            .map_err(|e| SmtpError::Config(format!("parse {}: {e}", self.config_path.display())))
    }

    fn store(&self, doc: &BTreeMap<String, String>) -> Result<(), SmtpError> {
        let data = format!("{}\n", serde_json::to_string_pretty(doc)?);
        mailstack_core::atomic::atomic_as(&self.config_path, data.as_bytes(), 0o600, None)?;
        Ok(())
    }

    fn update<F>(&self, mutate: F) -> Result<(), SmtpError>
    where
        F: FnOnce(&mut BTreeMap<String, String>),
    {
        let path = self.config_path.clone();

        mailstack_core::atomic::locked(&path, || {
            let mut doc = self.load().map_err(to_core_error)?;
            mutate(&mut doc);
            self.store(&doc).map_err(to_core_error)
        })?;
        Ok(())
    }
}

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

    fn reload(&mut self) -> Result<(), SmtpError> {
        Ok(())
    }
}

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
        let dir = temp_dir("nativee2e");
        let path = dir.join("relay.json");
        let mut store = NativeRelayStore::at(&path);

        let result = apply_relay(&mut store, &endpoint(587, "STARTTLS"), &passed_test()).unwrap();

        assert!(result.applied);
        assert_eq!(result.relayhost, "[smtp.sendgrid.net]:587");

        let raw = std::fs::read_to_string(&path).unwrap();
        let doc: BTreeMap<String, String> = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc[KEY_RELAYHOST], "[smtp.sendgrid.net]:587");
        assert_eq!(doc[KEY_SASL_AUTH_ENABLE], "yes");
        assert_eq!(doc[KEY_TLS_SECURITY_LEVEL], "encrypt");
        assert_eq!(doc[KEY_SASL_SECURITY_OPTIONS], "noanonymous");
        assert!(doc[CREDENTIALS_KEY].contains("apikey:"));

        assert_eq!(
            doc[KEY_TLS_WRAPPERMODE], "no",
            "587 + STARTTLS 必须显式写 no（而不是留空/不写）"
        );
        assert!(!result.wrappermode, "回读值必须为 false");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn native_store_end_to_end_writes_wrappermode_for_465() {
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

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,

        values: Mutex<BTreeMap<String, String>>,

        fail_on: Mutex<Vec<String>>,

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
        let dir = temp_dir("pfrollbackremove");
        let runner = Arc::new(RecordingRunner::new());
        let mut store = postfix_store(runner.clone(), &dir);

        let snapshot = ConfigSnapshot {
            keys: vec![
                (KEY_RELAYHOST.to_string(), None),
                (KEY_SASL_SECURITY_OPTIONS.to_string(), None),
            ],
            credentials: None,
        };

        assert!(rollback_snapshot(&mut store, &snapshot), "回滚应成功");

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

        assert_eq!(
            std::fs::read_to_string(dir.join("sasl_passwd")).unwrap(),
            "[h]:587 apikey:secret\n"
        );

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

        store.remove_credentials().unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn postfix_store_full_apply_sequence_is_correct() {
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

        assert!(!dir.join("sasl_passwd").exists(), "回滚应移除凭证文件");

        std::fs::remove_dir_all(&dir).ok();
    }

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
