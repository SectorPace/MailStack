use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mailstack_smtp::relay_apply::{RelayConfigStore, KEY_RELAYHOST};
use mailstack_smtp::relay_store::PostfixRelayStore;

const SCRATCH_KEY: &str = "smtp_sasl_security_options";

fn postfix_binaries_present() -> bool {
    let found: Vec<&str> = ["postconf", "postmap", "postfix"]
        .into_iter()
        .filter(|bin| resolve(bin).is_some())
        .collect();
    found.len() == 3
}

fn resolve(program: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(
        ["/usr/sbin", "/sbin", "/usr/local/sbin"]
            .iter()
            .map(PathBuf::from),
    );
    dirs.into_iter()
        .map(|d| d.join(program))
        .find(|p| p.is_file())
}

fn guard(test_name: &str) -> Option<std::sync::MutexGuard<'static, ()>> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let lock = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

    let enabled = std::env::var("MAILSTACK_POSTFIX_INTEGRATION").is_ok();
    if !enabled {
        eprintln!(
            "SKIP {test_name}: 未设置 MAILSTACK_POSTFIX_INTEGRATION=1。\
             该测试会修改真实 /etc/postfix/main.cf，故必须显式开启。\
             推荐用 deploy/test-relay-postfix-in-container.sh 在一次性容器中运行。"
        );
        return None;
    }

    if !postfix_binaries_present() {
        let message = format!(
            "{test_name}: postconf/postmap/postfix 不可用。\
             请用 deploy/test-relay-postfix-in-container.sh 在容器中运行。"
        );
        if std::env::var("MAILSTACK_REQUIRE_POSTFIX").is_ok() {
            panic!("{message} 但 MAILSTACK_REQUIRE_POSTFIX 已设置，因此判定为失败。");
        }
        eprintln!("SKIP {message}");
        return None;
    }

    Some(lock)
}

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "mailstack-pfint-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn real_postconf_round_trips_values_and_reports_unset_keys_as_absent() {
    let _guard = match guard("real_postconf_round_trips_values_and_reports_unset_keys_as_absent") {
        Some(g) => g,
        None => return,
    };

    let dir = temp_dir("roundtrip");
    let mut store = PostfixRelayStore::with_runner(
        std::sync::Arc::new(mailstack_smtp::SystemCommandRunner),
        dir.join("sasl_passwd"),
    );

    let original = store.read_key(SCRATCH_KEY).unwrap();

    store.remove_key(SCRATCH_KEY).unwrap();
    assert_eq!(
        store.read_key(SCRATCH_KEY).unwrap(),
        None,
        "postconf -X 移除后，read_key 必须返回 None"
    );

    store.write_key(SCRATCH_KEY, "noanonymous").unwrap();
    assert_eq!(
        store.read_key(SCRATCH_KEY).unwrap().as_deref(),
        Some("noanonymous"),
        "postconf -e / -n 必须能往返一个普通值"
    );

    let original_relayhost = store.read_key(KEY_RELAYHOST).unwrap();
    store
        .write_key(KEY_RELAYHOST, "[smtp.sendgrid.net]:587")
        .unwrap();
    assert_eq!(
        store.read_key(KEY_RELAYHOST).unwrap().as_deref(),
        Some("[smtp.sendgrid.net]:587"),
        "relayhost 的 [host]:port 形式必须原样往返 —— 回读校验直接依赖它"
    );

    match original {
        Some(v) => store.write_key(SCRATCH_KEY, &v).unwrap(),
        None => store.remove_key(SCRATCH_KEY).unwrap(),
    }
    match original_relayhost {
        Some(v) => store.write_key(KEY_RELAYHOST, &v).unwrap(),
        None => store.remove_key(KEY_RELAYHOST).unwrap(),
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn removing_a_key_restores_its_default_while_blanking_it_destroys_the_default() {
    let _guard =
        match guard("removing_a_key_restores_its_default_while_blanking_it_destroys_the_default") {
            Some(g) => g,
            None => return,
        };

    let dir = temp_dir("defaults");
    let mut store = PostfixRelayStore::with_runner(
        std::sync::Arc::new(mailstack_smtp::SystemCommandRunner),
        dir.join("sasl_passwd"),
    );

    let original = store.read_key(SCRATCH_KEY).unwrap();
    let original_effective = store.effective_value(SCRATCH_KEY).unwrap();

    store.remove_key(SCRATCH_KEY).unwrap();
    assert_eq!(
        store.read_key(SCRATCH_KEY).unwrap(),
        None,
        "移除后不应再是「显式设置」"
    );
    let after_remove = store.effective_value(SCRATCH_KEY).unwrap();
    assert_eq!(
        after_remove.as_deref(),
        Some("noplaintext, noanonymous"),
        "移除后有效值必须回到默认的 noplaintext 保护"
    );

    store.write_key(SCRATCH_KEY, "").unwrap();
    let after_blank = store.effective_value(SCRATCH_KEY).unwrap();
    assert_ne!(
        after_blank.as_deref(),
        Some("noplaintext, noanonymous"),
        "设为空必须能观测到「默认保护被抹掉」这一事实，否则本测试失去意义"
    );
    eprintln!("实测确认：移除后 effective={after_remove:?}，设为空后 effective={after_blank:?}");

    store.remove_key(SCRATCH_KEY).unwrap();
    if let Some(v) = original {
        store.write_key(SCRATCH_KEY, &v).unwrap();
    }
    let _ = original_effective;

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn real_postmap_builds_the_hash_table_from_sasl_passwd() {
    let _guard = match guard("real_postmap_builds_the_hash_table_from_sasl_passwd") {
        Some(g) => g,
        None => return,
    };

    let dir = temp_dir("postmap");
    let sasl = dir.join("sasl_passwd");
    let mut store = PostfixRelayStore::with_runner(
        std::sync::Arc::new(mailstack_smtp::SystemCommandRunner),
        sasl.clone(),
    );

    store
        .write_credentials("[smtp.sendgrid.net]:587 apikey:SG.integration\n")
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(&sasl).unwrap(),
        "[smtp.sendgrid.net]:587 apikey:SG.integration\n"
    );

    let db = mailstack_smtp::relay_store::hash_db_path(&sasl);
    assert!(
        db.exists(),
        "postmap 应生成 hash 表 {}，实际目录内容: {:?}",
        db.display(),
        std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sasl).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sasl_passwd 必须是 0600");
    }

    store.remove_credentials().unwrap();
    assert!(!sasl.exists());
    assert!(!db.exists(), "remove_credentials 应连 hash 表一起清除");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn real_postfix_check_validates_configuration() {
    let _guard = match guard("real_postfix_check_validates_configuration") {
        Some(g) => g,
        None => return,
    };

    let output =
        std::process::Command::new(mailstack_smtp::relay_store::resolve_program("postfix"))
            .args(["check"])
            .output()
            .expect("应能执行 postfix check");

    assert!(
        output.status.success(),
        "postfix check 在容器里应成功，stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn real_reload_runs_check_then_reload() {
    let _guard = match guard("real_reload_runs_check_then_reload") {
        Some(g) => g,
        None => return,
    };

    let dir = temp_dir("reload");
    let mut store = PostfixRelayStore::with_runner(
        std::sync::Arc::new(mailstack_smtp::SystemCommandRunner),
        dir.join("sasl_passwd"),
    );

    match store.reload() {
        Ok(()) => {
            eprintln!("reload(): postfix check + reload 均成功（守护进程在运行）");
        }
        Err(e) => {
            let message = e.to_string();
            assert!(
                !message.trim().is_empty(),
                "reload 失败时必须带诊断信息，不能是空错误"
            );
            eprintln!("reload(): 守护进程未运行，如实报错 → {message}");
        }
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn real_postconf_reports_unset_relay_key_as_absent() {
    let _guard = match guard("real_postconf_reports_unset_relay_key_as_absent") {
        Some(g) => g,
        None => return,
    };

    let dir = temp_dir("unsetkey");
    let mut store = PostfixRelayStore::with_runner(
        std::sync::Arc::new(mailstack_smtp::SystemCommandRunner),
        dir.join("sasl_passwd"),
    );

    let original = store.read_key(KEY_RELAYHOST).unwrap();
    store.remove_key(KEY_RELAYHOST).unwrap();

    assert_eq!(
        store.read_key(KEY_RELAYHOST).unwrap(),
        None,
        "移除 relayhost 后必须读回 None"
    );

    if let Some(v) = original {
        store.write_key(KEY_RELAYHOST, &v).unwrap();
    }
    std::fs::remove_dir_all(&dir).ok();
}
