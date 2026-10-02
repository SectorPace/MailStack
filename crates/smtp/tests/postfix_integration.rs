//! Postfix 载体的**真实**集成测试。
//!
//! 单元测试用注入的运行器验证了「命令序列与参数」，但**无法**验证我对真实
//! `postconf` / `postmap` 输出格式的假设。最典型的一条：
//!
//! > `postconf -h <key>` 对**未设置**的键是否真的输出空行？
//!
//! 如果这条假设错了，`read_key` 会把「未设置」误判成「设置成了某个值」，
//! 于是快照与回读全部失真。这类错误在注入运行器的测试里**永远发现不了**。
//!
//! 因此本测试需要真实的 Postfix：
//!
//! * 正常情况下（CI 里没装 Postfix）→ 打印 SKIP 并直接返回，不失败
//! * 设置 `MAILSTACK_REQUIRE_POSTFIX=1` 时（容器里跑）→ 缺少 Postfix 即**失败**
//!
//! 后者是关键：否则「容器没装成功」会被伪装成「测试通过」。
//!
//! 运行方式见 `deploy/test-relay-postfix-in-container.sh`。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use mailstack_smtp::relay_apply::{RelayConfigStore, KEY_RELAYHOST};
use mailstack_smtp::relay_store::PostfixRelayStore;

/// 复用一个与中继无关的键，避免踩到真实中继配置。
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

/// 前置检查 + 串行化守卫。
///
/// **两个必须同时满足的条件**：
///
/// 1. **必须显式开启**：这些测试会修改宿主机**真实的** `/etc/postfix/main.cf`。
///    只要环境里有 Postfix 就跑，会在用户不知情的情况下改动系统配置 ——
///    本机（WSL）就装着 Postfix，第一次写这组测试时踩到了这一点。
///    故改为必须设置 `MAILSTACK_POSTFIX_INTEGRATION=1` 才执行。
/// 2. **必须串行**：所有测试共用同一个 `main.cf`，并行会互相覆盖。
///    实测症状是两个测试交错后 `read_key` 读回 `Some("")` 而不是写入的值。
///    用静态 Mutex 保证串行，不依赖调用方是否传 `--test-threads=1`。
///
/// 返回 `None` 表示应跳过。
fn guard(test_name: &str) -> Option<std::sync::MutexGuard<'static, ()>> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // 某个测试 panic 后互斥锁会中毒；这里恢复它，避免连带其它测试全部失败。
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
            // 显式要求时必须失败 —— 否则「容器没装成功」会被伪装成「测试通过」。
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

/// 读/写往返：验证真实的 `postconf -n` 与 `postconf -e` 行为。
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

    // 保存原值以便还原。
    let original = store.read_key(SCRATCH_KEY).unwrap();

    // ── 关键假设 1：移除后读回应为 None ──
    //
    // 注意这里用 remove_key 而不是「写空串」：写空串会让 -n 返回 `key =`，
    // 即「显式设为空」——两者语义不同（见 RelayConfigStore::read_key 文档）。
    store.remove_key(SCRATCH_KEY).unwrap();
    assert_eq!(
        store.read_key(SCRATCH_KEY).unwrap(),
        None,
        "postconf -X 移除后，read_key 必须返回 None"
    );

    // ── 关键假设 2：写入后能原样读回 ──
    store.write_key(SCRATCH_KEY, "noanonymous").unwrap();
    assert_eq!(
        store.read_key(SCRATCH_KEY).unwrap().as_deref(),
        Some("noanonymous"),
        "postconf -e / -n 必须能往返一个普通值"
    );

    // ── 关键假设 3：含方括号与冒号的 relayhost 形式不被改写 ──
    let original_relayhost = store.read_key(KEY_RELAYHOST).unwrap();
    store
        .write_key(KEY_RELAYHOST, "[smtp.sendgrid.net]:587")
        .unwrap();
    assert_eq!(
        store.read_key(KEY_RELAYHOST).unwrap().as_deref(),
        Some("[smtp.sendgrid.net]:587"),
        "relayhost 的 [host]:port 形式必须原样往返 —— 回读校验直接依赖它"
    );

    // 还原：原本有值则写回，原本没有则移除。
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

/// **语义差异的关键验证**：`-h`（有效值）与 `-n`（显式）确实不同，
/// 且「移除」与「设为空」对默认安全项的影响不同。
///
/// 这条测试是回滚逻辑安全性的依据 —— 若哪天 Postfix 改变语义，
/// 它会先失败，而不是让回滚静默地弱化安全策略。
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

    // 1) 移除后，有效值应回到默认的 noplaintext 保护。
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

    // 2) 设为空则会把默认保护抹掉 —— 这正是「写空串」不能用于回滚的原因。
    store.write_key(SCRATCH_KEY, "").unwrap();
    let after_blank = store.effective_value(SCRATCH_KEY).unwrap();
    assert_ne!(
        after_blank.as_deref(),
        Some("noplaintext, noanonymous"),
        "设为空必须能观测到「默认保护被抹掉」这一事实，否则本测试失去意义"
    );
    eprintln!("实测确认：移除后 effective={after_remove:?}，设为空后 effective={after_blank:?}");

    // 还原。
    store.remove_key(SCRATCH_KEY).unwrap();
    if let Some(v) = original {
        store.write_key(SCRATCH_KEY, &v).unwrap();
    }
    let _ = original_effective;

    std::fs::remove_dir_all(&dir).ok();
}

/// 凭证写入 + `postmap`：验证 hash 表确实被生成。
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

    // 明文文件内容逐字正确。
    assert_eq!(
        std::fs::read_to_string(&sasl).unwrap(),
        "[smtp.sendgrid.net]:587 apikey:SG.integration\n"
    );

    // postmap 必须真的生成了 .db —— 这是「写凭证后 postmap」这一步的实证。
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

    // 权限：0600（key_permission_scan 会断言这一点）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sasl).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "sasl_passwd 必须是 0600");
    }

    // 删除时应同时清掉 .db。
    store.remove_credentials().unwrap();
    assert!(!sasl.exists());
    assert!(!db.exists(), "remove_credentials 应连 hash 表一起清除");

    std::fs::remove_dir_all(&dir).ok();
}

/// `postfix check` 必须真的能校验配置。
#[test]
fn real_postfix_check_validates_configuration() {
    let _guard = match guard("real_postfix_check_validates_configuration") {
        Some(g) => g,
        None => return,
    };

    // 直接调用真实命令，确认它可用且返回 0。
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

/// `reload()` 的完整路径。
///
/// `postfix reload` 需要守护进程在运行；容器脚本会先 `postfix start`。
/// 若守护进程没起来，则只要求**干净失败**（带诊断信息），不要求成功 ——
/// 因为本测试要验证的是「命令被正确调用且失败能被观测」，而不是「容器里
/// Postfix 一定在跑」。
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

/// 未设置的中继键在真实 Postfix 上也应是「未设置」。
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
