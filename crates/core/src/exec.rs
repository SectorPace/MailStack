//! 外部命令与服务控制原语（规格书 §5.7.4）。
//!
//! 存在的理由有两条：
//!
//! 1. **可测试**：让「调用 postconf / postmap / systemctl」的代码能在**没有装这些
//!    东西的机器上**被测试（注入记录型 runner 与环境探测即可）。
//! 2. **单一实现**：`postmap` 的语义（编译 hash 表 → `postfix check` → 重载）被
//!    store 的表文件与 smtp 的中继凭证两处使用，不能各写一遍。
//!
//! ## `service_ctl` 的降级链为什么值得认真实现
//!
//! 目标发行版横跨 systemd 与非 systemd（安装矩阵含 Rocky Linux 9 与 Alpine）。
//! 如果只认 `systemctl`，在非 systemd 主机上「重载 postfix」会静默失败 ——
//! 表文件写好了、hash 表也编译了，但 Postfix 仍在用旧配置读。因此降级链必须
//! **逐级按基线语义**实现，并且每一级都要有测试。

use std::path::{Path, PathBuf};

use crate::error::{CoreError, CoreResult};

/// 外部命令的执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// 失败时拼接一段可读的诊断文本。
    pub fn diagnostic(&self, program: &str) -> String {
        let detail = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        format!("{program} exited with {}: {detail}", self.status)
    }
}

/// 外部命令运行器。
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> CoreResult<CommandOutput>;

    /// 通过 **stdin** 把 `stdin` 喂给子进程后取回结果。
    ///
    /// 只有需要保密的输入才走这条路：`chpasswd` 的口令绝不能出现在 argv 里
    /// （`ps` 能看到整条命令行）。
    ///
    /// 默认实现**必须是明确报错**，不能静默丢弃输入：既有的测试 runner 大多只实现
    /// `run`，一旦某个动作走了这条路，它们应当**响亮失败**，而不是让子进程收到空
    /// 输入后以「口令设为空/格式错」这种误导性的方式失败。
    fn run_with_input(
        &self,
        program: &str,
        args: &[&str],
        stdin: &str,
    ) -> CoreResult<CommandOutput> {
        let _ = (args, stdin);
        Err(CoreError::invalid(format!(
            "{program}: 该 runner 未实现 stdin 注入（run_with_input）"
        )))
    }

    /// 带超时地运行外部命令。
    ///
    /// 与 [`CommandRunner::run_with_input`] 同一风格：默认实现**明确报错**，
    /// 既有的测试 runner 不必改动；一旦某个动作真的需要超时却用了没有超时能力的
    /// runner，它会**响亮失败**，而不是悄悄地无限期挂住。
    ///
    /// 存在理由：`acme.sh` 的申请/续期可能耗时数分钟，基线用 180/300/120 秒超时。
    /// 没有超时意味着一个卡住的 ACME 流程会永久占住调用方。
    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        timeout: std::time::Duration,
    ) -> CoreResult<CommandOutput> {
        let _ = (args, timeout);
        Err(CoreError::invalid(format!(
            "{program}: 该 runner 未实现超时（run_with_timeout）"
        )))
    }
}

/// 真实运行器。
#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> CoreResult<CommandOutput> {
        let resolved = resolve_program(program);
        let output = std::process::Command::new(&resolved)
            .args(args)
            .output()
            .map_err(|e| CoreError::invalid(format!("cannot run {resolved}: {e}")))?;

        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn run_with_input(
        &self,
        program: &str,
        args: &[&str],
        stdin: &str,
    ) -> CoreResult<CommandOutput> {
        use std::io::Write;
        use std::process::Stdio;

        let resolved = resolve_program(program);
        let mut child = std::process::Command::new(&resolved)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::invalid(format!("cannot run {resolved}: {e}")))?;

        // 写完后必须 drop 句柄以关闭管道，否则子进程会一直等 EOF。
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(stdin.as_bytes()).map_err(|e| {
                CoreError::invalid(format!("cannot write stdin to {resolved}: {e}"))
            })?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| CoreError::invalid(format!("cannot wait for {resolved}: {e}")))?;

        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        timeout: std::time::Duration,
    ) -> CoreResult<CommandOutput> {
        use std::process::Stdio;
        use std::time::Instant;

        let resolved = resolve_program(program);
        let mut child = std::process::Command::new(&resolved)
            .args(args)
            // 不继承调用方的 stdin：外部命令不该从助手进程偷读输入。
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::invalid(format!("cannot run {resolved}: {e}")))?;

        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(e) => {
                    return Err(CoreError::invalid(format!(
                        "cannot wait for {resolved}: {e}"
                    )))
                }
            }
            if Instant::now() >= deadline {
                // 超时必须 kill 并回收，否则会留下僵尸进程。
                let _ = child.kill();
                let _ = child.wait();
                return Ok(CommandOutput {
                    status: -1,
                    stdout: String::new(),
                    stderr: format!("{resolved} timed out after {timeout:?}"),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let output = child
            .wait_with_output()
            .map_err(|e| CoreError::invalid(format!("cannot wait for {resolved}: {e}")))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// 解析可执行文件路径：先查 `PATH`，再查常见 sbin 目录。
///
/// 与 `core.py` 的 `run()` 行为一致 —— 特权助手的 `PATH` 通常不含 `/usr/sbin`。
pub fn resolve_program(program: &str) -> String {
    if program.contains('/') {
        return program.to_string();
    }
    if let Some(found) = which(program) {
        return found;
    }
    for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"] {
        let candidate = format!("{dir}/{program}");
        if Path::new(&candidate).exists() {
            return candidate;
        }
    }
    program.to_string()
}

fn which(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

// ───────────────────────── 服务控制（§5.7.4） ─────────────────────────

/// 服务控制动作。
///
/// 用枚举而不是裸字符串：基线的 `service_ctl` 收到未知 verb 会一路走到最后的
/// `true`（静默什么都不做），那正是「配置改了但没人重载」这类问题的温床。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceVerb {
    Start,
    Stop,
    Restart,
    Reload,
}

impl ServiceVerb {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceVerb::Start => "start",
            ServiceVerb::Stop => "stop",
            ServiceVerb::Restart => "restart",
            ServiceVerb::Reload => "reload",
        }
    }

    /// 解析动词。**未知动词返回 `None`** —— 绝不回落到某个默认值：
    /// 基线的 `service_ctl` 收到未知 verb 会一路走到最后的 `true`（静默什么都不做），
    /// 那正是「配置改了但没人重载」这类问题的温床。调用方拿到 `None` 必须报错。
    ///
    /// 只读动词 `status` 刻意**不**在这里：它没有任何副作用，调用方直接读状态即可，
    /// 不需要经过这条「执行一条命令」的通道。
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "start" => Some(ServiceVerb::Start),
            "stop" => Some(ServiceVerb::Stop),
            "restart" => Some(ServiceVerb::Restart),
            "reload" => Some(ServiceVerb::Reload),
            _ => None,
        }
    }
}

/// 服务控制所需的环境探测。抽出来是为了让**整条降级链**可测 ——
/// 这条链一旦退化（例如永远命中第一级），在非 systemd 主机上就是静默不重载。
pub trait ServiceEnv: Send + Sync {
    /// 等价 `shutil.which(program).is_some()` —— **只查 `PATH`**，不查 sbin 目录。
    fn program_available(&self, program: &str) -> bool;

    /// 路径是否存在（`/run/systemd/system` 是否为目录、`/etc/init.d/<unit>` 等）。
    fn path_exists(&self, path: &Path) -> bool;
}

/// 真实环境探测。
#[derive(Debug, Default)]
pub struct SystemServiceEnv;

impl ServiceEnv for SystemServiceEnv {
    fn program_available(&self, program: &str) -> bool {
        which(program).is_some()
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// 实际命中的后端（用于测试与日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceBackend {
    Systemctl,
    Service,
    RcService,
    InitScript(PathBuf),
    /// `postfix <verb>` 专用分支。
    Postfix,
    /// `dovecot <verb|reload>` 专用分支。
    Dovecot,
    /// `fail2ban-client` 专用分支。
    Fail2ban,
    /// 所有分支都不适用：基线执行 `true`（等价于成功但什么都没做）。
    Noop,
}

/// 一次服务控制的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCtlOutcome {
    pub backend: ServiceBackend,
    /// 真正执行的命令；[`ServiceBackend::Noop`] 时为 `None`。
    pub output: Option<CommandOutput>,
}

impl ServiceCtlOutcome {
    /// 是否成功。`Noop` 视为成功 —— 与基线执行 `true` 的语义一致。
    pub fn success(&self) -> bool {
        match &self.output {
            Some(output) => output.success(),
            None => true,
        }
    }
}

/// 服务控制：按基线的**首命中**降级链执行（`core.py:579-600`）。
///
/// 顺序（与基线逐条对应，且是 `elif` 而非「逐个尝试」）：
///
/// 1. `systemctl`（且 `/run/systemd/system` 存在）
/// 2. `service`
/// 3. `rc-service`（`reload` 退化为 `restart` —— OpenRC 没有 reload 概念）
/// 4. `/etc/init.d/<unit>`
/// 5. 专用分支：`postfix` / `dovecot`（`restart` 退化为 `reload`）/ `fail2ban-client`
/// 6. 都不适用 → `Noop`
pub fn service_ctl(
    env: &dyn ServiceEnv,
    runner: &dyn CommandRunner,
    unit: &str,
    verb: ServiceVerb,
) -> ServiceCtlOutcome {
    let run = |program: &str, args: &[&str]| ServiceCtlOutcome {
        backend: match program {
            "systemctl" => ServiceBackend::Systemctl,
            "service" => ServiceBackend::Service,
            "rc-service" => ServiceBackend::RcService,
            "postfix" => ServiceBackend::Postfix,
            "dovecot" => ServiceBackend::Dovecot,
            "fail2ban-client" => ServiceBackend::Fail2ban,
            other => ServiceBackend::InitScript(PathBuf::from(other)),
        },
        output: runner.run(program, args).ok(),
    };

    if env.program_available("systemctl") && env.path_exists(Path::new("/run/systemd/system")) {
        return run("systemctl", &[verb.as_str(), unit]);
    }
    if env.program_available("service") {
        return run("service", &[unit, verb.as_str()]);
    }
    if env.program_available("rc-service") {
        let rc_verb = if verb == ServiceVerb::Reload {
            "restart"
        } else {
            verb.as_str()
        };
        return run("rc-service", &[unit, rc_verb]);
    }
    let init_script = PathBuf::from(format!("/etc/init.d/{unit}"));
    if env.path_exists(&init_script) {
        return ServiceCtlOutcome {
            backend: ServiceBackend::InitScript(init_script.clone()),
            output: runner
                .run(&init_script.to_string_lossy(), &[verb.as_str()])
                .ok(),
        };
    }
    if unit == "postfix" && env.program_available("postfix") {
        return run("postfix", &[verb.as_str()]);
    }
    if unit == "dovecot" && env.program_available("dovecot") {
        // Dovecot 没有 `restart`：它的等价动作是 `reload`。
        let dovecot_verb = if verb == ServiceVerb::Restart {
            "reload"
        } else {
            verb.as_str()
        };
        return run("dovecot", &[dovecot_verb]);
    }
    if unit == "fail2ban" && env.program_available("fail2ban-client") {
        let command = match verb {
            ServiceVerb::Start | ServiceVerb::Restart => Some("start"),
            ServiceVerb::Stop => Some("stop"),
            ServiceVerb::Reload => Some("reload"),
        };
        if let Some(command) = command {
            return run("fail2ban-client", &[command]);
        }
    }

    ServiceCtlOutcome {
        backend: ServiceBackend::Noop,
        output: None,
    }
}

/// 服务是否在运行：按基线的**逐级探测**（`core.py:602-619`）。
///
/// 注意这里是「逐个尝试、命中即真」，与 [`service_ctl`] 的首命中不同 ——
/// 探测要尽量给出一致的结论，而执行必须只走一条路。
pub fn is_service_active(env: &dyn ServiceEnv, runner: &dyn CommandRunner, unit: &str) -> bool {
    if env.program_available("systemctl") && env.path_exists(Path::new("/run/systemd/system")) {
        if let Ok(out) = runner.run("systemctl", &["is-active", "--quiet", unit]) {
            if out.success() {
                return true;
            }
        }
    }

    if env.program_available("service") {
        if let Ok(out) = runner.run("service", &[unit, "status"]) {
            let combined = format!("{}{}", out.stdout, out.stderr).to_lowercase();
            if out.success() || combined.contains("running") {
                return true;
            }
        }
    }

    if env.program_available("rc-service") {
        if let Ok(out) = runner.run("rc-service", &[unit, "status"]) {
            if out.success() {
                return true;
            }
        }
    }

    if unit == "fail2ban" {
        if env.path_exists(Path::new("/var/run/fail2ban/fail2ban.sock"))
            || env.path_exists(Path::new("/run/fail2ban/fail2ban.sock"))
        {
            return true;
        }
        if let Ok(out) = runner.run("fail2ban-client", &["ping"]) {
            if out.success() && out.stdout.to_lowercase().contains("pong") {
                return true;
            }
        }
    }

    match runner.run("pgrep", &["-f", unit]) {
        Ok(out) => out.success(),
        Err(_) => false,
    }
}

/// `postmap` 序列的每一步结果，供调用方与测试断言。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PostmapOutcome {
    /// `postmap <table>` 是否成功。
    pub postmap_ok: bool,
    /// `postfix check` 是否成功。
    pub check_ok: bool,
    /// 重载 Postfix 是否成功。
    pub reload_ok: bool,
}

/// 把表文件编译成 Postfix 的 hash 数据库，并让 Postfix 重读配置
/// （`core.py:765-772` 的 `postmap()`）。
///
/// 重载走 [`service_ctl`] 的降级链（基线用的就是 `service_ctl('postfix','reload')`），
/// 因此非 systemd 主机（OpenRC / sysv init）同样能重载。
///
/// **每一步失败都是非致命的**：原实现一律 `check=False`，靠 `warn()` 上报。
/// 这里保持同样的语义 —— 但把结果返回给调用方，因为「hash 表没编译成功」是一个
/// 值得让上层知道的事实（写表成功但 Postfix 仍在读旧表）。
///
/// 刻意**不**返回 `Result`：写表本身已经成功，postmap 失败不该让整个操作报错回滚。
pub fn postmap_and_reload(
    env: &dyn ServiceEnv,
    runner: &dyn CommandRunner,
    table: &Path,
) -> PostmapOutcome {
    let table_str = table.to_string_lossy().to_string();

    let postmap_ok = match runner.run("postmap", &[table_str.as_str()]) {
        Ok(out) => {
            if !out.success() {
                crate::warn::warn_with_detail("postmap", &out.diagnostic("postmap"));
            }
            out.success()
        }
        Err(e) => {
            crate::warn::warn_with_detail("postmap", &e.to_string());
            false
        }
    };

    let check_ok = match runner.run("postfix", &["check"]) {
        Ok(out) => {
            if !out.success() {
                crate::warn::warn_with_detail("postfix check", &out.diagnostic("postfix check"));
            }
            out.success()
        }
        Err(e) => {
            crate::warn::warn_with_detail("postfix check", &e.to_string());
            false
        }
    };

    let reload = service_ctl(env, runner, "postfix", ServiceVerb::Reload);
    if !reload.success() {
        if let Some(output) = &reload.output {
            crate::warn::warn_with_detail("postfix reload", &output.diagnostic("postfix reload"));
        }
    }

    PostmapOutcome {
        postmap_ok,
        check_ok,
        reload_ok: reload.success(),
    }
}

/// 表文件对应的 hash 数据库路径（`postmap` 的产物）。
///
/// Postfix 在同目录下生成 `<name>.db`（Berkeley DB 默认后缀）。
pub fn hash_db_path(table: &Path) -> PathBuf {
    let name = table
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    table.with_file_name(format!("{name}.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 记录调用并按脚本返回结果。
    struct RecordingRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        postmap_status: i32,
        check_status: i32,
        reload_status: i32,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                postmap_status: 0,
                check_status: 0,
                reload_status: 0,
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn programs(&self) -> Vec<String> {
            self.calls().into_iter().map(|(p, _)| p).collect()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str]) -> CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            let status = match program {
                "postmap" => self.postmap_status,
                "postfix" if args.first() == Some(&"check") => self.check_status,
                "postfix" => self.reload_status,
                _ => 0,
            };
            Ok(CommandOutput {
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

    /// 可编排的环境探测。
    #[derive(Default)]
    struct FakeEnv {
        programs: Vec<&'static str>,
        paths: Vec<&'static str>,
    }

    impl FakeEnv {
        fn with(programs: &[&'static str], paths: &[&'static str]) -> Self {
            Self {
                programs: programs.to_vec(),
                paths: paths.to_vec(),
            }
        }

        /// 只提供 `postfix`，且没有 systemd —— 走专用分支。
        fn postfix_only() -> Self {
            Self::with(&["postfix"], &[])
        }
    }

    impl ServiceEnv for FakeEnv {
        fn program_available(&self, program: &str) -> bool {
            self.programs.contains(&program)
        }

        fn path_exists(&self, path: &Path) -> bool {
            self.paths.iter().any(|p| Path::new(p) == path)
        }
    }

    #[test]
    fn postmap_sequence_matches_the_python_order() {
        // core.py: postmap <table> → postfix check → 重载。顺序不能变。
        let runner = RecordingRunner::new();
        let env = FakeEnv::postfix_only();
        let outcome =
            postmap_and_reload(&env, &runner, Path::new("/etc/postfix/mailstack_domains"));

        let calls = runner.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, "postmap");
        assert_eq!(calls[0].1, vec!["/etc/postfix/mailstack_domains"]);
        assert_eq!(calls[1].0, "postfix");
        assert_eq!(calls[1].1, vec!["check"]);
        assert_eq!(calls[2].0, "postfix");
        assert_eq!(calls[2].1, vec!["reload"]);
        assert_eq!(
            outcome,
            PostmapOutcome {
                postmap_ok: true,
                check_ok: true,
                reload_ok: true
            }
        );
    }

    #[test]
    fn postmap_failure_is_non_fatal_but_reported() {
        // 写表已经成功，postmap 失败不该让调用方以为整件事失败了。
        let mut runner = RecordingRunner::new();
        runner.postmap_status = 1;
        let env = FakeEnv::postfix_only();
        let outcome = postmap_and_reload(&env, &runner, Path::new("/tmp/t"));

        assert!(!outcome.postmap_ok, "失败必须如实反映在结果里");
        assert!(outcome.check_ok, "后续步骤仍应继续执行");
        assert_eq!(runner.calls().len(), 3, "失败不得提前中断序列");
    }

    #[test]
    fn every_step_still_runs_when_all_fail() {
        let mut runner = RecordingRunner::new();
        runner.postmap_status = 1;
        runner.check_status = 1;
        runner.reload_status = 1;
        let env = FakeEnv::postfix_only();
        let outcome = postmap_and_reload(&env, &runner, Path::new("/tmp/t"));

        assert_eq!(runner.calls().len(), 3, "三步都必须被尝试");
        assert!(!outcome.postmap_ok && !outcome.check_ok && !outcome.reload_ok);
    }

    // ───────────────────── service_ctl 降级链逐级覆盖 ─────────────────────

    #[test]
    fn service_ctl_prefers_systemctl_when_systemd_is_present() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(
            &["systemctl", "service", "rc-service"],
            &["/run/systemd/system"],
        );
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Systemctl);
        assert_eq!(runner.calls()[0].0, "systemctl");
        assert_eq!(runner.calls()[0].1, vec!["reload", "postfix"]);
    }

    #[test]
    fn service_ctl_does_not_use_systemctl_without_the_systemd_runtime_dir() {
        // 容器里可能装着 systemctl 但没有 systemd 在跑；此时 `systemctl` 会失败，
        // 必须继续降级。判据是「命令存在 **且** /run/systemd/system 存在」。
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl", "service"], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Service);
        assert_eq!(runner.programs(), vec!["service"]);
    }

    #[test]
    fn service_ctl_falls_back_to_rc_service_and_maps_reload_to_restart() {
        // OpenRC 没有 reload 概念，基线把它退化为 restart。
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["rc-service"], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::RcService);
        assert_eq!(runner.calls()[0].1, vec!["postfix", "restart"]);
    }

    #[test]
    fn service_ctl_falls_back_to_the_init_script() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&[], &["/etc/init.d/postfix"]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(
            outcome.backend,
            ServiceBackend::InitScript(PathBuf::from("/etc/init.d/postfix"))
        );
        assert_eq!(runner.calls()[0].0, "/etc/init.d/postfix");
        assert_eq!(runner.calls()[0].1, vec!["reload"]);
    }

    #[test]
    fn service_ctl_uses_the_postfix_special_case() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::postfix_only();
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);
        assert_eq!(outcome.backend, ServiceBackend::Postfix);
        assert_eq!(runner.calls()[0].1, vec!["reload"]);
    }

    #[test]
    fn service_ctl_maps_dovecot_restart_to_reload() {
        // Dovecot 没有 restart。
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["dovecot"], &[]);
        let outcome = service_ctl(&env, &runner, "dovecot", ServiceVerb::Restart);
        assert_eq!(outcome.backend, ServiceBackend::Dovecot);
        assert_eq!(runner.calls()[0].1, vec!["reload"]);
    }

    #[test]
    fn service_ctl_routes_fail2ban_verbs_through_the_client() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["fail2ban-client"], &[]);

        for (verb, expected) in [
            (ServiceVerb::Start, "start"),
            (ServiceVerb::Restart, "start"),
            (ServiceVerb::Stop, "stop"),
            (ServiceVerb::Reload, "reload"),
        ] {
            runner.calls.lock().unwrap().clear();
            let outcome = service_ctl(&env, &runner, "fail2ban", verb);
            assert_eq!(outcome.backend, ServiceBackend::Fail2ban, "verb={verb:?}");
            assert_eq!(runner.calls()[0].1, vec![expected]);
        }
    }

    #[test]
    fn service_ctl_is_a_no_op_when_nothing_applies() {
        // 基线执行 `true`（成功但什么都没做）。这里不 fork，语义相同。
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&[], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Noop);
        assert!(outcome.output.is_none());
        assert!(outcome.success(), "与基线的 `true` 一致：视为成功");
        assert!(runner.calls().is_empty(), "Noop 不应产生任何 fork");
    }

    #[test]
    fn service_ctl_only_applies_the_special_case_to_its_own_unit() {
        // 有 dovecot 可执行文件时，控制 postfix 不该跑 dovecot。
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["dovecot"], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);
        assert_eq!(outcome.backend, ServiceBackend::Noop);
    }

    // ───────────────────── ServiceVerb 解析 ─────────────────────

    #[test]
    fn service_verb_parsing_rejects_anything_it_does_not_know() {
        // 未知动词必须是 `None`：调用方据此报错，而不是静默走一条「什么都不做」的路径。
        for (raw, expected) in [
            ("start", Some(ServiceVerb::Start)),
            ("STOP", Some(ServiceVerb::Stop)),
            (" restart ", Some(ServiceVerb::Restart)),
            ("Reload", Some(ServiceVerb::Reload)),
        ] {
            assert_eq!(ServiceVerb::parse(raw), expected, "{raw:?}");
        }
        for raw in ["status", "enable", "", "  ", "reloadx"] {
            assert_eq!(ServiceVerb::parse(raw), None, "{raw:?} 必须被拒绝");
        }
    }

    // ───────────────────── is_service_active 逐级探测 ─────────────────────

    #[test]
    fn is_service_active_accepts_systemctl_success() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl"], &["/run/systemd/system"]);
        assert!(is_service_active(&env, &runner, "postfix"));
        assert_eq!(runner.calls()[0].0, "systemctl");
    }

    #[test]
    fn is_service_active_keeps_probing_after_a_failed_backend() {
        // 与 service_ctl 不同：探测是「逐个尝试、命中即真」。
        let runner = StatusRunner::new(&[("systemctl", 3, ""), ("pgrep", 0, "")]);
        let env = FakeEnv::with(
            &["systemctl", "service", "rc-service"],
            &["/run/systemd/system"],
        );
        assert!(
            is_service_active(&env, &runner, "postfix"),
            "systemctl 说 inactive 时仍应继续探测到 pgrep"
        );
        let programs = runner.programs();
        assert!(programs.contains(&"pgrep".to_string()));
    }

    #[test]
    fn is_service_active_accepts_a_running_string_from_service_status() {
        let runner = StatusRunner::new(&[("service", 3, "postfix is running")]);
        let env = FakeEnv::with(&["service"], &[]);
        assert!(is_service_active(&env, &runner, "postfix"));
    }

    #[test]
    fn is_service_active_recognises_the_fail2ban_socket() {
        let runner = StatusRunner::new(&[]);
        let env = FakeEnv::with(&[], &["/run/fail2ban/fail2ban.sock"]);
        assert!(is_service_active(&env, &runner, "fail2ban"));
    }

    #[test]
    fn is_service_active_is_false_when_nothing_answers() {
        let runner = StatusRunner::new(&[("pgrep", 1, "")]);
        let env = FakeEnv::with(&[], &[]);
        assert!(!is_service_active(&env, &runner, "postfix"));
    }

    /// 按程序名返回预设状态码的 runner。
    struct StatusRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        table: Vec<(&'static str, i32, &'static str)>,
    }

    impl StatusRunner {
        fn new(table: &[(&'static str, i32, &'static str)]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                table: table.to_vec(),
            }
        }

        fn programs(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(p, _)| p.clone())
                .collect()
        }
    }

    impl CommandRunner for StatusRunner {
        fn run(&self, program: &str, args: &[&str]) -> CoreResult<CommandOutput> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            let (status, stdout) = self
                .table
                .iter()
                .find(|(name, _, _)| *name == program)
                .map(|(_, status, stdout)| (*status, *stdout))
                .unwrap_or((1, ""));
            Ok(CommandOutput {
                status,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn resolve_program_passes_through_absolute_paths() {
        assert_eq!(resolve_program("/usr/sbin/postconf"), "/usr/sbin/postconf");
    }

    #[test]
    fn hash_db_path_appends_db_suffix() {
        assert_eq!(
            hash_db_path(Path::new("/etc/postfix/mailstack_domains")),
            PathBuf::from("/etc/postfix/mailstack_domains.db")
        );
    }

    #[test]
    fn command_output_diagnostic_prefers_stderr() {
        let out = CommandOutput {
            status: 1,
            stdout: "stdout text".to_string(),
            stderr: "stderr text".to_string(),
        };
        assert!(out.diagnostic("postmap").contains("stderr text"));
        assert!(out
            .diagnostic("postmap")
            .starts_with("postmap exited with 1"));

        let out = CommandOutput {
            status: 2,
            stdout: "only stdout".to_string(),
            stderr: "   ".to_string(),
        };
        assert!(out.diagnostic("postfix").contains("only stdout"));
    }
}
