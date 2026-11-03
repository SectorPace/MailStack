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

use std::ffi::OsStr;
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
        let resolved = resolve_program_for_execution(program)?;
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

        let resolved = resolve_program_for_execution(program)?;
        let mut child = std::process::Command::new(&resolved)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::invalid(format!("cannot run {resolved}: {e}")))?;

        // 死锁修复：原先在主线程上**先写完整个 stdin** 再读输出。子进程若把自己的
        // stdout 管道填满（通常 64 KB）就会阻塞在 write 上，而主线程还堵在
        // `write_all(stdin)` 上等它腾出管道空间 —— 两边互相等待，谁也动不了。
        // 把 stdin 写入挪到独立线程与 `wait_with_output()` 并发：读输出的一方
        // 不再被写输入的一方挡住。句柄在线程结束时 drop，管道随之关闭，
        // 子进程自然看到 EOF。
        let writer = child.stdin.take().map(|mut pipe| {
            let payload = stdin.as_bytes().to_vec();
            // 写入失败（含子进程提前退出导致的 EPIPE）由 join 结果带回；
            // 无论成败，`pipe` 在线程结束时 drop，管道关闭即给出 EOF。
            std::thread::spawn(move || pipe.write_all(&payload).map_err(|e| e.to_string()))
        });

        let output = child
            .wait_with_output()
            .map_err(|e| CoreError::invalid(format!("cannot wait for {resolved}: {e}")))?;

        // 子进程已退出，stdin 管道要么写完要么 EPIPE —— 写入线程此刻必然已结束，
        // join 不会悬挂。写入失败仍要如实报错（chpasswd 收到半截口令不该被当成
        // 「设置成功」），且此时子进程已被回收，不会留下孤儿。
        if let Some(Err(detail)) = writer.and_then(|handle| handle.join().ok()) {
            return Err(CoreError::invalid(format!(
                "cannot write stdin to {resolved}: {detail}"
            )));
        }

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

        let resolved = resolve_program_for_execution(program)?;
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
                    // try_wait 出错同样要 kill 并回收，否则与超时路径一样会留下
                    // 孤儿/僵尸进程。
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CoreError::invalid(format!(
                        "cannot wait for {resolved}: {e}"
                    )));
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

/// 解析可信可执行文件路径：先查 `PATH`，再查常见 sbin 目录。
///
/// 与 `core.py` 的 `run()` 行为一致 —— 特权助手的 `PATH` 通常不含 `/usr/sbin`。
/// Unix 下只接受由 root 或当前进程用户拥有、且自身不可被组/其他用户改写的程序，
/// 并跳过不可信目录，避免特权进程执行被 PATH 劫持的命令。
pub fn resolve_program(program: &str) -> String {
    if program.contains('/') {
        return program.to_string();
    }
    if let Some(found) = which(program) {
        return found;
    }
    for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"] {
        let candidate = format!("{dir}/{program}");
        if is_trusted_executable(Path::new(&candidate)) {
            return candidate;
        }
    }
    program.to_string()
}

fn which(program: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    find_in_path(program, &path)
}

fn find_in_path(program: &str, path: &OsStr) -> Option<String> {
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_trusted_executable(candidate))
        .map(|p| p.to_string_lossy().into_owned())
}

/// 解析**可执行**路径：只返回通过可信检查（属主 / 权限位 / 目录链）的程序。
///
/// 与 [`resolve_program`] 的区别：那个是「展示/兼容用」的宽松版本（找不到就原样
/// 返回程序名）；本函数是**执行前**的唯一入口 —— 解析不出来就报错，绝不把裸名
/// 交回给调用方（`Command::new("gpg")` 会让内核按 `PATH` 搜索，等于绕开全部检查）。
///
/// 公开它是因为特权路径上还有别的执行点（如 `backup::GpgCipher` 直接调 gpg），
/// 它们必须复用同一条解析链，而不是各写一份。
pub fn resolve_program_for_execution(program: &str) -> CoreResult<String> {
    let path = if program.contains('/') {
        PathBuf::from(program)
    } else {
        which(program)
            .map(PathBuf::from)
            .or_else(|| {
                ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"]
                    .iter()
                    .map(|dir| PathBuf::from(dir).join(program))
                    .find(|candidate| is_trusted_executable(candidate))
            })
            .ok_or_else(|| CoreError::NotFound(PathBuf::from(program)))?
    };
    if !is_trusted_executable(&path) {
        return Err(CoreError::io(
            path,
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ));
    }
    std::fs::canonicalize(&path)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| CoreError::io(path, error))
}

#[cfg(unix)]
fn is_trusted_executable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(path) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return false;
    };
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode();
    if !metadata.is_file()
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || !is_trusted_owner(metadata.uid(), effective_uid)
    {
        return false;
    }

    let mut directory = path.parent();
    while let Some(path) = directory {
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        let mode = metadata.mode();
        if !metadata.is_dir()
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
            || !is_trusted_owner(metadata.uid(), effective_uid)
        {
            return false;
        }
        directory = path.parent();
    }
    true
}

#[cfg(unix)]
fn is_trusted_owner(owner: u32, effective_uid: u32) -> bool {
    owner == 0 || owner == effective_uid
}

#[cfg(not(unix))]
fn is_trusted_executable(path: &Path) -> bool {
    path.is_file()
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

const SERVICE_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 表文件同步序列（`postmap` / `postfix check`）的单步超时。
///
/// 这两步跑在 `store` 的 `locked()` 临界区内（flock 是**跨进程**的），而
/// `postmap` 是外部二进制：它可能卡在 Berkeley DB 锁、网络文件系统、或一个挂死
/// 的 `postfix` 上。没有超时的话，一次卡死会让此后所有 `domains.add/delete`
/// 永久阻塞 —— 特权助手没有请求级超时，客户端超时只是让调用方看到失败，锁不会
/// 释放。取 60s：正常表在毫秒级完成，再慢也远不到一分钟的量级。
pub const POSTMAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// spawn 失败的原因（程序不存在 / 权限不足 / fork 失败）。
    ///
    /// 与 `output == None` 的区别见 [`ServiceCtlOutcome::success`]。
    pub spawn_error: Option<String>,
}

impl ServiceCtlOutcome {
    /// 是否成功。
    ///
    /// ## 为什么 `Noop` 与「执行失败」不能同义
    ///
    /// 原实现是 `None => true`，而 `None` 同时表示两件**性质相反**的事：
    ///
    /// * [`ServiceBackend::Noop`] —— 该单元不适用任何后端（真的什么都不用做）；
    /// * **spawn 失败** —— `systemctl` 存在但 fork/exec 失败、权限不足、OOM。
    ///   这时 `success()` 返回 `true`，于是「配置改了但没人重载」——
    ///   正是本模块文档 [`service_ctl`] 自己声明要根除的失败模式。
    ///
    /// 调用方（`reload_ok`、API 响应）都只看这个布尔值，所以必须区分。
    /// spawn 失败用 [`ServiceCtlOutcome::spawn_error`] 承载，不再压成 `None`。
    pub fn success(&self) -> bool {
        match &self.output {
            Some(output) => output.success(),
            None => self.spawn_error.is_none(),
        }
    }

    /// 是否是「命令根本没跑起来」。
    ///
    /// 与「跑了但失败」分开：前者通常是环境/权限问题（该叫人），
    /// 后者是服务自己拒绝（可能是正常的）。
    pub fn spawn_failed(&self) -> bool {
        self.spawn_error.is_some()
    }

    /// 人类可读的原因，供 API 层如实上报。
    pub fn failure_reason(&self) -> Option<String> {
        match (&self.output, &self.spawn_error) {
            (Some(output), _) if !output.success() => Some(output.stderr.clone()),
            (_, Some(message)) => Some(message.clone()),
            _ => None,
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
    let run = |program: &str, args: &[&str]| {
        match runner.run_with_timeout(program, args, SERVICE_COMMAND_TIMEOUT) {
            Ok(output) => ServiceCtlOutcome {
                backend: match program {
                    "systemctl" => ServiceBackend::Systemctl,
                    "service" => ServiceBackend::Service,
                    "rc-service" => ServiceBackend::RcService,
                    "postfix" => ServiceBackend::Postfix,
                    "dovecot" => ServiceBackend::Dovecot,
                    "fail2ban-client" => ServiceBackend::Fail2ban,
                    other => ServiceBackend::InitScript(PathBuf::from(other)),
                },
                output: Some(output),
                spawn_error: None,
            },
            // 曾经是 `.ok()` —— spawn 失败被压成 `None`，而 `success()` 对 `None`
            // 返回 `true`，于是「systemctl 根本没跑起来」被报成「重载成功」。
            Err(error) => ServiceCtlOutcome {
                backend: match program {
                    "systemctl" => ServiceBackend::Systemctl,
                    "service" => ServiceBackend::Service,
                    "rc-service" => ServiceBackend::RcService,
                    "postfix" => ServiceBackend::Postfix,
                    "dovecot" => ServiceBackend::Dovecot,
                    "fail2ban-client" => ServiceBackend::Fail2ban,
                    other => ServiceBackend::InitScript(PathBuf::from(other)),
                },
                output: None,
                spawn_error: Some(error.to_string()),
            },
        }
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
        return run(&init_script.to_string_lossy(), &[verb.as_str()]);
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
        // 真的什么都不用做 —— 与上面「跑了但失败」相反的情形。
        spawn_error: None,
    }
}

/// 服务是否在运行：按基线的**逐级探测**（`core.py:602-619`）。
///
/// 注意这里是「逐个尝试、命中即真」，与 [`service_ctl`] 的首命中不同 ——
/// 探测要尽量给出一致的结论，而执行必须只走一条路。
///
/// 探测**全部带超时**（与 [`service_ctl`] 用同一个 `SERVICE_COMMAND_TIMEOUT`）：
/// `status` 子命令可能卡在挂死的 init 脚本上，没超时的探测会把调用方一起拖住。
///
/// 「running」判定刻意收窄：基线用 `contains("running")`，而 `postfix is not
/// running` 这类失败输出同样包含它 —— 一台服务挂了的主机会被报成「在运行」。
/// 现在的规则：命令成功即在运行；失败时只有输出明示 `active (running)` 且**不含**
/// `inactive` / `not running` / `failed` 才算在运行。pgrep 兜底按退出码判定，
/// 不受文本误匹配影响。
pub fn is_service_active(env: &dyn ServiceEnv, runner: &dyn CommandRunner, unit: &str) -> bool {
    if env.program_available("systemctl") && env.path_exists(Path::new("/run/systemd/system")) {
        if let Ok(out) = runner.run_with_timeout(
            "systemctl",
            &["is-active", "--quiet", unit],
            SERVICE_COMMAND_TIMEOUT,
        ) {
            if out.success() {
                return true;
            }
        }
    }

    if env.program_available("service") {
        if let Ok(out) =
            runner.run_with_timeout("service", &[unit, "status"], SERVICE_COMMAND_TIMEOUT)
        {
            if out.success() {
                return true;
            }
            let combined = format!("{}{}", out.stdout, out.stderr).to_lowercase();
            let says_running = combined.contains("active (running)");
            let says_stopped = combined.contains("inactive")
                || combined.contains("not running")
                || combined.contains("failed");
            if says_running && !says_stopped {
                return true;
            }
        }
    }

    if env.program_available("rc-service") {
        if let Ok(out) =
            runner.run_with_timeout("rc-service", &[unit, "status"], SERVICE_COMMAND_TIMEOUT)
        {
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
        if let Ok(out) =
            runner.run_with_timeout("fail2ban-client", &["ping"], SERVICE_COMMAND_TIMEOUT)
        {
            if out.success() && out.stdout.to_lowercase().contains("pong") {
                return true;
            }
        }
    }

    let pattern = format!(".*{}.*", regex::escape(unit));
    match runner.run_with_timeout("pgrep", &["-f", &pattern], SERVICE_COMMAND_TIMEOUT) {
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
    /// 本机**没有安装 Postfix**（`postmap` 可执行文件不存在）。
    ///
    /// 这不是失败：MailStack 是 Postfix 的替代品，表文件由 MailStack 自己按文本读取，
    /// 只有「Postfix 仍在跑、需要重新编译 hash 表」时这一步才有意义。
    /// 把「没装 Postfix」判成失败，会让管理台在**纯 MailStack 主机**上加域名/加别名
    /// 一律报错 —— 而那正是 v1.0.0 的目标部署形态。
    pub postfix_absent: bool,
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

    // 「找不到 postmap 可执行文件」= 本机没有 Postfix，而不是这一步失败。
    //
    // 必须与「postmap 存在但执行失败」严格区分：
    //   * 不存在 → 没有 Postfix 在消费 hash 表，跳过整条同步序列是正确行为；
    //   * 存在但失败/db 编译失败 → 调用方必须知道（Postfix 可能还在读旧表）。
    // 只看 `CoreError::NotFound`，不看错误文案 —— 文案是给人看的，判定必须基于类型。
    // 超时是必须的：这一整段跑在 `store` 的跨进程 `locked()` 临界区里，
    // 卡住的 `postmap` 会把之后所有域表操作一起拖死（见 `POSTMAP_TIMEOUT`）。
    let postmap_result = runner.run_with_timeout("postmap", &[table_str.as_str()], POSTMAP_TIMEOUT);
    if matches!(postmap_result, Err(CoreError::NotFound(_))) {
        crate::warn::warn_with_detail(
            "postmap",
            &format!(
                "Postfix 未安装（找不到 postmap），跳过 {} 的 hash 表同步；\
                 MailStack 直接读取文本表，无需 Postfix 侧动作",
                table.display()
            ),
        );
        return PostmapOutcome {
            postmap_ok: true,
            check_ok: true,
            reload_ok: true,
            postfix_absent: true,
        };
    }

    let postmap_ok = match postmap_result {
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

    let check_ok = match runner.run_with_timeout("postfix", &["check"], POSTMAP_TIMEOUT) {
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
        postfix_absent: false,
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
        timeouts: Mutex<Vec<(String, std::time::Duration)>>,
        postmap_status: i32,
        check_status: i32,
        reload_status: i32,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                timeouts: Mutex::new(Vec::new()),
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

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            timeout: std::time::Duration,
        ) -> CoreResult<CommandOutput> {
            self.timeouts
                .lock()
                .unwrap()
                .push((program.to_string(), timeout));
            self.run(program, args)
        }
    }

    #[test]
    fn service_ctl_runs_its_command_with_a_bounded_timeout() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl"], &["/run/systemd/system"]);

        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert!(outcome.success());
        assert_eq!(
            *runner.timeouts.lock().unwrap(),
            vec![("systemctl".to_string(), SERVICE_COMMAND_TIMEOUT)]
        );
    }

    /// 可编排的环境探测。
    #[derive(Default)]
    struct FakeEnv {
        programs: Vec<&'static str>,
        paths: Vec<&'static str>,
    }

    #[test]
    fn is_service_active_treats_unit_metacharacters_as_literals() {
        let runner = StatusRunner::new(&[("pgrep", 1, "")]);
        let env = FakeEnv::with(&[], &[]);

        assert!(!is_service_active(&env, &runner, "postfix|bash"));
        assert_eq!(
            runner.calls.lock().unwrap()[0].1,
            vec!["-f", ".*postfix\\|bash.*"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_resolution_rejects_non_executable_and_group_writable_commands() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "mailstack-exec-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let command = dir.join("helper");
        std::fs::write(&command, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(find_in_path("helper", dir.as_os_str()), None);

        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(find_in_path("helper", dir.as_os_str()), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn command_execution_refuses_to_fall_back_to_an_unresolved_bare_name() {
        let error =
            resolve_program_for_execution("mailstack-no-such-command-2b3e35c1").unwrap_err();
        assert!(matches!(error, CoreError::NotFound(_)));
    }

    #[cfg(unix)]
    #[test]
    fn command_execution_refuses_a_program_in_an_untrusted_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "mailstack-exec-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let command = dir.join("helper");
        std::fs::write(&command, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = SystemCommandRunner
            .run(command.to_str().unwrap(), &[])
            .unwrap_err();

        assert!(matches!(error, CoreError::Io { .. }));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_resolution_skips_commands_in_untrusted_writable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "mailstack-exec-unsafe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let unsafe_dir = dir.join("unsafe");
        std::fs::create_dir(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let command = unsafe_dir.join("helper");
        std::fs::write(&command, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(find_in_path("helper", unsafe_dir.as_os_str()), None);
        std::fs::remove_dir_all(dir).unwrap();
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
                reload_ok: true,
                postfix_absent: false
            }
        );
    }

    /// 反例守卫：`postmap` / `postfix check` 必须在**有界超时**下执行。
    ///
    /// 回归背景：这两步跑在 `store::tables` 的跨进程 `locked()` 临界区里，用的却是
    /// 无超时的 `run()`。一个卡在 Berkeley DB 锁 / 网络文件系统 / 挂死的 `postfix`
    /// 上的 `postmap` 会让之后所有 `domains.add/delete` **永久阻塞**（flock 不会因为
    /// 调用方超时而释放）。这条测试断言两步都走 `run_with_timeout`，且超时值有界。
    #[test]
    fn the_postmap_sequence_is_bounded_by_a_timeout() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::postfix_only();
        let outcome =
            postmap_and_reload(&env, &runner, Path::new("/etc/postfix/mailstack_domains"));

        assert!(outcome.postmap_ok && outcome.check_ok);
        let observed = runner.timeouts.lock().unwrap().clone();
        assert!(
            observed
                .iter()
                .any(|(program, timeout)| program == "postmap" && *timeout == POSTMAP_TIMEOUT),
            "postmap 必须带超时执行，实际见过: {observed:?}"
        );
        assert!(
            observed
                .iter()
                .any(|(program, timeout)| program == "postfix" && *timeout == POSTMAP_TIMEOUT),
            "postfix check 必须带超时执行，实际见过: {observed:?}"
        );
    }

    /// 本机没有 Postfix（找不到 `postmap`）时，整条同步序列必须被视为「无需同步」，
    /// 而不是「同步失败」。
    ///
    /// 回归背景：v1.0.0 的纯 MailStack 主机（Postfix 已移除）上，`domains.add` /
    /// `aliases.add` 会把「没有 postmap 可执行文件」判成 Postfix 更新失败并让整个
    /// 动作报错 —— 新装的服务器上第一次加域名就会失败。
    #[test]
    fn missing_postmap_means_postfix_is_absent_not_a_failure() {
        struct NoPostfix;
        impl CommandRunner for NoPostfix {
            fn run(&self, program: &str, _args: &[&str]) -> CoreResult<CommandOutput> {
                Err(CoreError::NotFound(PathBuf::from(program)))
            }

            // 同步序列现在走**带超时**的入口：替身必须把同一语义透传下去，
            // 否则默认实现会返回 `Invalid`（"未实现超时"），
            // 「找不到 postmap」就再也识别不出来（会被当成同步失败）。
            fn run_with_timeout(
                &self,
                program: &str,
                args: &[&str],
                _timeout: std::time::Duration,
            ) -> CoreResult<CommandOutput> {
                self.run(program, args)
            }
        }

        let env = FakeEnv::with(&[], &[]);
        let outcome = postmap_and_reload(
            &env,
            &NoPostfix,
            Path::new("/etc/postfix/mailstack_domains"),
        );

        assert!(outcome.postfix_absent, "必须识别出 Postfix 未安装");
        assert!(outcome.postmap_ok, "没有 Postfix 时这不叫失败");
        assert!(outcome.check_ok);
        assert!(outcome.reload_ok);
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

    /// 反例守卫：**命令没跑起来**不得报成功。
    ///
    /// 原实现把 spawn 失败 `.ok()` 成 `None`，而 `success()` 对 `None` 一律 `true`
    /// —— 于是 `systemctl` 因权限不足 / fork 失败而根本没执行时，
    /// `reload_ok` 仍然是 `true`，API 回答「已重载」。
    /// 这正是本模块文档开头声明要根除的「配置改了但没人重载」。
    #[test]
    fn a_command_that_never_started_is_not_reported_as_success() {
        struct FailingRunner;
        impl CommandRunner for FailingRunner {
            fn run(&self, program: &str, _args: &[&str]) -> CoreResult<CommandOutput> {
                Err(CoreError::io(
                    PathBuf::from(program),
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                ))
            }
        }

        // 命中第一条降级链，于是确实会去 fork systemctl。
        let env = FakeEnv::with(&["systemctl"], &["/run/systemd/system"]);
        let outcome = service_ctl(&env, &FailingRunner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Systemctl, "应走 systemctl");
        assert!(outcome.output.is_none(), "spawn 失败时没有输出");
        assert!(outcome.spawn_failed(), "spawn 失败必须被标记出来");
        assert!(
            !outcome.success(),
            "命令没跑起来绝不能报成功：配置改了但没人重载"
        );
        assert!(
            outcome.failure_reason().is_some(),
            "如实上报原因，别让调用方只看到一个 bool"
        );
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
        // systemd 风格的「active (running)」是唯一被认作在运行的失败输出。
        let runner = StatusRunner::new(&[("service", 3, "postfix is active (running)")]);
        let env = FakeEnv::with(&["service"], &[]);
        assert!(is_service_active(&env, &runner, "postfix"));
    }

    /// 反例守卫：`contains("running")` 曾把 `is not running` 也当成在运行。
    #[test]
    fn is_service_active_rejects_a_not_running_string_from_service_status() {
        let runner = StatusRunner::new(&[("service", 3, "postfix is not running")]);
        let env = FakeEnv::with(&["service"], &[]);
        assert!(
            !is_service_active(&env, &runner, "postfix"),
            "「is not running」绝不能被当成在运行"
        );
    }

    #[test]
    fn is_service_active_rejects_inactive_and_failed_status_strings() {
        for body in ["postfix is inactive (dead)", "postfix failed to start"] {
            let runner = StatusRunner::new(&[("service", 3, body)]);
            let env = FakeEnv::with(&["service"], &[]);
            assert!(
                !is_service_active(&env, &runner, "postfix"),
                "{body} 必须被判定为未运行"
            );
        }
    }

    #[test]
    fn is_service_active_probes_run_with_a_bounded_timeout() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl"], &["/run/systemd/system"]);
        assert!(is_service_active(&env, &runner, "postfix"));
        let timeouts = runner.timeouts.lock().unwrap();
        assert!(!timeouts.is_empty(), "探测必须实际发起命令");
        assert!(
            timeouts.iter().all(|(_, t)| *t == SERVICE_COMMAND_TIMEOUT),
            "每个探测都必须带超时：{timeouts:?}"
        );
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

        // is_service_active 的探测现在全部走超时通道；替身必须同样应答，
        // 否则默认实现会「响亮失败」而让整条探测链测不到。
        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            _timeout: std::time::Duration,
        ) -> CoreResult<CommandOutput> {
            self.run(program, args)
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
