use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, CoreResult};

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

    pub fn diagnostic(&self, program: &str) -> String {
        let detail = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        format!("{program} exited with {}: {detail}", self.status)
    }
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> CoreResult<CommandOutput>;

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

        let writer = child.stdin.take().map(|mut pipe| {
            let payload = stdin.as_bytes().to_vec();

            std::thread::spawn(move || pipe.write_all(&payload).map_err(|e| e.to_string()))
        });

        let output = child
            .wait_with_output()
            .map_err(|e| CoreError::invalid(format!("cannot wait for {resolved}: {e}")))?;

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
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CoreError::invalid(format!(
                        "cannot wait for {resolved}: {e}"
                    )));
                }
            }
            if Instant::now() >= deadline {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceVerb {
    Start,
    Stop,
    Restart,
    Reload,
}

const SERVICE_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

pub trait ServiceEnv: Send + Sync {
    fn program_available(&self, program: &str) -> bool;

    fn path_exists(&self, path: &Path) -> bool;
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceBackend {
    Systemctl,
    Service,
    RcService,
    InitScript(PathBuf),

    Postfix,

    Dovecot,

    Fail2ban,

    Noop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCtlOutcome {
    pub backend: ServiceBackend,

    pub output: Option<CommandOutput>,

    pub spawn_error: Option<String>,
}

impl ServiceCtlOutcome {
    pub fn success(&self) -> bool {
        match &self.output {
            Some(output) => output.success(),
            None => self.spawn_error.is_none(),
        }
    }

    pub fn spawn_failed(&self) -> bool {
        self.spawn_error.is_some()
    }

    pub fn failure_reason(&self) -> Option<String> {
        match (&self.output, &self.spawn_error) {
            (Some(output), _) if !output.success() => Some(output.stderr.clone()),
            (_, Some(message)) => Some(message.clone()),
            _ => None,
        }
    }
}

pub fn service_ctl(
    env: &dyn ServiceEnv,
    runner: &dyn CommandRunner,
    unit: &str,
    verb: ServiceVerb,
) -> ServiceCtlOutcome {
    let run = |program: &str, args: &[&str]| match runner.run_with_timeout(
        program,
        args,
        SERVICE_COMMAND_TIMEOUT,
    ) {
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

        spawn_error: None,
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PostmapOutcome {
    pub postmap_ok: bool,

    pub check_ok: bool,

    pub reload_ok: bool,

    pub postfix_absent: bool,
}

pub fn postmap_and_reload(
    env: &dyn ServiceEnv,
    runner: &dyn CommandRunner,
    table: &Path,
) -> PostmapOutcome {
    let table_str = table.to_string_lossy().to_string();

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

    #[test]
    fn missing_postmap_means_postfix_is_absent_not_a_failure() {
        struct NoPostfix;
        impl CommandRunner for NoPostfix {
            fn run(&self, program: &str, _args: &[&str]) -> CoreResult<CommandOutput> {
                Err(CoreError::NotFound(PathBuf::from(program)))
            }

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
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl", "service"], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Service);
        assert_eq!(runner.programs(), vec!["service"]);
    }

    #[test]
    fn service_ctl_falls_back_to_rc_service_and_maps_reload_to_restart() {
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
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&[], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);

        assert_eq!(outcome.backend, ServiceBackend::Noop);
        assert!(outcome.output.is_none());
        assert!(outcome.success(), "与基线的 `true` 一致：视为成功");
        assert!(runner.calls().is_empty(), "Noop 不应产生任何 fork");
    }

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
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["dovecot"], &[]);
        let outcome = service_ctl(&env, &runner, "postfix", ServiceVerb::Reload);
        assert_eq!(outcome.backend, ServiceBackend::Noop);
    }

    #[test]
    fn service_verb_parsing_rejects_anything_it_does_not_know() {
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

    #[test]
    fn is_service_active_accepts_systemctl_success() {
        let runner = RecordingRunner::new();
        let env = FakeEnv::with(&["systemctl"], &["/run/systemd/system"]);
        assert!(is_service_active(&env, &runner, "postfix"));
        assert_eq!(runner.calls()[0].0, "systemctl");
    }

    #[test]
    fn is_service_active_keeps_probing_after_a_failed_backend() {
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
        let runner = StatusRunner::new(&[("service", 3, "postfix is active (running)")]);
        let env = FakeEnv::with(&["service"], &[]);
        assert!(is_service_active(&env, &runner, "postfix"));
    }

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
