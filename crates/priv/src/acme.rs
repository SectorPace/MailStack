//! 证书签发与续期（`certs.renew` / `setup.cert.issue`）。
//!
//! ## ACME 依赖选择：调用外部 `acme.sh`，不引入 Rust ACME crate
//!
//! 这不是本模块的即兴决定，而是基线的答案（`backend/mailstackctl/certs.py`）：
//! 续期与签发都通过子进程调用 `/root/.acme.sh/acme.sh`。因此这里**不新增任何依赖**，
//! 只经 [`CommandRunner`] 调子进程 —— 与 `postconf` / `systemctl` 走同一条通道。
//!
//! ## 三处有意偏离基线（理由见各自注释）
//!
//! 1. **自定义证书校验不落盘**：openssl 的输入全部走 **stdin**，私钥根本不写临时文件。
//! 2. **校验先于副作用**：基线先 `mkdir -p /etc/tls/<domain>` 再校验邮箱/method，
//!    于是「邮箱非法」会留下一个空目录。这里改成**全部校验通过后才建目录**。
//! 3. **子进程超时**：基线给 acme.sh 设了 180/300/120 秒超时；本 runner 通过
//!    [`CommandRunner::run_with_timeout`] 实现同一约束。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mailstack_core::atomic;
use mailstack_core::error::CoreResult;
use mailstack_core::exec::{service_ctl, CommandRunner, ServiceEnv, ServiceVerb};
use mailstack_core::paths::Paths;
use mailstack_core::validate::DOMAIN_RE;
use serde_json::{json, Value};

use crate::handlers::HandlerError;
use crate::readers::Clock;

/// `acme.sh` 的**硬编码**位置。
///
/// 不从请求体取：那会把这两个动作变成一个「任意脚本执行器」。基线同样是写死的。
const ACME_BIN: &str = "/root/.acme.sh/acme.sh";

/// `acme.sh` 的 home（证书与账号元数据所在）。
const ACME_HOME: &str = "/root/.acme.sh";

/// 安装证书时交给 acme.sh 的重载脚本路径（硬编码，理由同上）。
const RELOAD_SCRIPT: &str = "/usr/local/sbin/mailstack-reload-certificates";

/// 重载脚本正文。与基线逐字一致：优先 systemd，其次 OpenRC/init，最后裸命令。
const RELOAD_SCRIPT_BODY: &str = "#!/bin/sh\npostfix check 2>/dev/null && (systemctl reload postfix 2>/dev/null || rc-service postfix reload 2>/dev/null || postfix reload 2>/dev/null)\ndoveconf >/dev/null 2>&1 && (systemctl reload dovecot 2>/dev/null || rc-service dovecot reload 2>/dev/null || dovecot reload 2>/dev/null)\n";

/// 三处子进程超时（与基线逐字一致）。
const RENEW_TIMEOUT: Duration = Duration::from_secs(180);
const ISSUE_TIMEOUT: Duration = Duration::from_secs(300);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(120);

/// 文件与程序探测。
///
/// 抽成 trait 的理由与 `users.rs` 的 `ProgramEnv` 相同：单测绝不能真的读写
/// `/usr/local/sbin`、探测真实的 `/root/.acme.sh`。
pub trait AcmeProbes: Send + Sync {
    /// 等价 `shutil.which(program)`。
    fn which(&self, program: &str) -> Option<PathBuf>;
    /// 等价 `Path.is_file()`。
    fn is_file(&self, path: &Path) -> bool;
    /// 等价 `Path.is_dir()`。
    fn is_dir(&self, path: &Path) -> bool;
    /// 原子写文件（重载脚本）。走探测是为了让测试不碰真实 `/usr/local/sbin`。
    fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> CoreResult<()>;
}

/// 生产探测：真实 `PATH` / 文件系统 / `atomic` 写入。
#[derive(Debug, Default)]
pub struct SystemAcmeProbes;

impl AcmeProbes for SystemAcmeProbes {
    fn which(&self, program: &str) -> Option<PathBuf> {
        let resolved = mailstack_core::exec::resolve_program(program);
        (resolved != program).then(|| PathBuf::from(resolved))
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> CoreResult<()> {
        atomic::atomic_as(path, contents, mode, None)
    }
}

/// `certs.*` 的执行体。
pub struct Acme {
    paths: Paths,
    probes: Arc<dyn AcmeProbes>,
    /// 重载 Postfix / Dovecot 用的服务探测。
    services: Arc<dyn ServiceEnv>,
    runner: Arc<dyn CommandRunner>,
    clock: Clock,
}

impl Acme {
    pub fn new(
        paths: Paths,
        probes: Arc<dyn AcmeProbes>,
        services: Arc<dyn ServiceEnv>,
        runner: Arc<dyn CommandRunner>,
        clock: Clock,
    ) -> Self {
        Self {
            paths,
            probes,
            services,
            runner,
            clock,
        }
    }

    /// 生产构造。
    pub fn system(paths: Paths) -> Self {
        Self::new(
            paths,
            Arc::new(SystemAcmeProbes),
            Arc::new(mailstack_core::exec::SystemServiceEnv),
            Arc::new(mailstack_core::exec::SystemCommandRunner),
            Arc::new(|| time::OffsetDateTime::now_utc().unix_timestamp()),
        )
    }

    /// 覆盖探测（测试用）。
    pub fn with_probes(mut self, probes: Arc<dyn AcmeProbes>) -> Self {
        self.probes = probes;
        self
    }

    fn now_dt(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp((self.clock)())
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
    }

    /// 证书列表（与 `certs.list` 同源），供 `certs.renew` 成功后返回新状态。
    fn certificates(&self) -> Vec<Value> {
        mailstack_core::certs::list_certificates(&self.paths.etc, self.now_dt())
            .into_iter()
            .map(crate::readers::certificate_to_json)
            .collect()
    }

    /// `certs.renew`：强制续期一个域名的证书。
    ///
    /// **失败是「数据」不是「错误」**：只有域名非法才抛错，`acme.sh` 缺失或续期
    /// 失败都返回 `{status: failed, error}`。这个不对称是基线的真实行为，照抄。
    pub fn renew(&self, data: &Value) -> Result<Value, HandlerError> {
        let domain = str_field(data, "domain").trim().to_ascii_lowercase();
        if !DOMAIN_RE.is_match(&domain) {
            return Err(HandlerError::new("invalid domain format"));
        }

        if !self.probes.is_file(Path::new(ACME_BIN)) {
            return Ok(json!({
                "status": "failed",
                "domain": domain,
                "error": "acme.sh is not installed",
            }));
        }

        let output = self.runner.run_with_timeout(
            ACME_BIN,
            &[
                "--renew",
                "-d",
                domain.as_str(),
                "--force",
                "--home",
                ACME_HOME,
            ],
            RENEW_TIMEOUT,
        )?;
        if !output.success() {
            return Ok(json!({
                "status": "failed",
                "domain": domain,
                "error": "certificate renewal failed",
            }));
        }

        Ok(json!({
            "status": "ok",
            "domain": domain,
            "certificates": self.certificates(),
        }))
    }

    /// `setup.cert.issue`：签发/导入一个域名的证书。
    ///
    /// ## 为什么校验先于建目录（偏离基线）
    ///
    /// 基线在函数开头就 `out_dir.mkdir(parents=True, exist_ok=True)`，于是「邮箱
    /// 非法」这类纯校验失败也会在 `/etc/mailstack/tls/` 下留下一个空目录 —— 一个
    /// 没人会去清理、又会让 `certs.list` 多出一条「未配置证书」的垃圾。这里把建目录
    /// 推迟到所有校验之后：成功路径行为不变，失败路径不再留痕。
    pub fn issue(&self, data: &Value) -> Result<Value, HandlerError> {
        let domain = ["domain", "mailHost", "customDomain"]
            .iter()
            .find_map(|key| crate::handlers::optional_str(data, key))
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !DOMAIN_RE.is_match(&domain) {
            return Err(HandlerError::new("invalid certificate domain"));
        }
        let method = crate::handlers::optional_str(data, "method")
            .unwrap_or("standalone")
            .trim()
            .to_ascii_lowercase();

        let out_dir = self.paths.etc.join("tls").join(&domain);
        let fullchain = out_dir.join("fullchain.pem");
        let privkey = out_dir.join("privkey.pem");

        if method == "custom" {
            let cert_pem = ["certPem", "customCertPem"]
                .iter()
                .find_map(|key| crate::handlers::optional_str(data, key))
                .unwrap_or("")
                .trim()
                .to_string();
            let key_pem = ["keyPem", "customKeyPem"]
                .iter()
                .find_map(|key| crate::handlers::optional_str(data, key))
                .unwrap_or("")
                .trim()
                .to_string();
            if cert_pem.is_empty() || !cert_pem.contains("BEGIN CERTIFICATE") {
                return Err(HandlerError::new(
                    "Invalid certificate PEM format (missing BEGIN CERTIFICATE)",
                ));
            }
            if key_pem.is_empty() || !key_pem.contains("PRIVATE KEY") {
                return Err(HandlerError::new(
                    "Invalid private key PEM format (missing PRIVATE KEY)",
                ));
            }
            // 全部校验通过后才落盘。
            self.validate_custom_certificate(&cert_pem, &key_pem, &domain)?;
            std::fs::create_dir_all(&out_dir).map_err(|e| HandlerError::new(e.to_string()))?;
            atomic::atomic_as(&fullchain, format!("{cert_pem}\n").as_bytes(), 0o644, None)?;
            atomic::atomic_as(&privkey, format!("{key_pem}\n").as_bytes(), 0o600, None)?;
        } else {
            let email = str_field(data, "email").trim().to_string();
            if email.is_empty() || !email.contains('@') {
                return Err(HandlerError::new("invalid certificate email for ACME"));
            }
            if !self.probes.is_file(Path::new(ACME_BIN)) {
                // 基线这里是 RuntimeError（基础设施缺失），不是 ValueError。
                return Err(HandlerError::new("acme.sh is not installed"));
            }

            let mut issue_args: Vec<&str> = vec![
                "--issue",
                "-d",
                domain.as_str(),
                "--accountemail",
                email.as_str(),
                "--server",
                "letsencrypt",
                "--keylength",
                "ec-256",
                "--home",
                ACME_HOME,
            ];
            let webroot;
            match method.as_str() {
                "webroot" => {
                    webroot = str_field(data, "webroot").trim().to_string();
                    if !webroot.starts_with('/') || !self.probes.is_dir(Path::new(&webroot)) {
                        return Err(HandlerError::new("invalid ACME webroot"));
                    }
                    issue_args.push("--webroot");
                    issue_args.push(webroot.as_str());
                }
                "standalone" => issue_args.push("--standalone"),
                other => {
                    return Err(HandlerError::new(format!(
                        "unsupported ACME method: {other}"
                    )))
                }
            }

            // 校验全部通过，以下开始产生副作用。
            std::fs::create_dir_all(&out_dir).map_err(|e| HandlerError::new(e.to_string()))?;

            let issued = self
                .runner
                .run_with_timeout(ACME_BIN, &issue_args, ISSUE_TIMEOUT)?;
            if !issued.success() {
                return Err(HandlerError::new("ACME certificate issue failed"));
            }

            self.probes.write_file(
                Path::new(RELOAD_SCRIPT),
                RELOAD_SCRIPT_BODY.as_bytes(),
                0o750,
            )?;

            let stage = PrivateCertStage::create(&out_dir)?;
            let staged_fullchain = stage.0.join("fullchain.pem");
            let staged_privkey = stage.0.join("privkey.pem");
            let fullchain_str = staged_fullchain.display().to_string();
            let privkey_str = staged_privkey.display().to_string();
            let installed = self.runner.run_with_timeout(
                ACME_BIN,
                &[
                    "--install-cert",
                    "-d",
                    domain.as_str(),
                    "--ecc",
                    "--key-file",
                    privkey_str.as_str(),
                    "--fullchain-file",
                    fullchain_str.as_str(),
                    "--reloadcmd",
                    RELOAD_SCRIPT,
                    "--home",
                    ACME_HOME,
                ],
                INSTALL_TIMEOUT,
            )?;
            if !installed.success() {
                return Err(HandlerError::new("ACME certificate installation failed"));
            }

            set_mode(&staged_privkey, 0o600)?;
            set_mode(&staged_fullchain, 0o644)?;
            let key_pem = std::fs::read(&staged_privkey)
                .map_err(|error| HandlerError::new(format!("read staged TLS key: {error}")))?;
            let cert_pem = std::fs::read(&staged_fullchain).map_err(|error| {
                HandlerError::new(format!("read staged certificate chain: {error}"))
            })?;
            atomic::atomic_as(&privkey, &key_pem, 0o600, None)?;
            atomic::atomic_as(&fullchain, &cert_pem, 0o644, None)?;
        }

        if self.probes.which("postconf").is_some() {
            // 基线一律 `check=False`：postconf 失败不中止。
            let cert_line = format!("smtpd_tls_cert_file = {}", fullchain.display());
            let key_line = format!("smtpd_tls_key_file = {}", privkey.display());
            let _ = self.runner.run("postconf", &["-e", cert_line.as_str()]);
            let _ = self.runner.run("postconf", &["-e", key_line.as_str()]);
            let _ = self
                .runner
                .run("postconf", &["-e", "smtpd_tls_security_level = may"]);
        }
        let _ = service_ctl(
            self.services.as_ref(),
            self.runner.as_ref(),
            "postfix",
            ServiceVerb::Reload,
        );
        let _ = service_ctl(
            self.services.as_ref(),
            self.runner.as_ref(),
            "dovecot",
            ServiceVerb::Reload,
        );

        Ok(json!({
            "status": "ok",
            "method": method,
            "reloaded": true,
            "cert": crate::readers::certificate_to_json(
                mailstack_core::certs::read_certificate(&self.paths.etc, &domain, self.now_dt())
            ),
        }))
    }

    /// 校验自定义证书与私钥是否匹配、是否覆盖该域名、是否未过期。
    ///
    /// ## 为什么走 stdin 而不是临时文件（偏离基线）
    ///
    /// 基线把两段 PEM 写成 `0600` 临时文件再让 openssl 读。这里改成把 PEM 从 stdin
    /// 喂进去：**私钥根本不落盘**（哪怕只是短暂的），也省掉了一个临时目录。
    fn validate_custom_certificate(
        &self,
        cert_pem: &str,
        key_pem: &str,
        domain: &str,
    ) -> Result<(), HandlerError> {
        if self.probes.which("openssl").is_none() {
            return Err(HandlerError::new(
                "openssl is required for certificate validation",
            ));
        }

        let openssl = |args: &[&str], stdin: &str| -> Result<String, HandlerError> {
            let output = self
                .runner
                .run_with_input("openssl", args, stdin)
                .map_err(|e| HandlerError::new(e.to_string()))?;
            if !output.success() {
                let detail = if output.stderr.trim().is_empty() {
                    output.stdout
                } else {
                    output.stderr
                };
                // 基线取 detail[-500:]：错误详情可能很长，截尾保留。
                let detail = detail.trim();
                let count = detail.chars().count();
                let tail: String = if count <= 500 {
                    detail.to_string()
                } else {
                    detail.chars().skip(count - 500).collect()
                };
                return Err(HandlerError::new(tail));
            }
            Ok(output.stdout)
        };

        openssl(&["x509", "-noout"], cert_pem)?;
        openssl(&["x509", "-checkend", "0", "-noout"], cert_pem)?;
        let host_check = openssl(&["x509", "-checkhost", domain, "-noout"], cert_pem)?;
        if !host_check.to_lowercase().contains("does match") {
            return Err(HandlerError::new(format!(
                "certificate SAN/CN does not match {domain}"
            )));
        }
        let cert_public = openssl(&["x509", "-pubkey", "-noout"], cert_pem)?;
        let key_public = openssl(&["pkey", "-pubout"], key_pem)?;
        if cert_public.trim() != key_public.trim() {
            return Err(HandlerError::new(
                "certificate and private key do not match",
            ));
        }
        Ok(())
    }
}

/// 取字符串字段（缺失/非字符串 → 空串）。
fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(Value::as_str).unwrap_or("")
}

struct PrivateCertStage(PathBuf);

impl PrivateCertStage {
    fn create(parent: &Path) -> Result<Self, HandlerError> {
        #[cfg(unix)]
        use std::os::unix::fs::DirBuilderExt;

        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        for _ in 0..16 {
            let sequence = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = parent.join(format!(
                ".mailstack-acme-install.{}.{sequence}.{nanos}",
                std::process::id()
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    set_mode(&path, 0o700)?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(HandlerError::new(format!(
                        "create private ACME staging directory: {error}"
                    )))
                }
            }
        }
        Err(HandlerError::new(
            "unable to create a unique private ACME staging directory",
        ))
    }
}

impl Drop for PrivateCertStage {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            if error.kind() != std::io::ErrorKind::NotFound {
                mailstack_core::warn::warn_with_detail(
                    "remove private ACME staging directory",
                    &format!("{}: {error}", self.0.display()),
                );
            }
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), HandlerError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| HandlerError::new(format!("chmod {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), HandlerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::sync::Mutex;

    /// 固定时钟：2026-01-01T00:00:00Z。
    const NOW: i64 = 1_767_225_600;

    #[derive(Clone, Debug)]
    struct Call {
        program: String,
        args: Vec<String>,
        stdin: Option<String>,
        timeout: Option<Duration>,
    }

    /// 脚本化的假运行器：记录 program/args/stdin/timeout，并按配置返回结果。
    struct FakeRunner {
        calls: Mutex<Vec<Call>>,
        renew_status: i32,
        issue_status: i32,
        install_status: i32,
        /// `x509 -checkhost` 的输出；不含 `does match` 即表示 SAN 不匹配。
        checkhost_output: String,
        cert_pubkey: String,
        key_pubkey: String,
        /// 任一 openssl 调用返回非 0。
        openssl_failure: bool,
        /// `--install-cert` 时把 cert/key 落到真实（rooted）路径，模拟 acme.sh 产物。
        materialize_on_install: bool,
    }

    impl Default for FakeRunner {
        fn default() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                renew_status: 0,
                issue_status: 0,
                install_status: 0,
                checkhost_output: "Hostname example.com does match certificate".to_string(),
                cert_pubkey: "PUBKEY".to_string(),
                key_pubkey: "PUBKEY".to_string(),
                openssl_failure: false,
                materialize_on_install: false,
            }
        }
    }

    impl FakeRunner {
        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn acme_calls(&self) -> Vec<Call> {
            self.calls()
                .into_iter()
                .filter(|c| c.program == ACME_BIN)
                .collect()
        }

        fn record(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<String>,
            timeout: Option<Duration>,
        ) {
            self.calls.lock().unwrap().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin,
                timeout,
            });
        }

        fn acme_status(&self, args: &[String]) -> i32 {
            if args.iter().any(|a| a == "--renew") {
                self.renew_status
            } else if args.iter().any(|a| a == "--issue") {
                self.issue_status
            } else if args.iter().any(|a| a == "--install-cert") {
                self.install_status
            } else {
                0
            }
        }

        fn materialize(&self, args: &[String]) {
            let value = |flag: &str| {
                args.iter()
                    .position(|a| a == flag)
                    .and_then(|i| args.get(i + 1))
                    .cloned()
            };
            if let Some(key) = value("--key-file") {
                let _ = fs::write(
                    key,
                    "-----BEGIN PRIVATE KEY-----\nZZZ\n-----END PRIVATE KEY-----\n",
                );
            }
            if let Some(chain) = value("--fullchain-file") {
                let _ = fs::write(
                    chain,
                    "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
                );
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            self.record(program, args, None, None);
            let strings: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            let status = if program == ACME_BIN {
                self.acme_status(&strings)
            } else {
                0
            };
            Ok(mailstack_core::exec::CommandOutput {
                status,
                stdout: String::new(),
                stderr: if status == 0 {
                    String::new()
                } else {
                    format!("{program} failed")
                },
            })
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            stdin: &str,
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            self.record(program, args, Some(stdin.to_string()), None);
            if self.openssl_failure {
                return Ok(mailstack_core::exec::CommandOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "openssl: error".to_string(),
                });
            }
            let joined = args.join(" ");
            let stdout = if joined.contains("-checkhost") {
                self.checkhost_output.clone()
            } else if args.contains(&"-pubkey") {
                self.cert_pubkey.clone()
            } else if args.first() == Some(&"pkey") {
                self.key_pubkey.clone()
            } else {
                String::new()
            };
            Ok(mailstack_core::exec::CommandOutput {
                status: 0,
                stdout,
                stderr: String::new(),
            })
        }

        fn run_with_timeout(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
        ) -> mailstack_core::CoreResult<mailstack_core::exec::CommandOutput> {
            self.record(program, args, None, Some(timeout));
            let strings: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            let status = self.acme_status(&strings);
            if status == 0
                && self.materialize_on_install
                && strings.iter().any(|a| a == "--install-cert")
            {
                self.materialize(&strings);
            }
            Ok(mailstack_core::exec::CommandOutput {
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

    /// 可编排的文件 / 程序探测。
    #[derive(Default)]
    struct FakeProbes {
        programs: BTreeMap<String, PathBuf>,
        files: BTreeSet<PathBuf>,
        dirs: BTreeSet<PathBuf>,
        writes: Mutex<Vec<(PathBuf, Vec<u8>, u32)>>,
    }

    impl FakeProbes {
        /// 默认存在 acme.sh / openssl / postconf，且证书已是受管邮箱的惯用布局。
        fn ready() -> Self {
            let mut programs = BTreeMap::new();
            programs.insert("openssl".to_string(), PathBuf::from("/usr/bin/openssl"));
            programs.insert("postconf".to_string(), PathBuf::from("/usr/sbin/postconf"));
            let mut files = BTreeSet::new();
            files.insert(PathBuf::from(ACME_BIN));
            Self {
                programs,
                files,
                dirs: BTreeSet::new(),
                writes: Mutex::new(Vec::new()),
            }
        }

        fn writes(&self) -> Vec<(PathBuf, Vec<u8>, u32)> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl AcmeProbes for FakeProbes {
        fn which(&self, program: &str) -> Option<PathBuf> {
            self.programs.get(program).cloned()
        }

        fn is_file(&self, path: &Path) -> bool {
            self.files.contains(path)
        }

        fn is_dir(&self, path: &Path) -> bool {
            self.dirs.contains(path)
        }

        fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> CoreResult<()> {
            self.writes
                .lock()
                .unwrap()
                .push((path.to_path_buf(), contents.to_vec(), mode));
            Ok(())
        }
    }

    /// 只声明给定程序 / 路径存在的服务探测。
    struct FakeServices {
        programs: Vec<&'static str>,
    }

    impl FakeServices {
        fn none() -> Arc<Self> {
            Arc::new(Self {
                programs: Vec::new(),
            })
        }

        /// 只有 `service`：`service_ctl` 会走 `service <unit> reload` 分支。
        fn with_service() -> Arc<Self> {
            Arc::new(Self {
                programs: vec!["service"],
            })
        }
    }

    impl ServiceEnv for FakeServices {
        fn program_available(&self, program: &str) -> bool {
            self.programs.contains(&program)
        }

        fn path_exists(&self, _path: &Path) -> bool {
            false
        }
    }

    struct Fixture {
        root: PathBuf,
        paths: Paths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut root = std::env::temp_dir();
            root.push(format!(
                "mailstack-acme-{tag}-{}-{}",
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

        fn acme(
            &self,
            probes: Arc<FakeProbes>,
            runner: Arc<FakeRunner>,
            services: Arc<FakeServices>,
        ) -> Acme {
            Acme::new(
                self.paths.clone(),
                probes,
                services,
                runner,
                Arc::new(|| NOW),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----";

    // ───────────────────────── certs.renew ─────────────────────────

    #[test]
    fn cert_renew_rejects_an_invalid_domain() {
        let f = Fixture::new("renewbad");
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::new(FakeRunner::default()),
            FakeServices::none(),
        );
        let err = a.renew(&json!({ "domain": "not a domain" })).unwrap_err();
        assert_eq!(err.to_string(), "invalid domain format");
    }

    #[test]
    fn cert_renew_reports_a_missing_acme_sh_as_data_not_an_error() {
        // 基线：acme.sh 缺失是**返回值**（status: failed），不是异常。
        let f = Fixture::new("renewnoacme");
        let runner = Arc::new(FakeRunner::default());
        let a = f.acme(
            Arc::new(FakeProbes::default()),
            Arc::clone(&runner),
            FakeServices::none(),
        );
        let out = a.renew(&json!({ "domain": "Example.com" })).unwrap();
        assert_eq!(out["status"], "failed");
        assert_eq!(out["domain"], "example.com", "域名字段已归一化");
        assert_eq!(out["error"], "acme.sh is not installed");
        assert!(
            runner.calls().is_empty(),
            "acme.sh 不存在时不得执行任何命令"
        );
    }

    #[test]
    fn cert_renew_reports_a_failed_renewal_as_data() {
        let f = Fixture::new("renewfail");
        let runner = Arc::new(FakeRunner {
            renew_status: 1,
            ..FakeRunner::default()
        });
        let a = f.acme(Arc::new(FakeProbes::ready()), runner, FakeServices::none());
        let out = a.renew(&json!({ "domain": "example.com" })).unwrap();
        assert_eq!(out["status"], "failed");
        assert_eq!(out["error"], "certificate renewal failed");
    }

    #[test]
    fn cert_renew_runs_the_exact_command_and_returns_the_certificate_list() {
        let f = Fixture::new("renewok");
        let runner = Arc::new(FakeRunner::default());
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::clone(&runner),
            FakeServices::none(),
        );
        let out = a.renew(&json!({ "domain": "example.com" })).unwrap();

        assert_eq!(out["status"], "ok");
        assert_eq!(out["domain"], "example.com");
        assert!(out["certificates"].is_array(), "必须返回证书数组: {out}");

        let calls = runner.acme_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].args,
            vec![
                "--renew",
                "-d",
                "example.com",
                "--force",
                "--home",
                ACME_HOME
            ]
        );
        assert_eq!(calls[0].timeout, Some(RENEW_TIMEOUT));
    }

    // ───────────────────────── setup.cert.issue: custom ─────────────────────────

    fn custom_payload(domain: &str) -> Value {
        json!({
            "domain": domain,
            "method": "custom",
            "certPem": CERT_PEM,
            "keyPem": KEY_PEM,
        })
    }

    #[test]
    fn custom_issue_requires_the_pem_markers() {
        let f = Fixture::new("custommarker");
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::new(FakeRunner::default()),
            FakeServices::none(),
        );
        let err = a
            .issue(&json!({ "domain": "example.com", "method": "custom", "certPem": "nope", "keyPem": KEY_PEM }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid certificate PEM format (missing BEGIN CERTIFICATE)"
        );
        let err = a
            .issue(&json!({ "domain": "example.com", "method": "custom", "certPem": CERT_PEM, "keyPem": "nope" }))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid private key PEM format (missing PRIVATE KEY)"
        );
    }

    #[test]
    fn custom_issue_reports_a_san_mismatch() {
        let f = Fixture::new("customsan");
        let runner = Arc::new(FakeRunner {
            checkhost_output: "Hostname other.example does not match certificate".to_string(),
            ..FakeRunner::default()
        });
        let a = f.acme(Arc::new(FakeProbes::ready()), runner, FakeServices::none());
        let err = a.issue(&custom_payload("example.com")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "certificate SAN/CN does not match example.com"
        );
    }

    #[test]
    fn custom_issue_reports_a_key_that_does_not_match() {
        let f = Fixture::new("customkey");
        let runner = Arc::new(FakeRunner {
            cert_pubkey: "AAAA".to_string(),
            key_pubkey: "BBBB".to_string(),
            ..FakeRunner::default()
        });
        let a = f.acme(Arc::new(FakeProbes::ready()), runner, FakeServices::none());
        let err = a.issue(&custom_payload("example.com")).unwrap_err();
        assert_eq!(err.to_string(), "certificate and private key do not match");
    }

    #[test]
    fn custom_issue_validates_via_stdin_and_writes_with_the_right_modes() {
        let f = Fixture::new("customok");
        let runner = Arc::new(FakeRunner::default());
        let probes = Arc::new(FakeProbes::ready());
        let a = f.acme(
            Arc::clone(&probes),
            Arc::clone(&runner),
            FakeServices::none(),
        );
        let out = a.issue(&custom_payload("example.com")).unwrap();
        assert_eq!(out["status"], "ok");
        assert_eq!(out["method"], "custom");

        // openssl 全部经 stdin 收到 PEM，且没有任何临时文件路径出现在 argv 里。
        let openssl_calls: Vec<Call> = runner
            .calls()
            .into_iter()
            .filter(|c| c.program == "openssl")
            .collect();
        assert!(!openssl_calls.is_empty());
        for call in &openssl_calls {
            assert!(
                call.stdin.is_some(),
                "openssl 必须从 stdin 读 PEM: {call:?}"
            );
            assert!(
                !call
                    .args
                    .iter()
                    .any(|a| a == "-in" || a.contains("mailstack-cert-")),
                "不得落盘临时文件: {call:?}"
            );
        }
        // 私钥那次调用拿到的是 key PEM，其余是 cert PEM。
        let pkey = openssl_calls
            .iter()
            .find(|c| c.args.first().map(String::as_str) == Some("pkey"))
            .unwrap();
        assert_eq!(pkey.stdin.as_deref(), Some(KEY_PEM));

        // 落盘内容与权限位。
        let dir = f.paths.etc.join("tls").join("example.com");
        assert_eq!(
            fs::read_to_string(dir.join("fullchain.pem")).unwrap(),
            format!("{CERT_PEM}\n")
        );
        assert_eq!(
            fs::read_to_string(dir.join("privkey.pem")).unwrap(),
            format!("{KEY_PEM}\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join("privkey.pem")), 0o600);
            assert_eq!(mode(&dir.join("fullchain.pem")), 0o644);
            assert_eq!(
                fs::metadata(dir.join("privkey.pem")).unwrap().gid(),
                unsafe { libc::getegid() },
                "TLS 私钥不应 chown 到 mailstack-admin 组"
            );
        }
        // custom 分支不写 reload 脚本。
        assert!(probes.writes().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn certificate_mode_failure_is_returned_instead_of_ignored() {
        let f = Fixture::new("chmodfailure");
        let missing = f.root.join("missing-privkey.pem");
        let error = set_mode(&missing, 0o600).unwrap_err();
        assert!(error.to_string().contains("chmod "));
    }

    // ───────────────────────── setup.cert.issue: ACME ─────────────────────────

    #[test]
    fn acme_issue_validates_before_creating_any_directory() {
        let f = Fixture::new("acmebad");
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::new(FakeRunner::default()),
            FakeServices::none(),
        );

        // 邮箱非法。
        let err = a
            .issue(&json!({ "domain": "example.com", "method": "standalone", "email": "nope" }))
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid certificate email for ACME");

        // method 非法（邮箱合法、acme.sh 在）。
        let err = a
            .issue(&json!({ "domain": "example.com", "method": "dns", "email": "ops@example.com" }))
            .unwrap_err();
        assert_eq!(err.to_string(), "unsupported ACME method: dns");

        // 偏离 #2 的落点：校验失败不得留下 /etc/tls/<domain> 目录。
        assert!(
            !f.paths.etc.join("tls").join("example.com").exists(),
            "校验失败不得建目录"
        );
    }

    #[test]
    fn acme_issue_rejects_an_invalid_webroot() {
        let f = Fixture::new("acmewebroot");
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::new(FakeRunner::default()),
            FakeServices::none(),
        );
        let err = a
            .issue(&json!({
                "domain": "example.com",
                "method": "webroot",
                "email": "ops@example.com",
                "webroot": "relative/path",
            }))
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid ACME webroot");

        // 绝对路径但目录不存在，同样拒绝。
        let err = a
            .issue(&json!({
                "domain": "example.com",
                "method": "webroot",
                "email": "ops@example.com",
                "webroot": "/var/www/missing",
            }))
            .unwrap_err();
        assert_eq!(err.to_string(), "invalid ACME webroot");
    }

    #[test]
    fn acme_issue_reports_a_missing_acme_sh_as_an_error() {
        let f = Fixture::new("acmenoacme");
        // 存在 openssl/postconf 但没有 acme.sh。
        let mut probes = FakeProbes::ready();
        probes.files.clear();
        let a = f.acme(
            Arc::new(probes),
            Arc::new(FakeRunner::default()),
            FakeServices::none(),
        );
        let err = a
            .issue(&json!({
                "domain": "example.com",
                "method": "standalone",
                "email": "ops@example.com",
            }))
            .unwrap_err();
        assert_eq!(err.to_string(), "acme.sh is not installed");
        assert!(!f.paths.etc.join("tls").join("example.com").exists());
    }

    #[test]
    fn acme_issue_reports_issue_and_install_failures() {
        let f = Fixture::new("acmefail");
        let issue_runner = Arc::new(FakeRunner {
            issue_status: 1,
            ..FakeRunner::default()
        });
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            issue_runner,
            FakeServices::none(),
        );
        let err = a
            .issue(&json!({
                "domain": "example.com",
                "method": "standalone",
                "email": "ops@example.com",
            }))
            .unwrap_err();
        assert_eq!(err.to_string(), "ACME certificate issue failed");

        let install_runner = Arc::new(FakeRunner {
            install_status: 1,
            materialize_on_install: true,
            ..FakeRunner::default()
        });
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            install_runner,
            FakeServices::none(),
        );
        let err = a
            .issue(&json!({
                "domain": "example.com",
                "method": "standalone",
                "email": "ops@example.com",
            }))
            .unwrap_err();
        assert_eq!(err.to_string(), "ACME certificate installation failed");
    }

    #[test]
    fn acme_issue_treats_a_timed_out_child_as_a_failure() {
        // 超时在 `SystemCommandRunner` 里折算成非 0（status=-1）；动作只需把它当失败。
        let f = Fixture::new("acmetimeout");
        let runner = Arc::new(FakeRunner {
            renew_status: -1,
            ..FakeRunner::default()
        });
        let a = f.acme(
            Arc::new(FakeProbes::ready()),
            Arc::clone(&runner),
            FakeServices::none(),
        );
        let out = a.renew(&json!({ "domain": "example.com" })).unwrap();
        assert_eq!(out["status"], "failed");
        assert_eq!(out["error"], "certificate renewal failed");
    }

    #[test]
    fn acme_issue_succeeds_with_the_exact_command_and_reloads_the_services() {
        let f = Fixture::new("acmeok");
        let runner = Arc::new(FakeRunner {
            materialize_on_install: true,
            ..FakeRunner::default()
        });
        let probes = Arc::new(FakeProbes::ready());
        let a = f.acme(
            Arc::clone(&probes),
            Arc::clone(&runner),
            FakeServices::with_service(),
        );

        let out = a
            .issue(&json!({
                "domain": "example.com",
                "method": "standalone",
                "email": "ops@example.com",
            }))
            .unwrap();
        assert_eq!(out["status"], "ok");
        assert_eq!(out["method"], "standalone");
        assert_eq!(out["reloaded"], true);

        // reload 脚本经探测写入，路径硬编码、权限 0750。
        let writes = probes.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, PathBuf::from(RELOAD_SCRIPT));
        assert_eq!(writes[0].2, 0o750);
        assert!(String::from_utf8_lossy(&writes[0].1).starts_with("#!/bin/sh\n"));

        // issue 命令逐字正确。
        let issue = runner
            .acme_calls()
            .into_iter()
            .find(|c| c.args.iter().any(|a| a == "--issue"))
            .unwrap();
        assert_eq!(
            issue.args,
            vec![
                "--issue",
                "-d",
                "example.com",
                "--accountemail",
                "ops@example.com",
                "--server",
                "letsencrypt",
                "--keylength",
                "ec-256",
                "--home",
                ACME_HOME,
                "--standalone",
            ]
        );
        assert_eq!(issue.timeout, Some(ISSUE_TIMEOUT));

        let install = runner
            .acme_calls()
            .into_iter()
            .find(|call| call.args.iter().any(|arg| arg == "--install-cert"))
            .unwrap();
        let arg_value = |flag: &str| {
            install.args[install.args.iter().position(|arg| arg == flag).unwrap() + 1].clone()
        };
        let key_path = arg_value("--key-file");
        let chain_path = arg_value("--fullchain-file");
        let key_path = PathBuf::from(key_path);
        let chain_path = PathBuf::from(chain_path);
        assert_ne!(key_path, f.paths.etc.join("tls/example.com/privkey.pem"));
        assert_eq!(key_path.parent(), chain_path.parent());
        assert!(!key_path.parent().unwrap().exists(), "私有暂存目录必须清理");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let private_key = f.paths.etc.join("tls/example.com/privkey.pem");
            assert_eq!(
                fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(private_key).unwrap().gid(),
                unsafe { libc::getegid() },
                "ACME TLS key 不应属于共享管理组"
            );
        }

        // postconf 三条 -e 与两次服务重载的顺序与参数。
        let tail: Vec<Call> = runner
            .calls()
            .into_iter()
            .filter(|c| c.program == "postconf" || c.program == "service")
            .collect();
        assert_eq!(tail.len(), 5, "3 条 postconf + 2 条重载: {tail:?}");
        assert_eq!(tail[0].program, "postconf");
        assert_eq!(tail[0].args[0], "-e");
        assert!(tail[0].args[1].starts_with("smtpd_tls_cert_file = "));
        assert!(tail[1].args[1].starts_with("smtpd_tls_key_file = "));
        assert_eq!(tail[2].args, vec!["-e", "smtpd_tls_security_level = may"]);
        assert_eq!(tail[3].args, vec!["postfix", "reload"]);
        assert_eq!(tail[4].args, vec!["dovecot", "reload"]);
    }

    #[test]
    fn issue_skips_postconf_when_it_is_not_installed() {
        let f = Fixture::new("acmenopostconf");
        let mut probes = FakeProbes::ready();
        probes.programs.remove("postconf");
        let runner = Arc::new(FakeRunner {
            materialize_on_install: true,
            ..FakeRunner::default()
        });
        let a = f.acme(
            Arc::new(probes),
            Arc::clone(&runner),
            FakeServices::with_service(),
        );
        a.issue(&json!({
            "domain": "example.com",
            "method": "standalone",
            "email": "ops@example.com",
        }))
        .unwrap();
        assert!(
            runner.calls().iter().all(|c| c.program != "postconf"),
            "postconf 不存在时不得调用"
        );
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_kills_a_process_that_exceeds_its_timeout() {
        // 真实超时路径：`sleep 5` 配 100ms 超时必须被杀掉并如实上报，而不是挂 5 秒。
        let runner = mailstack_core::exec::SystemCommandRunner;
        let started = std::time::Instant::now();
        let out = runner
            .run_with_timeout("sleep", &["5"], Duration::from_millis(100))
            .unwrap();
        assert_eq!(out.status, -1);
        assert!(out.stderr.contains("timed out"), "实际: {out:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "必须真正超时返回，而不是等 sleep 结束"
        );
    }
}
