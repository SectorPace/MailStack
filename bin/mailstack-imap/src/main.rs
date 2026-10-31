//! `mailstack-imap` 进程入口 —— 替代 Dovecot 的协议面。
//!
//! 刻意保持极薄：解析参数 → 组装 [`mailstack_imapd::Config`] → 调
//! [`mailstack_imapd::servers::run`]。所有可测决策都在库里（账号目录、
//! Maildir 解析、TLS 装载、多用户切换），这里只做"读命令行"这一件事。
//!
//! **默认 fail-closed**：不给证书就拒绝启动（`--allow-plaintext-login` 是
//! 显式的开发开关，等价于 Dovecot 的 `disable_plaintext_auth = no`）。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use tokio::sync::watch;

use mailstack_core::Paths;
use mailstack_imapd::servers::{run, CertPair, Config, Listeners};

#[derive(Debug, Parser)]
#[command(
    name = "mailstack-imap",
    about = "MailStack IMAP/POP3 守护进程：IMAP 143/993、POP3 110/995，多账号共用一个监听器",
    version
)]
struct Cli {
    /// IMAP 明文口（通常 143，配 STARTTLS）。可重复。
    #[arg(long = "imap", value_name = "ADDR")]
    imap: Vec<SocketAddr>,

    /// IMAP 隐式 TLS 口（993）。必须配 `--cert` / `--key`。
    #[arg(long = "imaps", value_name = "ADDR")]
    imaps: Vec<SocketAddr>,

    /// POP3 明文口（110，配 STLS）。可重复。
    #[arg(long = "pop3", value_name = "ADDR")]
    pop3: Vec<SocketAddr>,

    /// POP3 隐式 TLS 口（995）。
    #[arg(long = "pop3s", value_name = "ADDR")]
    pop3s: Vec<SocketAddr>,

    /// 证书链（PEM，含中间证书）。默认从 `--letsencrypt` 推导。
    #[arg(long = "cert", value_name = "FILE")]
    cert: Option<PathBuf>,

    /// 私钥（PEM）。
    #[arg(long = "key", value_name = "FILE")]
    key: Option<PathBuf>,

    /// 从 Let's Encrypt 布局取证书：`<DIR>/live/<domain>/{fullchain,privkey}.pem`。
    #[arg(long = "cert-domain", value_name = "DOMAIN")]
    cert_domain: Option<String>,

    /// Let's Encrypt 根目录（默认 `/etc/letsencrypt`）。
    #[arg(long = "letsencrypt", value_name = "DIR")]
    letsencrypt: Option<PathBuf>,

    /// 问候语里的服务器名（通常是 MX 主机名）。
    #[arg(long = "server-name", value_name = "NAME", default_value = "mailstack")]
    server_name: String,

    /// 配置根目录：把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`（测试/旁路部署）。
    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    /// `/etc/passwd` 所在目录（默认 `/etc`；仅测试需要改成临时根）。
    #[arg(long = "passwd-root", value_name = "DIR", default_value = "/etc")]
    passwd_root: PathBuf,

    /// 家目录下的 Maildir 目录名（Dovecot 的 `mail_location` 对应项）。
    #[arg(long = "maildir", value_name = "NAME", default_value = "Maildir")]
    maildir: String,

    /// 允许在**明文连接**上提交口令。等价于 Dovecot 的
    /// `disable_plaintext_auth = no`，**只限开发/内网**。
    #[arg(long = "allow-plaintext-login")]
    allow_plaintext_login: bool,

    /// 单协议最大并发连接数。
    #[arg(long = "max-connections", value_name = "N", default_value_t = 512)]
    max_connections: usize,

    /// 日志级别；`RUST_LOG` 存在时以后者为准。
    #[arg(long = "log", value_name = "LEVEL", default_value = "info")]
    log: String,
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn single(list: &[SocketAddr], label: &str) -> Result<Option<SocketAddr>, String> {
    match list {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        _ => Err(format!(
            "--{label} 只接受一个地址（每个协议口起一个监听器）"
        )),
    }
}

/// 解析证书来源：显式 `--cert/--key` 优先，其次 `--cert-domain`。
fn resolve_cert(cli: &Cli, paths: &Paths) -> Result<Option<CertPair>, String> {
    match (&cli.cert, &cli.key) {
        (Some(cert), Some(key)) => Ok(Some(CertPair {
            cert: cert.clone(),
            key: key.clone(),
        })),
        (Some(_), None) | (None, Some(_)) => Err("--cert 与 --key 必须同时给出".to_string()),
        (None, None) => match &cli.cert_domain {
            Some(domain) => {
                let root = cli
                    .letsencrypt
                    .clone()
                    .unwrap_or_else(|| paths.letsencrypt.clone());
                mailstack_imapd::servers::cert_pair_from_le(&root, domain)
                    .map(Some)
                    .ok_or_else(|| {
                        format!(
                            "在 {} 下找不到 {} 的 fullchain.pem/privkey.pem",
                            root.display(),
                            domain
                        )
                    })
            }
            None => Ok(None),
        },
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let paths = match &cli.config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };

    let listeners = match (|| {
        Ok::<_, String>(Listeners {
            imap: single(&cli.imap, "imap")?,
            imaps: single(&cli.imaps, "imaps")?,
            pop3: single(&cli.pop3, "pop3")?,
            pop3s: single(&cli.pop3s, "pop3s")?,
        })
    })() {
        Ok(listeners) => listeners,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    let tls = match resolve_cert(&cli, &paths) {
        Ok(tls) => tls,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    let config = Config {
        server_name: cli.server_name.clone(),
        listeners,
        tls,
        require_tls: !cli.allow_plaintext_login,
        passwd_root: cli.passwd_root.clone(),
        maildir_name: cli.maildir.clone(),
        max_connections: cli.max_connections,
    };

    // 停机：SIGTERM（systemd）与 Ctrl-C 都当作优雅停机信号。
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("注册 SIGTERM 处理器");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        let _ = shutdown_tx.send(true);
    });

    match run(&paths, config, shutdown_rx).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mailstack-imap: {error}");
            ExitCode::FAILURE
        }
    }
}
