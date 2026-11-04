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
    about = "MailStack IMAP/POP3/ManageSieve 守护进程：IMAP 143/993、POP3 110/995、Sieve 4190，多账号共用一个监听器",
    version
)]
struct Cli {
    #[arg(long = "imap", value_name = "ADDR")]
    imap: Vec<SocketAddr>,

    #[arg(long = "imaps", value_name = "ADDR")]
    imaps: Vec<SocketAddr>,

    #[arg(long = "pop3", value_name = "ADDR")]
    pop3: Vec<SocketAddr>,

    #[arg(long = "pop3s", value_name = "ADDR")]
    pop3s: Vec<SocketAddr>,

    #[arg(long = "managesieve", value_name = "ADDR")]
    managesieve: Vec<SocketAddr>,

    #[arg(long = "metrics", value_name = "ADDR")]
    metrics: Vec<SocketAddr>,

    #[arg(long = "migrate-maildir", value_name = "DIR")]
    migrate_maildir: Option<PathBuf>,

    #[arg(long = "cert", value_name = "FILE")]
    cert: Option<PathBuf>,

    #[arg(long = "key", value_name = "FILE")]
    key: Option<PathBuf>,

    #[arg(long = "cert-domain", value_name = "DOMAIN")]
    cert_domain: Option<String>,

    #[arg(long = "letsencrypt", value_name = "DIR")]
    letsencrypt: Option<PathBuf>,

    #[arg(long = "server-name", value_name = "NAME", default_value = "mailstack")]
    server_name: String,

    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    #[arg(long = "passwd-root", value_name = "DIR", default_value = "/etc")]
    passwd_root: PathBuf,

    #[arg(long = "maildir", value_name = "NAME", default_value = "Maildir")]
    maildir: String,

    #[arg(long = "allow-plaintext-login")]
    allow_plaintext_login: bool,

    #[arg(long = "max-connections", value_name = "N", default_value_t = 512)]
    max_connections: usize,

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

    if let Some(root) = &cli.migrate_maildir {
        return match mailstack_imapd::servers::migrate_dovecot_maildir(root) {
            Ok(report) => {
                println!(
                    "迁移完成：{} 个文件夹 / 导入 UID 映射 {} 份（{} 封）/ 丢弃 {} 条记录 / 关键字 {} 个 / 回退磁盘重建 {} 个",
                    report.folders,
                    report.uidlists_imported,
                    report.messages_mapped,
                    report.messages_unresolved,
                    report.keywords_imported,
                    report.rebuilt_from_disk
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("迁移失败：{error}");
                ExitCode::FAILURE
            }
        };
    }

    let listeners = match (|| {
        Ok::<_, String>(Listeners {
            imap: single(&cli.imap, "imap")?,
            imaps: single(&cli.imaps, "imaps")?,
            pop3: single(&cli.pop3, "pop3")?,
            pop3s: single(&cli.pop3s, "pop3s")?,
            managesieve: single(&cli.managesieve, "managesieve")?,
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

    let metrics_bind = match single(&cli.metrics, "metrics") {
        Ok(bind) => bind,
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
        metrics_bind,
    };

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
