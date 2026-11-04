use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "mailstack-webmail",
    about = "MailStack Webmail 服务：/mail/api + 前端产物（mail.html）托管",
    version
)]
struct Cli {
    #[arg(long = "bind", value_name = "ADDR", default_value = mailstack_webmail_bin::DEFAULT_BIND)]
    bind: String,

    #[arg(long = "dist", value_name = "DIR")]
    dist: Option<PathBuf>,

    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    #[arg(long = "passwd-root", value_name = "DIR")]
    passwd_root: Option<PathBuf>,

    #[arg(long = "maildir", value_name = "NAME")]
    maildir: Option<String>,

    #[arg(long = "log", value_name = "LEVEL", default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let bind: SocketAddr = match cli.bind.parse() {
        Ok(addr) => addr,
        Err(error) => {
            eprintln!("--bind 不是合法的监听地址 {:?}：{error}", cli.bind);
            return ExitCode::FAILURE;
        }
    };

    let config = mailstack_webmail_bin::build_webmail_config(
        cli.config_dir.as_deref(),
        cli.passwd_root,
        cli.maildir,
        cli.dist,
    );
    if let Err(message) = config.validate() {
        eprintln!("mailstack-webmail 配置无效：{message}");
        return ExitCode::FAILURE;
    }

    let server = mailstack_webmail_bin::ServerConfig {
        bind,
        webmail: config,
    };
    match mailstack_webmail_bin::run(server).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(target: "mailstack_webmail", %error, "启动失败");
            eprintln!("mailstack-webmail 启动失败：{error}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
