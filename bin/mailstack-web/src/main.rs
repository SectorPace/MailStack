use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mailstack_core::Paths;

#[derive(Debug, Parser)]
#[command(
    name = "mailstack-web",
    about = "MailStack 管理控制台服务：管理 API + 前端产物",
    version
)]
struct Cli {
    #[arg(long = "bind", value_name = "ADDR", default_value = mailstack_web_bin::DEFAULT_BIND)]
    bind: String,

    #[arg(long = "dist", value_name = "DIR")]
    dist: Option<PathBuf>,

    #[arg(long = "sample-interval", value_name = "SECS", default_value_t = 2)]
    sample_interval: u64,

    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

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

    let paths = match &cli.config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };

    let config = mailstack_web_bin::WebConfig {
        bind,
        dist: cli.dist.clone(),

        sample_interval: Duration::from_secs(cli.sample_interval.max(1)),
    };

    match mailstack_web_bin::run(paths, config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "启动失败");
            eprintln!("mailstack-web 启动失败：{error}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
