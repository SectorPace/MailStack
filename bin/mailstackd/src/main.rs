use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mailstack_core::Paths;

#[derive(Debug, Parser)]
#[command(
    name = "mailstackd",
    about = "MailStack 守护进程：入站 SMTP（25/465/587）与出站队列调度",
    version
)]
struct Cli {
    #[arg(long = "port", value_name = "PORT")]
    ports: Vec<u16>,

    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    #[arg(long = "log", value_name = "LEVEL", default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    let paths = match &cli.config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };
    let ports = if cli.ports.is_empty() {
        mailstackd::DEFAULT_PORTS.to_vec()
    } else {
        cli.ports.clone()
    };

    match mailstackd::run(paths, ports).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "启动失败");
            eprintln!("mailstackd 启动失败：{error}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
