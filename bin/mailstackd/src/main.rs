//! `mailstackd` 进程入口。
//!
//! 这里刻意保持极薄：解析参数、初始化日志、调 [`mailstackd::run`]。所有可测的决策都
//! 在库里 —— 二进制自身的逻辑一旦复杂起来，就只能靠「跑一遍」来验证了。

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
    /// 监听的端口，可重复指定；缺省为 25 465 587。
    #[arg(long = "port", value_name = "PORT")]
    ports: Vec<u16>,

    /// 配置根目录：把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`。
    ///
    /// 用于测试与旁路部署 —— 迁移期需要与既有实现并存，不能直接占用生产路径。
    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    /// 日志级别；`RUST_LOG` 存在时以后者为准。
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
            // 启动失败必须明确落日志**并**给非零退出码：否则 systemd 只会看到一个
            // 反复重启的服务，而日志里没有原因。
            tracing::error!(error = %error, "启动失败");
            eprintln!("mailstackd 启动失败：{error}");
            ExitCode::FAILURE
        }
    }
}

/// 初始化日志。`RUST_LOG` 优先于 `--log`。
fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // 已初始化过就忽略（例如测试里重复调用）。
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
