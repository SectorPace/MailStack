//! `mailstack-web` 进程入口。
//!
//! 与 `mailstackd` 一样刻意保持极薄：解析参数、初始化日志、调 `mailstack_web::run`。
//! 所有可测的决策都在库里 —— 二进制自身的逻辑一旦复杂起来，就只能靠「跑一遍」验证。

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
    /// 监听地址。缺省只绑回环；对外暴露请交给反向代理或 SSH 隧道。
    #[arg(long = "bind", value_name = "ADDR", default_value = mailstack_web_bin::DEFAULT_BIND)]
    bind: String,

    /// 前端产物目录。给出即托管界面；省略则只提供 API。
    #[arg(long = "dist", value_name = "DIR")]
    dist: Option<PathBuf>,

    /// 遥测采样周期（秒）。
    #[arg(long = "sample-interval", value_name = "SECS", default_value_t = 2)]
    sample_interval: u64,

    /// 配置根目录：把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`。
    ///
    /// 与 `mailstackd` 同义，用于测试与旁路部署。
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

    let bind: SocketAddr = match cli.bind.parse() {
        Ok(addr) => addr,
        Err(error) => {
            // 地址解析失败必须在 listen 之前就说清楚：否则运维只会看到
            // 「服务起不来」，而真正的原因（比如漏了端口号）藏在参数里。
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
        // 0 秒会让采样任务变成一个忙等循环，直接按 1 秒兜底。
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

/// 初始化日志。`RUST_LOG` 优先于 `--log`。
fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
