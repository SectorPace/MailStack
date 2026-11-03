//! `mailstack-webmail` 进程入口。
//!
//! 刻意极薄：解析参数、初始化日志、调 `mailstack_webmail_bin::run`。
//! 所有可测的决策（入口回退、路由、会话、静态托管）都在库里 —— 二进制自身
//! 的逻辑一旦复杂起来，就只能靠「跑一遍」验证。

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
    /// 监听地址。缺省只绑回环；对外暴露请交给反向代理或 SSH 隧道。
    #[arg(long = "bind", value_name = "ADDR", default_value = mailstack_webmail_bin::DEFAULT_BIND)]
    bind: String,

    /// 前端产物目录。给出即托管界面；省略则只提供 API（页面请求 503）。
    #[arg(long = "dist", value_name = "DIR")]
    dist: Option<PathBuf>,

    /// 配置根目录：把 `/etc/mailstack`、`/var/lib/mailstack` 视作 `<DIR>/...`。
    ///
    /// 与 `mailstackd` / `mailstack-web` 同义，用于测试与旁路部署。
    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    /// `passwd` 文件所在根目录（默认 `/etc`，即读 `/etc/passwd`）。
    #[arg(long = "passwd-root", value_name = "DIR")]
    passwd_root: Option<PathBuf>,

    /// 家目录下的 Maildir 目录名（默认 `Maildir`）。
    #[arg(long = "maildir", value_name = "NAME")]
    maildir: Option<String>,

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
            // 地址解析失败必须在 listen 之前说清楚，否则运维只看到「起不来」。
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

/// 初始化日志。`RUST_LOG` 优先于 `--log`。
fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
