//! `mailstackctl` —— 向 MailStack 特权 RPC 面调用一个已登记动作。
//!
//! ```text
//! mailstackctl <action> [JSON] [--confirm] [--config-dir DIR] [--ro-socket PATH]
//! ```
//!
//! 通道由动作决定（只读 → socket；变更 → `sudo` 包装器），**不由调用方指定**。
//! 没有「强制走某个通道」的开关 —— 那会是一个绕过门控的入口。

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use mailstack_core::Paths;
use mailstack_priv::PrivilegedCaller;

#[derive(Debug, Parser)]
#[command(
    name = "mailstackctl",
    about = "MailStack CLI：调用特权 RPC 面上的已登记动作（只读走 socket，变更走 sudo 包装器）",
    version
)]
struct Cli {
    /// 动作名，例如 `domains.list`、`settings.set`。
    action: String,

    /// 动作载荷（JSON 对象）。省略时为空对象 `{}`。
    #[arg(value_name = "JSON")]
    data: Option<String>,

    /// 破坏性动作的显式确认（INV-2）。注入 `confirm: true`（布尔）。
    #[arg(long)]
    confirm: bool,

    /// 配置根目录：把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`（影响公网模式判定）。
    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    /// 只读面 socket 路径；覆盖 `MAILSTACK_HELPER_RO_SOCKET`。
    #[arg(long = "ro-socket", value_name = "PATH")]
    ro_socket: Option<PathBuf>,

    /// `sudo` 包装器路径（变更面唯一入口）。
    ///
    /// 变更动作**不经** `--ro-socket`，而是 `sudo <wrapper>` —— 它是系统级路径，
    /// 不受 `--config-dir` 影响。旁路部署或测试时要整条链都避开生产，就用这个开关。
    #[arg(long = "sudo-wrapper", value_name = "PATH")]
    sudo_wrapper: Option<PathBuf>,

    /// 调用超时（毫秒）；覆盖 `MAILSTACK_HELPER_TIMEOUT_MS`。
    #[arg(long = "timeout-ms", value_name = "MS")]
    timeout_ms: Option<u64>,

    /// 输出紧凑 JSON（默认缩进两格）。
    #[arg(long)]
    compact: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let (action, data) =
        match mailstackctl::build_request(&cli.action, cli.data.as_deref(), cli.confirm) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("mailstackctl: {error}");
                return ExitCode::from(mailstackctl::EXIT_USAGE);
            }
        };

    // 公网模式影响只读面能否回退到 sudo（INV-26），因此必须与守护进程同源判定。
    let paths = match &cli.config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };
    let public_mode = mailstack_core::mode::is_public_mode(&paths);

    let mut caller = PrivilegedCaller::new(public_mode);
    if let Some(socket) = cli.ro_socket {
        caller.ro_socket = socket;
    }
    if let Some(wrapper) = cli.sudo_wrapper {
        caller.sudo_wrapper = wrapper;
    }
    if let Some(ms) = cli.timeout_ms {
        caller.timeout = Duration::from_millis(ms);
    }

    match caller.call(&action, &data).await {
        Ok(value) => {
            let rendered = if cli.compact {
                serde_json::to_string(&value)
            } else {
                serde_json::to_string_pretty(&value)
            };
            match rendered {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::from(mailstackctl::EXIT_OK)
                }
                Err(error) => {
                    eprintln!("mailstackctl: 结果无法序列化：{error}");
                    ExitCode::from(mailstackctl::EXIT_OPERATION_FAILED)
                }
            }
        }
        Err(error) => {
            // 错误码与失败性质都打出来：脚本看退出码，人看这一行。
            eprintln!("mailstackctl: {error}（{:?}）", error.kind);
            ExitCode::from(mailstackctl::exit_code_for(&error))
        }
    }
}
