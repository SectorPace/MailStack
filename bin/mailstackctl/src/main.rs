//! `mailstackctl` —— 向 MailStack 特权 RPC 面调用一个已登记动作。
//!
//! ```text
//! mailstackctl <action> [JSON] [--confirm] [--config-dir DIR] [--ro-socket PATH]
//! mailstackctl --privileged-stdin        # sudo 包装器的目标模式（stdin JSON 协议）
//! ```
//!
//! 通道由动作决定（只读 → socket；变更 → `sudo` 包装器），**不由调用方指定**。
//! 没有「强制走某个通道」的开关 —— 那会是一个绕过门控的入口。
//!
//! ## `--privileged-stdin`（sudo 包装器协议）
//!
//! `PrivilegedCaller::call_via_sudo` 以 `sudo <wrapper>`（无 argv）启动包装器，
//! 把 `{"action","data"}` 写进 stdin、从 stdout 读 `{"ok",...}`。因此安装脚本生成的
//! 包装器必须是 `exec /usr/local/bin/mailstackctl --privileged-stdin` —— 不转发 `"$@"`。
//! 本模式以 root 运行，但门控仍走同一个 `ActionGate` + 同一份动作白名单。

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
    ///
    /// `--privileged-stdin` 模式下**不接受**位置参数（动作名只来自 stdin 的 JSON）。
    action: Option<String>,

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

    /// 特权 stdin 模式：从 stdin 读 `{"action","data"}`，stdout 回 `{"ok",...}`。
    ///
    /// 这是 `sudo <wrapper>` 协议的服务端实现。包装器由安装脚本写成
    /// `exec /usr/local/bin/mailstackctl --privileged-stdin`，**不得**转发 `"$@"`：
    /// 动作名只能来自 stdin，argv 注入不得改变被执行的动作用域。
    #[arg(long = "privileged-stdin")]
    privileged_stdin: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let paths = match &cli.config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };

    if cli.privileged_stdin {
        return run_privileged_stdin(cli, paths).await;
    }

    let Some(action_name) = cli.action.as_deref() else {
        eprintln!("mailstackctl: 缺少动作名（用法：mailstackctl <action> [JSON]）");
        return ExitCode::from(mailstackctl::EXIT_USAGE);
    };

    let (action, data) =
        match mailstackctl::build_request(action_name, cli.data.as_deref(), cli.confirm) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("mailstackctl: {error}");
                return ExitCode::from(mailstackctl::EXIT_USAGE);
            }
        };

    // 公网模式影响只读面能否回退到 sudo（INV-26），因此必须与守护进程同源判定。
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

/// `--privileged-stdin`：sudo 包装器���目标模式。
///
/// 输出**始终**是一条 `RpcResponse` JSON（连解析失败也回结构化错误），
/// 这样客户端能区分「门控拒绝 / 动作失败」而不是只看到一句 stderr。
async fn run_privileged_stdin(cli: Cli, paths: Paths) -> ExitCode {
    // 该模式下 argv 不参与动作选择：任何位置参数都视为配置错误。
    if cli.action.is_some() || cli.data.is_some() || cli.confirm {
        eprintln!(
            "mailstackctl: --privileged-stdin 不接受位置参数/--confirm（动作名只能来自 stdin JSON）"
        );
        return ExitCode::from(mailstackctl::EXIT_USAGE);
    }

    let response = match mailstackctl::read_privileged_request(std::io::stdin().lock()) {
        Ok(request) => mailstackctl::dispatch_privileged(paths, request).await,
        Err(message) => mailstack_priv::RpcResponse::err(format!("BAD_REQUEST: {message}")),
    };

    // 客户端按 stdout 的 JSON 判定成功/失败；进程退出码保持 0 表示「协议交换完成」。
    // 真正的失败在 `ok:false` 里，避免客户端把业务错误误判成「包装器崩了」。
    match serde_json::to_string(&response) {
        Ok(text) => {
            println!("{text}");
            ExitCode::from(mailstackctl::EXIT_OK)
        }
        Err(error) => {
            eprintln!("mailstackctl: 响应无法序列化：{error}");
            ExitCode::from(mailstackctl::EXIT_OPERATION_FAILED)
        }
    }
}
