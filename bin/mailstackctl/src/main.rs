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
    action: Option<String>,

    #[arg(value_name = "JSON")]
    data: Option<String>,

    #[arg(long)]
    confirm: bool,

    #[arg(long = "config-dir", value_name = "DIR")]
    config_dir: Option<PathBuf>,

    #[arg(long = "ro-socket", value_name = "PATH")]
    ro_socket: Option<PathBuf>,

    #[arg(long = "sudo-wrapper", value_name = "PATH")]
    sudo_wrapper: Option<PathBuf>,

    #[arg(long = "timeout-ms", value_name = "MS")]
    timeout_ms: Option<u64>,

    #[arg(long)]
    compact: bool,

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
            eprintln!("mailstackctl: {error}（{:?}）", error.kind);
            ExitCode::from(mailstackctl::exit_code_for(&error))
        }
    }
}

async fn run_privileged_stdin(cli: Cli, paths: Paths) -> ExitCode {
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
