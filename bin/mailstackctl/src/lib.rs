//! `mailstackctl` 的可测部分：参数 → 特权调用的翻译，以及退出码映射。
//!
//! ## 为什么单独抽出来
//!
//! 命令行本身没什么好测的，但**两件事必须测**，因为它们一旦写错，错误会发生在
//! 特权边界上：
//!
//! 1. `--confirm` 必须产出**真正的布尔** `confirm: true`。`ActionGate` 明确拒绝
//!    「真值」（字符串 `"true"`、数字 `1`），因为那会让破坏性动作的确认形同虚设
//!    （INV-2）。这里若拼成字符串，破坏性动作会**永远无法执行**；若被宽松解析，
//!    则确认门形同虚设 —— 两个方向都不可接受。
//! 2. 退出码必须区分「助手不可达」与「动作失败」。INV-8 要求前者是 503 而不是
//!    400/500，脚本与监控靠状态码判断该重试还是该报警；CLI 同理，一律返回 1
//!    会把这两种情况混为一谈。
//!
//! ## 通道不由本模块决定
//!
//! 动作走只读 socket 还是 `sudo` 包装器，由
//! [`mailstack_priv::PrivilegedCaller::channel_for`]（即 `core::actions::classify`）
//! 唯一判定。CLI **不**提供「强制走某个通道」的开关 —— 那会成为一个绕过门控的入口。

use mailstack_priv::{CallError, FailureKind};
use serde_json::{json, Value};

/// 成功。
pub const EXIT_OK: u8 = 0;
/// 动作执行失败（业务错误）。
pub const EXIT_OPERATION_FAILED: u8 = 1;
/// 用法错误（JSON 非法、参数不合法）。
pub const EXIT_USAGE: u8 = 2;
/// 特权助手不可达（INV-8：不得降级执行）。
pub const EXIT_HELPER_UNAVAILABLE: u8 = 3;
/// 操作中途超时：请求可能已执行，**不得**重试（INV-25）。
pub const EXIT_TIMEOUT: u8 = 4;

/// 命令行用法错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("data 不是合法 JSON：{0}")]
    InvalidJson(String),
    #[error("--confirm 只能用于对象载荷（实际是 {0}）")]
    ConfirmNeedsObject(&'static str),
}

/// 把参数翻译成一次特权调用的 `(action, data)`。
pub fn build_request(
    action: &str,
    raw_data: Option<&str>,
    confirm: bool,
) -> Result<(String, Value), UsageError> {
    let mut data = match raw_data {
        Some(raw) => serde_json::from_str::<Value>(raw)
            .map_err(|error| UsageError::InvalidJson(error.to_string()))?,
        None => json!({}),
    };

    if confirm {
        match &mut data {
            Value::Object(map) => {
                // 必须是**布尔**：字符串 "true" / 数字 1 会被 ActionGate 判为无效确认。
                map.insert("confirm".to_string(), Value::Bool(true));
            }
            other => return Err(UsageError::ConfirmNeedsObject(kind_of(other))),
        }
    }

    Ok((action.to_string(), data))
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "布尔",
        Value::Number(_) => "数字",
        Value::String(_) => "字符串",
        Value::Array(_) => "数组",
        Value::Object(_) => "对象",
    }
}

/// 把调用失败映射为退出码。
pub fn exit_code_for(error: &CallError) -> u8 {
    match error.kind {
        FailureKind::TransportUnavailable => EXIT_HELPER_UNAVAILABLE,
        FailureKind::MidOperationTimeout => EXIT_TIMEOUT,
        FailureKind::BusinessError => EXIT_OPERATION_FAILED,
    }
}

// ───────────────────────── 特权 stdin 模式（sudo 包装器的目标） ─────────────────────────
//
// ## 为什么需要它
//
// `PrivilegedCaller::call_via_sudo` 的协议是：`sudo <wrapper>`（**不带任何 argv**），
// 把 `{"action","data"}` JSON 写进 stdin，从 stdout 读回 `{"ok",...}` JSON。
// 这是全仓唯一的变更面客户端实现，所以包装器**必须**能说同一套协议。
//
// 早期文档里的包装器是 `exec /usr/local/bin/mailstackctl "$@"` —— 但 `mailstackctl`
// 的 CLI 协议是 `<action> [JSON]` argv，而客户端不传 argv。两者对不上时 36 个变更
// 动作在生产上全部不可用，且错误只会显示成笼统的 `PRIVILEGED_OPERATION_FAILED`。
// 这里补上 stdin 模式，让「包装器 = mailstackctl --privileged-stdin」成为可工作的
// 硬前置条件（安装脚本按此生成包装器）。
//
// ## 安全边界
//
// 本模式**以 root 运行**，但门控与 daemon 完全同源：同一个 `ActionGate`、同一份
// `core::actions` 白名单、同一条 `Channel::Rw` 判定、同一个 `confirm: true` 要求。
// 它不读 argv 里的动作名（动作名只来自 stdin 的 JSON），因此包装器不转发 `"$@"`
// 也不会被参数注入改变行为。

/// 单次特权请求的 stdin 上限（与 `framing::MAX_REQUEST_BYTES` 同源）。
pub const MAX_PRIVILEGED_REQUEST_BYTES: usize = mailstack_priv::framing::MAX_REQUEST_BYTES;

/// 从任意 reader 读一个 `RpcRequest`（有界读取 + 严格 JSON）。
///
/// 失败返回面向运维的短句：调用方会把它包成 `RpcResponse::err` 输出，
/// 不打印栈、不打印原始字节。
pub fn read_privileged_request(
    reader: impl std::io::Read,
) -> Result<mailstack_priv::RpcRequest, String> {
    use std::io::Read as _;

    let mut buffer = Vec::new();
    // 多读 1 字节用于判断「超限」，而不是把 16 MB 全读进来再拒绝。
    reader
        .take((MAX_PRIVILEGED_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut buffer)
        .map_err(|error| format!("读取 stdin 失败：{error}"))?;
    if buffer.len() > MAX_PRIVILEGED_REQUEST_BYTES {
        return Err(format!("请求超过 {MAX_PRIVILEGED_REQUEST_BYTES} 字节上限"));
    }
    if buffer.is_empty() {
        return Err("stdin 为空：特权模式需要一条 JSON 请求".to_string());
    }
    serde_json::from_slice(&buffer).map_err(|error| format!("请求不是合法 JSON：{error}"))
}

/// 在进程内以**变更面（Rw）**执行一条已登记动作。
///
/// 与 `mailstackd` 的 `helper.sock` 走完全相同的 [`RoServer::handle_request`]，
/// 因此门控、超时、错误形状都不会出现第二套实现。
pub async fn dispatch_privileged(
    paths: mailstack_core::Paths,
    request: mailstack_priv::RpcRequest,
) -> mailstack_priv::RpcResponse {
    use std::sync::Arc;

    use mailstack_core::actions::Channel;
    use mailstack_priv::handlers::Registry;
    use mailstack_priv::{RoServer, RoServerConfig};

    let registry = Arc::new(Registry::with_core_actions(paths.clone()));
    // socket 路径在本模式下不被绑定（只复用 handle_request 的门控 + 派发），
    // 传 rw_socket 的默认路径是为了让配置对象保持生产语义。
    let server = RoServer::new(RoServerConfig::rw_socket(paths), registry);
    server.handle_request(Channel::Rw, request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_data_means_an_empty_object() {
        let (action, data) = build_request("domains.list", None, false).unwrap();
        assert_eq!(action, "domains.list");
        assert_eq!(data, json!({}));
    }

    #[test]
    fn a_json_payload_is_parsed_verbatim() {
        let (_action, data) =
            build_request("domains.add", Some(r#"{"name":"example.org"}"#), false).unwrap();
        assert_eq!(data, json!({"name": "example.org"}));
    }

    #[test]
    fn malformed_json_is_a_usage_error_not_a_silent_empty_payload() {
        // 静默变成 {} 会让 `domains.add` 之类以「参数缺失」失败，掩盖真正的原因。
        let error = build_request("domains.add", Some("{oops"), false).unwrap_err();
        assert!(
            matches!(error, UsageError::InvalidJson(_)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn confirm_is_injected_as_a_real_boolean() {
        // INV-2：ActionGate 拒绝「真值」；必须是真的布尔。
        let (_action, data) = build_request(
            "admin.set",
            Some(r#"{"username":"root","password":"x"}"#),
            true,
        )
        .unwrap();
        assert_eq!(
            data.get("confirm"),
            Some(&Value::Bool(true)),
            "--confirm 必须产出布尔 true：{data}"
        );
        assert!(
            !data["confirm"].is_string(),
            "字符串 \"true\" 会被 ActionGate 判为无效确认"
        );
    }

    #[test]
    fn confirm_on_a_non_object_payload_is_refused() {
        // 数组载荷没法携带 confirm，静默忽略 = 破坏性动作在未确认的情况下发出。
        let error = build_request("admin.set", Some("[1,2,3]"), true).unwrap_err();
        assert_eq!(error, UsageError::ConfirmNeedsObject("数组"));
        let error = build_request("admin.set", Some("\"str\""), true).unwrap_err();
        assert_eq!(error, UsageError::ConfirmNeedsObject("字符串"));
    }

    #[test]
    fn without_the_flag_no_confirm_key_is_added() {
        let (_action, data) = build_request("admin.set", Some(r#"{"a":1}"#), false).unwrap();
        assert_eq!(data, json!({"a": 1}), "不加 --confirm 就不得替调用方补确认");
    }

    #[test]
    fn helper_unavailable_and_operation_failure_get_different_exit_codes() {
        // INV-8：脚本必须能区分「特权通道没了」与「动作失败了」。
        let unavailable = CallError {
            kind: FailureKind::TransportUnavailable,
            code: mailstack_priv::ERR_HELPER_UNAVAILABLE,
            message: "x".into(),
        };
        let failed = CallError {
            kind: FailureKind::BusinessError,
            code: mailstack_priv::ERR_OPERATION_FAILED,
            message: "x".into(),
        };
        let timeout = CallError {
            kind: FailureKind::MidOperationTimeout,
            code: mailstack_priv::ERR_HELPER_TIMEOUT,
            message: "x".into(),
        };

        assert_eq!(exit_code_for(&unavailable), EXIT_HELPER_UNAVAILABLE);
        assert_eq!(exit_code_for(&failed), EXIT_OPERATION_FAILED);
        assert_eq!(exit_code_for(&timeout), EXIT_TIMEOUT);
        assert_ne!(
            exit_code_for(&unavailable),
            exit_code_for(&failed),
            "两种失败不得共用退出码"
        );
    }

    // ─────────────── 特权 stdin 模式（sudo 包装器协议的服务端实现） ───────────────

    fn rooted_paths() -> (tempfile::TempDir, mailstack_core::Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        std::fs::create_dir_all(&paths.etc).unwrap();
        (dir, paths)
    }

    fn request(action: &str, data: Value) -> mailstack_priv::RpcRequest {
        mailstack_priv::RpcRequest {
            action: action.to_string(),
            data,
        }
    }

    #[test]
    fn privileged_request_parsing_rejects_empty_oversize_and_malformed_input() {
        // 空 stdin：直接报「需要一条 JSON 请求」，而不是当成 {} 去执行某个默认动作。
        assert!(read_privileged_request(std::io::empty()).is_err());

        // 畸形 JSON 必须拒绝，不得静默当成空对象。
        let error = read_privileged_request(&b"{oops"[..]).unwrap_err();
        assert!(error.contains("JSON"), "实际：{error}");

        // 超过上限的输入不得被整段读入后执行。
        let oversize = vec![b' '; MAX_PRIVILEGED_REQUEST_BYTES + 2];
        let error = read_privileged_request(&oversize[..]).unwrap_err();
        assert!(error.contains("上限"), "实际：{error}");

        let ok = read_privileged_request(&br#"{"action":"domains.list","data":{}}"#[..]).unwrap();
        assert_eq!(ok.action, "domains.list");
    }

    #[tokio::test]
    async fn privileged_dispatch_refuses_unknown_actions() {
        // 包装器以 root 运行，门控必须与 daemon 同源：未登记动作一律拒绝。
        let (_dir, paths) = rooted_paths();
        let response = dispatch_privileged(paths, request("totally.unknown", json!({}))).await;
        assert!(!response.ok);
        assert!(
            response
                .error
                .unwrap_or_default()
                .contains("UNKNOWN_ACTION"),
            "未登记动作必须以 UNKNOWN_ACTION 拒绝"
        );
    }

    #[tokio::test]
    async fn privileged_dispatch_executes_allowlisted_actions() {
        // 正向：一个只读动作在变更面上可执行（RW 通道有权执行 RO 动作）。
        let (_dir, paths) = rooted_paths();
        let response = dispatch_privileged(paths, request("domains.list", json!({}))).await;
        assert!(response.ok, "domains.list 应成功：{:?}", response.error);

        // 变更动作：admin.set 在没有 admin.json 时创建它（安装脚本的引导路径）。
        let (_dir2, paths2) = rooted_paths();
        let response = dispatch_privileged(
            paths2.clone(),
            request(
                "admin.set",
                json!({"username": "admin", "password": "Bootstrap-Pass-9"}),
            ),
        )
        .await;
        assert!(response.ok, "admin.set 应成功：{:?}", response.error);
        assert!(
            paths2.admin_config.exists(),
            "特权 stdin 模式必须真的创建 /etc/mailstack/admin.json（安装脚本依赖此行为）"
        );
    }

    #[tokio::test]
    async fn privileged_dispatch_keeps_the_confirmation_gate_for_destructive_actions() {
        // 破坏性动作缺少 confirm: true → 与 daemon 一样拒绝，不得因为「是 root」就放行。
        let (_dir, paths) = rooted_paths();
        let response = dispatch_privileged(
            paths,
            request("users.delete", json!({"address": "nobody@example.com"})),
        )
        .await;
        assert!(!response.ok);
        assert!(
            response
                .error
                .unwrap_or_default()
                .contains("CONFIRMATION_REQUIRED"),
            "破坏性动作必须要求 confirm: true"
        );
    }
}
