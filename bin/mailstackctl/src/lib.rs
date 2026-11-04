use mailstack_priv::{CallError, FailureKind};
use serde_json::{json, Value};

pub const EXIT_OK: u8 = 0;

pub const EXIT_OPERATION_FAILED: u8 = 1;

pub const EXIT_USAGE: u8 = 2;

pub const EXIT_HELPER_UNAVAILABLE: u8 = 3;

pub const EXIT_TIMEOUT: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("data 不是合法 JSON：{0}")]
    InvalidJson(String),
    #[error("--confirm 只能用于对象载荷（实际是 {0}）")]
    ConfirmNeedsObject(&'static str),
}

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

pub fn exit_code_for(error: &CallError) -> u8 {
    match error.kind {
        FailureKind::TransportUnavailable => EXIT_HELPER_UNAVAILABLE,
        FailureKind::MidOperationTimeout => EXIT_TIMEOUT,
        FailureKind::BusinessError => EXIT_OPERATION_FAILED,
    }
}

pub const MAX_PRIVILEGED_REQUEST_BYTES: usize = mailstack_priv::framing::MAX_REQUEST_BYTES;

pub fn read_privileged_request(
    reader: impl std::io::Read,
) -> Result<mailstack_priv::RpcRequest, String> {
    use std::io::Read as _;

    let mut buffer = Vec::new();

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

pub async fn dispatch_privileged(
    paths: mailstack_core::Paths,
    request: mailstack_priv::RpcRequest,
) -> mailstack_priv::RpcResponse {
    use std::sync::Arc;

    use mailstack_core::actions::Channel;
    use mailstack_priv::handlers::Registry;
    use mailstack_priv::{RoServer, RoServerConfig};

    let registry = Arc::new(
        Registry::with_core_actions(paths.clone())
            .with_readers(Arc::new(mailstack_priv::Readers::system(paths.clone()))),
    );

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
        let error = build_request("domains.add", Some("{oops"), false).unwrap_err();
        assert!(
            matches!(error, UsageError::InvalidJson(_)),
            "实际：{error:?}"
        );
    }

    #[test]
    fn confirm_is_injected_as_a_real_boolean() {
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
        assert!(read_privileged_request(std::io::empty()).is_err());

        let error = read_privileged_request(&b"{oops"[..]).unwrap_err();
        assert!(error.contains("JSON"), "实际：{error}");

        let oversize = vec![b' '; MAX_PRIVILEGED_REQUEST_BYTES + 2];
        let error = read_privileged_request(&oversize[..]).unwrap_err();
        assert!(error.contains("上限"), "实际：{error}");

        let ok = read_privileged_request(&br#"{"action":"domains.list","data":{}}"#[..]).unwrap();
        assert_eq!(ok.action, "domains.list");
    }

    #[tokio::test]
    async fn privileged_dispatch_refuses_unknown_actions() {
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
        let (_dir, paths) = rooted_paths();
        let response = dispatch_privileged(paths, request("domains.list", json!({}))).await;
        assert!(response.ok, "domains.list 应成功：{:?}", response.error);

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

    #[tokio::test]
    async fn privileged_dispatch_exposes_the_reader_action_families() {
        let (_dir, paths) = rooted_paths();
        for action in ["users.list", "certs.list", "setup.status"] {
            let response = dispatch_privileged(paths.clone(), request(action, json!({}))).await;
            assert!(
                response.ok,
                "{action} should be implemented on the privileged channel: {:?}",
                response.error
            );
        }
    }
}
