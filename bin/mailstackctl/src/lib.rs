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
}
