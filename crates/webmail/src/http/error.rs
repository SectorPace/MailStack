//! API 错误的 HTTP 外壳：`{"error":{"code","message"}}`（契约 §2）。
//!
//! 与 `crates/web` 的错误模型刻意不同：管理台包 `{ok:false, error}`，webmail 的
//! 冻结契约只要求 `error` 对象。形状以契约为准，前端按 `error.code` 分支。

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::error::WebmailError;

/// 把错误渲染成契约要求的 JSON 响应（含可选 `Retry-After`）。
pub fn json_error(error: WebmailError) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": error.code,
            "message": error.message,
        }
    });
    let mut response = (error.status, Json(body)).into_response();
    if let Some(seconds) = error.retry_after_secs {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

impl IntoResponse for WebmailError {
    fn into_response(self) -> Response {
        // 5xx 已在构造时把细节写进日志（`WebmailError::internal`）；这里只负责
        // 输出固定形状的响应体。
        if self.status >= StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(
                target: "mailstack_webmail",
                code = self.code,
                status = self.status.as_u16(),
                "responded with a server error"
            );
        }
        json_error(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn errors_use_the_frozen_envelope() {
        let response = json_error(WebmailError::invalid_credentials());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INVALID_CREDENTIALS");
        assert!(body["error"]["message"].is_string());
        // 契约形状：**没有** ok 字段。
        assert!(body.get("ok").is_none());
    }

    #[tokio::test]
    async fn too_many_attempts_carries_retry_after() {
        let response = json_error(WebmailError::too_many_attempts(42));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "42");
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "TOO_MANY_ATTEMPTS");
    }
}
