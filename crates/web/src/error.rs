//! API 错误模型（规格书 §4.4）。
//!
//! 响应体形状：`{ ok: false, error: { code, message } }`。
//! 前端提取 `error.message` 与 `error.code`，故这两个字段名是契约。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::ratelimit::{
    ERR_AUTH_REQUIRED, ERR_CSRF_INVALID, ERR_INTERNAL_ERROR, ERR_PAYLOAD_TOO_LARGE,
    ERR_RATE_LIMITED,
};

/// API 错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    /// 可选的 `Retry-After`（秒）。
    pub retry_after_secs: Option<i64>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
            retry_after_secs: None,
        }
    }

    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn with_retry_after(mut self, secs: i64) -> Self {
        self.retry_after_secs = Some(secs);
        self
    }

    /// 401 未认证（INV-7：用 401 而不是 403，以免泄露资源存在性）。
    pub fn auth_required() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: ERR_AUTH_REQUIRED.to_string(),
            message: "authentication required".to_string(),
            retry_after_secs: None,
        }
    }

    /// 403 CSRF 校验失败。
    pub fn csrf_invalid() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: ERR_CSRF_INVALID.to_string(),
            message: "missing or invalid CSRF token".to_string(),
            retry_after_secs: None,
        }
    }

    /// 429 限流。
    pub fn rate_limited(retry_after_secs: i64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: ERR_RATE_LIMITED.to_string(),
            message: "too many requests".to_string(),
            retry_after_secs: Some(retry_after_secs),
        }
    }

    /// 413 请求体过大。
    pub fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: ERR_PAYLOAD_TOO_LARGE.to_string(),
            message: "request payload exceeds the configured limit".to_string(),
            retry_after_secs: None,
        }
    }

    /// 503 特权助手不可达（INV-8：**不得**降级为无特权执行）。
    pub fn helper_unavailable(message: impl Into<String>) -> Self {
        Self::with_status(
            Self::new(crate::ratelimit::ERR_PRIVILEGED_HELPER_UNAVAILABLE, message),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::with_status(
            Self::new(ERR_INTERNAL_ERROR, message),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "ok": false,
            "error": { "code": self.code, "message": self.message }
        });
        let mut response = (self.status, Json(body)).into_response();
        if let Some(secs) = self.retry_after_secs {
            if let Ok(value) = secs.to_string().parse() {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// 成功响应：**裸对象**，不套 `{ ok: true, data }`。
///
/// 为什么：基线 `backend/server.production.ts` 的业务路由是 `res.json(result)` ——
/// 裸对象。管理前端（mailstack-admin-frontend）对非列表动作直接读 `body.<field>`，
/// 套壳会让 `snapshot` / `settings.get` / `users.status` 这类动作**读不到任何字段**。
/// 列表动作之所以没暴露这个问题，是它自己的 `pickList` 兜底了 `o.data ?? o`。
///
/// 错误响应形状不受影响，仍是 `{ ok: false, error: { code, message } }`。
pub fn ok_json(data: serde_json::Value) -> Response {
    Json(data).into_response()
}

/// RPC 桥（`POST /api/rpc`）的成功响应：`{ ok: true, data }`。
///
/// 与 [`ok_json`] **故意不同**：桥是前端唯一的 fallback 传输层，其返回值由前端
/// `bridge()` 统一拆包（`body.ok` / `body.data`），不能裸对象 —— 前端会把整个
/// 响应体当成 `data`。REST 路由与桥并存两套形状，是前端传输层设计的结果。
pub fn rpc_ok_json(data: serde_json::Value) -> Response {
    Json(serde_json::json!({ "ok": true, "data": data })).into_response()
}

/// RPC 桥的失败响应：`{ ok: false, error: "<可读消息>" }`。
///
/// `error` 是**字符串**而非对象：前端 `bridge()` 把它直接当 message 展示。
/// 若沿用 [`ApiError`] 的嵌套形状，界面只会显示 `HTTP 5xx`，丢掉可读原因。
pub fn rpc_err_json(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message.into() })),
    )
        .into_response()
}

/// `/api/*` 兜底 404（**必须**返回 JSON，不是 404 HTML，规格书 §5.1）。
pub fn api_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "ok": false,
            "error": {
                "code": crate::ratelimit::ERR_API_NOT_FOUND,
                "message": "no such API endpoint"
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn error_body_has_the_documented_shape() {
        let response = ApiError::new("LOGIN_FAILED", "invalid credentials").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = body_json(response).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "LOGIN_FAILED");
        assert_eq!(body["error"]["message"], "invalid credentials");
    }

    #[tokio::test]
    async fn auth_required_is_401_not_403() {
        // INV-7：401 避免泄露资源存在性。
        let response = ApiError::auth_required().into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "AUTH_REQUIRED");
    }

    #[tokio::test]
    async fn rate_limited_sets_retry_after_header() {
        let response = ApiError::rate_limited(42).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "42");
    }

    #[tokio::test]
    async fn helper_unavailable_is_503_and_never_silently_succeeds() {
        // INV-8：不可达必须是 503，不得降级为无特权执行。
        let response = ApiError::helper_unavailable("socket gone").into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PRIVILEGED_HELPER_UNAVAILABLE");
    }

    #[tokio::test]
    async fn success_body_is_the_bare_object_without_an_ok_wrapper() {
        // 套壳会让前端的非列表动作（snapshot / settings.get / users.status…）读空。
        let response = ok_json(serde_json::json!({ "name": "example.com" }));
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["name"], "example.com");
        assert!(body.get("ok").is_none(), "成功响应不得套 {{ok,data}} 外壳");
        assert!(
            body.get("data").is_none(),
            "成功响应不得套 {{ok,data}} 外壳"
        );
    }

    #[tokio::test]
    async fn rpc_bridge_shapes_are_the_opposite_of_the_rest_routes() {
        // 桥的返回值由前端 bridge() 拆包，必须带外壳；error 必须是字符串。
        let ok = body_json(rpc_ok_json(serde_json::json!({ "name": "x" }))).await;
        assert_eq!(ok["ok"], true);
        assert_eq!(ok["data"]["name"], "x");

        let failed = rpc_err_json(StatusCode::BAD_REQUEST, "域名已存在");
        assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
        let body = body_json(failed).await;
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"], "域名已存在");
    }

    #[tokio::test]
    async fn api_not_found_is_json_not_html() {
        // §5.1：/api 兜底必须是 JSON 响应，不能回落到 SPA 的 index.html。
        let response = api_not_found();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .contains("application/json"),
            "必须是 JSON 内容类型"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "API_NOT_FOUND");
    }

    #[tokio::test]
    async fn payload_too_large_is_413() {
        let response = ApiError::payload_too_large().into_response();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PAYLOAD_TOO_LARGE");
    }

    #[tokio::test]
    async fn internal_error_does_not_leak_details_by_default() {
        let response = ApiError::internal("boom").into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    }

    #[test]
    fn status_can_be_overridden() {
        let err = ApiError::new("X", "y").with_status(StatusCode::CONFLICT);
        assert_eq!(err.status, StatusCode::CONFLICT);
    }
}
