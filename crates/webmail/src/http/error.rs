use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::error::WebmailError;

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
