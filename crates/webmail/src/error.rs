use axum::http::StatusCode;

use mailstack_imappop3::error::MailError;

pub type WebmailResult<T> = std::result::Result<T, WebmailError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebmailError {
    pub status: StatusCode,

    pub code: &'static str,

    pub message: String,

    pub retry_after_secs: Option<u64>,
}

impl WebmailError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn invalid_json() -> Self {
        Self::bad_request(
            "INVALID_JSON",
            "request body is not valid JSON for this endpoint",
        )
    }

    pub fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "request body must be application/json",
        )
    }

    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "authentication required",
        )
    }

    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email address or password",
        )
    }

    pub fn csrf_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "missing or invalid CSRF token",
        )
    }

    pub fn origin_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "ORIGIN_REJECTED",
            "cross-origin login request is not allowed",
        )
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    pub fn api_not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", "no such API endpoint")
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn too_many_attempts(retry_after_secs: i64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_ATTEMPTS",
            "too many login attempts; retry later",
        );
        error.retry_after_secs = Some(u64::try_from(retry_after_secs.max(1)).unwrap_or(1));
        error
    }

    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", message)
    }

    pub fn internal(label: &'static str, detail: impl std::fmt::Display) -> Self {
        tracing::error!(target: "mailstack_webmail", label, detail = %detail, "webmail internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "internal server error",
        )
    }

    pub fn service_unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }

    pub fn from_mail(error: MailError) -> Self {
        match error {
            MailError::Invalid(message) => Self::bad_request("INVALID_REQUEST", message),
            MailError::Protocol(message) => Self::bad_request("INVALID_REQUEST", message),
            MailError::NotFound(message) => Self::not_found(message),
            MailError::AlreadyExists(message) => Self::conflict(
                "ALREADY_EXISTS",
                format!("resource already exists: {message}"),
            ),
            MailError::QuotaExceeded(message) => Self::conflict(
                "QUOTA_EXCEEDED",
                format!("mailbox quota exceeded: {message}"),
            ),
            MailError::Timeout => Self::service_unavailable(
                "STORAGE_TIMEOUT",
                "mailbox storage did not respond in time; retry later",
            ),
            other => Self::internal("maildir", other),
        }
    }
}

impl std::fmt::Display for WebmailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WebmailError {}

impl From<MailError> for WebmailError {
    fn from(error: MailError) -> Self {
        Self::from_mail(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_codes_and_statuses_are_pinned() {
        assert_eq!(
            WebmailError::invalid_credentials().status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebmailError::invalid_credentials().code,
            "INVALID_CREDENTIALS"
        );
        assert_eq!(WebmailError::csrf_rejected().status, StatusCode::FORBIDDEN);
        assert_eq!(WebmailError::csrf_rejected().code, "CSRF_REJECTED");
        assert_eq!(
            WebmailError::too_many_attempts(30).status,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            WebmailError::too_many_attempts(30).retry_after_secs,
            Some(30)
        );
        assert_eq!(WebmailError::api_not_found().status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn client_input_errors_stay_4xx_and_storage_faults_are_redacted() {
        let invalid = WebmailError::from_mail(MailError::invalid("bad folder"));
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
        assert_eq!(invalid.code, "INVALID_REQUEST");

        let internal = WebmailError::from_mail(MailError::io(
            "/var/vmail/alice/Maildir/cur/x",
            std::io::Error::other("disk on fire"),
        ));
        assert_eq!(internal.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(internal.code, "INTERNAL_ERROR");
        assert!(
            !internal.message.contains("/var/vmail") && !internal.message.contains("disk on fire"),
            "内部细节泄露到响应体：{}",
            internal.message
        );
    }

    #[test]
    fn a_retry_after_is_clamped_to_at_least_one_second() {
        assert_eq!(WebmailError::too_many_attempts(0).retry_after_secs, Some(1));
        assert_eq!(
            WebmailError::too_many_attempts(-5).retry_after_secs,
            Some(1)
        );
    }
}
