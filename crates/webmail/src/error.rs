//! Webmail 错误模型。
//!
//! 对外响应体形状（契约 §2）：`{"error":{"code":"...","message":"..."}}`。
//!
//! ## 为什么错误对象自己带 status
//!
//! 契约给每个失败场景都规定了状态码与 `code`（401 `INVALID_CREDENTIALS`、
//! 403 `CSRF_REJECTED`、409 `FOLDER_NOT_EMPTY`、429 `TOO_MANY_ATTEMPTS` …）。
//! 把「HTTP 状态」与「代码」拆成两个模块各判一次，迟早会出现 401 配
//! `CSRF_REJECTED` 这种自相矛盾的响应；因此这里一个值同时决定两者。
//!
//! ## 内部错误绝不回显细节
//!
//! I/O 错误、uidlist 损坏、路径、堆栈都只进日志（`tracing::error!`）。响应体只给
//! 固定的 `INTERNAL_ERROR` 文案：把 `/var/.../Maildir` 暴露给浏览器既无用，也
//! 是信息泄露（泄露主机布局）。构造内部错误时就把细节写日志，是**强制**的：
//! 没有「拿了 detail 却不记」的路径。

use axum::http::StatusCode;

use mailstack_imappop3::error::MailError;

/// Webmail 的库级错误别名。
pub type WebmailResult<T> = std::result::Result<T, WebmailError>;

/// Webmail 错误：状态码 + 稳定 code + 面向用户的消息（内部细节只进日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebmailError {
    /// HTTP 状态码。
    pub status: StatusCode,
    /// 稳定的机器可读 code（契约里点名的那些）。**不随文案变化。**
    pub code: &'static str,
    /// 面向用户的消息；不得包含内部路径/堆栈。
    pub message: String,
    /// 可选的 `Retry-After`（秒），仅 429 使用。
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

    /// 400：调用方输入非法。`code` 应当描述**哪一类**输入（如 `INVALID_FOLDER`）。
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// 400：JSON 请求体畸形。统一成同一句文案，不回显 serde 的内部报错。
    pub fn invalid_json() -> Self {
        Self::bad_request(
            "INVALID_JSON",
            "request body is not valid JSON for this endpoint",
        )
    }

    /// 400：请求体 Content-Type 不是 JSON。
    pub fn unsupported_media_type() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "request body must be application/json",
        )
    }

    /// 401：没有有效会话（契约 §1.2）。
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "authentication required",
        )
    }

    /// 401：登录失败。**不区分**用户不存在 / 口令错 / 邮箱未建（契约 §1.1）。
    pub fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "invalid email address or password",
        )
    }

    /// 403：CSRF 校验失败（契约 §1.3）。
    pub fn csrf_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "CSRF_REJECTED",
            "missing or invalid CSRF token",
        )
    }

    /// 403：登录请求的 Origin 与 Host 不同源（契约 §1.3 同源检查）。
    pub fn origin_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "ORIGIN_REJECTED",
            "cross-origin login request is not allowed",
        )
    }

    /// 404：请求的对象不存在（文件夹 / 邮件 / 部件）。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    /// 404：`/mail/api` 未匹配路径的兜底（契约 §3：必须是 JSON）。
    pub fn api_not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", "no such API endpoint")
    }

    /// 409：资源冲突（重名文件夹等）。
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// 429：登录限流（契约 §1.1）。
    pub fn too_many_attempts(retry_after_secs: i64) -> Self {
        let mut error = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_ATTEMPTS",
            "too many login attempts; retry later",
        );
        error.retry_after_secs = Some(u64::try_from(retry_after_secs.max(1)).unwrap_or(1));
        error
    }

    /// 413：请求体 / 附件超过上限。
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", message)
    }

    /// 500：内部错误。`detail` **只进日志**，响应体固定文案。
    ///
    /// 这是构造内部错误的唯一入口：想拿到一个 500 就必须把细节交出来（被记日志），
    /// 因此不存在「某条路径忘了记日志」的漏洞。
    pub fn internal(label: &'static str, detail: impl std::fmt::Display) -> Self {
        tracing::error!(target: "mailstack_webmail", label, detail = %detail, "webmail internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "internal server error",
        )
    }

    /// 503：某个依赖暂时不可用（队列落盘失败等）。语义是「这次没做成，可以重试」。
    pub fn service_unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }

    /// 把 Maildir 层的错误映射成对外的错误模型。
    ///
    /// 映射原则：**客户端输入非法**必须与**服务器故障**可分辨。前者回 4xx（如实
    /// 告诉调用方是哪个参数不对），后者回 500 且细节只进日志。
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

        // 内部错误：响应里**不得**出现路径或 OS 错误串。
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
