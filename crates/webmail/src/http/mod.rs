pub mod assets;
pub mod auth;
pub mod error;
pub mod handlers;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, HeaderMap, HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, patch, post};
use axum::Router;

use crate::account::AccountDirectory;
use crate::auth::LoginThrottle;
use crate::error::{WebmailError, WebmailResult};
use crate::session::{self, EpochStore, SessionStore};
use crate::{WebmailConfig, API_BODY_LIMIT_BYTES, COMPOSE_BODY_LIMIT_BYTES, VERSION};

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppInner>,
}

pub struct AppInner {
    pub config: WebmailConfig,

    pub accounts: Arc<AccountDirectory>,
    pub sessions: SessionStore,
    pub throttle: LoginThrottle,
    pub epochs: EpochStore,

    pub entry: Option<assets::EntryPoint>,

    pub runtime_id: String,
}

impl AppState {
    pub fn new(config: WebmailConfig) -> Self {
        let entry = assets::resolve_entry(&config.dist);
        let epochs = EpochStore::new(config.paths.webmail_session_epoch.clone());
        let accounts = Arc::new(AccountDirectory::new(&config));
        Self {
            inner: Arc::new(AppInner {
                accounts,
                sessions: SessionStore::new(),
                throttle: LoginThrottle::new(),
                epochs,
                entry,
                runtime_id: format!("mailstack-webmail/{} (rust)", VERSION),
                config,
            }),
        }
    }

    pub fn config(&self) -> &WebmailConfig {
        &self.inner.config
    }

    pub fn entry_file(&self) -> Option<&str> {
        self.inner.entry.as_ref().map(|entry| entry.file.as_str())
    }
}

pub async fn blocking<T, F>(work: F) -> WebmailResult<T>
where
    F: FnOnce() -> WebmailResult<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => Err(WebmailError::internal("blocking task", error)),
    }
}

pub fn cookie_context(
    state: &AppState,
    peer: Option<&SocketAddr>,
    headers: &HeaderMap,
) -> (&'static str, bool) {
    let env_flag = session::cookie_secure_env();
    session::session_cookie_context(
        env_flag.as_deref(),
        state.inner.config.public_mode,
        peer,
        headers,
    )
}

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             script-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; form-action 'self'",
        ),
    );
    response
}

async fn no_store_api(request: Request, next: Next) -> Response {
    let is_api = is_api_path(request.uri().path());
    let mut response = next.run(request).await;
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn body_limit_guard(request: Request, next: Next) -> Response {
    let limit = body_limit_for(request.method(), request.uri().path());
    if let Some(length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        if length > limit as u64 {
            return error::json_error(WebmailError::payload_too_large(
                "request body exceeds the configured limit",
            ));
        }
    }
    next.run(request).await
}

fn body_limit_for(method: &Method, path: &str) -> usize {
    let is_compose =
        *method == Method::POST && matches!(path, "/mail/api/send" | "/mail/api/messages");
    if is_compose {
        COMPOSE_BODY_LIMIT_BYTES
    } else {
        API_BODY_LIMIT_BYTES
    }
}

pub fn is_api_path(path: &str) -> bool {
    path == "/mail/api" || path.starts_with("/mail/api/")
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/mail/api/health", get(handlers::health))
        .route(
            "/mail/api/session",
            post(handlers::login)
                .get(handlers::session_info)
                .delete(handlers::logout),
        )
        .route(
            "/mail/api/folders",
            get(handlers::list_folders).post(handlers::create_folder),
        )
        .route(
            "/mail/api/folders/:folder",
            patch(handlers::rename_folder).delete(handlers::delete_folder),
        )
        .route(
            "/mail/api/messages",
            get(handlers::list_messages)
                .post(handlers::create_draft)
                .layer(DefaultBodyLimit::max(COMPOSE_BODY_LIMIT_BYTES)),
        )
        .route("/mail/api/messages/batch", post(handlers::batch))
        .route(
            "/mail/api/messages/:folder/:uid",
            get(handlers::message_detail)
                .patch(handlers::patch_flags)
                .delete(handlers::delete_message),
        )
        .route(
            "/mail/api/messages/:folder/:uid/raw",
            get(handlers::raw_message),
        )
        .route(
            "/mail/api/messages/:folder/:uid/parts/:part",
            get(handlers::message_part),
        )
        .route(
            "/mail/api/messages/:folder/:uid/move",
            post(handlers::move_message),
        )
        .route("/mail/api/search", get(handlers::search))
        .route("/mail/api/quota", get(handlers::quota))
        .route(
            "/mail/api/send",
            post(handlers::send_message).layer(DefaultBodyLimit::max(COMPOSE_BODY_LIMIT_BYTES)),
        )
        .fallback(handlers::fallback)
        .with_state(state)
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(body_limit_guard))
        .layer(middleware::from_fn(no_store_api))
        .layer(middleware::from_fn(security_headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_path_boundary_is_exact() {
        assert!(is_api_path("/mail/api"));
        assert!(is_api_path("/mail/api/"));
        assert!(is_api_path("/mail/api/messages"));
        assert!(is_api_path("/mail/api/definitely-not"));

        assert!(!is_api_path("/mail/apix"));
        assert!(!is_api_path("/mail/api-docs"));
        assert!(!is_api_path("/"));
        assert!(!is_api_path("/mail.html"));
    }

    #[test]
    fn body_limits_follow_the_contract_split() {
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/send"),
            COMPOSE_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/messages"),
            COMPOSE_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::POST, "/mail/api/folders"),
            API_BODY_LIMIT_BYTES
        );
        assert_eq!(
            body_limit_for(&Method::GET, "/mail/api/messages"),
            API_BODY_LIMIT_BYTES
        );
        for path in ["/mail/api/session", "/mail/api/folders", "/mail/api/quota"] {
            assert_eq!(
                body_limit_for(&Method::POST, path),
                API_BODY_LIMIT_BYTES,
                "{path} 不能拿到写信口子的 32 MiB 额度"
            );
        }
    }
}
