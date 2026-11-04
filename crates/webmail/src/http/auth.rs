use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::error::WebmailError;
use crate::http::AppState;
use crate::session::{self, Session};

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub session: Session,
}

impl AuthSession {
    pub fn account(&self) -> &crate::account::Account {
        &self.session.account
    }
}

impl FromRequestParts<AppState> for AuthSession {
    type Rejection = WebmailError;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 AppState,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let token =
                session::session_cookie(&parts.headers).ok_or_else(WebmailError::unauthorized)?;
            let now = time::OffsetDateTime::now_utc();
            let session = state
                .inner
                .sessions
                .get(&token, now)
                .ok_or_else(WebmailError::unauthorized)?;

            let epochs = state.inner.epochs.clone();
            let email = session.account.email.clone();
            let current = tokio::task::spawn_blocking(move || epochs.current(&email))
                .await
                .map_err(|error| WebmailError::internal("epoch lookup", error))?;
            if current > session.epoch {
                state
                    .inner
                    .sessions
                    .remove_by_fingerprint(&session.token_fingerprint);
                tracing::info!(
                    target: "mailstack_webmail",
                    email = %session.account.email,
                    "webmail session invalidated by a session-epoch bump"
                );
                return Err(WebmailError::unauthorized());
            }

            if session::method_requires_csrf(&parts.method) {
                let provided = parts
                    .headers
                    .get("x-csrf-token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                if !session::csrf_matches(&session.csrf, provided) {
                    return Err(WebmailError::csrf_rejected());
                }
            }

            Ok(AuthSession { session })
        })
    }
}

pub fn peer_addr(peer: Option<ConnectInfo<SocketAddr>>) -> Option<SocketAddr> {
    peer.map(|ConnectInfo(address)| address)
}

pub fn client_key(peer: Option<&SocketAddr>) -> String {
    peer.map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
