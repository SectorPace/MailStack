pub mod assets;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::Uri;
use axum::middleware;
use axum::Router;
use mailstack_core::paths::Paths;
use mailstack_web::{build_api_router, AppState};

pub const DEFAULT_BIND: &str = "127.0.0.1:8443";

pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub bind: SocketAddr,

    pub dist: Option<PathBuf>,
    pub sample_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("cannot bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("server stopped: {0}")]
    Serve(#[source] std::io::Error),
}

pub fn build_app(state: AppState, dist: Option<PathBuf>) -> Router {
    build_api_router(state)
        .fallback(move |uri: Uri| {
            let dist = dist.clone();
            async move { assets::serve(&dist, uri.path()).await }
        })
        .layer(middleware::from_fn(mailstack_web::security_headers))
}

pub async fn run(paths: Paths, config: WebConfig) -> Result<(), WebError> {
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|source| WebError::Bind {
            addr: config.bind,
            source,
        })?;

    let state = AppState::new(paths);

    let sampling = state.inner.telemetry.start_sampling(config.sample_interval);

    let app = build_app(state, config.dist.clone());

    tracing::info!(
        bind = %config.bind,
        dist = ?config.dist,
        "管理控制台已启动（API 路由 + 前端产物）"
    );

    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await;
    sampling.abort();
    result.map_err(WebError::Serve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use tower::ServiceExt;

    fn temp_root(tag: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-webbin-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn app_with_dist(root: &PathBuf) -> Router {
        let paths = Paths::rooted(root);
        build_app(AppState::new(paths), Some(root.join("dist")))
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn an_unknown_api_path_is_json_404_and_never_the_spa() {
        let root = temp_root("api404");
        let dist = root.join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("index.html"), "<html>spa</html>").unwrap();

        let app = app_with_dist(&root);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/definitely-not-a-route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(content_type.contains("application/json"), "{content_type}");
        assert!(!body_text(response).await.contains("spa"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_deep_link_falls_back_to_the_spa_entry() {
        let root = temp_root("spa");
        let dist = root.join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("index.html"), "<html>spa-entry</html>").unwrap();

        let app = app_with_dist(&root);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/some/deep/link")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("spa-entry"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_real_asset_is_served_with_its_content_type() {
        let root = temp_root("asset");
        let dist = root.join("dist");
        std::fs::create_dir_all(dist.join("assets")).unwrap();
        std::fs::write(dist.join("index.html"), "<html>spa</html>").unwrap();
        std::fs::write(dist.join("assets/app-abc.js"), "console.log(1)").unwrap();

        let app = app_with_dist(&root);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/assets/app-abc.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            content_type.starts_with("text/javascript"),
            "{content_type}"
        );
        assert_eq!(body_text(response).await, "console.log(1)");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_bundle_entry_is_served_as_html_not_octet_stream() {
        let root = temp_root("entrytype");
        let dist = root.join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("index.html"), "<html>spa</html>").unwrap();

        let app = app_with_dist(&root);
        let response = app
            .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            content_type.starts_with("text/html"),
            "入口必须是 text/html，实际是 {content_type}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_missing_bundle_reports_503_instead_of_a_blank_page() {
        let root = temp_root("nobundle");
        let paths = Paths::rooted(&root);
        let app = build_app(AppState::new(paths), None);

        let response = app
            .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_text(response)
            .await
            .contains("frontend is not available"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn static_responses_still_carry_the_security_headers() {
        let root = temp_root("headers");
        let dist = root.join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("index.html"), "<html>spa</html>").unwrap();

        let app = app_with_dist(&root);
        let response = app
            .oneshot(HttpRequest::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(response.headers().contains_key("content-security-policy"));
        std::fs::remove_dir_all(&root).ok();
    }
}
