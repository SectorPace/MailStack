//! `mailstack-web` 服务：把管理 API 与前端产物组装成一个可运行的 HTTP 服务。
//!
//! 为什么需要这个进程：`mailstack-web` 这个 crate 一直只提供 [`build_router`]，
//! **没有任何二进制在跑它**。路由接得再全，没有人 listen 就等于不存在；遥测的后台
//! 采样任务也因此没有宿主 —— 没有它，`points` 永远不会自己增长，仪表盘的曲线会
//! 永远停在「按需采样」的那一个点上。
//!
//! 这里刻意保持极薄：可测的决策（路径解析、内容类型、SPA 回退、API 兜底）都在
//! [`assets`] 与 [`build_app`] 里，`main` 只负责解析参数与初始化日志。

pub mod assets;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::http::Uri;
use axum::middleware;
use axum::Router;
use mailstack_core::paths::Paths;
use mailstack_web::{build_api_router, AppState};

/// 默认监听地址。
///
/// **只绑回环**：管理面直面上网等于把控制台的门开在公网上。对外暴露应当由反向代理
/// 或 SSH 隧道承担 —— 前端自己的安全提示也是这么写的。TLS 终止同样属于部署层，
/// 不在本进程内做（规格书 §3.4 把 TLS 栈留给真正需要出站/入站加密的组件）。
pub const DEFAULT_BIND: &str = "127.0.0.1:8443";

/// 遥测后台采样周期，与基线 `SystemMetricsCollector` 的 2 秒一致。
pub const DEFAULT_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

/// 运行参数。
#[derive(Debug, Clone)]
pub struct WebConfig {
    pub bind: SocketAddr,
    /// 前端产物目录。`None` 表示本次部署只提供 API。
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

/// 组装最终应用：`/api/*` 交给管理 API，其余路径落到前端产物。
///
/// 顺序上**先**挂 API、**再**挂静态兜底，是为了让 `/api` 的形状保持 JSON ——
/// `assets::serve` 也会独立地把 `/api/*` 挡回去，两道都要有：只靠路由顺序的话，
/// 将来有人在 API 里漏注册一条路径，它就会静默地回一段 HTML 给前端。
pub fn build_app(state: AppState, dist: Option<PathBuf>) -> Router {
    build_api_router(state)
        .fallback(move |uri: Uri| {
            let dist = dist.clone();
            async move { assets::serve(&dist, uri.path()).await }
        })
        // 静态响应同样要带安全响应头（nosniff / frame-options / CSP）。
        // 生产环境里这个进程返回的绝大多数响应都是静态文件，漏掉它们等于没加。
        .layer(middleware::from_fn(mailstack_web::security_headers))
}

/// 启动服务，直到进程被终止。
pub async fn run(paths: Paths, config: WebConfig) -> Result<(), WebError> {
    let state = AppState::new(paths);

    // 采样任务的生命周期与进程一致：`run` 返回（出错或退出）时就该收掉它，
    // 否则测试里会留下一条一直在读 `/proc` 的后台任务。
    let sampling = state.inner.telemetry.start_sampling(config.sample_interval);

    let app = build_app(state, config.dist.clone());
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|source| WebError::Bind {
            addr: config.bind,
            source,
        })?;

    tracing::info!(
        bind = %config.bind,
        dist = ?config.dist,
        "管理控制台已启动（API 路由 + 前端产物）"
    );

    let result = axum::serve(
        listener,
        // `into_make_service_with_connect_info` 是 `client_key` 能取到真实对端的前提：
        // 不启用它，`Option<ConnectInfo<_>>` 永远是 `None`，per-IP 限流桶就退化成
        // 全站共用一个（限流形同虚设，且任何人都能把自己挤在门外）。
        //
        // 为什么只认传输层对端、不解析 `X-Forwarded-For`：见 `mailstack_web::routes`
        // 里 `client_key` 的注释 —— 那个头是请求可控的明文，读它等于让限流器失效。
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
        // 规格书 §5.1：`/api` 兜底必须是 JSON。回 index.html 会让前端把「接口不存在」
        // 误报成「服务端坏了」。
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
        // hash 路由下刷新任意深链接都应回到入口。
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
        // 回归：内容类型一度按 **URL** 判定，于是入口 `/`（URL 没有扩展名）拿到
        // `application/octet-stream`，浏览器会把整个管理界面**下载**下来而不是渲染它。
        // 深链接走的是 SPA 回退分支（硬编码 text/html），所以只有 `/` 会暴露这个问题 ——
        // 而那正是用户打开控制台时请求的第一个路径。
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
        // 「没部署」不是「没这个文件」：503 才能让反向代理与监控把它当服务不可用。
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

        // 这个进程返回的大多数响应都是静态文件，漏掉安全头等于没加。
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(response.headers().contains_key("content-security-policy"));
        std::fs::remove_dir_all(&root).ok();
    }
}
