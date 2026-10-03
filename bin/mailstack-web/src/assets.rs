//! 前端产物的静态托管。
//!
//! 只做三件事，且每件都有明确的失败姿态：
//!
//! 1. **`/api/*` 的未匹配路径绝不落到这里**。管理 API 的兜底必须是 JSON 404
//!    （规格书 §5.1）—— 若把 `index.html` 回给一个打错的 API 路径，前端会拿到
//!    一段 HTML 并报「解析失败」，把「接口不存在」伪装成「服务端坏了」。
//! 2. **路径穿越必须被拒**。产物目录下的文件名来自 URL，`..` 与绝对路径都要挡死，
//!    否则 `/../../etc/passwd` 就能读走任意文件。
//! 3. **找不到文件时回 `index.html`**。前端用的是 hash 路由，刷新任意深链接都
//!    应当回到同一个入口；但若产物根本不存在，要如实说「没部署」，不能回一个
//!    空白 200 让人以为是前端白屏。

use std::path::{Path, PathBuf};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// 托管前端的入口页面。
const INDEX: &str = "index.html";

/// 为 `path` 生成响应。
///
/// `dist` 为 `None` 表示本次部署没有配置前端产物目录 —— 这时**只**提供 API，
/// 对页面请求如实返回 404 并说明原因。
pub async fn serve(dist: &Option<PathBuf>, path: &str) -> Response {
    if is_api_path(path) {
        return mailstack_web::error::api_not_found();
    }

    let Some(root) = dist.as_deref() else {
        return not_deployed(
            "this deployment serves the API only (no frontend bundle is configured)",
        );
    };

    match resolve(root, path).await {
        // 内容类型按**解析后的真实文件名**判定，不能按 URL 判定：入口 `/` 的 URL 没有
        // 扩展名，按 URL 判会给 `index.html` 一个 `application/octet-stream`，
        // 于是浏览器把整个管理界面**下载**下来而不是渲染它。
        Some(file) => file_response(&file).await,
        // 文件不存在（或路径非法）→ 交给 SPA 入口。
        None => index_response(root).await,
    }
}

/// `/api` 与其子路径 —— 这类路径的兜底必须是 JSON，绝不能回 SPA 的 HTML。
fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// 把请求路径解析成产物目录下的一个**已存在且确实位于目录内**的文件。
///
/// 返回 `None` 的情形都当作「没有这个静态文件」，让调用方回退到 SPA 入口；
/// 其中也包含被拒绝的非法路径 —— 对穿越尝试回 `index.html` 比回 404 更好：
/// 既不泄露「这个路径有意思」，也不给它任何额外信息。
async fn resolve(root: &Path, path: &str) -> Option<PathBuf> {
    let relative = path.trim_start_matches('/');
    let relative = if relative.is_empty() { INDEX } else { relative };

    if !is_safe_relative(relative) {
        return None;
    }

    let candidate = root.join(relative);
    let metadata = tokio::fs::metadata(&candidate).await.ok()?;
    if !metadata.is_file() {
        return None;
    }

    // 即使逐段检查过 `..`，符号链接仍可能指到目录之外，因此再做一次真实路径的
    // 前缀校验 —— 产物目录是**唯一**允许被读出的范围。
    let real_root = tokio::fs::canonicalize(root).await.ok()?;
    let real_candidate = tokio::fs::canonicalize(&candidate).await.ok()?;
    if !real_candidate.starts_with(&real_root) {
        mailstack_core::warn::warn_with_detail(
            "serve frontend asset",
            &format!(
                "refused {} because it resolves outside the bundle root",
                candidate.display()
            ),
        );
        return None;
    }

    Some(candidate)
}

/// 相对路径是否安全：不含父目录跳转、不含绝对路径、不含 NUL 与反斜杠。
///
/// 反斜杠一并拒绝是因为 Windows 上它是分隔符，而产物是在构建机生成的 ——
/// 一条在 Linux 上「看起来只是个普通文件名」的 `a\..\b` 不应有第二种解释。
fn is_safe_relative(relative: &str) -> bool {
    if relative.contains('\0') || relative.contains('\\') {
        return false;
    }
    relative
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// 回 SPA 入口。入口缺失时说明「产物没部署」，而不是回一个空白成功。
async fn index_response(root: &Path) -> Response {
    let index = root.join(INDEX);
    match tokio::fs::read(&index).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                // 入口**不缓存**：它引用带内容哈希的资源文件名，缓存住会让下一次
                // 重新部署后浏览器仍然去要旧资源，表现为「界面还是上一版」。
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => not_deployed(&format!(
            "frontend bundle not found at {} ({error})",
            index.display()
        )),
    }
}

async fn file_response(file: &Path) -> Response {
    match tokio::fs::read(file).await {
        Ok(bytes) => {
            // 用真实文件名（而不是 URL）推内容类型 —— 见 `serve` 里的说明。
            let content_type = content_type_for(&file.to_string_lossy());
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
                    // 一天。产物文件名由 Vite 带内容哈希，但 `favicon` 之类的固定名
                    // 不走哈希，长缓存会让重新部署后仍取到旧文件，因此不设 `immutable`。
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600"),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(error) => not_deployed(&format!("cannot read {} ({error})", file.display())),
    }
}

/// 「没有前端产物」的统一响应：**503 而不是 404**。
///
/// 这不是「用户要的东西不存在」，而是「这台机器还没部署好」—— 用 503 才能让
/// 反向代理与监控把它当成服务不可用，而不是一条普通的 404 噪音。
fn not_deployed(reason: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        format!("frontend is not available: {reason}\n"),
    )
        .into_response()
}

/// 按扩展名给出内容类型。
///
/// 只列产物里真会出现的类型；未知扩展名回 `application/octet-stream`，让浏览器
/// 下载而不是**猜**着当脚本执行 —— 猜错等于把一个静态文件变成可执行内容。
fn content_type_for(path: &str) -> &'static str {
    let extension = path.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    match extension.to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "map" => "application/json; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_paths_are_never_served_as_spa() {
        // 这条是规格书 §5.1 的边界：打错的 API 路径必须回 JSON，不能回 HTML。
        assert!(is_api_path("/api"));
        assert!(is_api_path("/api/"));
        assert!(is_api_path("/api/nope"));
        assert!(!is_api_path("/apidocs"));
        assert!(!is_api_path("/"));
        assert!(!is_api_path("/assets/app.js"));
    }

    #[test]
    fn traversal_and_odd_segments_are_rejected() {
        assert!(is_safe_relative("assets/app-abc.js"));
        assert!(is_safe_relative("index.html"));
        for bad in [
            "../etc/passwd",
            "a/../../b",
            "a//b",
            "./a",
            "a\\b",
            "a\0b",
            "../../../",
        ] {
            assert!(!is_safe_relative(bad), "{bad:?} 必须被拒");
        }
    }

    #[test]
    fn content_types_cover_the_bundle_and_default_to_octet_stream() {
        assert_eq!(
            content_type_for("/assets/x.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for("/assets/x.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("/logo.svg"), "image/svg+xml");
        // 未知扩展名不能被猜成可执行内容。
        assert_eq!(content_type_for("/payload.bin"), "application/octet-stream");
        assert_eq!(
            content_type_for("/no-extension"),
            "application/octet-stream"
        );
    }
}
