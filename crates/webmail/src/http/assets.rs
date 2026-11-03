//! 前端产物静态托管（契约 §3）。
//!
//! 与管理台 `bin/mailstack-web/src/assets.rs` 同一套安全要点，入口不同：
//! webmail 的入口是 `mail.html`（与管理台 `index.html` 由同一次构建产出）。
//!
//! ## 部署可用性与入口回退
//!
//! 契约要求 `GET /` 返回 `dist/mail.html`。如果当前产物里**还没有** `mail.html`
//! （前端实现暂未合入），退回 `index.html` 并在日志里说明——否则整个服务连
//! 登录页都打不开，部署直接不可用。这是**有意偏离**契约字面、按部署可用性
//! 优先的降级，且只做一次日志告警。
//!
//! ## 必须守住的边界
//!
//! 1. `/mail/api/*` 绝不落到这里（未匹配 API 必须 JSON 404）；
//! 2. 路径穿越 / 符号链接逃逸必须被拒（产物目录是唯一可读范围）；
//! 3. 内容类型按**真实文件名**判定（入口 `/` 没有扩展名）；
//! 4. 单文件 ≤ 16 MiB，先 stat 再读（超限不读进内存）；
//! 5. `--dist` 未配置 / 产物缺失 → **503**，而不是空白 200。

use std::path::{Path, PathBuf};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::http::is_api_path;

/// 入口页面（契约 §3）。
const ENTRY: &str = "mail.html";

/// 兼容入口：`mail.html` 缺失时回落到管理台入口。
const FALLBACK_ENTRY: &str = "index.html";

/// 单个静态文件的大小上限（16 MiB）。
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;

/// 解析后的入口信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    /// 实际入口文件名（`mail.html` 或回落的 `index.html`）。
    pub file: String,
}

/// 启动期解析入口：`mail.html` 优先，缺失时回落 `index.html`。
pub fn resolve_entry(dist: &Option<PathBuf>) -> Option<EntryPoint> {
    let Some(root) = dist.as_deref() else {
        tracing::info!(
            target: "mailstack_webmail",
            "no --dist configured; serving the API only (page requests will return 503)"
        );
        return None;
    };
    if root.join(ENTRY).is_file() {
        tracing::info!(
            target: "mailstack_webmail",
            entry = ENTRY,
            root = %root.display(),
            "frontend bundle entry resolved"
        );
        return Some(EntryPoint {
            file: ENTRY.to_string(),
        });
    }
    if root.join(FALLBACK_ENTRY).is_file() {
        tracing::warn!(
            target: "mailstack_webmail",
            expected = ENTRY,
            actual = FALLBACK_ENTRY,
            root = %root.display(),
            "mail.html is missing from the frontend bundle; falling back to index.html so the deployment stays usable"
        );
        return Some(EntryPoint {
            file: FALLBACK_ENTRY.to_string(),
        });
    }
    tracing::warn!(
        target: "mailstack_webmail",
        root = %root.display(),
        "frontend bundle has neither mail.html nor index.html; page requests will return 503"
    );
    None
}

/// 为一个静态请求生成响应。
pub async fn serve(dist: &Option<PathBuf>, entry: Option<&EntryPoint>, path: &str) -> Response {
    // 第二道 `/mail/api` 守卫：即使路由层将来漏了 fallback，这里也不会回 HTML。
    if is_api_path(path) {
        return crate::http::error::json_error(crate::error::WebmailError::api_not_found());
    }
    let Some(root) = dist.as_deref() else {
        return not_deployed(
            "this deployment serves the API only (no frontend bundle is configured)",
        );
    };
    let Some(entry) = entry else {
        return not_deployed("frontend bundle is not usable on this host (no entry html)");
    };

    let Some(decoded) = percent_decode_path(path) else {
        // 非法编码按「没有这个文件」处理：回 SPA 入口，不泄露任何诊断信息。
        return entry_response(root, entry).await;
    };
    if decoded.is_empty() || decoded == "mail.html" || decoded == "index.html" {
        return entry_response(root, entry).await;
    }
    if !is_safe_relative(&decoded) {
        // 穿越尝试同样回入口：既不泄露「这个路径有意思」，也不给额外信息。
        return entry_response(root, entry).await;
    }

    match resolve_file(root, &decoded).await {
        Some(file) => file_response(&file).await,
        None => entry_response(root, entry).await,
    }
}

/// 把请求路径解析成产物目录下的一个已存在、且真实路径仍在目录内的文件。
async fn resolve_file(root: &Path, relative: &str) -> Option<PathBuf> {
    let candidate = root.join(relative);
    let metadata = tokio::fs::metadata(&candidate).await.ok()?;
    if !metadata.is_file() {
        return None;
    }
    if metadata.len() > MAX_ASSET_BYTES {
        tracing::warn!(
            target: "mailstack_webmail",
            file = %candidate.display(),
            len = metadata.len(),
            "refusing to serve an oversized static asset"
        );
        return None;
    }
    // 逐段检查过 `..` 之后仍要做真实路径前缀校验：符号链接可以指到产物目录之外，
    // 而 `serve` 的契约是「产物目录是唯一可读范围」。
    let real_root = tokio::fs::canonicalize(root).await.ok()?;
    let real_candidate = tokio::fs::canonicalize(&candidate).await.ok()?;
    if !real_candidate.starts_with(&real_root) {
        tracing::warn!(
            target: "mailstack_webmail",
            file = %candidate.display(),
            "refused a static asset that resolves outside the bundle root"
        );
        return None;
    }
    Some(candidate)
}

/// 回 SPA 入口。
async fn entry_response(root: &Path, entry: &EntryPoint) -> Response {
    let index = root.join(&entry.file);
    let metadata = match tokio::fs::metadata(&index).await {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::warn!(
                target: "mailstack_webmail",
                path = %index.display(),
                %error,
                "frontend entry html is not readable"
            );
            return not_deployed("frontend bundle is not available on this host");
        }
    };
    if metadata.len() > MAX_ASSET_BYTES {
        tracing::warn!(
            target: "mailstack_webmail",
            path = %index.display(),
            len = metadata.len(),
            "frontend entry html is implausibly large"
        );
        return not_deployed("frontend bundle is not usable on this host");
    }
    match tokio::fs::read(&index).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                // 入口不缓存：它引用带内容哈希的资源；缓存住会让重新部署后
                // 浏览器仍去要旧资源（界面还是上一版）。
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(
                target: "mailstack_webmail",
                path = %index.display(),
                %error,
                "cannot read the frontend entry html"
            );
            not_deployed("frontend bundle is not available on this host")
        }
    }
}

/// 单个静态文件的响应。
async fn file_response(file: &Path) -> Response {
    match tokio::fs::read(file).await {
        Ok(bytes) => {
            let content_type = content_type_for(&file.to_string_lossy());
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600"),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Err(error) => {
            // 响应体只给固定文案：内部路径与 OS 错误属于日志。
            tracing::warn!(
                target: "mailstack_webmail",
                path = %file.display(),
                %error,
                "cannot read a static asset"
            );
            not_deployed("frontend asset is not available on this host")
        }
    }
}

/// 「没有前端产物」的统一响应：**503 而不是 404**。
///
/// 这不是「这个 URL 不存在」，而是「这台机器还没部署好」——503 才能让反向代理
/// 与监控把它当作服务不可用，而不是一条普通 404 噪音。
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

/// 相对路径是否安全：不含父目录跳转、绝对路径、反斜杠、NUL 与空段。
fn is_safe_relative(relative: &str) -> bool {
    if relative.contains('\0') || relative.contains('\\') {
        return false;
    }
    relative
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// 百分号解码请求路径（`%2e%2e` 也要在解码后才判穿越）。
fn percent_decode_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Some(String::new());
    }
    let mut segments: Vec<String> = Vec::new();
    for raw in path.split('/') {
        let bytes = percent_decode_bytes(raw)?;
        // 段内解码出分隔符/反斜杠/NUL：这是编码过的穿越尝试，直接判非法。
        if bytes.iter().any(|byte| matches!(*byte, b'/' | b'\\' | 0)) {
            return None;
        }
        segments.push(String::from_utf8(bytes).ok()?);
    }
    Some(segments.join("/"))
}

fn percent_decode_bytes(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 按扩展名给出内容类型。
///
/// 未知扩展名回 `application/octet-stream`，让浏览器下载而不是**猜**着当脚本
/// 执行——猜错等于把一个静态文件变成可执行内容。
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
    fn traversal_and_odd_segments_are_rejected() {
        assert!(is_safe_relative("assets/app-abc.js"));
        assert!(is_safe_relative("mail.html"));
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
    fn percent_encoded_traversal_is_rejected_after_decoding() {
        assert_eq!(
            percent_decode_path("/assets/app.js").as_deref(),
            Some("assets/app.js")
        );
        assert_eq!(
            percent_decode_path("/assets/app%20v2.js").as_deref(),
            Some("assets/app v2.js")
        );
        // `%2e%2e` 解码后是 `..` —— 交给 is_safe_relative 拒绝。
        let decoded = percent_decode_path("/%2e%2e/etc/passwd").unwrap();
        assert!(!is_safe_relative(&decoded));
        // 编码过的分隔符在段内出现：直接判非法。
        assert!(percent_decode_path("/a%2Fb").is_none());
        assert!(percent_decode_path("/a%5Cb").is_none());
        assert!(percent_decode_path("/a%00b").is_none());
        // 非法百分号序列。
        assert!(percent_decode_path("/a%zzb").is_none());
    }

    #[test]
    fn content_types_cover_the_bundle_and_default_to_octet_stream() {
        assert_eq!(
            content_type_for("/assets/x.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for("/assets/x.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("/logo.svg"), "image/svg+xml");
        assert_eq!(content_type_for("/payload.bin"), "application/octet-stream");
        assert_eq!(
            content_type_for("/no-extension"),
            "application/octet-stream"
        );
    }

    #[test]
    fn entry_resolution_prefers_mail_html_and_falls_back_without_panicking() {
        let root = tempfile::tempdir().unwrap();
        let dist = root.path().to_path_buf();
        assert!(
            resolve_entry(&None).is_none(),
            "未配置 --dist 时必须只提供 API"
        );

        std::fs::write(dist.join("index.html"), "<html>admin</html>").unwrap();
        let entry = resolve_entry(&Some(dist.clone())).expect("回落 index.html");
        assert_eq!(entry.file, "index.html");

        std::fs::write(dist.join("mail.html"), "<html>mail</html>").unwrap();
        let entry = resolve_entry(&Some(dist.clone())).expect("优先 mail.html");
        assert_eq!(entry.file, "mail.html");
    }
}
