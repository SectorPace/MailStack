use std::path::{Path, PathBuf};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const INDEX: &str = "index.html";

const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;

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
        Some(file) => file_response(&file).await,

        None => index_response(root).await,
    }
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

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

fn is_safe_relative(relative: &str) -> bool {
    if relative.contains('\0') || relative.contains('\\') {
        return false;
    }
    relative
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

async fn index_response(root: &Path) -> Response {
    let index = root.join(INDEX);

    if let Ok(metadata) = tokio::fs::metadata(&index).await {
        if metadata.len() > MAX_ASSET_BYTES {
            mailstack_core::warn::warn_with_detail(
                "serve frontend index",
                &format!(
                    "{} is {} bytes, above the {} MiB cap",
                    index.display(),
                    metadata.len(),
                    MAX_ASSET_BYTES / (1024 * 1024)
                ),
            );
            return not_deployed("frontend bundle is not usable on this host");
        }
    }
    match tokio::fs::read(&index).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            bytes,
        )
            .into_response(),
        Err(error) => {
            mailstack_core::warn::warn_with_detail(
                "serve frontend index",
                &format!("cannot read {}: {error}", index.display()),
            );
            not_deployed("frontend bundle is not available on this host")
        }
    }
}

async fn file_response(file: &Path) -> Response {
    if let Ok(metadata) = tokio::fs::metadata(file).await {
        if metadata.len() > MAX_ASSET_BYTES {
            mailstack_core::warn::warn_with_detail(
                "serve frontend asset",
                &format!(
                    "{} is {} bytes, above the {} MiB static-asset cap",
                    file.display(),
                    metadata.len(),
                    MAX_ASSET_BYTES / (1024 * 1024)
                ),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                )],
                "frontend asset is too large to serve\n",
            )
                .into_response();
        }
    }
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
            mailstack_core::warn::warn_with_detail(
                "serve frontend asset",
                &format!("cannot read {}: {error}", file.display()),
            );
            not_deployed("frontend asset is not available on this host")
        }
    }
}

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

        assert_eq!(content_type_for("/payload.bin"), "application/octet-stream");
        assert_eq!(
            content_type_for("/no-extension"),
            "application/octet-stream"
        );
    }
}
