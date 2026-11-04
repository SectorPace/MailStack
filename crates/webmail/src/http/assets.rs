use std::path::{Path, PathBuf};

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::http::is_api_path;

const ENTRY: &str = "mail.html";

const FALLBACK_ENTRY: &str = "index.html";

const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    pub file: String,
}

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

pub async fn serve(dist: &Option<PathBuf>, entry: Option<&EntryPoint>, path: &str) -> Response {
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
        return entry_response(root, entry).await;
    };
    if decoded.is_empty() || decoded == "mail.html" || decoded == "index.html" {
        return entry_response(root, entry).await;
    }
    if !is_safe_relative(&decoded) {
        return entry_response(root, entry).await;
    }

    match resolve_file(root, &decoded).await {
        Some(file) => file_response(&file).await,
        None => entry_response(root, entry).await,
    }
}

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

fn is_safe_relative(relative: &str) -> bool {
    if relative.contains('\0') || relative.contains('\\') {
        return false;
    }
    relative
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn percent_decode_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Some(String::new());
    }
    let mut segments: Vec<String> = Vec::new();
    for raw in path.split('/') {
        let bytes = percent_decode_bytes(raw)?;

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

        let decoded = percent_decode_path("/%2e%2e/etc/passwd").unwrap();
        assert!(!is_safe_relative(&decoded));

        assert!(percent_decode_path("/a%2Fb").is_none());
        assert!(percent_decode_path("/a%5Cb").is_none());
        assert!(percent_decode_path("/a%00b").is_none());

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
