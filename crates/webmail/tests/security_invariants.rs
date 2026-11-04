mod common;

use axum::http::{header, Method, StatusCode};
use common::{base64_of_x_bytes, body_bytes, body_json, html_message, plain_message, Fixture};
use mailstack_imappop3::maildir::{Flag, FlagSet, SystemFlag};
use mailstack_webmail::compose::{build_message, AttachmentInput, ComposeRequest, Purpose};
use mailstack_webmail::MAX_ATTACHMENT_TOTAL_BYTES;

#[tokio::test]
async fn webmail_session_requires_authentication() {
    let fixture = Fixture::new();
    for (method, uri) in [
        (Method::GET, "/mail/api/folders"),
        (Method::GET, "/mail/api/session"),
        (Method::GET, "/mail/api/messages?folder=INBOX"),
        (Method::GET, "/mail/api/quota"),
        (Method::POST, "/mail/api/messages/batch"),
        (Method::POST, "/mail/api/send"),
        (Method::DELETE, "/mail/api/session"),
    ] {
        let response = fixture.request(method.clone(), uri, &[], None).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} 未认证时必须 401"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "UNAUTHORIZED", "{uri}");
    }

    let response = fixture
        .request(
            Method::GET,
            "/mail/api/folders",
            &[("cookie".to_string(), "mailstack_mail=deadbeef".to_string())],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webmail_csrf_rejects_missing_token() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;

    let response = fixture
        .request(
            Method::POST,
            "/mail/api/folders",
            &[("cookie".to_string(), cookie.clone())],
            Some(serde_json::json!({ "name": "CSRF" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error"]["code"], "CSRF_REJECTED");

    let response = fixture
        .request(
            Method::POST,
            "/mail/api/folders",
            &[
                ("cookie".to_string(), cookie.clone()),
                ("x-csrf-token".to_string(), "wrong-token".to_string()),
            ],
            Some(serde_json::json!({ "name": "CSRF2" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for method in [Method::PATCH, Method::DELETE] {
        let response = fixture
            .request(
                method.clone(),
                "/mail/api/messages/INBOX/1",
                &[("cookie".to_string(), cookie.clone())],
                Some(serde_json::json!({ "flags": { "seen": true } })),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
    }

    let response = fixture
        .request(
            Method::POST,
            "/mail/api/folders",
            &Fixture::auth_headers(&cookie, &csrf),
            Some(serde_json::json!({ "name": "CSRF" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn webmail_session_epoch_bump_invalidates_existing_sessions() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let response = fixture
        .request(
            Method::GET,
            "/mail/api/session",
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK, "登录后会话应有效");

    std::fs::write(
        &fixture.paths.webmail_session_epoch,
        r#"{"version":1,"epochs":{"alice@example.com":1}}"#,
    )
    .expect("write epoch");

    let response = fixture
        .request(
            Method::GET,
            "/mail/api/session",
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "纪元 bump 之后旧会话必须 401"
    );

    let (cookie2, _csrf2) = fixture.login().await;
    let response = fixture
        .request(
            Method::GET,
            "/mail/api/session",
            &[("cookie".to_string(), cookie2)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn webmail_folder_name_traversal_is_rejected() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let headers = Fixture::auth_headers(&cookie, &csrf);

    for folder in ["..", "../..", "../../etc", "a/b", "a\\b", "..%2f..%2fetc"] {
        let uri = format!("/mail/api/messages?folder={folder}");
        let response = fixture.request(Method::GET, &uri, &headers, None).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "folder={folder:?} 必须被拒绝"
        );
    }

    let response = fixture
        .request(
            Method::DELETE,
            "/mail/api/folders/..%2F..%2Fetc",
            &headers,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = fixture
        .request(
            Method::PATCH,
            "/mail/api/folders/INBOX",
            &headers,
            Some(serde_json::json!({ "name": "../../etc" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = fixture
        .request(Method::GET, "/mail/api/folders", &headers, None)
        .await;
    let body = body_json(response).await;
    let names: Vec<&str> = body["folders"]
        .as_array()
        .expect("folders")
        .iter()
        .filter_map(|folder| folder["name"].as_str())
        .collect();
    assert_eq!(names, vec!["INBOX"]);
}

#[tokio::test]
async fn webmail_html_sanitizer_strips_scripts_and_event_handlers() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let uid = fixture.append(&html_message(
        "<p>hello</p>\
         <script>alert('xss')</script>\
         <img src=x onerror=alert(1)>\
         <iframe src=\"https://evil.example\"></iframe>\
         <a href=\"javascript:alert(1)\">link</a>\
         <svg onload=alert(1)></svg>\
         <div style=\"background:url(https://evil.example/x)\">styled</div>",
    ));

    let response = fixture
        .request(
            Method::GET,
            &format!("/mail/api/messages/INBOX/{uid}"),
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let html = body["message"]["body"]["html"]
        .as_str()
        .expect("HTML 正文必须存在")
        .to_string();

    for needle in [
        "<script",
        "onerror",
        "onload",
        "javascript:",
        "<iframe",
        "<svg",
        "url(",
    ] {
        assert!(!html.contains(needle), "消毒后仍含 {needle:?}：{html}");
    }
    assert!(html.contains("hello"), "正常文本必须保留：{html}");
}

#[tokio::test]
async fn webmail_html_sanitizer_blocks_remote_images_by_default() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let uid = fixture.append(&html_message(
        "<p>pic</p><img src=\"https://evil.example/pixel.png\" alt=\"p\">",
    ));

    let response = fixture
        .request(
            Method::GET,
            &format!("/mail/api/messages/INBOX/{uid}"),
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    let body = body_json(response).await;
    let html = body["message"]["body"]["html"].as_str().expect("html");
    assert!(
        !html.contains("<img src="),
        "默认不得保留远程图片 src：{html}"
    );
    assert!(
        html.contains("data-blocked-src=\"https://evil.example/pixel.png\""),
        "被阻断的地址必须留在惰性属性里：{html}"
    );
    assert_eq!(body["message"]["remoteImagesBlocked"], 1);

    let response = fixture
        .request(
            Method::GET,
            &format!("/mail/api/messages/INBOX/{uid}?images=1"),
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    let body = body_json(response).await;
    let html = body["message"]["body"]["html"].as_str().expect("html");
    assert!(html.contains("src=\"https://evil.example/pixel.png\""));
    assert_eq!(body["message"]["remoteImagesBlocked"], 0);
}

#[tokio::test]
async fn webmail_compose_rejects_header_injection() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let headers = Fixture::auth_headers(&cookie, &csrf);

    for (label, payload) in [
        (
            "subject CRLF",
            serde_json::json!({
                "to": ["bob@example.org"],
                "subject": "hi\r\nBcc: evil@example.com",
                "text": "body",
            }),
        ),
        (
            "subject LF",
            serde_json::json!({
                "to": ["bob@example.org"],
                "subject": "hi\nBcc: evil@example.com",
                "text": "body",
            }),
        ),
        (
            "recipient CRLF",
            serde_json::json!({
                "to": ["bob@example.org\r\nBcc: evil@example.com"],
                "subject": "hi",
                "text": "body",
            }),
        ),
        (
            "inReplyTo CRLF",
            serde_json::json!({
                "to": ["bob@example.org"],
                "subject": "hi",
                "text": "body",
                "inReplyTo": "<a@b>\r\nBcc: evil@example.com",
            }),
        ),
    ] {
        let response = fixture
            .request(Method::POST, "/mail/api/send", &headers, Some(payload))
            .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{label} 必须被拒绝"
        );
        let code = body_json(response).await["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(
            code == "HEADER_INJECTION" || code == "INVALID_ADDRESS",
            "{label} 的错误码不合契约：{code}"
        );
    }

    let entries = fixture.queue_root().join("entries");
    let queued = entries
        .read_dir()
        .map(|mut dir| dir.next().is_some())
        .unwrap_or(false);
    assert!(!queued, "头注入请求不得入队");
}

#[tokio::test]
async fn webmail_attachment_size_limit_is_enforced() {
    let account = common::test_account();
    let request = ComposeRequest {
        to: vec!["bob@example.org".to_string()],
        subject: "huge".to_string(),
        text: Some("body".to_string()),
        attachments: vec![AttachmentInput {
            filename: "huge.bin".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            data_base64: base64_of_x_bytes(MAX_ATTACHMENT_TOTAL_BYTES + 1),
        }],
        ..Default::default()
    };
    let error =
        build_message(&account, &request, Purpose::Send).expect_err("超过 25 MiB 的附件必须被拒绝");
    assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error.code, "PAYLOAD_TOO_LARGE");

    let small = ComposeRequest {
        to: vec!["bob@example.org".to_string()],
        subject: "small".to_string(),
        text: Some("body".to_string()),
        attachments: vec![AttachmentInput {
            filename: "a.txt".to_string(),
            content_type: Some("text/plain".to_string()),
            data_base64: "aGVsbG8=".to_string(),
        }],
        ..Default::default()
    };
    assert!(build_message(&account, &small, Purpose::Send).is_ok());
}

#[tokio::test]
async fn webmail_non_empty_folder_delete_is_refused() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let headers = Fixture::auth_headers(&cookie, &csrf);

    let response = fixture
        .request(
            Method::POST,
            "/mail/api/folders",
            &headers,
            Some(serde_json::json!({ "name": "Projects" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let uid = fixture.append(&plain_message("keep", "body"));
    let response = fixture
        .request(
            Method::POST,
            &format!("/mail/api/messages/INBOX/{uid}/move"),
            &headers,
            Some(serde_json::json!({ "to": "Projects" })),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = fixture
        .request(Method::DELETE, "/mail/api/folders/Projects", &headers, None)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "非空文件夹删除必须 409"
    );
    assert_eq!(
        body_json(response).await["error"]["code"],
        "FOLDER_NOT_EMPTY"
    );

    let response = fixture
        .request(Method::GET, "/mail/api/folders", &headers, None)
        .await;
    let body = body_json(response).await;
    assert!(body["folders"]
        .as_array()
        .expect("folders")
        .iter()
        .any(|folder| folder["name"] == "Projects"));

    let store = fixture.store();
    let projects = store.open_folder("Projects", false).expect("open");
    let project_uid = projects.messages[0].uid;
    let response = fixture
        .request(
            Method::DELETE,
            &format!("/mail/api/messages/Projects/{project_uid}"),
            &headers,
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = fixture
        .request(Method::DELETE, "/mail/api/folders/Projects", &headers, None)
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn webmail_api_never_falls_back_to_html() {
    let dist = tempfile::tempdir().expect("dist");
    std::fs::write(dist.path().join("mail.html"), "<html>MAIL-ENTRY</html>").expect("mail.html");
    let fixture = Fixture::with_dist(Some(dist.path().to_path_buf()));

    let response = fixture
        .request(Method::GET, "/mail/api/definitely-not-a-route", &[], None)
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.contains("application/json"),
        "API 兜底必须是 JSON，实际 {content_type}"
    );
    let bytes = body_bytes(response).await;
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("MAIL-ENTRY"), "API 兜底不得回入口 HTML");
    assert!(!text.contains("<html"));

    let response = fixture.request(Method::GET, "/", &[], None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_bytes(response).await).contains("MAIL-ENTRY"));
}

#[tokio::test]
async fn webmail_queue_enqueue_failure_is_reported() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;

    let entries = fixture.queue_root().join("entries");
    std::fs::create_dir_all(entries.parent().expect("queue parent")).expect("queue dir");
    std::fs::write(&entries, b"not a directory").expect("sabotage queue");

    let response = fixture
        .request(
            Method::POST,
            "/mail/api/send",
            &Fixture::auth_headers(&cookie, &csrf),
            Some(serde_json::json!({
                "to": ["bob@example.org"],
                "subject": "hello",
                "text": "body",
            })),
        )
        .await;
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "队列入队失败必须 5xx，不能 202"
    );
    assert_eq!(
        body_json(response).await["error"]["code"],
        "QUEUE_UNAVAILABLE"
    );

    let store = fixture.store();
    let sent_empty = store
        .open_folder("Sent", false)
        .map(|folder| folder.messages.is_empty())
        .unwrap_or(true);
    assert!(sent_empty, "入队失败时不得产生 Sent 副本");
}

#[tokio::test]
async fn webmail_login_is_rate_limited() {
    let fixture = Fixture::new();
    let mut saw_429 = false;
    let mut retry_after = None;
    let mut statuses = Vec::new();
    for _ in 0..8 {
        let response = fixture
            .request(
                Method::POST,
                "/mail/api/session",
                &[],
                Some(serde_json::json!({
                    "login": common::EMAIL,
                    "password": "definitely-wrong-password",
                })),
            )
            .await;
        let status = response.status();
        statuses.push(status);
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_429 = true;
            let body = body_json(response).await;
            assert_eq!(body["error"]["code"], "TOO_MANY_ATTEMPTS");
            retry_after = Some(true);
            break;
        } else {
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "限流触发前的失败必须统一 401，实际 {status}"
            );
            assert_eq!(
                body_json(response).await["error"]["code"],
                "INVALID_CREDENTIALS"
            );
        }
    }
    assert!(
        saw_429,
        "连续失败后必须出现 429，实际状态序列：{statuses:?}"
    );
    assert_eq!(retry_after, Some(true));
}

#[tokio::test]
async fn logging_out_invalidates_the_session_cookie() {
    let fixture = Fixture::new();
    let (cookie, csrf) = fixture.login().await;
    let response = fixture
        .request(
            Method::DELETE,
            "/mail/api/session",
            &Fixture::auth_headers(&cookie, &csrf),
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("Set-Cookie");
    assert!(set_cookie.contains("Max-Age=0"), "{set_cookie}");

    let response = fixture
        .request(
            Method::GET,
            "/mail/api/session",
            &[("cookie".to_string(), cookie)],
            None,
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn flag_imports_match_the_contract_names() {
    let mut flags = FlagSet::new();
    flags.insert(Flag::System(SystemFlag::Seen));
    assert_eq!(
        mailstack_webmail::maildir_service::flag_names(&flags),
        vec!["seen".to_string()]
    );
}
