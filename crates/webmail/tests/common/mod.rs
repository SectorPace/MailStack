#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, Response, StatusCode};
use axum::Router;
use mailstack_core::paths::Paths;
use mailstack_imappop3::maildir::{FlagSet, MailStore, SystemClock};
use mailstack_webmail::http::{build_app, AppState};
use mailstack_webmail::WebmailConfig;
use serde_json::Value;
use tower::ServiceExt;

pub const EMAIL: &str = "alice@example.com";

pub const PASSWORD: &str = "Correct-Horse-9";

pub struct Fixture {
    pub root: tempfile::TempDir,
    pub paths: Paths,
    pub config: WebmailConfig,
    pub maildir: PathBuf,
    pub state: AppState,
    pub app: Router,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_dist(None)
    }

    pub fn with_dist(dist: Option<PathBuf>) -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let paths = Paths::rooted(root.path());
        std::fs::create_dir_all(&paths.etc).expect("etc dir");
        std::fs::create_dir_all(&paths.var_lib).expect("var/lib dir");

        let home = root.path().join("home/alice");
        std::fs::create_dir_all(&home).expect("home");
        let maildir = home.join("Maildir");
        MailStore::new(&maildir, Arc::new(SystemClock)).expect("maildir");

        let passwd = format!(
            "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:Alice:{}:/bin/sh\n",
            home.display()
        );
        std::fs::write(root.path().join("etc/passwd"), passwd).expect("passwd");

        std::fs::write(
            &paths.managed_mailboxes,
            r#"[{"email":"alice@example.com","unixUser":"alice","displayName":"Alice"}]"#,
        )
        .expect("registry");

        let record = mailstack_core::password::mailbox_password_record(EMAIL, PASSWORD)
            .expect("password record");
        let mut records = serde_json::Map::new();
        records.insert(
            EMAIL.to_string(),
            serde_json::to_value(record).expect("record json"),
        );
        let db = serde_json::json!({ "version": 1, "records": records });
        std::fs::write(
            &paths.mailbox_passwords,
            serde_json::to_string_pretty(&db).expect("db json"),
        )
        .expect("password db");

        let config = WebmailConfig {
            paths: paths.clone(),
            passwd_root: root.path().join("etc"),
            maildir_name: "Maildir".to_string(),
            dist,
            public_mode: false,
        };
        let state = AppState::new(config.clone());
        let app = build_app(state.clone());
        Self {
            root,
            paths,
            config,
            maildir,
            state,
            app,
        }
    }

    pub fn store(&self) -> MailStore {
        MailStore::new(&self.maildir, Arc::new(SystemClock)).expect("mailstore")
    }

    pub fn append(&self, raw: &str) -> u32 {
        self.append_with_flags(raw, FlagSet::new())
    }

    pub fn append_with_flags(&self, raw: &str, flags: FlagSet) -> u32 {
        let store = self.store();
        let (_, uid) = store
            .append("INBOX", raw.as_bytes(), &flags, None)
            .expect("append");
        uid
    }

    pub fn append_to(&self, folder: &str, raw: &str) -> u32 {
        let store = self.store();
        if !store.exists(folder).unwrap_or(false) {
            store.create(folder).expect("create folder");
        }
        let (_, uid) = store
            .append(folder, raw.as_bytes(), &FlagSet::new(), None)
            .expect("append");
        uid
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        headers: &[(String, String)],
        body: Option<Value>,
    ) -> Response<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = match body {
            Some(body) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("json body")))
                .expect("request"),
            None => builder.body(Body::empty()).expect("request"),
        };
        self.app.clone().oneshot(request).await.expect("response")
    }

    pub async fn login(&self) -> (String, String) {
        self.login_with(EMAIL, PASSWORD).await
    }

    pub async fn login_with(&self, email: &str, password: &str) -> (String, String) {
        let response = self
            .request(
                Method::POST,
                "/mail/api/session",
                &[],
                Some(serde_json::json!({ "login": email, "password": password })),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "登录应成功");
        let cookie = extract_session_cookie(&response);
        let body = body_json(response).await;
        let csrf = body["csrfToken"].as_str().expect("csrfToken").to_string();
        (cookie, csrf)
    }

    pub fn auth_headers(cookie: &str, csrf: &str) -> Vec<(String, String)> {
        vec![
            ("cookie".to_string(), cookie.to_string()),
            ("x-csrf-token".to_string(), csrf.to_string()),
        ]
    }

    pub fn queue_root(&self) -> PathBuf {
        self.config.queue_root()
    }
}

pub fn extract_session_cookie(response: &Response<Body>) -> String {
    let raw = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("Set-Cookie");
    raw.split(';')
        .next()
        .expect("cookie pair")
        .trim()
        .to_string()
}

pub async fn body_json(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json response")
}

pub async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
        .await
        .expect("body")
        .to_vec()
}

pub fn plain_message(subject: &str, body: &str) -> String {
    format!(
        "From: Bob <bob@example.org>\r\n\
         To: alice@example.com\r\n\
         Subject: {subject}\r\n\
         Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
         Message-ID: <{subject}@example.org>\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {body}\r\n"
    )
}

pub fn html_message(html: &str) -> String {
    format!(
        "From: Bob <bob@example.org>\r\n\
         To: alice@example.com\r\n\
         Subject: html\r\n\
         Date: Fri, 23 Oct 2026 14:30:00 +0800\r\n\
         Message-ID: <html@example.org>\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         {html}\r\n"
    )
}

pub fn test_account() -> mailstack_webmail::Account {
    mailstack_webmail::Account {
        email: EMAIL.to_string(),
        account: "alice".to_string(),
        display_name: "Alice".to_string(),
        unix_user: "alice".to_string(),
        maildir: PathBuf::from("/nonexistent/Maildir"),
    }
}

pub fn base64_of_x_bytes(count: usize) -> String {
    let mut out = String::with_capacity(count / 3 * 4 + 4);
    let mut remaining = count;
    while remaining >= 3 {
        out.push_str("eHh4");
        remaining -= 3;
    }
    match remaining {
        0 => {}
        1 => out.push_str("eA=="),
        _ => out.push_str("eHg="),
    }
    out
}
