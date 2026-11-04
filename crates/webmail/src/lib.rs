pub mod account;
pub mod auth;
pub mod compose;
pub mod error;
pub mod http;
pub mod maildir_service;
pub mod mime_view;
pub mod sanitize;
pub mod send;
pub mod session;

pub use account::Account;
pub use error::{WebmailError, WebmailResult};

use std::path::PathBuf;

use mailstack_core::paths::Paths;

pub const VERSION: &str = mailstack_core::VERSION;

pub const SESSION_TTL_SECONDS: i64 = 28_800;

pub const SESSION_ABSOLUTE_MAX_SECONDS: i64 = 7 * 24 * 3600;

pub const MAX_SESSIONS: usize = 4_096;

pub const LOGIN_FAILURE_THRESHOLD: u32 = 5;

pub const LOGIN_BASE_LOCK_SECONDS: i64 = 30;

pub const LOGIN_MAX_LOCK_SECONDS: i64 = 900;

pub const LOGIN_ATTEMPTS_PER_WINDOW: u32 = 30;

pub const LOGIN_WINDOW_SECONDS: i64 = 60;

pub const MAX_TRACKED_LOGIN_KEYS: usize = 4_096;

pub const MAX_LOGIN_KEY_LEN: usize = 256;

pub const MAX_EMAIL_LEN: usize = 320;

pub const API_BODY_LIMIT_BYTES: usize = 256 * 1024;

pub const COMPOSE_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

pub const MAX_ATTACHMENT_TOTAL_BYTES: usize = 25 * 1024 * 1024;

pub const MAX_ATTACHMENTS: usize = 50;

pub const MESSAGE_PREFIX_BYTES: usize = 64 * 1024;

pub const SEARCH_TEXT_BYTES: usize = 256 * 1024;

pub const MAX_SEARCH_SCAN: usize = 500;

pub const MAX_SEARCH_QUERY_CHARS: usize = 200;

pub const MAX_LIST_LIMIT: usize = 200;

pub const DEFAULT_LIST_LIMIT: usize = 50;

pub const MAX_BATCH_UIDS: usize = 500;

pub const MAX_DETAIL_BYTES: usize = 25 * 1024 * 1024;

pub const MAX_RAW_BYTES: usize = 32 * 1024 * 1024;

pub const MAX_BODY_TEXT_CHARS: usize = 1_000_000;

pub const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;

pub const MAX_PARTS: usize = 1_000;

pub const MAX_SANITIZE_INPUT_BYTES: usize = 4 * 1024 * 1024;

pub const MAX_ADDRESS_LEN: usize = 320;

pub const MAX_SUBJECT_CHARS: usize = 400;

#[derive(Debug, Clone)]
pub struct WebmailConfig {
    pub paths: Paths,

    pub passwd_root: PathBuf,

    pub maildir_name: String,

    pub dist: Option<PathBuf>,

    pub public_mode: bool,
}

impl WebmailConfig {
    pub fn production() -> Self {
        Self::from_paths(Paths::production())
    }

    pub fn from_paths(paths: Paths) -> Self {
        let public_mode = mailstack_core::mode::is_public_mode(&paths);
        Self {
            paths,
            passwd_root: PathBuf::from("/etc"),
            maildir_name: "Maildir".to_string(),
            dist: None,
            public_mode,
        }
    }

    pub fn with_dist(mut self, dist: Option<PathBuf>) -> Self {
        self.dist = dist;
        self
    }

    pub fn with_passwd_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.passwd_root = root.into();
        self
    }

    pub fn with_maildir_name(mut self, name: impl Into<String>) -> Self {
        self.maildir_name = name.into();
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        let name = self.maildir_name.trim();
        if name.is_empty() {
            return Err("--maildir 目录名不得为空".to_string());
        }
        if name.len() > 100 {
            return Err("--maildir 目录名过长（上限 100 字节）".to_string());
        }
        if name.contains('/') || name.contains('\\') || name.contains('\0') {
            return Err("--maildir 目录名不得包含路径分隔符或 NUL".to_string());
        }
        if name == "." || name == ".." || name.starts_with('.') {
            return Err("--maildir 目录名不得是 . / .. 或以 '.' 开头".to_string());
        }
        if name.chars().any(|ch| ch.is_control()) {
            return Err("--maildir 目录名不得包含控制字符".to_string());
        }
        Ok(())
    }

    pub fn queue_root(&self) -> PathBuf {
        self.paths.var_lib.join("queue")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maildir_name_validation_rejects_path_shaped_values() {
        let base = WebmailConfig::from_paths(Paths::rooted("/tmp/mailstack-webmail-test"));
        assert!(base.clone().with_maildir_name("Maildir").validate().is_ok());
        for bad in [
            "",
            "   ",
            "../Maildir",
            "Maildir/other",
            "Maildir\\other",
            ".Maildir",
            "..",
            "Mail\0dir",
            "Mail\ndir",
        ] {
            assert!(
                base.clone().with_maildir_name(bad).validate().is_err(),
                "{bad:?} 必须被启动期校验拒绝"
            );
        }
    }

    #[test]
    fn queue_root_follows_paths_injection() {
        let paths = Paths::rooted("/tmp/mailstack-webmail-test");
        let config = WebmailConfig::from_paths(paths.clone());
        assert_eq!(
            config.queue_root(),
            paths.var_lib.join("queue"),
            "队列根必须由 Paths 推导，不能硬编码 /var/lib"
        );
    }
}
