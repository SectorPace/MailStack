//! MailStack Webmail —— 邮箱用户的 Web 客户端后端库。
//!
//! ## 定位
//!
//! Webmail 是**独立进程**（`bin/mailstack-webmail`）：与管理台 `mailstack-web`
//! 端口、进程、会话体系全部隔离。本 crate 只放可测的业务与安全决策，进程装配
//! （bind / listener / CLI）在 bin 里。
//!
//! ## 信任边界（这是本 crate 全部设计的出发点）
//!
//! * **认证输入**（登录名 / 口令）来自匿名互联网：统一失败语义、恒定计时、
//!   限流、无账号枚举；
//! * **邮件内容**（头、正文、MIME 结构、附件名、Content-Type）全部是不可信输入：
//!   RFC2047 / charset 解码、MIME 解析、HTML 消毒都在服务端做，绝不把原始字节
//!   交给前端；
//! * **文件夹名 / uid** 来自 URL：一律经 `normalize_folder_name` 与「在文件夹
//!   元数据里定位」两道校验，不接受任意路径；
//! * **Maildir 是同步 `std::fs`**：所有调用都必须经 `tokio::task::spawn_blocking`
//!   （由 `http` 层统一包，见 [`http::blocking`]）；
//! * **发信只入出站队列**（DKIM 由队列 runner 统一签名），webmail 不自己拨号。
//!
//! ## 文件归属与契约
//!
//! 接口契约见 `review/WEBMAIL_CONTRACT.md`（冻结）。本 crate 不直接依赖
//! `mailstack-web`：会话判定（Cookie `Secure` / `__Host-` 前缀）按契约要求
//! **等价实现**，避免两个进程的安全语义通过 crate 耦合而漂移。

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

/// 当前版本（与其它二进制一致，来自 workspace 包版本）。
pub const VERSION: &str = mailstack_core::VERSION;

// ---------------------------------------------------------------------------
// 会话与认证
// ---------------------------------------------------------------------------

/// 会话滑动过期：8 小时（契约 §1.2）。
pub const SESSION_TTL_SECONDS: i64 = 28_800;

/// 会话绝对上限：7 天，自建立时起算，不因活动延长（契约 §1.2）。
pub const SESSION_ABSOLUTE_MAX_SECONDS: i64 = 7 * 24 * 3600;

/// 服务端会话表上限（契约「服务端上限（如 4096）」）。
pub const MAX_SESSIONS: usize = 4_096;

/// 登录失败锁定阈值：连续失败达到该次数即进入指数退避窗口。
pub const LOGIN_FAILURE_THRESHOLD: u32 = 5;

/// 指数退避的基础锁定时长（秒）；每次继续失败翻倍，封顶 [`LOGIN_MAX_LOCK_SECONDS`]。
pub const LOGIN_BASE_LOCK_SECONDS: i64 = 30;

/// 单次锁定上限（秒）。
pub const LOGIN_MAX_LOCK_SECONDS: i64 = 900;

/// 每个限流键（IP 或登录名）每窗口允许的**尝试**次数。
///
/// 失败锁定之外的另一道闸：某个 IP 用大量不同登录名撞库时，per-login 锁定
/// 不会触发，只有 per-IP 的尝试窗口能把它挡住。
pub const LOGIN_ATTEMPTS_PER_WINDOW: u32 = 30;

/// 尝试窗口长度（秒）。
pub const LOGIN_WINDOW_SECONDS: i64 = 60;

/// 限流表条目上限，防止匿名请求用随机登录名把内存顶爆。
pub const MAX_TRACKED_LOGIN_KEYS: usize = 4_096;

/// 限流键的最大长度（超出截断）。
pub const MAX_LOGIN_KEY_LEN: usize = 256;

/// 登录名（邮箱地址）长度上限（RFC 5321 的 254 之上留余量，与队列一致）。
pub const MAX_EMAIL_LEN: usize = 320;

// ---------------------------------------------------------------------------
// 请求体与邮件大小
// ---------------------------------------------------------------------------

/// 普通 JSON 请求体上限：256 KiB（契约 §2.2）。
pub const API_BODY_LIMIT_BYTES: usize = 256 * 1024;

/// 写信 / 发信 / 存草稿的请求体上限：32 MiB（契约 §2.2）。
pub const COMPOSE_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// 单封邮件附件总量上限：25 MiB（base64 解码后，契约 §2.2）。
pub const MAX_ATTACHMENT_TOTAL_BYTES: usize = 25 * 1024 * 1024;

/// 单封邮件附件个数上限。
///
/// 契约只给了字节上限；个数不封顶时，一封带 10 万个 0 字节附件的信会让 MIME
/// 构造与解析各跑 10 万次。50 是常见 MUA 的默认上限量级。
pub const MAX_ATTACHMENTS: usize = 50;

/// 列表摘要只读邮件头前缀的字节数。
///
/// 列表页最多一页 200 封；为每封读全文会把「翻一页」变成「读几百 MB」。
/// 64 KiB 足以覆盖头部 + 常见正文开头，摘要/发件人/主题都在里面。
pub const MESSAGE_PREFIX_BYTES: usize = 64 * 1024;

/// 搜索时每封邮件参与匹配的正文上限（契约：正文前 256KB）。
pub const SEARCH_TEXT_BYTES: usize = 256 * 1024;

/// 单次搜索最多扫描的邮件数。
///
/// 这是**如实截断**的边界：超过它就在响应里给 `truncated: true`，而不是假装
/// 搜完了全部邮箱。按 256 KiB/封的上限，最坏 128 MiB 读取——有界但已经很重，
/// 所以 500 是吞吐与诚实之间的折中。
pub const MAX_SEARCH_SCAN: usize = 500;

/// 搜索词长度上限（字符）。
pub const MAX_SEARCH_QUERY_CHARS: usize = 200;

/// 列表分页上限（契约默认 50）。
pub const MAX_LIST_LIMIT: usize = 200;

/// 默认分页大小。
pub const DEFAULT_LIST_LIMIT: usize = 50;

/// 单次批量操作的 uid 数上限。
pub const MAX_BATCH_UIDS: usize = 500;

/// 详情页解析的邮件最大字节数。超过则只读前段并标记 `body.truncated`。
pub const MAX_DETAIL_BYTES: usize = 25 * 1024 * 1024;

/// 原始邮件下载（`.eml`）的大小上限。超过回 413，而不是把整个大文件读进内存。
pub const MAX_RAW_BYTES: usize = 32 * 1024 * 1024;

/// 详情页纯文本正文的字符上限。
pub const MAX_BODY_TEXT_CHARS: usize = 1_000_000;

/// 详情页 HTML 正文（消毒前）的字节上限；超出按截断处理。
pub const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;

/// MIME 部件数上限（与 `imappop3::mime::MAX_PARTS` 同量级）。
///
/// 一封邮件可以有任意多个部件；不封顶时一个 `boundary` 重复 10 万次就能让
/// 详情页把内存吃光。
pub const MAX_PARTS: usize = 1_000;

/// HTML 消毒器的输入上限（字节）。
///
/// 超过就按截断处理：消毒是 O(输入) 的字符串处理，一个 500 MB 的 HTML 正文
/// 能让一次详情请求占满 CPU 与堆。
pub const MAX_SANITIZE_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// 主发起人 / 收件人地址的最大长度（契约 §2.2 发送校验）。
pub const MAX_ADDRESS_LEN: usize = 320;

/// 主题最大字符数。
///
/// 400 而不是 RFC 的 998：非 ASCII 主题要按 RFC2047 编码，编码后每字符膨胀到
/// 4 字节再 base64 再 +33%，998 字节的编码行对应不到 300 个中文字符。400 字符
/// 的主题已被 MUA 截断，且能保证编码后仍可折行合法。
pub const MAX_SUBJECT_CHARS: usize = 400;

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// Webmail 运行配置。
///
/// 路径一律从 [`Paths`] 注入（测试用 [`Paths::rooted`]）；`passwd_root` 与
/// `maildir_name` 是契约 §4 允许覆盖的两项，默认 `/etc` 与 `Maildir`。
#[derive(Debug, Clone)]
pub struct WebmailConfig {
    /// 生产路径集合（`Paths::production` / `Paths::rooted`）。
    pub paths: Paths,
    /// `passwd` 文件所在根目录（默认 `/etc`，即读 `/etc/passwd`）。
    pub passwd_root: PathBuf,
    /// 家目录下的 Maildir 目录名（默认 `Maildir`）。
    pub maildir_name: String,
    /// 前端产物目录；`None` 表示本次部署只提供 API（页面 503）。
    pub dist: Option<PathBuf>,
    /// 公网模式（`ACCESS_MODE=caddy|direct`）——影响 Cookie `Secure` 判定。
    pub public_mode: bool,
}

impl WebmailConfig {
    /// 生产默认：路径取 [`Paths::production`]，其余按契约默认值。
    pub fn production() -> Self {
        Self::from_paths(Paths::production())
    }

    /// 用给定路径集合构造默认配置（公网模式由 `install-args.conf` 判定）。
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

    /// 覆盖前端产物目录。
    pub fn with_dist(mut self, dist: Option<PathBuf>) -> Self {
        self.dist = dist;
        self
    }

    /// 覆盖 passwd 根目录。
    pub fn with_passwd_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.passwd_root = root.into();
        self
    }

    /// 覆盖 Maildir 目录名。
    pub fn with_maildir_name(mut self, name: impl Into<String>) -> Self {
        self.maildir_name = name.into();
        self
    }

    /// 启动期校验：不合法的目录名在**启动时**报错，而不是每个请求都静默失败。
    ///
    /// `maildir_name` 直接参与路径拼接（`<home>/<name>`），若它含 `/`、`\`、`..`
    /// 或 NUL，就等于把「家目录 + 固定子目录」变成可配置的任意路径。它来自 CLI，
    /// 不是匿名输入，但仍然必须 fail-closed 地校验。
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

    /// 队列根目录（由 [`Paths`] 推导，与 `mailstackd` 的出站队列同一个）。
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
