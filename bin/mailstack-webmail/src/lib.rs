//! `mailstack-webmail` 服务装配：bind + 状态 + 静态托管。
//!
//! 与 `mailstack-web` 同一纪律：`main` 极薄（只解析参数、初始化日志），可测的
//! 决策（路径解析、路由、静态托管、入口回退）都在库里。
//!
//! ## 进程边界（契约 §0）
//!
//! Webmail 是**独立进程**：独立端口（默认 127.0.0.1:8444）、独立会话表、
//! 独立 Cookie 名。与管理台共享的只有磁盘上的账号/口令/Maildir 数据。
//! 它与管理台一样以 root 运行（要读 `/etc/mailstack/mailbox-passwords.json`
//! 与各账号 `~/Maildir`），因此**只绑回环**；TLS 终止交给反向代理 / SSH 隧道。

use std::net::SocketAddr;

use mailstack_core::Paths;
use mailstack_webmail::http::{build_app, AppState};
use mailstack_webmail::WebmailConfig;

/// 默认监听地址：只绑回环（契约 §0）。
pub const DEFAULT_BIND: &str = "127.0.0.1:8444";

/// 服务启动参数。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub webmail: WebmailConfig,
}

/// 启动错误。
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("cannot bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("server stopped: {0}")]
    Serve(#[source] std::io::Error),
}

/// 启动并运行服务，直到进程被终止。
pub async fn run(config: ServerConfig) -> Result<(), ServeError> {
    // 先绑定再建状态：bind 失败是唯一可能提前返回的路径，此时没有任何后台任务
    // 需要清理（与 mailstack-web 的顺序一致）。
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|source| ServeError::Bind {
            addr: config.bind,
            source,
        })?;
    let local_addr = listener.local_addr().unwrap_or(config.bind);

    let dist = config.webmail.dist.clone();
    let state = AppState::new(config.webmail);
    let entry = state.entry_file().map(str::to_string);
    let app = build_app(state);

    tracing::info!(
        target: "mailstack_webmail",
        bind = %local_addr,
        dist = ?dist,
        entry = ?entry,
        version = mailstack_core::VERSION,
        "mailstack-webmail 已启动（/mail/api + 前端产物）"
    );

    axum::serve(
        listener,
        // ConnectInfo 是 per-IP 限流取真实对端的前提；不启用时 `Option<
        // ConnectInfo>` 恒为 None，限流退化成全站共用一个桶。
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(ServeError::Serve)
}

/// 从 CLI 参数构造配置（`main` 与测试共用）。
///
/// 参数语义见契约 §4：
/// * `--config-dir`：`Paths::rooted`（测试用）；
/// * `--passwd-root`：默认 `/etc`；
/// * `--maildir`：家目录下的 Maildir 名，默认 `Maildir`；
/// * `--dist`：前端产物目录，省略则只提供 API（页面 503）。
#[allow(clippy::too_many_arguments)]
pub fn build_webmail_config(
    config_dir: Option<&std::path::Path>,
    passwd_root: Option<std::path::PathBuf>,
    maildir_name: Option<String>,
    dist: Option<std::path::PathBuf>,
) -> WebmailConfig {
    let paths = match config_dir {
        Some(dir) => Paths::rooted(dir),
        None => Paths::production(),
    };
    let mut config = WebmailConfig::from_paths(paths);
    if let Some(root) = passwd_root {
        config.passwd_root = root;
    }
    if let Some(name) = maildir_name {
        config.maildir_name = name;
    }
    config.dist = dist;
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_bind_is_loopback_only() {
        let addr: SocketAddr = DEFAULT_BIND.parse().unwrap();
        assert!(addr.ip().is_loopback(), "默认必须只绑回环");
        assert_eq!(addr.port(), 8444, "契约 §0：默认 127.0.0.1:8444");
    }

    #[test]
    fn config_dir_uses_the_rooted_path_layout() {
        let root = tempfile::tempdir().unwrap();
        let config = build_webmail_config(Some(root.path()), None, None, None);
        assert_eq!(config.paths.etc, root.path().join("etc/mailstack"));
        assert_eq!(config.paths.var_lib, root.path().join("var/lib/mailstack"));
        assert!(config.dist.is_none(), "省略 --dist 时只提供 API");
    }

    #[test]
    fn overrides_are_applied_to_the_config() {
        let root = tempfile::tempdir().unwrap();
        let config = build_webmail_config(
            Some(root.path()),
            Some(std::path::PathBuf::from("/tmp/passwd-root")),
            Some("Maildir2".to_string()),
            Some(std::path::PathBuf::from("/tmp/dist")),
        );
        assert_eq!(
            config.passwd_root,
            std::path::PathBuf::from("/tmp/passwd-root")
        );
        assert_eq!(config.maildir_name, "Maildir2");
        assert_eq!(config.dist, Some(std::path::PathBuf::from("/tmp/dist")));
        assert!(config.validate().is_ok());
    }
}
