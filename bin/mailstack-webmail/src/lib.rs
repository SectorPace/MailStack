use std::net::SocketAddr;

use mailstack_core::Paths;
use mailstack_webmail::http::{build_app, AppState};
use mailstack_webmail::WebmailConfig;

pub const DEFAULT_BIND: &str = "127.0.0.1:8444";

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub webmail: WebmailConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("invalid webmail configuration: {0}")]
    InvalidConfig(String),
    #[error("cannot bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("server stopped: {0}")]
    Serve(#[source] std::io::Error),
}

pub async fn run(config: ServerConfig) -> Result<(), ServeError> {
    config
        .webmail
        .validate()
        .map_err(ServeError::InvalidConfig)?;
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
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(ServeError::Serve)
}

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
