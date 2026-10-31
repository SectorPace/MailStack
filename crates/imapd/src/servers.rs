//! 把 imappop3 的 IMAP/POP3 服务端装配成"一个可运行的进程"。
//!
//! 装配内容：
//!
//! ```text
//! 账号目录（mailbox-passwords.json）──► AuthBackend ──┐
//! /etc/passwd + ~/Maildir ───────────► MailboxResolver ┴─► IMAP 143/993, POP3 110/995
//! Let's Encrypt fullchain/privkey ───► TlsAcceptor
//! ```
//!
//! 关键点：**`store` 只是占位**。多用户靠 `resolver` 在认证成功后按登录名切换
//! （`crates/imappop3` 的 `AuthOutcome::Success` 分支），所以一个监听器可以服务
//! 所有账号；占位 store 永远不会被读信/投递用到。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mailstack_imappop3::imap::server::{ImapServer, ImapServerConfig};
use mailstack_imappop3::imap::session::{ImapConfig, ImapSessionContext};
use mailstack_imappop3::maildir::{MailStore, SystemClock};
use mailstack_imappop3::metrics::Metrics;
use mailstack_imappop3::pop3::server::{Pop3Server, Pop3ServerConfig};
use mailstack_imappop3::pop3::session::{Pop3Config, Pop3SessionContext};
use mailstack_imappop3::resolver::MailboxResolver;
use mailstack_imappop3::tls::TlsAcceptor;
use tokio::sync::watch;

use crate::directory::{self, MailboxDirectory};
use crate::resolver::SystemMaildirResolver;

/// 装配或运行时错误。
#[derive(Debug, thiserror::Error)]
pub enum ImapdError {
    #[error("配置错误：{0}")]
    Config(String),
    #[error("TLS：{0}")]
    Tls(#[from] mailstack_imappop3::tls::TlsError),
    #[error("邮箱：{0}")]
    Mail(#[from] mailstack_imappop3::error::MailError),
    #[error("IO：{0}")]
    Io(#[from] std::io::Error),
}

/// 一个证书对（PEM）。
#[derive(Debug, Clone)]
pub struct CertPair {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// 监听地址集合。`None` 表示不启用该协议口。
#[derive(Debug, Clone, Default)]
pub struct Listeners {
    pub imap: Option<SocketAddr>,
    pub imaps: Option<SocketAddr>,
    pub pop3: Option<SocketAddr>,
    pub pop3s: Option<SocketAddr>,
}

/// 装配参数。
#[derive(Debug, Clone)]
pub struct Config {
    /// 问候语里的服务器名（通常是 MX 主机名）。
    pub server_name: String,
    pub listeners: Listeners,
    /// 有证书才能开 STARTTLS / 隐式 TLS。
    pub tls: Option<CertPair>,
    /// 是否禁止在明文连接上提交口令。**没有 TLS 时必须显式设 false**。
    pub require_tls: bool,
    /// `/etc/passwd` 所在目录（测试可指向临时根）。
    pub passwd_root: PathBuf,
    /// 家目录下的 Maildir 目录名，生产为 `Maildir`。
    pub maildir_name: String,
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_name: "mailstack".to_string(),
            listeners: Listeners::default(),
            tls: None,
            // 安全默认：没有 TLS 就不能收明文口令。
            require_tls: true,
            passwd_root: PathBuf::from("/etc"),
            maildir_name: "Maildir".to_string(),
            max_connections: 512,
        }
    }
}

/// 装配结果：可直接交给 `ImapServer` / `Pop3Server` 的上下文。
pub struct Assembly {
    pub imap: ImapSessionContext,
    pub pop3: Pop3SessionContext,
    /// 保留一份解析器引用，便于部署层做健康检查/用户枚举。
    pub resolver: Arc<dyn MailboxResolver>,
}

/// 按 `Config` 组装认证、解析器、TLS 与两个会话上下文。
pub fn assemble(paths: &mailstack_core::Paths, config: &Config) -> Result<Assembly, ImapdError> {
    if config.require_tls && config.tls.is_none() {
        return Err(ImapdError::Config(
            "require_tls 为 true 但没有配置证书：要么给证书，要么显式关掉 require_tls".into(),
        ));
    }
    if config.listeners.imaps.is_some() && config.tls.is_none() {
        return Err(ImapdError::Config("993（隐式 TLS）必须配置证书".into()));
    }
    if config.listeners.pop3s.is_some() && config.tls.is_none() {
        return Err(ImapdError::Config("995（隐式 TLS）必须配置证书".into()));
    }

    let directory = MailboxDirectory::at(paths);
    let auth = directory::backend(directory);

    let resolver: Arc<dyn MailboxResolver> = Arc::new(SystemMaildirResolver::new(
        config.passwd_root.clone(),
        config.maildir_name.clone(),
    ));

    // 占位 store：认证前没有任何命令能碰到它，认证成功后会话会立刻被
    // resolver 换成登录用户自己的 Maildir。放 /var/lib 而不是 /var/vmail，
    // 避免在邮件根目录里制造一个像真实邮箱的目录。
    let placeholder_root = paths.var_lib.join("imap-unprovisioned");
    let placeholder = Arc::new(MailStore::new(placeholder_root, Arc::new(SystemClock))?);

    let metrics = Arc::new(Metrics::new("imap"));

    let imap = ImapSessionContext {
        store: Arc::clone(&placeholder),
        auth: auth.clone(),
        config: ImapConfig {
            server_name: config.server_name.clone(),
            require_tls: config.require_tls,
            ..ImapConfig::default()
        },
        metrics: Arc::clone(&metrics),
        resolver: Some(Arc::clone(&resolver)),
    };

    let pop3 = Pop3SessionContext {
        store: placeholder,
        auth,
        config: Pop3Config {
            server_name: config.server_name.clone(),
            require_tls: config.require_tls,
            ..Pop3Config::default()
        },
        resolver: Some(Arc::clone(&resolver)),
    };

    Ok(Assembly {
        imap,
        pop3,
        resolver,
    })
}

fn acceptor(config: &Config) -> Result<Option<TlsAcceptor>, ImapdError> {
    match &config.tls {
        Some(pair) => Ok(Some(mailstack_imappop3::tls::acceptor(
            &pair.cert, &pair.key,
        )?)),
        None => Ok(None),
    }
}

fn imap_server_config(
    bind: SocketAddr,
    implicit_tls: bool,
    max_connections: usize,
) -> ImapServerConfig {
    ImapServerConfig {
        bind,
        implicit_tls,
        max_connections,
        handshake_timeout: Duration::from_secs(15),
        ..ImapServerConfig::default()
    }
}

fn pop3_server_config(
    bind: SocketAddr,
    implicit_tls: bool,
    max_connections: usize,
) -> Pop3ServerConfig {
    Pop3ServerConfig {
        bind,
        implicit_tls,
        max_connections,
        handshake_timeout: Duration::from_secs(15),
        ..Pop3ServerConfig::default()
    }
}

/// 绑定并运行全部已配置的监听器，直到 `shutdown` 被触发。
///
/// 任何一个监听器启动失败都会让整个调用返回错误（半启动的守护进程最难排障）。
pub async fn run(
    paths: &mailstack_core::Paths,
    config: Config,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ImapdError> {
    if config.listeners.imap.is_none()
        && config.listeners.imaps.is_none()
        && config.listeners.pop3.is_none()
        && config.listeners.pop3s.is_none()
    {
        return Err(ImapdError::Config("没有启用任何监听口".into()));
    }

    let assembly = assemble(paths, &config)?;
    let tls = acceptor(&config)?;
    let grace = config.listeners;

    let mut tasks: tokio::task::JoinSet<std::io::Result<()>> = tokio::task::JoinSet::new();

    if let Some(bind) = grace.imap {
        let server = ImapServer::new(
            assembly.imap.clone(),
            imap_server_config(bind, false, config.max_connections),
            tls.clone(),
        )?;
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = grace.imaps {
        let server = ImapServer::new(
            assembly.imap.clone(),
            imap_server_config(bind, true, config.max_connections),
            tls.clone(),
        )?;
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = grace.pop3 {
        let server = Pop3Server::new(
            assembly.pop3.clone(),
            pop3_server_config(bind, false, config.max_connections),
            tls.clone(),
        )?;
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = grace.pop3s {
        let server = Pop3Server::new(
            assembly.pop3.clone(),
            pop3_server_config(bind, true, config.max_connections),
            tls,
        )?;
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }

    // 等第一个「停机信号 / 监听器自己结束 / 监听器出错」，三者都是终止条件，
    // 因此这里是 select 而不是 loop（每个分支都会离开）。
    let mut shutdown = shutdown;
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received; IMAP/POP3 listeners are draining");
        }
        completed = tasks.join_next() => {
            match completed {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(error))) => return Err(ImapdError::Io(error)),
                Some(Err(error)) => {
                    return Err(ImapdError::Config(format!("监听任务异常退出：{error}")));
                }
                None => {}
            }
        }
    }
    // 让各监听器在自己的 grace 内收尾。
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// 从证书目录推导一对证书（Let's Encrypt 布局）。
pub fn cert_pair_from_le(letsencrypt: &Path, domain: &str) -> Option<CertPair> {
    let live = letsencrypt.join("live").join(domain);
    let cert = live.join("fullchain.pem");
    let key = live.join("privkey.pem");
    if cert.is_file() && key.is_file() {
        Some(CertPair { cert, key })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_tls_without_a_certificate_is_refused_before_binding() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        let config = Config::default();
        let error = assemble(&paths, &config)
            .err()
            .expect("没有证书就不能要求 TLS");
        assert!(format!("{error}").contains("require_tls"), "{error}");
    }

    #[test]
    fn implicit_tls_ports_require_a_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        let config = Config {
            require_tls: false,
            listeners: Listeners {
                imaps: Some("127.0.0.1:993".parse().unwrap()),
                ..Listeners::default()
            },
            ..Config::default()
        };
        let error = assemble(&paths, &config)
            .err()
            .expect("993 没有证书必须拒绝");
        assert!(format!("{error}").contains("993"), "{error}");
    }

    #[test]
    fn plaintext_only_is_allowed_when_explicitly_configured() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        let config = Config {
            require_tls: false,
            ..Config::default()
        };
        let assembly = assemble(&paths, &config).expect("明文部署必须能装配起来");
        assert!(assembly.imap.resolver.is_some(), "必须注入多用户解析器");
        assert!(assembly.pop3.resolver.is_some());
    }
}
