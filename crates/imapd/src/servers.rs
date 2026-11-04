use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mailstack_imappop3::imap::server::{ImapServer, ImapServerConfig};
use mailstack_imappop3::imap::session::{ImapConfig, ImapSessionContext};
use mailstack_imappop3::maildir::{MailStore, SystemClock};
use mailstack_imappop3::managesieve::{
    ManageSieveContext, ManageSieveServer, ManageSieveServerConfig,
};
use mailstack_imappop3::metrics::Metrics;
use mailstack_imappop3::pop3::server::{Pop3Server, Pop3ServerConfig};
use mailstack_imappop3::pop3::session::{Pop3Config, Pop3SessionContext};
use mailstack_imappop3::resolver::MailboxResolver;
use mailstack_imappop3::tls::TlsAcceptor;
use tokio::sync::watch;

use crate::directory::{self, MailboxDirectory};
use crate::resolver::SystemMaildirResolver;

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

#[derive(Debug, Clone)]
pub struct CertPair {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct Listeners {
    pub imap: Option<SocketAddr>,
    pub imaps: Option<SocketAddr>,
    pub pop3: Option<SocketAddr>,
    pub pop3s: Option<SocketAddr>,

    pub managesieve: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server_name: String,
    pub listeners: Listeners,

    pub tls: Option<CertPair>,

    pub require_tls: bool,

    pub passwd_root: PathBuf,

    pub maildir_name: String,
    pub max_connections: usize,

    pub metrics_bind: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_name: "mailstack".to_string(),
            listeners: Listeners::default(),
            tls: None,

            require_tls: true,
            passwd_root: PathBuf::from("/etc"),
            maildir_name: "Maildir".to_string(),
            max_connections: 512,
            metrics_bind: None,
        }
    }
}

pub struct Assembly {
    pub imap: ImapSessionContext,
    pub pop3: Pop3SessionContext,
    pub managesieve: ManageSieveContext,

    pub resolver: Arc<dyn MailboxResolver>,
}

pub fn assemble(paths: &mailstack_core::Paths, config: &Config) -> Result<Assembly, ImapdError> {
    if config.listeners.managesieve.is_some() && config.require_tls && config.tls.is_none() {
        return Err(ImapdError::Config(
            "4190（ManageSieve）要收明文口令：要么给证书走 STARTTLS，要么显式关掉 require_tls"
                .into(),
        ));
    }
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

    let managesieve = ManageSieveContext::new(auth.clone(), Arc::clone(&resolver));

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
        managesieve,
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

fn managesieve_server_config(bind: SocketAddr, max_connections: usize) -> ManageSieveServerConfig {
    ManageSieveServerConfig {
        bind,
        implicit_tls: false,
        max_connections,
        handshake_timeout: Duration::from_secs(15),
        ..ManageSieveServerConfig::default()
    }
}

pub async fn run(
    paths: &mailstack_core::Paths,
    config: Config,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ImapdError> {
    if config.listeners.imap.is_none()
        && config.listeners.imaps.is_none()
        && config.listeners.pop3.is_none()
        && config.listeners.pop3s.is_none()
        && config.listeners.managesieve.is_none()
    {
        return Err(ImapdError::Config("没有启用任何监听口".into()));
    }

    let assembly = assemble(paths, &config)?;
    let tls = acceptor(&config)?;
    let listener_configs = config.listeners;

    let imap_metrics = Arc::clone(&assembly.imap.metrics);
    let pop3_metrics = Arc::new(Metrics::new("pop3"));
    let sieve_metrics = Arc::new(Metrics::new("managesieve"));

    let mut tasks: tokio::task::JoinSet<std::io::Result<()>> = tokio::task::JoinSet::new();

    if let Some(bind) = listener_configs.imap {
        let server = ImapServer::new(
            assembly.imap.clone(),
            imap_server_config(bind, false, config.max_connections),
            tls.clone(),
        )?
        .with_metrics(Arc::clone(&imap_metrics));
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = listener_configs.imaps {
        let server = ImapServer::new(
            assembly.imap.clone(),
            imap_server_config(bind, true, config.max_connections),
            tls.clone(),
        )?
        .with_metrics(Arc::clone(&imap_metrics));
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = listener_configs.pop3 {
        let server = Pop3Server::new(
            assembly.pop3.clone(),
            pop3_server_config(bind, false, config.max_connections),
            tls.clone(),
        )?
        .with_metrics(Arc::clone(&pop3_metrics));
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = listener_configs.pop3s {
        let server = Pop3Server::new(
            assembly.pop3.clone(),
            pop3_server_config(bind, true, config.max_connections),
            tls.clone(),
        )?
        .with_metrics(Arc::clone(&pop3_metrics));
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = listener_configs.managesieve {
        let server = ManageSieveServer::new(
            assembly.managesieve,
            managesieve_server_config(bind, config.max_connections),
            tls,
        )?
        .with_metrics(Arc::clone(&sieve_metrics));
        let shutdown = shutdown.clone();
        tasks.spawn(async move { server.serve(shutdown).await });
    }
    if let Some(bind) = config.metrics_bind {
        let registries = vec![
            Arc::clone(&imap_metrics),
            Arc::clone(&pop3_metrics),
            Arc::clone(&sieve_metrics),
        ];
        let shutdown = shutdown.clone();
        tasks.spawn(async move { crate::metrics_http::serve(bind, registries, shutdown).await });
    }

    let mut shutdown = shutdown;
    let mut failure: Option<ImapdError> = None;
    tokio::select! {
        _ = shutdown.changed() => {
            tracing::info!("shutdown signal received; IMAP/POP3 listeners are draining");
        }
        completed = tasks.join_next() => {
            failure = classify_listener_exit(completed);
        }
    }

    let drained = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if let Some(error) = failure {
        return Err(error);
    }
    if drained.is_err() {
        return Err(ImapdError::Config(format!(
            "监听器在 {DRAIN_TIMEOUT:?} 内未完成收尾；进程退出以触发 systemd 重启"
        )));
    }
    Ok(())
}

pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn classify_listener_exit(
    completed: Option<Result<std::io::Result<()>, tokio::task::JoinError>>,
) -> Option<ImapdError> {
    match completed {
        Some(Ok(Ok(()))) => Some(ImapdError::Config(
            "监听器在未收到停机信号时自行退出（退出码必须非零，否则 systemd 不会重启）".into(),
        )),
        Some(Ok(Err(error))) => Some(ImapdError::Io(error)),
        Some(Err(error)) => Some(ImapdError::Config(format!("监听任务异常退出：{error}"))),
        None => None,
    }
}

pub fn migrate_dovecot_maildir(
    root: &Path,
) -> Result<mailstack_imappop3::migration::MigrationReport, ImapdError> {
    let store = Arc::new(MailStore::new(root.to_path_buf(), Arc::new(SystemClock))?);
    Ok(mailstack_imappop3::migration::migrate_maildir(&store)?)
}

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
    fn a_listener_that_returns_ok_without_a_shutdown_signal_is_an_error() {
        let error = classify_listener_exit(Some(Ok(Ok(()))))
            .expect("未停机就正常返回必须翻译成错误，而不能让 run() 回 Ok(())");
        assert!(
            format!("{error}").contains("未收到停机信号"),
            "错误原因必须可诊断：{error}"
        );

        let io = classify_listener_exit(Some(Ok(Err(std::io::Error::other("accept failed")))))
            .expect("监听器出错必须上抛");
        assert!(matches!(io, ImapdError::Io(_)), "应保留 IO 错误：{io:?}");

        assert!(
            classify_listener_exit(None).is_none(),
            "没有完成的任务（空 JoinSet）不是失败"
        );
    }

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

    #[test]
    fn managesieve_with_require_tls_needs_a_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        let config = Config {
            require_tls: true,
            listeners: Listeners {
                managesieve: Some("127.0.0.1:4190".parse().unwrap()),
                ..Listeners::default()
            },
            ..Config::default()
        };
        let error = assemble(&paths, &config)
            .err()
            .expect("ManageSieve 要收明文口令，没证书必须拒绝");
        assert!(format!("{error}").contains("4190"), "{error}");
    }

    #[tokio::test]
    async fn managesieve_listener_greets_with_its_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let paths = mailstack_core::Paths::rooted(dir.path());
        let config = Config {
            require_tls: false,
            listeners: Listeners {
                managesieve: Some("127.0.0.1:0".parse().unwrap()),
                ..Listeners::default()
            },
            ..Config::default()
        };
        let assembly = assemble(&paths, &config).expect("装配");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = ManageSieveServer::new(
            assembly.managesieve,
            managesieve_server_config(address, 16),
            None,
        )
        .expect("服务端配置合法");
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(async move { server.serve_on(listener, rx).await });

        use tokio::io::AsyncBufReadExt;
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut lines = tokio::io::BufReader::new(stream).lines();
        let mut greeting = String::new();
        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), lines.next_line())
                .await
                .expect("读超时")
                .expect("读取失败")
                .expect("连接被关闭");
            greeting.push_str(&line);
            greeting.push('\n');
            if line.starts_with("OK") {
                break;
            }
        }
        assert!(greeting.contains("\"IMPLEMENTATION\""), "{greeting}");
        assert!(
            greeting.contains("\"SIEVE\""),
            "必须通告 SIEVE 扩展集：{greeting}"
        );
        assert!(greeting.contains("\"SASL\" \"PLAIN\""), "{greeting}");
    }
}
