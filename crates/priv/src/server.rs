//! 特权 RPC 服务端（规格书 §2.3、§5.4.2、§5.4.3）。
//!
//! ```text
//! RO action  → 直连 /run/mailstack/helper-ro.sock（0660 root:mailstack-admin）
//!              服务进程属 mailstack-admin 组，可直接连接
//!
//! RW action  → sudo /usr/local/libexec/mailstack-privileged
//!              （helper.sock 是 0600 root:root，服务进程连不上）
//! ```
//!
//! **架构要点**：单个常驻 root 进程服务所有请求，避免每次 `sudo + 进程` fork。
//! 实测注释指出，5 秒一次的 `logs.list` 轮询曾为此每轮 fork 一次。

use std::path::PathBuf;
use std::sync::Arc;

use mailstack_core::actions::Channel;
use mailstack_core::paths::Paths;

use crate::dispatch::{ActionGate, GateDecision};
use crate::handlers::Registry;
use crate::{RpcRequest, RpcResponse};

// Unix socket 相关符号仅在 Unix 目标存在（生产目标为 Linux）；
// 其余逻辑保持可移植，以便在开发机上跑通与平台无关的测试。
#[cfg(unix)]
use crate::framing::{read_json_request_frame, write_json_frame};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// RO socket 默认路径。
pub const DEFAULT_RO_SOCKET: &str = "/run/mailstack/helper-ro.sock";
/// RW socket 默认路径（0600 root:root）。
pub const DEFAULT_RW_SOCKET: &str = "/run/mailstack/helper.sock";
/// 助手调用超时默认值（毫秒），对应 `MAILSTACK_HELPER_TIMEOUT_MS`。
pub const HELPER_TIMEOUT_MS_DEFAULT: u64 = 120_000;
/// 单个 RPC 请求帧读取超时，避免占满 worker 的连接停留在半帧状态。
const RPC_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// RO 服务配置。
#[derive(Debug, Clone)]
pub struct RoServerConfig {
    pub socket_path: PathBuf,
    /// socket 权限位。RO 面默认 `0660`（root:mailstack-admin）。
    pub socket_mode: u32,
    /// 属组名（用于 chown）。`None` 表示不改属组。
    pub socket_group: Option<String>,
    pub paths: Paths,
    /// 并发 worker 上限（对应 `MAX_WORKERS=8`）。
    pub max_workers: usize,
}

impl RoServerConfig {
    pub fn ro_socket(paths: Paths) -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_RO_SOCKET),
            socket_mode: 0o660,
            socket_group: Some(mailstack_core::atomic::ADMIN_GROUP.to_string()),
            paths,
            max_workers: 8,
        }
    }

    /// 变更面：`0600 root:root`，服务进程连不上。
    pub fn rw_socket(paths: Paths) -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_RW_SOCKET),
            socket_mode: 0o600,
            socket_group: None,
            paths,
            max_workers: 8,
        }
    }

    /// 测试用：把 socket 放到临时目录。
    pub fn at(socket_path: impl Into<PathBuf>, paths: Paths) -> Self {
        Self {
            socket_path: socket_path.into(),
            socket_mode: 0o660,
            socket_group: None,
            paths,
            max_workers: 8,
        }
    }
}

/// RO 面服务端。
pub struct RoServer {
    config: RoServerConfig,
    gate: ActionGate,
    registry: Arc<Registry>,
}

impl RoServer {
    pub fn new(config: RoServerConfig, registry: Arc<Registry>) -> Self {
        let gate = ActionGate::new(config.paths.clone());
        Self {
            config,
            gate,
            registry,
        }
    }

    /// 处理单个连接上的一帧请求。
    ///
    /// 这是全部安全门控的汇聚点：任何请求都必须先过 [`ActionGate`]。
    pub async fn handle_request(&self, channel: Channel, request: RpcRequest) -> RpcResponse {
        let RpcRequest { action, data } = request;

        match self.gate.evaluate(channel, &action, &data) {
            GateDecision::Allow => {}
            GateDecision::Deny(reason) => {
                return RpcResponse::err(format!("{}: {}", reason.code, reason.message));
            }
        }

        match self.registry.dispatch(&action, &data).await {
            Ok(value) => RpcResponse::ok(value),
            Err(e) => RpcResponse::err(e.to_string()),
        }
    }

    /// 在已建立的连接上服务请求，直到对端关闭。
    #[cfg(unix)]
    pub async fn serve_connection(&self, channel: Channel, stream: UnixStream) {
        self.serve_connection_with_timeout(channel, stream, RPC_REQUEST_READ_TIMEOUT)
            .await;
    }

    #[cfg(unix)]
    async fn serve_connection_with_timeout(
        &self,
        channel: Channel,
        mut stream: UnixStream,
        read_timeout: std::time::Duration,
    ) {
        loop {
            let request: RpcRequest = match tokio::time::timeout(
                read_timeout,
                read_json_request_frame(&mut stream),
            )
            .await
            {
                Ok(Ok(request)) => request,
                Ok(Err(crate::framing::FrameError::Io(e)))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    // 对端正常关闭。
                    return;
                }
                Ok(Err(e)) => {
                    let _ = write_json_frame(&mut stream, &RpcResponse::err(e.to_string())).await;
                    return;
                }
                Err(_) => {
                    let _ = write_json_frame(
                        &mut stream,
                        &RpcResponse::err("RPC request read timed out"),
                    )
                    .await;
                    return;
                }
            };

            let response = self.handle_request(channel, request).await;
            if write_json_frame(&mut stream, &response).await.is_err() {
                return;
            }
        }
    }

    /// 绑定 socket 并设置权限。
    ///
    /// 已存在的陈旧 socket 会被移除——否则重启后会因 `EADDRINUSE` 起不来。
    #[cfg(unix)]
    pub fn bind(&self) -> std::io::Result<UnixListener> {
        bind_unix_socket(
            &self.config.socket_path,
            self.config.socket_mode,
            self.config.socket_group.as_deref(),
        )
    }

    pub fn config(&self) -> &RoServerConfig {
        &self.config
    }

    /// 绑定 socket 后运行 accept 循环。仅 Unix 提供（生产目标为 Linux）。
    #[cfg(unix)]
    pub async fn run(self: Arc<Self>, channel: Channel) -> std::io::Result<()> {
        let listener = self.bind()?;
        self.serve(listener, channel).await
    }

    /// 在**已绑定**的 listener 上运行 accept 循环。
    ///
    /// 与 [`RoServer::run`] 的唯一区别是「谁负责绑定」：调用方先 `bind()` 再 `serve()`，
    /// 就能在**启动阶段**发现「socket 建不起来」（目录不存在、权限不足），而不是让一个
    /// 后台任务悄悄失败、进程却看起来一切正常。
    #[cfg(unix)]
    pub async fn serve(
        self: Arc<Self>,
        listener: UnixListener,
        channel: Channel,
    ) -> std::io::Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_workers));

        loop {
            let (stream, _addr) = listener.accept().await?;
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    drop(stream);
                    continue;
                }
                Err(tokio::sync::TryAcquireError::Closed) => return Ok(()),
            };
            let server = Arc::clone(&self);
            tokio::spawn(async move {
                server.serve_connection(channel, stream).await;
                drop(permit);
            });
        }
    }
}

/// 绑定 Unix socket 并应用权限。
#[cfg(unix)]
pub fn bind_unix_socket(
    path: &Path,
    mode: u32,
    group: Option<&str>,
) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 陈旧 socket 必须先移除，否则 bind 报 EADDRINUSE。
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    let permission_result = (|| {
        if let Some(group) = group {
            let gid = mailstack_core::atomic::gid_by_name(group).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("cannot resolve socket group {group}"),
                )
            })?;
            std::os::unix::fs::chown(path, None, Some(gid))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    })();
    if let Err(error) = permission_result {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }

    Ok(listener)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::handlers::Registry;
    use serde_json::json;
    use std::sync::Arc;

    fn test_paths(tag: &str) -> (PathBuf, Paths) {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-srv-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = Paths::rooted(&root);
        (root, paths)
    }

    fn server_for(root: &Path, paths: Paths) -> Arc<RoServer> {
        let socket = root.join("helper-ro.sock");
        let cfg = RoServerConfig::at(socket, paths.clone());
        // 必须装配核心动作，否则 settings.get 会（正确地）返回 NOT_IMPLEMENTED。
        Arc::new(RoServer::new(
            cfg,
            Arc::new(Registry::with_core_actions(paths)),
        ))
    }

    #[tokio::test]
    async fn unknown_action_is_rejected_over_the_wire_contract() {
        let (root, paths) = test_paths("unknown");
        let server = server_for(&root, paths);
        let resp = server
            .handle_request(
                Channel::Ro,
                RpcRequest {
                    action: "nope".into(),
                    data: json!({}),
                },
            )
            .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().starts_with("UNKNOWN_ACTION"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn socket_group_resolution_failure_aborts_binding() {
        let (root, _) = test_paths("missing-group");
        let socket = root.join("helper-ro.sock");
        let missing_group = format!("mailstack-missing-{}", std::process::id());

        let error = bind_unix_socket(&socket, 0o660, Some(&missing_group))
            .expect_err("不存在的 socket 属组必须令绑定失败");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!socket.exists(), "失败的 bind 不得留下可被抢占的 socket");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn ro_surface_rejects_mutating_action() {
        let (root, paths) = test_paths("rw-on-ro");
        let server = server_for(&root, paths);
        let resp = server
            .handle_request(
                Channel::Ro,
                RpcRequest {
                    action: "admin.set".into(),
                    data: json!({"username": "admin", "password": "x"}),
                },
            )
            .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().starts_with("ACTION_REQUIRES_PRIVILEGE"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn destructive_action_needs_confirm_over_the_wire() {
        let (root, paths) = test_paths("confirm");
        let server = server_for(&root, paths);
        let resp = server
            .handle_request(
                Channel::Rw,
                RpcRequest {
                    action: "domains.delete".into(),
                    data: json!({"domain": "example.com"}),
                },
            )
            .await;
        assert!(!resp.ok);
        assert!(resp.error.unwrap().starts_with("CONFIRMATION_REQUIRED"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn binding_creates_socket_with_requested_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (root, paths) = test_paths("bind");
        let socket = root.join("nested/helper-ro.sock");
        let cfg = RoServerConfig::at(socket.clone(), paths);
        let server = RoServer::new(cfg, Arc::new(Registry::new()));
        let _listener = server.bind().unwrap();

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "RO socket 必须为 0660");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn rebinding_replaces_stale_socket_file() {
        let (root, paths) = test_paths("stale");
        let socket = root.join("helper-ro.sock");
        // 先造一个陈旧 socket 文件。
        std::fs::write(&socket, b"stale").unwrap();

        let cfg = RoServerConfig::at(socket.clone(), paths);
        let server = RoServer::new(cfg, Arc::new(Registry::new()));
        let _listener = server.bind().expect("陈旧 socket 应被移除后重新绑定");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn round_trip_over_a_real_unix_socket() {
        let (root, paths) = test_paths("e2e");
        let socket = root.join("helper-ro.sock");
        let cfg = RoServerConfig::at(socket.clone(), paths.clone());
        let server = Arc::new(RoServer::new(
            cfg,
            Arc::new(Registry::with_core_actions(paths)),
        ));
        let listener = server.bind().unwrap();

        let accept = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                server.serve_connection(Channel::Ro, stream).await;
            })
        };

        let mut client = UnixStream::connect(&socket).await.unwrap();
        crate::framing::write_json_frame(
            &mut client,
            &RpcRequest {
                action: "settings.get".into(),
                data: json!({}),
            },
        )
        .await
        .unwrap();
        let resp: RpcResponse = crate::framing::read_json_frame(&mut client).await.unwrap();
        assert!(resp.ok, "settings.get 应成功: {:?}", resp.error);

        drop(client);
        let _ = accept.await;
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn idle_rpc_connections_are_closed_after_the_request_read_timeout() {
        use std::time::Duration;

        let (root, paths) = test_paths("idle-timeout");
        let server = server_for(&root, paths);
        let listener = server.bind().unwrap();
        let accept = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                server
                    .serve_connection_with_timeout(Channel::Ro, stream, Duration::from_millis(20))
                    .await;
            })
        };

        let mut client = UnixStream::connect(root.join("helper-ro.sock"))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(1),
            crate::framing::read_json_frame::<RpcResponse, _>(&mut client),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(!response.ok);
        assert!(response
            .error
            .as_deref()
            .unwrap()
            .contains("request read timed out"));
        accept.await.unwrap();
        std::fs::remove_dir_all(&root).ok();
    }
}
