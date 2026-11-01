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
/// 单个 RPC 请求的服务端执行上限。
///
/// 客户端默认 120s 就会超时返回，但服务端此前没有兜底 —— 一个挂死的
/// 处理器（acme.sh、备份还原、磁盘 IO）会永远占着一条分派路径。900s 是
/// **慷慨**的上限：比最长的合法动作（acme.sh 300s + 安装 120s）还宽得多，
/// 这条线只该命中「处理器永远不会返回」的故障，而不是正常长动作。
///
/// 注意 `spawn_blocking` 里的处理器**不可取消**：超时后应答立即回给客户端、
/// 分派结果被丢弃，但阻塞线程会在后台自然跑完 —— 这是 tokio 的语义限制，
/// 仍远好于此前「客户端早已超时、服务端还在无限等」的状态。
const RPC_REQUEST_EXEC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(900);

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

        // 服务端执行兜底：处理器挂死时客户端至少能在 900s 内拿到确定的失败
        // 应答，而不是各端各自挂死。spawn_blocking 的处理器不可取消，超时后
        // 阻塞线程会在后台跑完 —— 见 [`RPC_REQUEST_EXEC_TIMEOUT`] 的说明。
        let dispatch = self.registry.dispatch(&action, &data);
        match tokio::time::timeout(RPC_REQUEST_EXEC_TIMEOUT, dispatch).await {
            Ok(Ok(value)) => RpcResponse::ok(value),
            Ok(Err(e)) => RpcResponse::err(e.to_string()),
            Err(_) => RpcResponse::err(format!(
                "PRIVILEGED_OPERATION_TIMEOUT: {action} exceeded the {}s server-side execution limit",
                RPC_REQUEST_EXEC_TIMEOUT.as_secs()
            )),
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
                    // 满载必须**可见**：静默 drop 会让运维把「新连接连不上」
                    // 误判成网络故障。许可按**连接**持有（keep-alive 的长连接会
                    // 一直占着），所以这里打的是 warn 而不是 debug —— 改成按
                    // 请求持有许可是更大的重构，留作后续工作。
                    mailstack_core::warn::warn(
                        "privileged helper is at its concurrent connection limit; dropping new connection",
                    );
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
        // 特权 socket 的父目录**不能停在 umask 给出的 0755**（root 常见 umask 022）：
        // 那样任何本地用户都能列举目录、看到 socket 的存在。收紧到 0750 ——
        // 刻意**不是** 0700：RO 面（0660 root:mailstack-admin）要靠属组用户穿越
        // 目录去连接 socket，0700 会把整个只读面掐断；0750 + 尽力把属组对齐
        // socket 属组，既挡住其他用户又保住这条通路。
        // 根目录与空路径不动（相对路径测试场景下 parent 可能为空）。
        if !parent.as_os_str().is_empty() && parent != Path::new("/") {
            let mut permissions = std::fs::metadata(parent)?.permissions();
            permissions.set_mode(0o750);
            std::fs::set_permissions(parent, permissions)?;
            #[cfg(unix)]
            if let Some(group) = group {
                if let Some(gid) = mailstack_core::atomic::gid_by_name(group) {
                    // 尽力而为：属组对不上时 socket 自身的 0660 + group chown
                    // 仍然会在下面被判为致命错误。
                    let _ = std::os::unix::fs::chown(parent, None, Some(gid));
                }
            }
        }
    }
    // 陈旧 socket 必须先移除，否则 bind 报 EADDRINUSE。
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    // socket 文件自身的权限位在下面的 `permission_result` 里显式设置
    // （RO 0660 / RW 0600），不依赖 umask。
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
        // 父目录不能停在 umask 的 0755：特权 socket 的存在性不该对所有人可见。
        let parent = socket.parent().unwrap();
        let parent_mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o750, "socket 父目录必须收紧到 0750");
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
