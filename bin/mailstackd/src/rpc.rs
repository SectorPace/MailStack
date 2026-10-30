//! 特权 RPC 面的装配（§3.3 的 RO / RW 双通道）。
//!
//! ```text
//! RO action  → 直连 <run_dir>/helper-ro.sock（0660 root:mailstack-admin）
//! RW action  → <run_dir>/helper.sock（0600 root:root，服务进程连不上）
//! ```
//!
//! ## 门控不在这一层
//!
//! 「哪些动作可以走哪个面」由 [`mailstack_priv::ActionGate`] 判定，本模块只负责**绑定、
//! 起循环、跟着停机信号收工**。这里再写一遍白名单判断，等于制造第二个真相源。
//!
//! ## socket 路径由 `run_dir` 推导，不写死
//!
//! 生产下 `run_dir` 就是 `/run/mailstack`，于是路径与 [`mailstack_priv::DEFAULT_RO_SOCKET`]
//! 逐字相同；而 `--config-dir` 旁路部署时它会随之落到临时目录，不会去动真实系统的
//! socket。**写死绝对路径会让旁路部署踩到生产**，这正是迁移期最要避免的事。
//!
//! ## 先绑定时装，再起循环
//!
//! 绑定放在启动阶段（[`bind_all`]）而不是后台任务里：socket 建不起来（目录不可写、
//! 路径被别的进程占着）必须在启动时就报出来，否则运维会看到一个「一切正常、但管理台
//! 永远 503」的进程。

use std::sync::Arc;

use mailstack_core::actions::Channel;
use mailstack_core::Paths;
use mailstack_priv::handlers::Registry;
use mailstack_priv::{RoServer, RoServerConfig};
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use crate::error::DaemonError;
use crate::shutdown::Shutdown;

/// 一个已绑定的 RPC 面。
struct Face {
    /// 日志用的短名。
    label: &'static str,
    channel: Channel,
    server: Arc<RoServer>,
    listener: UnixListener,
}

/// 两个已绑定的 RPC 面。
pub struct SecureFaces {
    faces: Vec<Face>,
}

/// 绑定 RO 与 RW 两个 socket，并装配全部已落地的动作。
///
/// 返回即代表两个 socket **已经建好**；此后任何失败都发生在服务阶段。
///
/// ⚠️ **部署前置条件**：RO 面是 `0660 root:mailstack-admin`，因此宿主上必须存在
/// `mailstack-admin` 组，否则 `bind` 直接失败（4.11 的 fail-closed，刻意不降级）。
pub fn bind_all(paths: &Paths) -> Result<SecureFaces, DaemonError> {
    bind_all_with(paths, Some(mailstack_core::atomic::ADMIN_GROUP))
}

/// [`bind_all`] 的内部实现；`ro_group` 是 RO 面要 `chown` 到的属组。
///
/// 抽出来是为了让测试可以传 `None`（不设属组）。**为什么测试必须能关掉它**：
///
/// * 干净主机（GitHub 的 `ubuntu-24.04` runner、新建的 Ubuntu 26.04、Alpine…）
///   上**没有** `mailstack-admin` 组 → `gid_by_name` 失败 → bind 失败；
/// * 换成一个"必然存在"的组（如 `root`）也不行：CI runner 是非 root，
///   `chown` 到不属于自己的组会 EPERM。
///
/// 也就是说「属组生效」这件事在非 root 的干净环境里**无法**被集成测试覆盖。
/// 因此拆成两块：
///   1. 绑定测试只验 mode（0660/0600）与可用性 —— 传 `None`，与宿主无关；
///   2. 属组契约用纯单元测试
///      `production_ro_socket_config_names_the_admin_group_and_is_world_unreadable`
///      钉住（只读配置值，不碰系统）。
fn bind_all_with(paths: &Paths, ro_group: Option<&str>) -> Result<SecureFaces, DaemonError> {
    // 只读聚合面（`snapshot` / `logs.list` / `metrics.realtime` / `certs.list` /
    // `network.check_port` / `system.doctor`）读真实 `/proc`、跑真实 `journalctl`，
    // 因此只在生产装配：测试用注入替身的 `Readers`。
    let readers = Arc::new(mailstack_priv::Readers::system(paths.clone()));
    let registry = Arc::new(Registry::with_core_actions(paths.clone()).with_readers(readers));

    // 复用生产构造器（权限位与属组都在那里定死），只把路径挪到 run_dir 下。
    let mut ro_config = RoServerConfig::ro_socket(paths.clone());
    ro_config.socket_path = paths.run_dir.join("helper-ro.sock");
    ro_config.socket_group = ro_group.map(str::to_string);
    let mut rw_config = RoServerConfig::rw_socket(paths.clone());
    rw_config.socket_path = paths.run_dir.join("helper.sock");

    let faces = vec![
        bind_face(ro_config, Arc::clone(&registry), Channel::Ro, "ro")?,
        bind_face(rw_config, registry, Channel::Rw, "rw")?,
    ];
    Ok(SecureFaces { faces })
}

fn bind_face(
    config: RoServerConfig,
    registry: Arc<Registry>,
    channel: Channel,
    label: &'static str,
) -> Result<Face, DaemonError> {
    let path = config.socket_path.clone();
    let server = Arc::new(RoServer::new(config, registry));
    let listener = server.bind().map_err(|source| DaemonError::RpcBind {
        path: path.clone(),
        source,
    })?;
    tracing::info!(face = label, socket = %path.display(), "RPC 面已就绪");
    Ok(Face {
        label,
        channel,
        server,
        listener,
    })
}

impl SecureFaces {
    /// 把两个面挂到任务集合上，并让它们跟随同一个停机信号收工。
    ///
    /// `RoServer::serve` 是无限循环且**没有**停机参数，所以这里用 `select!` 包一层：
    /// 信号到达即 drop 掉 serve future（连带 drop listener），停止接受新连接。
    /// **在途连接不会被排空** —— 它们各自是 `tokio::spawn` 出来的独立任务，会自然跑完。
    pub fn spawn(self, tasks: &mut JoinSet<Result<(), String>>, shutdown: &Shutdown) {
        for face in self.faces {
            let Face {
                label,
                channel,
                server,
                listener,
            } = face;
            let waiter = shutdown.waiter();
            tasks.spawn(async move {
                tokio::select! {
                    result = server.serve(listener, channel) => {
                        if let Err(error) = result {
                            tracing::error!(face = label, error = %error, "RPC 面异常退出");
                            // 5.19：异常退出要作为结果上报，不能只留一行日志。
                            return Err(format!("rpc face {label} exited: {error}"));
                        }
                        Ok(())
                    }
                    _ = waiter => {
                        tracing::info!(face = label, "RPC 面停止接受新连接");
                        Ok(())
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailstack_priv::framing::{read_json_frame, write_json_frame};
    use mailstack_priv::{RpcRequest, RpcResponse};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tokio::net::UnixStream;

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::rooted(dir.path());
        std::fs::create_dir_all(paths.etc.clone()).unwrap();
        std::fs::write(
            &paths.settings_config,
            r#"{"hostname":"mx.example.org","maxMessageSizeMb":50,"relayConcurrency":20}"#,
        )
        .unwrap();
        (dir, paths)
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// 生产 RO 面契约：`0660` + 属组 `mailstack-admin`。
    ///
    /// 这条**不碰系统组**（只读配置值），因此在任何主机上都能跑 ——
    /// 它替代了原先「靠绑定成功来间接验证组名」的做法。
    #[test]
    fn production_ro_socket_config_names_the_admin_group_and_is_world_unreadable() {
        let (_dir, paths) = test_paths();
        let config = RoServerConfig::ro_socket(paths.clone());
        assert_eq!(
            config.socket_mode, 0o660,
            "RO 面必须 0660（Web 进程可直连）"
        );
        assert_eq!(
            config.socket_group.as_deref(),
            Some(mailstack_core::atomic::ADMIN_GROUP),
            "RO 面的属组必须是 mailstack-admin"
        );
        assert_eq!(config.max_workers, 8);

        let rw = RoServerConfig::rw_socket(paths);
        assert_eq!(rw.socket_mode, 0o600, "RW 面必须 0600 root:root");
        assert!(
            rw.socket_group.is_none(),
            "RW 面不得设置属组（服务进程连不上它）"
        );
    }

    // 需要 tokio 运行时：`RoServer::bind` 返回的是 tokio 的 `UnixListener`，离开
    // reactor 就会 panic。
    #[tokio::test]
    async fn both_faces_are_bound_under_run_dir_with_the_documented_modes() {
        let (_dir, paths) = test_paths();
        let _faces = bind_all_with(&paths, None).expect("绑定两个面");

        let ro = paths.run_dir.join("helper-ro.sock");
        let rw = paths.run_dir.join("helper.sock");
        assert!(ro.exists(), "只读面 socket 未创建：{}", ro.display());
        assert!(rw.exists(), "变更面 socket 未创建：{}", rw.display());
        assert_eq!(mode_of(&ro), 0o660, "RO 面必须是 0660（Web 进程可直连）");
        assert_eq!(mode_of(&rw), 0o600, "RW 面必须是 0600 root:root");
    }

    #[tokio::test]
    async fn a_read_only_action_is_served_over_the_real_ro_socket() {
        // 端到端：绑定的 socket → 真实连接 → 门控 → 处理器 → 应答。
        let (_dir, paths) = test_paths();
        let faces = bind_all_with(&paths, None).expect("绑定两个面");

        let shutdown = Shutdown::channel();
        let mut tasks = JoinSet::new();
        faces.spawn(&mut tasks, &shutdown);

        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            UnixStream::connect(paths.run_dir.join("helper-ro.sock")),
        )
        .await
        .expect("连接超时")
        .expect("连接只读面");

        let request = RpcRequest {
            action: "settings.get".to_string(),
            data: json!({}),
        };
        write_json_frame(&mut stream, &request)
            .await
            .expect("写请求");
        let response: RpcResponse =
            tokio::time::timeout(Duration::from_secs(3), read_json_frame(&mut stream))
                .await
                .expect("读应答超时")
                .expect("解析应答");

        assert!(response.ok, "只读动作应当被放行：{response:?}");
        let data = response.data.expect("应有数据");
        assert_eq!(data["hostname"], "mx.example.org", "应返回真实配置");

        shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .expect("停机信号必须让 RPC 面退出");
    }
}
