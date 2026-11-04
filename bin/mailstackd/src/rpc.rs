use std::sync::Arc;

use mailstack_core::actions::Channel;
use mailstack_core::Paths;
use mailstack_priv::handlers::Registry;
use mailstack_priv::{RoServer, RoServerConfig};
use tokio::net::UnixListener;
use tokio::task::JoinSet;

use crate::error::DaemonError;
use crate::shutdown::Shutdown;

struct Face {
    label: &'static str,
    channel: Channel,
    server: Arc<RoServer>,
    listener: UnixListener,
}

pub struct SecureFaces {
    faces: Vec<Face>,
}

pub fn bind_all(paths: &Paths) -> Result<SecureFaces, DaemonError> {
    bind_all_with(paths, Some(mailstack_core::atomic::ADMIN_GROUP))
}

fn bind_all_with(paths: &Paths, ro_group: Option<&str>) -> Result<SecureFaces, DaemonError> {
    let readers = Arc::new(mailstack_priv::Readers::system(paths.clone()));
    let registry = Arc::new(Registry::with_core_actions(paths.clone()).with_readers(readers));

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
