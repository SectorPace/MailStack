# MailStack Docker 部署指南

本文档描述如何将 MailStack 以单容器方式构建与运行。相关资产：仓库根 `Dockerfile`、
`docker/entrypoint.sh`、`docker-compose.yml`、`.dockerignore`。

> 适用版本：v0.5.2-rc5 起。镜像基线 `ubuntu:24.04`（CI install-matrix 已验证该平台
> 可完成非交互安装并通过健康断言）。

## 快速开始

```bash
# 1) 构建镜像（需要网络：apt + npm registry + nodejs.org 钉死哈希下载）
docker compose build

# 2) 首次启动（二选一）
#    a. 显式指定管理员口令（12-256 位，须同时含字母与数字）
MAILSTACK_ADMIN_PASSWORD='Your-Strong-Admin-Pass-7' docker compose up -d
#    b. 留空：entrypoint 生成随机口令并在日志中只打印一次
docker compose up -d
docker compose logs mailstack | grep -A4 '随机管理员口令'

# 3) 验证
curl http://127.0.0.1:8787/api/health
curl http://127.0.0.1:18788/api/webmail/health
```

管理控制台：`http://127.0.0.1:8787`；Webmail：`http://127.0.0.1:18788`
（compose 默认只把这两个端口绑到宿主回环，远程访问请用 SSH 隧道或前置反代）。

## 构建流程说明

镜像构建完全复用裸机安装器，与 `.github/workflows/ci.yml` install-matrix 相同的路径：

```
bash deploy/install.sh --non-interactive --access-mode local --admin-password-stdin
```

- 仓库 `dist/` 若含通过 `build-manifest.json` SHA256 校验的预构建产物，安装器直接采用；
  否则自动执行 `npm ci && npm run build:all`（构建因此需要 Node 下载与 npm 网络）。
- Node.js 由安装器钉版本安装（22.20.0 + SHA256 校验），不由 Dockerfile 预装。
- 安装器自带的「构建产物门」与「安装后健康自检」在构建期同样生效，构建通过即代表
  该镜像在其自身构建环境里完成过一次完整的端到端自检。

## 管理员口令初始化（安全设计）

安装器要求安装期必须创建管理员（没有"跳过管理员"参数）。镜像因此采用如下方案，
**任何明文口令都不进入镜像层**：

1. 构建期使用一个当场从 `/dev/urandom` 生成的一次性口令走完安装器（不进 `ARG`/`ENV`，
   不出现在镜像历史），安装完成后立即删除其哈希文件 `admin.json`。
2. 首次容器启动时由 `docker/entrypoint.sh` 重新初始化 `/etc/mailstack/admin.json`：
   - 环境变量 `MAILSTACK_ADMIN_PASSWORD` 提供 → 直接使用（策略不满足则启动失败并报错）；
   - 未提供 → 生成随机口令，在容器日志中**只打印一次**。
3. 口令哈希与安装器相同：pbkdf2-sha256、310000 次迭代、16 字节盐，写入数据卷
   `/etc/mailstack`，跨重建保留。

约束：`MAILSTACK_ADMIN_PASSWORD` 仅在**首次启动（卷内无 admin.json）**时生效；
之后修改该环境变量不会改动已有凭证。改密请走管理控制台或
`docker compose exec mailstack ms`。

## 端口

| 端口 | 服务 | 说明 |
|---|---|---|
| 8787 | 管理控制台 | 容器内监听 0.0.0.0，compose 默认只映射到宿主 127.0.0.1 |
| 18788 | Webmail | 同上 |
| 25 | SMTP 入站 | Windows 宿主出站 25 通常被运营商封锁，本地验证别依赖它 |
| 465 | SMTPS | TLS wrappermode 提交 |
| 587 | Submission | SASL + TLS，本地发信验证首选 |
| 143 / 993 | IMAP / IMAPS | 993 用引导自签证书 |
| 110 / 995 | POP3 / POP3S | |

本地功能验证建议以 587 / 143 / 8787 / 18788 为主。

### 管理口默认回环与双旗标发布门控（A6）

管理面板默认绑**回环 `127.0.0.1`**，与裸机「面板回环 + 前置 TLS 反代」的安全模型一致。
容器网络有个现实约束：容器内进程若只绑回环，docker 的 `-p` 映射（走容器 eth0）就触达
不到它。因此把管理口发布到容器网络外需要**显式双旗标**，二者缺一不可：

| 旗标 | 语义 |
|---|---|
| `MAILSTACK_LISTEN_HOST=<非回环>` | 容器内监听地址（如 `0.0.0.0`）；不设则默认 `127.0.0.1`，不触发门控 |
| `MAILSTACK_I_PUBLISH_ADMIN=1` | 运维确认：知晓此举把管理面板发布到容器网络外 |

`docker/entrypoint.sh` 的 `gate_listen_host` 在启动最早期校验：`LISTEN_HOST` 为非回环却
缺少任一旗标，即打印拒绝原因并 `exit 1`。因此：

```bash
# ✗ 起不来：把端口映射出去了，却没声明发布意图，entrypoint 门控拒绝启动
docker run -p 8787:8787 mailstack:local
#   [mailstack-entrypoint] 拒绝启动：MAILSTACK_LISTEN_HOST=... 为非回环地址，但缺少 MAILSTACK_I_PUBLISH_ADMIN=1。

# ✓ 显式双旗标：容器内绑 0.0.0.0，宿主侧仍只映射到回环
docker run \
  -e MAILSTACK_LISTEN_HOST=0.0.0.0 \
  -e MAILSTACK_I_PUBLISH_ADMIN=1 \
  -p 127.0.0.1:8787:8787 \
  mailstack:local
```

`docker-compose.yml` 已按此显式设置 `MAILSTACK_LISTEN_HOST=0.0.0.0` +
`MAILSTACK_I_PUBLISH_ADMIN=1`（容器内监听），同时 `ports` 的宿主侧绑定保持
`${MAILSTACK_BIND:-127.0.0.1}`——**默认只绑宿主回环**，对外暴露面由宿主侧绑定收敛，
远程访问仍建议走 SSH 隧道或前置 TLS 反代。真正要公网发布时，再把 `MAILSTACK_BIND`
设为 `0.0.0.0` 并自行配好 TLS 终结。该门控的可复核测试证据见
[`pentest-2026-09.md`](pentest-2026-09.md)（面二含 sudoers/双 socket 通道证据）。

## 数据卷

| 卷 | 容器路径 | 内容 |
|---|---|---|
| `mailstack-etc` | `/etc/mailstack` | 管理员凭证哈希、安装参数、升级信任锚 |
| `mailstack-lib` | `/var/lib/mailstack` | 邮箱注册表等（供 webmail 读取） |
| `mailstack-home` | `/home` | 邮箱用户家目录，邮件存于 `/home/<user>/Maildir` |
| `mailstack-spool` | `/var/spool/postfix` | MTA 队列 |
| `mailstack-backups` | `/var/backups/mailstack` | 预安装备份 / `ms backup` 输出 |
| `mailstack-postfix-etc` | `/etc/postfix` | MTA 配置 |
| `mailstack-dovecot-etc` | `/etc/dovecot` | IMAP 配置、引导 TLS 证书 |
| `mailstack-opendkim-etc` | `/etc/opendkim` | DKIM 密钥与签名表 |

空卷首次挂载时由 entrypoint 从镜像内的构建期快照（`/opt/mailstack-seed`）回填；
非空卷绝不覆盖。注意 `/etc/opendkim.conf`（文件）与 `/etc/fail2ban` 未持久化，
重建镜像时以安装器重新生成的版本为准。

## 无 systemd 的进程模型

容器内没有 systemd，entrypoint 显式顺序拉起 6 个进程并直接监督（不引入
supervisor 类依赖；tini 作 PID1 负责信号转发与僵尸回收）：

1. `python3 /opt/mailstack/backend/mailstackctl.py --daemon` — 特权 helper，root 运行，
   监听 `/run/mailstack/helper.sock`。**安装器的 init-d 分支不会启动它，容器入口补上**；
2. `postfix start-fg`（前台化）；
3. `dovecot -F`（前台化）；
4. `opendkim -f`（装了才启动，缺失时降级，与安装器行为一致）；
5. `node /opt/mailstack/server.cjs`（以 `mailstack-admin` 账号，8787）；
6. `node /opt/mailstack/webmail.cjs`（以 `mailstack-webmail` 账号，18788）。

全部进程日志直通 stdout/stderr（`docker logs` 可见）。任一关键进程退出，入口脚本
立即终止其余进程并以非零码退出，由 `restart: unless-stopped` 接管整体重启。

与裸机安装的差异：

- helper 由入口脚本拉起（裸机由 `mailstack-helper.service` 管理）；
- 安装器写入的 systemd 单元与 `/etc/init.d/mailstack-web` 在容器内**均不生效**，
  Node 服务由入口脚本以服务账号直接启动；管理口默认绑回环 `127.0.0.1`，需发布到
  容器网络外时经 `gate_listen_host` 双旗标门控（见「管理口默认回环与双旗标发布门控」）；
- `fail2ban` 不在容器内运行（容器无 syslog 日志源，jail 无输入）；爆破防护依赖
  宿主网络层或前置反代；
- `cron` 不运行：acme.sh 自动续期不可用（local 模式本就不签公网证书）；
- 邮件服务日志依赖 syslog，容器内默认不落盘；postfix 3.8 自动回落到内置
  postlog，dovecot/opendkim 经前台参数输出到容器日志。

## 升级方式

数据全部在卷中，升级 = 重新构建镜像 + 保留卷：

```bash
git pull                       # 或切换到新版本源码
docker compose build --no-cache
docker compose up -d           # 卷不动，数据保留
```

如需回滚，切回旧源码重建即可。建议在升级前执行
`docker compose exec mailstack ms backup`（产物落在 `mailstack-backups` 卷）。

## 已知限制

- **出站 25 端口**：家用/企业宽带及多数云厂商默认封锁出站 25，对外投递会失败；
  本地验证用 587（提交）与回环投递（管理台 `test-mail`）。
- **WSL2（Docker Desktop）**：overlay2 上运行 postfix/dovecot 这类大量小文件
  工作负载性能较差，且个别文件系统语义（如 `fsync` 时延）会影响队列吞吐；
  生产请置于原生 Linux 宿主。`/var/spool/postfix` 建议保持为命名卷（位于
  WSL2 内部文件系统），不要绑定挂载到 `/mnt/c` 等 9P 路径。
- **主机名**：`MAILSTACK_HOSTNAME`（默认 `mail.local`）决定 postfix 的
  `myhostname`/HELO；对外服务请改真实 FQDN 并配好 A/AAAA 与 rDNS。
- **首启口令打印**：随机口令只出现在一次启动日志中，丢失则需删卷重建或走改密流程。
- **单容器模型**：全部组件共享一个容器的资源与故障域；水平拆分（如 MTA 独立）
  不在当前资产范围内。
