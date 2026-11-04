# MailStack v1.0.0 部署文档（Rust 重写）

> 对应规格书 `docs/REWRITE_TO_RUST.md`（v2）。v1.0.0 已完成全部协议面、Web 管理台与 Webmail（详见 README），
> 见文末「当前进度」。

## 1. 产物

| 产物 | 说明 |
|---|---|
| `mailstackd` | 主服务二进制：**入站 SMTP（25/465/587）+ 出站队列调度 + LMTP 本地投递 + 特权 RPC 的两个 Unix socket**。Webmail 由独立进程 `mailstack-webmail` 承载（见 §3.9） |
| `mailstackctl` | CLI：`mailstackctl <action> [JSON] [--confirm]`。只读动作直连 RO socket，变更动作经 `sudo` 包装器（见 §3.5）。`--privileged-stdin` 是包装器协议模式（无 argv + stdin JSON） |
| `mailstack-web` | 管理控制台服务：管理 API 的全部路由 + 前端产物托管 + 遥测后台采样（见 §3.7）。**可选**：不给 `--dist` 就只提供 API |
| `mailstack-imap` | IMAP4rev1 / POP3 / ManageSieve 守护进程（143/993/110/995/4190）+ metrics，替代 **Dovecot 的 imap/pop3**。口令来自 `mailbox-passwords.json`，邮箱来自 `/etc/passwd` + `~/Maildir`（见 §3.8） |
| `mailstack-webmail` | Webmail 服务：`/mail/api/*` + `webui/dist`（入口 `mail.html`）托管，默认 `127.0.0.1:8444`，与管理台进程/端口/会话隔离（见 §3.9） |
| `dist/SHA256SUMS` | 全部产物校验和（含发布 tarball 本身那一行） |
| `dist/sbom.spdx.json` | SBOM（依赖清单）。`cargo-sbom` 未安装时退化为 `dist/dependency-inventory.txt`（外部依赖逐条 `name version license`） |
| `dist/*-musl` | **可选**：`deploy/build.sh --musl` 产出的全静态二进制。用于 glibc 过旧或 musl 的目标平台，见 §6。**本期一键安装不下载 musl 变体**，需自行构建后以 `--binary-dir dist` 安装 |
| `dist/mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz` | 发布 tarball，供 `deploy/install.sh` 默认下载/`--archive` 使用；内含 5 个二进制、`deploy/install.sh`、`deploy/uninstall.sh`、systemd unit 模板、`webui-dist/`、README/README_EN/LICENSE/CHANGELOG |

> ⚠️ **libc 兼容性（2026-10-30 实测，见 §6）**：默认产物是动态链接 glibc，
> **下限 glibc 2.39**。本项目声明的安装矩阵里有 Rocky Linux 9 / Oracle Linux 9（glibc 2.34）
> 和 Alpine（musl）—— **这些平台必须用 `*-musl` 静态产物**，否则启动即
> `GLIBC_2.39 not found` / not found。

> `mailstackd` 的参数：`--port <PORT>`（可重复，缺省 25 465 587）、`--config-dir <DIR>`
> （把 `/etc/mailstack` 视作 `<DIR>/etc/mailstack`，供测试与旁路部署）、`--log <LEVEL>`
> （`RUST_LOG` 优先）。**启动是 fail-closed 的**：缺少 `setup.json`、域名表为空、
> 证书缺失、`relay.json` 损坏或中继未启用加密，都会拒绝启动而不是带病运行。
>
> `mailstack-web` 的参数：`--bind <ADDR>`（缺省 `127.0.0.1:8443`，**只绑回环**）、
> `--dist <DIR>`（前端产物目录）、`--sample-interval <SECS>`（遥测采样周期，缺省 2）、
> `--config-dir <DIR>`、`--log <LEVEL>`。前端产物是**外部输入**，构建方式见
> `README.md` 的「前端」一节。

供应链约束（规格书 §7）：
- 一律 `cargo build --locked`（`Cargo.lock` 已提交）
- 离线构建：`cargo vendor` + `.cargo/config.toml` 切换 `vendored-sources`
- 来源白名单：仅 crates.io，无 git 依赖
- **禁止**在生产机安装 cargo/rust；构建只在 WSL Ubuntu 24.04 或 CI 完成

## 2. 构建

```bash
# 前置：Linux（WSL Ubuntu 24.04）/ Rust 1.98.1 / C 编译器
# 开发机（Windows）请先执行 deploy/wsl-install-rust.sh 装配 WSL 工具链

deploy/build.sh             # release 构建（5 个二进制）+ SHA256SUMS + SBOM
deploy/build.sh --offline   # 使用已 vendor 的依赖离线构建
deploy/build.sh --vendor    # 先 vendor 再离线构建
deploy/build.sh --musl      # 额外产出 *-musl 全静态二进制

# 前端产物（管理台 index.html + Webmail mail.html，同一次构建）
cd webui && npm ci && npm run build && cd ..
```

质量门禁（与 CI 一致）：

```bash
deploy/wsl-quality-gate.sh   # rustfmt --check + clippy -D warnings + cargo test
```

## 3. 部署

v1.0.0 有两条部署路径：

1. **全新部署（推荐）**：用 `deploy/install.sh` 一次装好用户/组、目录与权限、二进制、
   特权包装器与 sudoers、systemd unit、前端产物，并初始化管理员凭据。
   一键脚本与源码构建两种形态见 [`docs/INSTALL.md`](INSTALL.md)。
2. **迁移期与旧栈双跑**：保留原 Postfix 与旧 `mailstack-web`，先以旁路端口验证，
   再切换端口与包装器。同一对 RPC socket、同一个 Maildir 都只能有一个实现占用。

> **迁移期双跑必须显式指定旁路端口**：`mailstackd` 的缺省端口是 25/465/587，那是
> **完全接管**时才该用的值，双跑时会和 Postfix 抢端口。双跑阶段请用
> `--port 2525`（`ALLOWED_RELAY_PORTS` 白名单内的非特权端口），由上游按需转发。
> 组件下线（停用 Postfix/OpenDKIM/fail2ban/Dovecot）是**迁移期的可选收尾步骤**，
> 不是安装器自动完成项；纯 MailStack 主机（未安装 Postfix）可完整工作。
>
> 注意：MailStack 仍会写出 Postfix 格式的表文件以兼容双跑；找不到 `postmap`（本机没装
> Postfix）时按「无需同步」处理，**不会**把域名/别名写入判为失败。

### 3.0 安装脚本（`deploy/install.sh`）

v1.0.0 起不再需要手工铺 systemd unit / 建用户 / 写包装器：安装器一次完成
（`deploy/uninstall.sh` 负责卸载）。两种形态：

```bash
# ① curl 一键（默认从 GitHub Release 下载并校验 SHA256；管道模式不能同时传口令）
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
  | sudo bash -s -- --domain mail.example.com

# ② 先落盘再执行（带口令的无人值守安装走这条）
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
printf '%s\n' "$MAILSTACK_ADMIN_PASSWORD" | sudo bash /tmp/mailstack-install.sh \
  --non-interactive --domain mail.example.com --admin-password-stdin

# ③ 源码构建后安装
git clone https://github.com/SectorPace/MailStack.git && cd MailStack
deploy/build.sh
sudo deploy/install.sh --binary-dir dist
```

要点（完整参数与流程见 [`docs/INSTALL.md`](INSTALL.md)）：

* 默认安装 release 产物并**校验 `SHA256SUMS`**；`--from-source` / `--archive FILE|URL` /
  `--binary-dir DIR` 覆盖来源；`--prefix DIR` 用于 staging/测试（自动不操作宿主 systemd）；
  `--no-systemd` 用于容器；
* `--access-mode local|caddy|direct` 写入 `/etc/mailstack/install-args.conf` 的 `ACCESS_MODE`
  （`crates/core/src/mode.rs` 据此判公网档：Cookie `Secure`、public 模式备份必须加密等）；
  `--imap yes|no` 控制 IMAP/POP3 服务（默认 `yes`）；
* 自动创建 `mailstack-admin`、`mailstack-webmail` 等系统用户/组与目录权限（§3.4），
  写入 `/usr/local/bin/` 下 5 个二进制、**正确的特权包装器**（§3.1.1）、sudoers 与 4 个 unit；
* 管理员凭据经特权通道写入（`admin.json` 已存在则跳过）；身份（域名/DKIM/DNS）留给管理台 setup 向导；
* `--uninstall` / `--purge`（或独立 `deploy/uninstall.sh`）提供卸载路径；
* 重复执行是幂等的，不覆盖既有配置（运维改动保留）。

### 3.1 systemd unit（安装器生成；以下为模板）

```ini
# /etc/systemd/system/mailstackd.service
[Unit]
Description=MailStack Rust daemon (inbound SMTP + outbound queue)
After=network.target

[Service]
Type=simple
# 全新部署直接接管 25/465/587；与 Postfix 双跑迁移期改用旁路端口，例如
#   ExecStart=/usr/local/bin/mailstackd --port 2525
ExecStart=/usr/local/bin/mailstackd --port 25 --port 465 --port 587
RuntimeDirectory=mailstack
User=root
Restart=on-failure
ProtectSystem=strict
ReadWritePaths=/var/lib/mailstack /etc/mailstack /etc/postfix
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

> 端口 25/465/587 都低于 1024，绑定它们需要 root 或 `CAP_NET_BIND_SERVICE`。
> 三个监听**共用同一份**限速配额与封禁表（否则轮换端口就能绕过限速）。
>
> 特权 RPC 的两个 socket 由本进程创建，路径从 `run_dir` 推导：
>
> | socket | 生产路径 | 权限 | 谁能连 |
> |---|---|---|---|
> | 只读面 | `/run/mailstack/helper-ro.sock` | `0660` root:mailstack-admin | Web 进程（属 `mailstack-admin` 组） |
> | 变更面 | `/run/mailstack/helper.sock` | `0600` root:root | 只有 root；Web 进程必须经 `sudo` 包装器 |
>
> 两者在**启动阶段**就绑定：建不起来（目录不可写、被别的进程占着）会直接启动失败，
> 而不是留下一个「进程正常、管理台永远 503」的状态。门控仍由 `ActionGate` 判定：
> 走只读 socket 的变更动作一律被拒（INV-24）。
>
> 迁移期与旧的 RPC 交付方式**不要同时跑** —— 两边都想绑同一对 socket，后启动的会
> 把先启动的那个顶掉。请确认切换完成后再停旧的。

> ### 3.1.1 sudo 包装器（RW 通道的唯一入口）
>
> **本节是部署的硬前置条件**：包装器没换对之前，**所有写操作都会失败**。
>
> `mailstackd` 只在 unix socket 上提供 RPC。RO 面（只读）Web 进程可直连
> `helper-ro.sock`，而 **RW 面恒经 `sudo /usr/local/libexec/mailstack-privileged`** ——
> `helper.sock` 是 `0600 root:root`，Web 进程（非 root）连不上，这是设计而不是缺陷。
>
> **包装器协议是「无 argv + stdin JSON」**：客户端（`PrivilegedCaller::call_via_sudo`）以
> `sudo <wrapper>` 启动包装器，把 `{"action","data"}` 写进 stdin、从 stdout 读 `{"ok",...}`。
> 因此包装器**必须转成 `--privileged-stdin` 模式**；转发 `"$@"` 是错的
> （`mailstackctl` 会把空 argv 当成缺动作名，全部 38 个变更动作都无法执行）。
> 这也是 R2-001/R7-002 记录的缺陷，安装器会写入正确内容：
>
> ```bash
> #!/usr/bin/env bash
> set -Eeuo pipefail
> export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
> exec /usr/local/bin/mailstackctl --privileged-stdin
> ```
>
> 迁移期主机上可能已经存在**重写之前**留下的同名包装器，它 exec 的是旧的 Python 助手：
>
> ```bash
> # 危险的旧包装器（重写前留下的）
> exec "$PY" /opt/mailstack/backend/mailstackctl.py
> ```
>
> 那个文件**可能仍然存在**，于是包装器会**正常执行**——但它不认识本项目的任何动作名，
> 对任何 RW 动作都以 `exit 1` 结束；若包装器改成了转发 `"$@"`，客户端则直接拿到用法错误。
> 两种情况客户端都只看到 `PRIVILEGED_OPERATION_FAILED`，界面报出来的是笼统的「操作失败」，
> 排查时容易误以为是权限或代码问题。
>
> 部署时必须确认包装器是上面那段正确内容（安装器已自动写入；手工部署时执行）：
>
> ```bash
> # 1) 看包装器现在指向什么（出现 .py 或 "$@" 即为错误）
> grep -E 'exec|mailstackctl' /usr/local/libexec/mailstack-privileged
>
> # 2) 写入正确包装器
> cat > /usr/local/libexec/mailstack-privileged <<'WRAPPER'
> #!/usr/bin/env bash
> set -Eeuo pipefail
> export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
> exec /usr/local/bin/mailstackctl --privileged-stdin
> WRAPPER
> chmod 0750 /usr/local/libexec/mailstack-privileged
>
> # 3) 验证：取一个只读动作（直连 socket，不经包装器）与一个变更动作（经包装器）
> mailstackctl domains.list --config-dir /etc/mailstack
> mailstackctl users.list   --config-dir /etc/mailstack   # RW，应能应答
> ```
>
> `deploy/verify-setup-wizard-e2e.sh` 会先检查这一点：包装器不可用时它**跳过**
> RW 步骤并如实说明，而不是把「包装器不对」报成「链路不通」。

### 3.2 提交端口 SASL（口令库 `mailbox-passwords.json`）

25/465/587 三个端口的认证能力**不同**，这是刻意的：

| 端口 | 用途 | TLS | 通告 `AUTH PLAIN` |
|---|---|---|---|
| 25 | MX 收信 | STARTTLS | **否**（不在 MX 口开放认证，少一个口令攻击面） |
| 465 | 提交 | 隐式 TLS | 是（且仅在 TLS 之上） |
| 587 | 提交 | STARTTLS | 是（且仅在 TLS 之上） |

* 凭据**只**在 TLS 之上接收：明文连接上的 `AUTH` 一律 `538 5.7.11`。
* 口令的真相源只有一份 —— `/etc/mailstack/mailbox-passwords.json`（INV-37 的
  PBKDF2-SHA256 记录）。提交端口的 SASL 与 IMAP/POP3/ManageSieve 校验的是
  **同一份**记录，`users.password` 改密后所有协议面同时生效。
* 登录名兼容：完整地址（`alice@example.com`）与本地部分（`alice`）都可登录，
  但**不做跨域猜测**（`bob@other.example` 不会命中 `bob@example.com`）。
  库缺失视为空库；**库损坏/版本不符时 AUTH 一律拒绝**（fail closed），日志给出原因。
* 认证结果与响应码：`235` 成功 / `535` 凭据错。未知用户同样回 `535` —— 服务端会先
  付一次 PBKDF2 再拒绝，避免用响应时间枚举账号。
* **通告 AUTH 却没有任何后端**会在启动时被拒绝。
* 仍在使用 Dovecot passdb 的部署可以注入 `mailstack_smtpd::DovecotAuthClient`
  （auth-client v1.2，`MAILSTACK_DOVECOT_AUTH_SOCKET` 覆盖 socket 路径）——
  但 `mailstackd` 默认不再装配它。
* 认证成功后会话即被允许提交（可向任意域中继，INV-17 的 submission 语义）；
  未认证会话仍只能投递本机纳管域。

### 3.3 出站两条路：中继与直投（互不兜底）

| 配置状态 | 出站路径 | 说明 |
|---|---|---|
| `relay.json` 有 `relayhost` | **只能**经中继 | 全部外发（含退信、系统通知）走同一条路；不存在「中继失败就退回直投」的兜底（INV-18 / INV-21） |
| `relay.json` 不存在或没有 `relayhost` | **直投** | 逐收件域解析 MX，按优先级依次连 25 端口 |

直投的运维要点：

* **先确认出站 25 端口可用**：多数住宅/云环境封禁 25。被判定不可用时管理台会给出
  「建议配置中继」的结论（§5.10.2 的出站探测，属于本机探测而非直投自检）。
* **MX 指向私网/环回会被拒绝**：这是 SSRF 防线（INV-15）。收件域可以用 MX 记录把
  本机变成内网扫描器，公开档部署一律拒绝此类目标，且**不会**因此改用中继。
* **`MX 0 .`（RFC 7505 null MX）会立即退信**：对方明确声明不收信，重试没有意义。
* **没有 MX 记录不是错误**：按 RFC 5321 §5.1 退化为「把域本身当 MX」（查 A/AAAA）。
* ⚠️ **直投当前是明文投递**：直投链路上没有凭证（与中继相反），因此没有「口令泄露」
  风险；但**也没有**做机会式加密。原因是机会式 TLS 在现实里必须「加密但不校验证书」，
  而那是一条独立的安全策略决定，需单独登记与测试。需要全程加密时请配置支持 TLS 的中继。
* 直投**不发** `AUTH`，即便传输上误配了中继凭证（有测试锁定）。

### 3.4 目录与权限契约（§2.5，不得改变）

| 路径 | 用途 | 权限 |
|---|---|---|
| `/etc/mailstack/` | 应用配置 | `0750` root:mailstack-admin |
| `/etc/mailstack/admin.json` | 管理员凭证 + 2FA 信封 | `0640` root:mailstack-admin |
| `/etc/mailstack/setup.json` | 身份（域名 / 邮件主机 / 服务器 IP / DKIM selector） | `0600` |
| `/etc/mailstack/relay.json` | 中继端点 + 明文凭证（`mailstackd` 读它决定出站路径） | `0600` root:root |
| `/etc/mailstack/install-args.conf` | 安装元数据（`ACCESS_MODE` / `MAILSTACK_VERSION` / `MAIL_HOST`） | `0600` root:root |
| `/etc/opendkim/keys/<domain>/<selector>.private` | DKIM 私钥 | `0640` root:opendkim |
| `/etc/mailstack/totp.key` | TOTP 主密钥 | `0600` root:root（仅特权进程可读） |
| `/var/lib/mailstack/` | 队列、注册表、Maildir 索引、会话纪元 | `0750` root:mailstack-webmail |
| `/var/lib/mailstack/manual-bans.json` | 管理台手工封禁（唯一真相源） | `0600` root:root |
| `/var/backups/mailstack/` | 备份归档 | `0700` root:root |
| `/var/log/mailstack-rpc-audit.log` | 审计哈希链 | `0600` |
| `/var/log/mailstack-rpc-audit.log.head` | 审计链锚文件 | `0600` |
| `/usr/share/mailstack/admin/` | 前端产物（管理台 `index.html` + Webmail `mail.html`） | `0755` root:root |
| `/usr/local/libexec/mailstack-privileged` | sudo 包装器（RW 通道唯一入口） | `0750` root:root |
| `/etc/sudoers.d/mailstack-admin` | 仅授权执行该包装器 | `0440` root:root |
| `/run/mailstack/helper-ro.sock` | 只读面 socket | `0660` root:mailstack-admin |
| `/run/mailstack/helper.sock` | 变更面 socket | `0600` root:root |

### 3.5 特权模型

```
RO action  → 直连 /run/mailstack/helper-ro.sock（服务进程属 mailstack-admin 组）
RW action  → sudo /usr/local/libexec/mailstack-privileged（恒走变更面）
```

> **⚠️ 部署前置条件：`mailstack-admin` 组必须存在。**
> RO socket 是 `0660 root:mailstack-admin`；`bind` 时会解析该组名，
> **解析不到就拒绝启动**（4.11 的 fail-closed，刻意不降级为 0600/0666）。
> 安装脚本必须先 `groupadd --system mailstack-admin` 并把管理台进程加入该组。
>
> 这条前置条件此前**既没写进文档、也没在测试里体现** —— 2026-10-30 在干净的
> Ubuntu 26.04 上跑 `cargo test` 才发现两个 RPC 绑定测试因此失败。
> 现在测试已改成不自洽依赖（绑定测试传 `None` 不设属组，只验 mode；
> 组名契约由纯单元测试 `production_ro_socket_config_names_the_admin_group_and_is_world_unreadable`
> 钉住），并有 `tests/` 里的 `socket_group_resolution_failure_aborts_binding` 覆盖失败路径。

`mailstackctl` 的用法：

```bash
mailstackctl domains.list                       # 只读 → 直连 RO socket
mailstackctl settings.set '{"transparency":50}' --confirm   # 变更 → sudo 包装器
mailstackctl domains.list --compact             # 紧凑 JSON（默认缩进）
```

退出码：`0` 成功 / `1` 动作失败 / `2` 用法错误 / `3` 助手不可达 / `4` 中途超时。
**`3` 与 `1` 必须分开** —— 脚本据此决定「重试/报警」还是「看错误信息」。
CLI **没有**「强制走某个通道」的开关：通道由动作唯一判定，提供开关就等于提供一个
绕过门控的入口。旁路部署时用 `--ro-socket` 与 `--sudo-wrapper` 把整条链一起挪开
（`--config-dir` 不会影响 `sudo` 包装器的系统级路径）。

**不得弱化的性质**：
1. 未登记动作一律拒绝，默认走只读面（静默提权防护）
2. 破坏性动作必须 `confirm: true`
3. 助手不可达 → `503 PRIVILEGED_HELPER_UNAVAILABLE`，绝不降级为无特权执行
4. 只读面业务错误/中途超时不得 fallback/重试；公网模式只读不得 fallback 到 sudo

### 3.6 初始化向导（`setup.*`）

管理台初始化向导的后端是一组变更面动作（`setup.*` 全部归 RW，因为即使 `dns.verify`
以出站查询为主，它仍属向导流程且不在只读白名单内）：

| 动作 | 做什么 | 落点 |
|---|---|---|
| `setup.identity.apply` | 校验身份 → 原生生成 DKIM → 写身份 | `/etc/mailstack/setup.json`、`/etc/opendkim/keys/<domain>/` |
| `setup.dns.verify` | A / MX / TXT（SPF、DKIM、DMARC）逐条比对 | 只读（不写任何东西） |
| `setup.relay.test` | 分阶段测试中继（DNS → connect → TLS → auth） | 只读（不写任何东西） |
| `setup.relay.apply` | **先测后写**，测试通过才落中继配置 | `/etc/mailstack/relay.json` |
| `setup.mail.test` | 向本机提交端点 `127.0.0.1:25` 投一封测试信 | 只读（本机 MTA 收下即入队） |
| `mail.test_loopback` | 投一封带一次性 token 的环路自检信，并在 Maildir 里找回它 | 只读（写入由本机 MTA/MDA 负责） |
| `setup.wizard.complete` | 向导收尾：置位 `setup.json` 的 `wizardCompleted`（幂等、非破坏性） | `/etc/mailstack/setup.json` |

三点运维语义：

* **`identity.apply` 不碰 Postfix / OpenDKIM**。本栈已移除它们（规格书 §3.3），DKIM
  密钥由进程内原生 RSA 生成，签名在出站路径完成。基线的 `postconf -e` /
  `opendkim-genkey` / `postmap` 在本栈**没有对应步骤**，不要按旧手册去改 `main.cf`。
* **`relay.apply` 先测后写**：测试不通过时**一行配置都不写**（`relay.json` 保持原样），
  响应里给 `{applied: false, test: {...}}`。中继测试失败是**结论**而非 HTTP 5xx，
  界面据 `connected` / `stages` 显示卡在哪一步。
* **两个自检动作都走本机提交端点**（`sendmail` 已随 Postfix 一起移除）。因此它们要求
  `mailstackd` 正在监听 25；提交被 `250` 接受即表示环路通了。`maildirDelivered: false`
  只说明没在 Maildir 里找到那封信（权威布局是 `<系统用户家目录>/Maildir`），
  **不是**投递失败。
`setup.mail.test` 恢复基线的**四步校验**（域名/发件人格式 → 口令格式回放 → 发件人必须对应一个受管邮箱 → 邮箱未锁定），
不再有 `mailboxChecksSkipped` 这类「跳过检查」的标记 —— 检查全部真实执行。

`setup.cert.issue`（ACME 签发）与 `certs.renew` 均已实现：**调外部 `/root/.acme.sh/acme.sh`**，
证书落 `/etc/mailstack/tls/<domain>/`（见 TEST_REPORT §3.8）。注意 `certs.renew` 的失败是**数据**
（`{status:"failed", error}`）而不是异常，只有域名非法才抛错。

### 3.7 管理控制台服务（`mailstack-web`）

```ini
# /etc/systemd/system/mailstack-web.service
[Unit]
Description=MailStack admin console (API + frontend bundle)
After=network.target mailstackd.service
# 特权通道由 mailstackd 建立；它没起来时管理台会以 503 如实报错，而不是
# 降级成无特权执行（INV-8）。
Requires=mailstackd.service

[Service]
Type=simple
# 只绑回环：对外暴露交给反向代理或 SSH 隧道，TLS 终止不在本进程内做。
ExecStart=/usr/local/bin/mailstack-web --bind 127.0.0.1:8443 --dist /usr/share/mailstack/admin
User=mailstack-admin
Group=mailstack-admin
Restart=on-failure
ProtectSystem=strict
ReadWritePaths=/var/lib/mailstack
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

要点：

* **`--dist` 省略即只提供 API**。省略后页面请求回 **503**（而不是空白 200 或 404）——
  「这台机器还没部署前端」是服务不可用，不是「用户要的页面不存在」。
* **`/api` 的兜底永远是 JSON 404**，绝不会回 `index.html`。否则前端打到不存在的接口时
  会拿到一段 HTML 并报「解析失败」，把「接口不存在」伪装成「服务端坏了」。
* 静态响应同样携带安全响应头（`nosniff` / `frame-options` / CSP）。这个进程返回的
  绝大多数响应都是静态文件，漏掉它们等于没加。
* 服务会启动**遥测后台采样**（2 秒一次）。没有它，`/api/metrics/telemetry` 只有
  「按需采样」兜底 —— `current` 有值但 `points` 永远不会自己增长，仪表盘曲线是平的。

### 3.8 IMAP/POP3 服务（`mailstack-imap`，替代 Dovecot 的 imap/pop3）

自研协议面（`crates/imappop3`）由 `bin/mailstack-imap` 承载，装配层在
`crates/imapd`。**一个监听器服务全部账号**：会话在认证成功后按登录名经
`MailboxResolver` 切到本人 Maildir；解析不到邮箱就拒绝登录，绝不退回默认邮箱。

```ini
# /etc/systemd/system/mailstack-imap.service
[Unit]
Description=MailStack IMAP/POP3/ManageSieve (replaces dovecot imap/pop3)
After=network.target

[Service]
Type=simple
# 993/995 隐式 TLS；143/110 配 STARTTLS/STLS；4190 ManageSieve 配 STARTTLS。
# /metrics 只绑回环，供 Prometheus 抓取。
ExecStart=/usr/local/bin/mailstack-imap \
    --imap 0.0.0.0:143 --imaps 0.0.0.0:993 \
    --pop3 0.0.0.0:110 --pop3s 0.0.0.0:995 \
    --managesieve 0.0.0.0:4190 \
    --metrics 127.0.0.1:9100 \
    --cert /etc/mailstack/tls/mail.example.com/fullchain.pem \
    --key  /etc/mailstack/tls/mail.example.com/privkey.pem \
    --server-name mail.example.com
# 证书用显式 --cert/--key：ACME（setup.cert.issue）落点是
#   /etc/mailstack/tls/<host>/{fullchain,privkey}.pem。
# --cert-domain 只认 Let's Encrypt 标准布局 /etc/letsencrypt/live/<host>/，
# 若你的证书放在那里，可改用：--cert-domain mail.example.com
# 需要读 /etc/mailstack/mailbox-passwords.json 与各账号 ~/Maildir；
# **不需要读 /etc/shadow** —— 口令来自 PBKDF2 记录。
User=root
Group=root
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
LimitNOFILE=65536

# ── 沙箱 ──
# 会写 Maildir（~/Maildir 下 cur/new/tmp 与 sieve/），因此 /home 必须可写；
# 其余路径（/etc/passwd、/etc/mailstack、证书）只读即可。
ProtectSystem=strict
ReadWritePaths=/home
ProtectHome=no
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes

[Install]
WantedBy=multi-user.target
```

**口令来源（与 Dovecot 的关键差异）**

| | Dovecot | `mailstack-imap` |
|---|---|---|
| passdb | PAM / `/etc/shadow` 的 crypt 哈希 | `/etc/mailstack/mailbox-passwords.json`（PBKDF2-SHA256，0600 root:root） |
| 写入时机 | `chpasswd`（只写系统口令） | `users.create` / `users.password` **并写**系统口令 + 该记录 |
| 用户目录 | `userdb static` / `mail_location` | `/etc/passwd` 家目录 + `~/Maildir`（`crates/store` 已定死的布局） |

`users.add` / `users.password` 现在会同时写系统口令与协议面记录；**任何一边写失败
都会如实报错**，不会出现"系统口令改了、IMAP 还是旧口令"。`users.delete` 连带删记录。

**本地投递与脚本**

* 本地邮件由 `mailstackd` 的**自有** LMTP socket（`<run_dir>/lmtp.sock`）落箱，
  队列的 `LmtpClient` 把邮件交给它；Sieve 的 `fileinto` / `reject` / `redirect` /
  `vacation` 都在这一层生效（`redirect`/`vacation` 产物回到同一条出站队列）。
  可用 `MAILSTACK_LMTP_SOCKET` 指向别的实现（例如仍在运行的 Dovecot）。
* ManageSieve 4190 让客户端上传脚本；脚本存进 `<maildir>/sieve/` 并由
  `.active` 标记生效，LMTP 下一次投递即使用它。
* `/metrics` 汇总 IMAP/POP3/ManageSieve 三份注册表（Prometheus 文本，带
  `protocol` 标签）；只监听回环，供 Prometheus 抓取（`mailstack-web` 不抓取该端点）。

**从 Dovecot 切换（必须离线，且只能有一个实现写同一个 Maildir）**

1. `systemctl stop dovecot`（停掉所有 imap/pop3 会话）；
2. 逐账号跑离线 UID 迁移（**先停 Dovecot，再迁移**）：

   ```sh
   mailstack-imap --migrate-maildir /home/alice/Maildir
   ```

   它把 `dovecot-uidlist` 的 UID 与 `.dovecot-keywords` 的关键字接管成
   `.mailstack-uidlist` / `.mailstack-keywords`，并打印逐文件夹计数；重复运行是
   幂等的（已迁移的文件夹会跳过）。**不迁移则所有客户端整体重新同步**。
   `crates/imappop3/tests/dovecot_cutover.rs` 用一份真实布局的夹具演练了这套不变量
   （UID/UIDVALIDITY 保留、已删除记录丢弃、uidlist 之外的邮件分配新 UID、关键字
   字母表接管、重复运行幂等）。
3. 确认每个账号在 `mailbox-passwords.json` 里都有记录（`users.password` 会写）；
4. 启动 `mailstack-imap`，验证 143/993/110/995/4190 与多账号隔离；
5. 停用 Dovecot 的 imap/pop3 与 **auth-client**：提交端口 SASL 已改读
   `mailbox-passwords.json`（§3.2），不再需要 Dovecot 的任何组件。

> ⚠️ **两套 UID 映射不能同时写**：同一封邮件被分配两套 UID 会让客户端重复拉信。

### 3.9 Webmail 服务（`mailstack-webmail`，v1.0.0 新增）

Webmail 是**独立进程**：与管理台 `mailstack-web` 的进程、端口、会话体系全部隔离，
默认只绑 `127.0.0.1:8444`（TLS 终止同样交给反向代理 / SSH 隧道）。

```ini
# /etc/systemd/system/mailstack-webmail.service
[Unit]
Description=MailStack Webmail (independent web client for mailbox users)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
# 只绑回环；前端产物与管理台同一份 webui/dist（入口 mail.html）。
ExecStart=/usr/local/bin/mailstack-webmail --bind 127.0.0.1:8444 --dist /usr/share/mailstack/admin --log info
Restart=on-failure
RestartSec=5s
TimeoutStopSec=20s
LimitNOFILE=16384

# 会写 Maildir（/home）与队列（/var/lib/mailstack）；其余只读。
ProtectSystem=strict
ReadWritePaths=/home /var/lib/mailstack
ProtectHome=no
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes

[Install]
WantedBy=multi-user.target
```

要点：

* Webmail 直接读写 Maildir 并经出站队列落盘投递，**不依赖 `mailstackd` 是否已启动**；
  与管理台是两个进程、两套会话（同一份前端产物、不同进程与端口），可独立重启。
* **认证**：登录名是**完整邮箱地址**；口令来自 `mailbox-passwords.json`（与 IMAP/POP3/提交端口同一份），
  账号解析走 `/var/lib/mailstack/managed-mailboxes.json` + `/etc/passwd` → `~/Maildir`；
  家目录或 Maildir 不存在 → 登录失败（**不自动创建**）。
* **会话**：服务端内存表 + Cookie（HTTPS 模式 `__Host-` 前缀 + `Secure`，恒为 `HttpOnly`/`SameSite=Strict`）；
  滑动 8 小时 / 绝对 7 天；会话纪元文件 `/var/lib/mailstack/webmail-session-epoch.json`
  在改密/锁定时 bump → 旧会话立即失效。
* **API**：全部在 `/mail/api/*`，未匹配路径恒为 JSON 404；页面入口是 `dist/mail.html`
  （管理台是 `index.html`，同一次 `npm run build` 产出）。
* **发信**：只入出站队列（DKIM 由队列统一签名）并保存 `Sent` 副本；
  队列成功而 `Sent` 失败时返回 202 + warning，不回滚已入队邮件。
* **安全**：服务端 HTML allowlist 消毒 + 前端 sandbox iframe + 远程图片默认阻断 + CSRF + 路径穿越拒绝。
* 功能清单、API 摘要、故障排查与已知限制见 [`docs/WEBMAIL.md`](WEBMAIL.md)。

---

### 3.10 访问模式与 `mailstack-manage`（v1.0.0 交付）

`deploy/install.sh` 一条命令即可完成安装并应用访问模式；安装后由
`/usr/local/bin/mailstack-manage` 维护（域/账号/TLS/访问方式），状态唯一真相源为
`/etc/mailstack/install-args.conf` 与 `/etc/mailstack/access/`。

| 访问模式 | 产物 | 说明 |
|---|---|---|
| `ssh` | `access/ssh/{README.txt,tunnel.sh}` | 默认；8443/8444 只绑回环 |
| `caddy` | `access/caddy/Caddyfile`（并尝试写入 `/etc/caddy/`） | 自动 ACME HTTPS |
| `nginx` | `access/nginx/mailstack-panel.conf`、`README.txt` | TLS 由 certbot/acme.sh 补 |
| `ip-acme` | `access/ip-acme/DNS-REQUIREMENTS.txt`、nginx 配置 | 证书走 `setup.cert.issue` |
| `panel-domain` | 同 caddy/nginx + 域名冲突校验 | 面板域必须 != `mail/imap/smtp` 域 |
| `cloudflared` | `access/cloudflared/{config.yml,mailstack-cloudflared.service,README.txt}` | Tunnel 到回环，本机不开端口 |

```bash
sudo mailstack-manage status
sudo mailstack-manage access set nginx --panel-host panel.example.com
sudo mailstack-manage access set cloudflared
sudo mailstack-manage domain set example.com --mail-host mail.example.com
sudo mailstack-manage account add alice@example.com --password-stdin
sudo mailstack-manage tls issue mail.example.com --email ops@example.com
```

动作统一经 `mailstackctl`（RO 直连 / RW sudo 包装器，`--privileged-stdin`）；
`MAILSTACK_PREFIX` 仅用于 staging，此时跳过 systemctl 操作。

## 4. 回滚

`mailstackd`、`mailstack-web`、`mailstack-imap`、`mailstack-webmail` 都是独立进程：
v1.0.0 安装可用 `deploy/uninstall.sh` 卸载（默认保留 `/etc/mailstack` 与 `/var/lib/mailstack`）；
回滚到旧栈则停止并移除新 unit、恢复旧的服务与包装器即可（旧 Postfix 若未被改动仍然可用）。
审计链未被改写（这些二进制均不含 `audit()` 调用点）。

三点必须注意：

* **停止 `mailstackd` 会同时摘掉特权 RPC 的两个 socket**，管理台与 Webmail 随即失去后端。回滚时
  必须**先把旧的 RPC 交付方式恢复起来**，否则会从一个「新进程不在了」变成
  「旧进程也没有」。残留的 socket 文件不影响下次启动（绑定前会先移除陈旧文件）。
* **队列里可能留有未投递的邮件**（`/var/lib/mailstack/queue`）。那些是已经对发送方回过
  250 的邮件 —— 直接删掉就是丢信。回滚前先确认队列为空，或把该目录保留下来。
* 停止是**优雅**的：SIGTERM 之后监听不再接受新连接、在途会话有 10s 宽限期、队列调度
  停止排新轮（单轮投递另有 600s 上限）。若 10s 内没退干净，进程会强制中止在途任务。

## 5. 当前进度（对照规格书 §6）

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0 契约冻结 | ✅ 基础 | 路由表 `crates/web/src/contract.rs`（当前 **62 条**，Phase 0 基线 62 条）、动作三集 `crates/core/src/actions.rs`（**52 条**：RO 20 + RW 32）、口令/审计/原语移植 |
| Phase 1 只读面 | ✅ 完成 | 只读聚合面、特权 RPC 协议与门控、管理面基础全部落地 |
| Phase 2 SMTP 核心 | 🟡 机制层完成，进程已可运行 | 自研 SMTP / 队列 / DKIM / TLS（1.2 起）/ 连接限速 / IP 封禁 / **提交端口 SASL（口令库 `mailbox-passwords.json`）** / **直投（MX 解析，逐域按优先级）** / 入站认证（SPF+DKIM+DMARC）/ **ARC 校验与封印** 全部落地并有测试；`mailstackd` 已能收信、投递（本地 LMTP 或中继/直投）、承载 RO/RW 特权 RPC 与优雅停机。**尚未**：真实公网 MX 联调、直投的机会式 TLS（见 TEST_REPORT §5） |
| Phase 3 前端切换 | ✅ 已接入 | 管理台为独立前端产物（Vite + React 19 单页应用，hash 路由），由 `bin/mailstack-web` 托管：`--dist <DIR>`、SPA 回退、`/api/*` 兜底保持 JSON 404、遥测后台采样（2 秒）。**Webmail 为 v1.0.0 新增**：独立进程 `bin/mailstack-webmail`（`127.0.0.1:8444`，见 §3.9），前端入口 `mail.html` 与管理台同一次构建产出 |
| Phase 4 写面切换 | ✅ 动作面完成 | 2FA 全生命周期、写面动作（`admin.set`/`settings.set`/域名/别名/`dkim.rotate`）、只读聚合面、控制台写面、备份、初始化向导（含 `setup.wizard.complete`）、ACME、8 个只读列表动作（见 TEST_REPORT §3.10）。白名单动作**已全部实现（52/52，RO 20/20 + RW 32/32）**；契约路由**已全部注册（62/62）**，没有任何路由落到 `/api` 兜底，由 `every_implemented_action_route_is_wired_and_behind_auth` 守门。**未完成**：真实环境验证与审计链的真实升级演练 |
| Phase 5 组件下线 | 🟡 协议面已接管；组件下线为迁移期可选 | Dovecot 的 imap/pop3、提交端口 SASL 与本地投递已由自研栈接管（`mailstack-imap` + `mailstackd` 自有 LMTP）。停用 Postfix/OpenDKIM/fail2ban/Dovecot 属迁移期**可选收尾步骤**，不是 v1.0.0 自动完成项；迁移期允许与 Postfix 双跑，纯 MailStack 主机（未装 Postfix）同样可完整工作 |

## 6. 发行包的 libc 兼容性（2026-10-30 实测）

> 这一节是**打包成可发行文件之后实测出来的**，不是推断。
> 做法：在 Ubuntu 26.04（Rust 1.98.1，与 CI 钉的版本一致）上跑
> `deploy/build.sh --musl`，把 `dist/` 复制到 7 个发行版里逐个执行
> `--version` / `--help`，并做平台侧 `sha256sum -c`。

### 6.1 兼容性矩阵

| 平台 | glibc | glibc 动态产物 | musl 全静态产物 |
|---|---:|---|---|
| Ubuntu 26.04.1 | 2.43 | ✅ | ✅ |
| Debian 13 (trixie) | 2.41 | ✅ | ✅ |
| Arch Linux | 2.44 | ✅ | ✅ |
| AlmaLinux 10.1 | 2.39 | ✅ | ✅ |
| openSUSE Tumbleweed | 2.43 | ✅ | ✅ |
| **Oracle Linux 9.5** | **2.34** | ❌ `GLIBC_2.39 not found` | ✅ |
| **Alpine 3.24**（musl） | 无 glibc | ❌ not found | ✅ `statically linked` |

### 6.2 结论

1. **glibc 动态产物的下限是 2.39**（等于 CI 的 `ubuntu-24.04` 宿主）。
   这个下限不是「构建机的 glibc 版本」，而是产物**实际引用到的最高符号版本**；
   在 26.04（2.43）上构建，实测 `objdump -T` 的最大符号仍是 `GLIBC_2.39`。
2. **安装矩阵里的 Rocky Linux 9 / Oracle Linux 9（glibc 2.34）与 Alpine（musl）
   不能用默认产物**。这是此前**没有声明过的**兼容性缺口 ——
   `crates/core/src/exec.rs` 的注释写着「安装矩阵含 Rocky Linux 9 与 Alpine」，
   但发行包在这些平台上一启动就失败。
3. 解法是 `--musl`：全静态、不依赖 glibc，实测在 glibc 2.34 与 musl-only 的
   Alpine 上均可运行。**GitHub Release 应同时上传两套产物**，并在下载页注明
   「glibc < 2.39 或 Alpine 请用 `*-musl`」。

### 6.3 复现

```bash
# 构建宿主需 Rust 1.98.1 + musl-gcc + x86_64-unknown-linux-musl target
deploy/build.sh --musl
ls dist/          # 5 个二进制 + SHA256SUMS + SBOM（--musl 时另加 5 个 *-musl 全静态产物）

# 在目标平台验证（示例）
sha256sum -c SHA256SUMS
./mailstackd-musl --version     # 任意 Linux 都应成功
```

---

## 7. 已知环境事实（开发机）

- Windows 开发机 rustup default 为 msvc 但**无 link.exe**；可用的链接器只随
  `stable-x86_64-pc-windows-gnu` 提供。**任何 tokio 异步测试在该 mingw 工具链上
  都会以 STATUS_ACCESS_VIOLATION 崩溃**（已用最小复现证实是工具链而非代码问题）。
  因此：异步/Unix-socket 相关测试一律在 WSL 执行，Windows 侧仅用于
  `cargo check --target x86_64-unknown-linux-gnu` 类型校验。
- WSL 出网必须走 Clash 混合端口 **7890**（7897 会接受连接但不可代理）。
- 详见 `TOOLCHAIN.md` 与 `deploy/wsl-*.sh`。