# 安装、升级与卸载（v1.0.0）

> 本文与 `deploy/install.sh` / `deploy/uninstall.sh` 的实际行为保持一致；脚本更新后以
> `deploy/install.sh --help` 的输出为准。首次部署后的配置步骤见 `README.md`「部署后首次配置」，
> 部署架构与目录权限契约见 `docs/DEPLOYMENT.md`。

## 1. 系统要求

| 项 | 要求 |
|---|---|
| 平台 | Linux x86_64（Debian/Ubuntu、RHEL 系、Arch、openSUSE 等） |
| libc | glibc **≥ 2.39**（默认动态产物）；glibc < 2.39（Rocky/Oracle Linux 9 等）或 Alpine 用 `deploy/build.sh --musl` 自建全静态产物 |
| 权限 | root（安装器会做 root 检查；服务端口 25/465/587/143/… 需要 root 或 `CAP_NET_BIND_SERVICE`）；真实安装还需要 `sudo` 与 `visudo`（用于 `/etc/sudoers.d` 语法校验） |
| 依赖命令 | `install`、`tar`、`sha256sum`、`mktemp`、`realpath`、`groupadd`、`useradd`；release 模式另需 `curl` 或 `wget` |
| init | systemd（容器/无 systemd 环境用 `--no-systemd`，安装器会打印手工启动命令） |
| 内存/磁盘 | 建议 ≥ 1 GiB 内存；邮件数据与队列位于 `/var/lib/mailstack`，按邮箱量预留 |
| 运行依赖 | 无 Node/npm/Python；ACME 需要本机 `acme.sh`；Postfix **不是**必需依赖（迁移期双跑时才需要） |
| 架构 | 单机单实例；同一 Maildir 只允许一个实现写入（迁移 Dovecot 时必须先停 Dovecot） |
| 发布产物 | `mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz`（含 5 个二进制、`deploy/install.sh`、`deploy/uninstall.sh`、systemd unit、`webui-dist/`、README/LICENSE/CHANGELOG）+ 同目录 `SHA256SUMS` |

## 2. 安装前准备

1. **DNS**：准备主邮件域名（如 `example.com`）与邮件主机名（如 `mail.example.com`），
   A/AAAA 指向本机，MX 指向邮件主机名；反向解析（PTR）建议与 HELO 名一致。
2. **端口**：
   - 入站：25（MX）、465/587（提交）、143/993（IMAP）、110/995（POP3）、4190（ManageSieve）；
   - 出站：25（直投）或你的中继端口；
   - ACME：80/443（HTTP-01 签发）。
3. **反向代理 TLS**：管理台（8443）与 Webmail（8444）**只绑回环**，
   公网访问必须由 nginx/Caddy 等终结 TLS（示例见 `docs/WEBMAIL.md` §6 与 `docs/DEPLOYMENT.md`）。
4. **备份**：若机器上有旧栈或既有 Postfix/Dovecot，先整体备份配置与 Maildir。

## 3. 方式一：curl 一键安装（推荐）

### 3.1 先落盘再执行（便于审阅）

```bash
VERSION=1.0.0
curl -fsSL "https://raw.githubusercontent.com/SectorPace/MailStack/v${VERSION}/deploy/install.sh" \
  -o /tmp/mailstack-install.sh
less /tmp/mailstack-install.sh

sudo bash /tmp/mailstack-install.sh \
  --domain mail.example.com \
  --admin-user admin \
  --admin-password-stdin
```

`--admin-password-stdin` 从标准输入读取一行作为管理员口令（不落 argv、不进 shell 历史）。
交互式安装可省略该参数，由脚本在终端提示输入（两次确认）。无人值守时：

```bash
# 口令经 stdin 传入（先落盘再执行时 stdin 可用；见 §3.2 的管道模式限制）
printf '%s\n' "$MAILSTACK_ADMIN_PASSWORD" | sudo bash /tmp/mailstack-install.sh \
  --non-interactive --domain mail.example.com --admin-password-stdin
```

口令策略：12–256 位、同时含字母与数字（与后端 `validate_mailbox_password` 的账号口令策略一致）。

### 3.2 直接一行

```bash
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh \
  | sudo bash -s -- --domain mail.example.com
```

> **管道模式不能同时传口令**：`curl | bash -s` 时 bash 的脚本输入就是 stdin，
> `--admin-password-stdin` 的 `read` 会消费脚本文本而不是口令。因此管道安装不传
> `--admin-password-stdin`；管理员账号请用管理台 setup 向导创建，或按安装器打印的
> `admin.set` 命令手工创建。需要无人值守口令时请用 §3.1「先落盘再执行」。
>
> 以普通用户执行 `| sudo bash -s --` 时，`--` 之后的参数才会传给安装器；脚本会做 root 检查。

### 3.3 常用参数

| 参数 | 说明 |
|---|---|
| `--domain DOMAIN` | 主邮件域名（非交互模式必填） |
| `--mail-host HOST` | 邮件主机名/MX（缺省由域名推导） |
| `--admin-user NAME` | 管理员用户名（默认 `admin`） |
| `--admin-password-stdin` | 从 stdin 读取管理员口令（12–256 位，含字母+数字，与后端口令策略一致） |
| `--admin-port PORT` | 管理台内部端口（默认 `8443`） |
| `--webmail-port PORT` | Webmail 内部端口（默认 `8444`） |
| `--imap yes\|no` | 是否安装/启用 IMAP/POP3 服务（默认 `yes`；也接受 `true/false/enable/disable`） |
| `--access-mode ssh\|caddy\|nginx\|ip-acme\|panel-domain\|cloudflared` | 访问模式（默认 `ssh`；旧值 `local`/`caddy`/`direct` 仍接受），写入 `install-args.conf` 并生成反向代理/Tunnel/隧道文件；影响 Cookie `Secure` 与 public 模式限制。详见 §3.5 |
| `--from-source` | 从源码构建（需要 Rust 1.98.1 + C 编译器；Node/npm 可选，用于构建前端产物） |
| `--archive FILE\|URL` | 使用指定发布包（离线安装/指定版本） |
| `--binary-dir DIR` | 使用已构建的二进制目录（测试/离线；不校验二进制内容） |
| `--prefix DIR` | 把整棵安装树安装到指定根目录（staging/测试，默认 `/`）；非 `/` 时自动不操作系统 systemd |
| `--non-interactive` | 非交互模式（所有必填参数必须显式给出） |
| `--no-systemd` | 不安装/不启用 systemd unit（容器或无 systemd 主机） |
| `--uninstall` | 定位并执行同目录 `deploy/uninstall.sh`（curl 管道模式则下载 main 分支的 uninstall.sh） |
| `--purge` | 仅随 `--uninstall` 使用：卸载时同时删除 `/etc/mailstack` 与 `/var/lib/mailstack` |
| `-h` / `--help` | 打印用法 |
| `--version` | 打印安装器版本 |

```bash
# 离线安装（先下载发布包与校验和；包内自带 install.sh）
curl -fsSLO https://github.com/SectorPace/MailStack/releases/download/v1.0.0/mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
curl -fsSLO https://github.com/SectorPace/MailStack/releases/download/v1.0.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# 解包后直接运行包内安装器，或用 --archive 指定发布包
tar -xzf mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
sudo bash ./mailstack-v1.0.0-x86_64-unknown-linux-gnu/deploy/install.sh \
  --archive ./mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz --domain mail.example.com

# 容器 / 无 systemd：只铺文件，不装 unit
sudo bash deploy/install.sh --non-interactive --no-systemd --domain mail.example.com --admin-password-stdin

# 测试：装到临时根目录，不碰宿主
sudo bash deploy/install.sh --binary-dir ./dist --prefix /tmp/mailstack-test --non-interactive --no-systemd
```

> musl 全静态产物：本期一键安装**不**下载 musl 变体；需要时用 `deploy/build.sh --musl` 构建，
> 再以 `--binary-dir dist` 方式安装。
>
> 内网/镜像：默认从 `RELEASE_BASE` 下载，可用环境变量
> `MAILSTACK_RELEASE_BASE_URL` 指向镜像目录（该目录需同时提供 tarball 与 `SHA256SUMS`）。

### 3.4 安装器做了什么

1. **root 检查** + 依赖与平台检查（不满足即失败，不做部分安装）；
2. **下载/定位发布包**：默认 GitHub Release 的 `mailstack-v1.0.0-x86_64-unknown-linux-gnu.tar.gz`
   并校验同目录 `SHA256SUMS`（`sha256sum -c`，针对 tarball 那一行）；`--from-source` 走源码构建，
   `--archive` 走指定包，`--binary-dir` 走现成二进制；
3. **系统用户/组**：`mailstack-admin`（system 用户+组，nologin home）、`mailstack-webmail`（组），
   按需确保 `opendkim` 组存在；
4. **目录与权限**：
   - `/etc/mailstack` `0750 root:mailstack-admin`
   - `/var/lib/mailstack` `0750 root:mailstack-webmail`
   - `/var/backups/mailstack` `0700 root:root`
   - `/usr/share/mailstack/admin` `0755 root:root`（前端产物）
   - `/run/mailstack`、`/usr/local/libexec`
5. **二进制**：`/usr/local/bin/{mailstackd,mailstackctl,mailstack-web,mailstack-imap,mailstack-webmail}`；
6. **特权包装器**：`/usr/local/libexec/mailstack-privileged`（`0750 root:root`），内容为
   `exec /usr/local/bin/mailstackctl --privileged-stdin`（**无 argv，stdin JSON 协议**）；
7. **sudoers**：`/etc/sudoers.d/mailstack-admin`（`0440 root:root`）仅授权执行该包装器，
   写后用 `visudo -cf` 校验；
8. **前端产物**：管理台 + Webmail 的 `webui-dist/` → `/usr/share/mailstack/admin`；
9. **systemd unit**：`mailstackd`、`mailstack-web`、`mailstack-imap`、`mailstack-webmail`
   （`--no-systemd` 时跳过并打印手工启动命令；`--prefix` 非 `/` 时自动不操作宿主 systemd）；
10. **管理员凭据**：经特权通道（`mailstackctl --privileged-stdin`）写入；已存在
    `/etc/mailstack/admin.json` 时跳过（幂等）。**身份（域名/DKIM/DNS）不写入 `setup.json`**，
    留给管理台 setup 向导完成；`--access-mode` 写入 `/etc/mailstack/install-args.conf` 的
    `ACCESS_MODE`（重跑不显式给则保留原值）；
11. **幂等**：重复执行不会重复建用户/目录，已存在的配置不被覆盖（保留运维改动）；
12. 结束时打印管理台 `http://127.0.0.1:8443/?login=1` 与 Webmail `http://127.0.0.1:8444`。

> 本节按安装器设计定稿整理；最终以 `deploy/install.sh --help` 与脚本源码为准。

### 3.5 访问模式（6 种，安装时或装完后切换）

| 模式 | 入口 | 安装器/管理脚本动作 |
|---|---|---|
| `ssh`（默认） | SSH 隧道 `ssh -L 8443:127.0.0.1:8443 -L 8444:127.0.0.1:8444 user@host` | 不装反代；生成 `access/ssh/README.txt` 与 `tunnel.sh` |
| `caddy` | `https://panel.example.com` | 生成 Caddyfile（ACME 自动证书），检测 caddy 安装并提示 reload |
| `nginx` | `https://panel.example.com` | 生成 nginx site 配置与 TLS 下一步说明（certbot/acme.sh） |
| `ip-acme` | 公网 IP + 域名 | nginx 终止 TLS，证书走 `mailstackctl setup.cert.issue`；打印精确 DNS 要求 |
| `panel-domain` | 独立面板域名 | 强制校正面板域名与 `mail/imap/smtp/pop.example.com` 不同 |
| `cloudflared` | Cloudflare Tunnel | 生成 `config.yml` + systemd unit，Tunnel 连回环 8443/8444，本机不开放端口 |

```bash
# 安装时
--access-mode caddy --panel-host panel.example.com --acme-email ops@example.com
# 安装后切换（幂等；会写 install-args.conf 与 /etc/mailstack/access/）
sudo mailstack-manage access set panel-domain --panel-host panel.example.com --acme-email ops@example.com
sudo mailstack-manage access show
```

约束：8443/8444 永远只绑 `127.0.0.1`；公网入口必须由 Caddy/nginx/Tunnel 终结 TLS。
`panel-domain` 模式会拒绝与邮件主机同名的面板域名（邮件域 `mail.example.com`、
面板域 `panel.example.com`）。

### 3.6 服务器管理脚本（`mailstack-manage`）

安装器会安装 `/usr/local/bin/mailstack-manage`（3x-ui 风格的 CLI + 交互菜单）：

```bash
sudo mailstack-manage                     # 交互菜单
sudo mailstack-manage status               # 域名/管理员/访问模式/服务/TLS/入口
sudo mailstack-manage domain set example.com --mail-host mail.example.com
sudo mailstack-manage domain list|add|delete
sudo mailstack-manage account add alice@example.com --password-stdin
sudo mailstack-manage account list|passwd|delete
sudo mailstack-manage tls issue mail.example.com --email ops@example.com
sudo mailstack-manage access set caddy --panel-host panel.example.com --acme-email ops@example.com
sudo mailstack-manage restart|logs
```

所有动作都经既有 `mailstackctl` 特权动作（RO 直连 / RW 经 sudo 包装器；
`--privileged-stdin` 协议），脚本本身不做第二套权限逻辑。
`MAILSTACK_PREFIX=/tmp/stage` 可用于 staging 测试（不操作宿主 systemd）。

## 4. 方式二：源码构建

### 4.1 构建依赖

- Linux（WSL2 亦可），Rust **1.98.1**（`deploy/build.sh` 与 CI 双重固定，版本不符会拒绝构建）、
  C 编译器（`cc`）；
- Node.js/npm（仅构建前端产物时需要）；
- 可选：`musl-gcc` + `x86_64-unknown-linux-musl` target（`--musl`）；
- 可选：`cargo-sbom`（否则退化为 `dependency-inventory.txt`）。

### 4.2 构建与安装

```bash
git clone https://github.com/SectorPace/MailStack.git
cd MailStack

# 后端：release 构建 → dist/（5 个二进制 + SHA256SUMS + SBOM）
deploy/build.sh
deploy/build.sh --musl        # 可选：额外产出 *-musl 全静态二进制
deploy/build.sh --offline     # 离线：使用已 vendor 的依赖
deploy/build.sh --vendor      # 先 cargo vendor 再离线构建

# 前端：管理台 index.html + Webmail mail.html（同一次构建）
cd webui && npm ci && npm run build && cd ..

# 安装已构建产物
sudo deploy/install.sh --binary-dir dist
```

### 4.3 质量门禁（与 CI 同一命令链）

```bash
deploy/wsl-quality-gate.sh      # rustfmt --check + clippy -D warnings + cargo test
deploy/verify-invariant-gate.sh # 不变量测试存在性
deploy/verify-deliverables.sh   # 交付物清单/版本一致性
cd webui && npm run build && npm test && cd ..
```

## 5. 安装后验证

```bash
# 1) 服务状态（--no-systemd 时跳过）
systemctl status mailstackd mailstack-web mailstack-imap mailstack-webmail

# 2) 监听与端口
ss -lntp | grep -E ':(25|465|587|143|993|110|995|4190|8443|8444|9100)\b'

# 3) 健康检查（管理台只绑回环）
curl -fsS http://127.0.0.1:8443/api/health

# 4) 特权通道与只读面
sudo mailstackctl snapshot --compact
sudo mailstackctl domains.list

# 5) 审计链与目录权限
ls -l /var/log/mailstack-rpc-audit.log* /run/mailstack/
```

预期：

- `mailstackd` 在 **fail-closed** 前置条件不满足时（缺 `setup.json`、证书、域名表为空等）
  **会拒绝启动**并打印原因 —— 首次安装后应先完成 setup 向导，再让它接管 25/465/587；
- 管理台与 Webmail 的页面请求在未给 `--dist` 时返回 **503**（部署前端后正常）；
- `/api` 下不存在的路径恒为 **JSON 404**（不会回 HTML）。

首次配置（向导、DNS、证书、2FA、邮箱用户、Webmail 登录）见 `README.md`。

## 6. 升级

### 6.1 1.0.x 内升级（推荐）

```bash
# 1) 备份（public 模式必须带口令）
sudo mailstackctl backup.create '{"passphrase":"<强口令>"}'
sudo mailstackctl backup.list

# 2) 用新版本重跑安装器（幂等；会覆盖二进制/unit，保留 /etc/mailstack 与数据）
curl -fsSL https://raw.githubusercontent.com/SectorPace/MailStack/main/deploy/install.sh -o /tmp/mailstack-install.sh
sudo bash /tmp/mailstack-install.sh --domain mail.example.com

# 3) 验证
systemctl status mailstackd mailstack-web mailstack-imap mailstack-webmail
sudo mailstackctl snapshot --compact
```

> 升级前先备份、升级后按 §5 验证；回滚方法见 `docs/DEPLOYMENT.md` §4。

### 6.2 从 legacy（`v0.8.0-beta.10`）迁移

**不能原地升级**（运行时栈完全不同）。迁移步骤见 `README.md`「从 legacy 迁移」：
备份 → 新装 v1.0.0 → `mailstack-imap --migrate-maildir` 迁移 UID/关键字（先停 Dovecot）→
切换特权包装器/unit → 验证 → 停用旧组件。迁移期允许与 Postfix 双跑。

## 7. 卸载

两种等价方式：

```bash
# 独立卸载脚本
sudo bash deploy/uninstall.sh                 # 停服务、删 unit/包装器/sudoers/二进制；保留配置与数据
sudo bash deploy/uninstall.sh --purge         # 一并删除 /etc/mailstack 与 /var/lib/mailstack
sudo bash deploy/uninstall.sh --prefix /tmp/mailstack-test --non-interactive   # staging/容器

# 或经安装器转发
sudo bash deploy/install.sh --uninstall
sudo bash deploy/install.sh --uninstall --purge
```

`deploy/uninstall.sh` 参数：`--prefix DIR`、`--purge`、`--non-interactive`。
默认保留 `/etc/mailstack` 与 `/var/lib/mailstack`（`--purge` 才删）。
安装时若发布包内带卸载脚本，会被安装到 `/usr/local/libexec/mailstack-uninstall`，
也可直接 `sudo bash /usr/local/libexec/mailstack-uninstall [--purge]`。

卸载后仍保留（默认）：

- `/etc/mailstack`（配置、管理员凭据、DKIM 密钥、证书位置等）与 `/var/lib/mailstack`（队列、
  注册表、Maildir 索引等）；
- `/var/backups/mailstack` 中的备份归档；
- 各账号家目录下的 `Maildir`（**邮件本体不在卸载范围内**）。

手工清理前请确认：队列非空时先投递或导出（队列里是已对发送方回过 250 的邮件，直接删 = 丢信）。

## 8. 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `GLIBC_2.39 not found` / `not found` | 系统 glibc 过旧（如 2.34）或 musl 系统：用 `deploy/build.sh --musl` 自行构建全静态产物并以 `--binary-dir dist` 安装，或换 glibc ≥ 2.39 的平台 |
| 安装器拒绝启动服务 | fail-closed：缺 `setup.json`/证书/域名表为空/`relay.json` 损坏；先完成 setup 向导或修配置 |
| 全部变更动作失败（界面笼统报「操作失败」） | 特权包装器指向旧 Python 助手或转发 `"$@"`；确认 `/usr/local/libexec/mailstack-privileged` 内容为 `exec /usr/local/bin/mailstackctl --privileged-stdin` |
| 管理台 503 `frontend is not available` | 未安装前端产物或 `--dist` 目录不对；重新构建并把 `dist/` 铺到 `/usr/share/mailstack/admin` |
| 25 端口被占用 | 机器上已有 Postfix/其他 MTA；停掉或迁移期用旁路端口（`mailstackd --port 2525`） |
| `postmap: not found` 警告 | 本机没装 Postfix：域名/别名表写入仍成功（按「无需同步」处理），不影响纯 MailStack 主机 |
| 出站投递全部失败并提示「25 被封」 | 云厂商封禁出站 25：配置中继（`setup.relay.apply`），直投不会回退中继 |
| Webmail 登录 401 | 账号未在受管邮箱表注册，或家目录/`Maildir` 不存在（登录 fail-closed，不自动创建） |
| IMAP/POP3 的 TLS 起不来 | ACME 证书落在 `/etc/mailstack/tls/<host>/{fullchain,privkey}.pem`，而 `--cert-domain` 只认 Let's Encrypt 标准布局 `/etc/letsencrypt/live/<host>/`；用显式 `--cert`/`--key` 指向实际文件（安装器 unit 即如此） |
| `systemctl` 不可用 | 容器/无 systemd 主机：安装时加 `--no-systemd`，按安装器打印的手工命令启动 |

更多部署细节（目录权限、RPC socket、Dovecot 迁移、libc 兼容矩阵）见 `docs/DEPLOYMENT.md`。
