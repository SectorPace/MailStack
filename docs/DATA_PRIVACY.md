# MailStack 数据隐私：数据停留与日志红线

> 适用版本：v0.5.2-rc.5。本文回答两个问题：**数据在哪里、谁能读**（数据停留），
> 以及**什么绝不允许进入日志与进程参数**（日志红线）。所有权限与路径均从
> 代码/脚本核实，可直接对照出处。威胁视角见 [`THREAT_MODEL.md`](THREAT_MODEL.md)。

## 1. 数据停留（数据在哪里，权限如何）

| 数据 | 位置 | 权限/属主 | 说明与出处 |
|---|---|---|---|
| 邮件内容（Maildir） | `/var/vmail`、`/home/<托管用户>/Maildir` | 属各邮箱账号所有 | 管理控制台进程无邮箱读权限；webmail 仅读当前登录邮箱（`SECURITY.md` 资产 2） |
| 管理员凭据 | `/etc/mailstack/admin.json` | `0640 root:mailstack-admin` | 仅存 PBKDF2-SHA256（310000 次）哈希；2FA 段含 TOTP secret 与恢复码的 SHA256 哈希（`backend/mailstackctl/core.py` `password_record`、`backend/mailstackctl/totp.py`） |
| `/etc/mailstack` 目录 | `/etc/mailstack` | `0750` | `ms doctor` 对权限做断言（`backend/mailstackctl/telemetry.py` `permission_targets`） |
| SMTP relay 口令 | `/etc/postfix/sasl_passwd(.db)` | `0600` | 备份默认排除；`ms doctor` 断言 `0600` |
| AI 提供方密钥 | `/etc/mailstack/ai-provider.json`（并镜像 `ai.json`） | `0600` | `backend/mailstackctl/ai.py`（`atomic(..., 0o600)`）；密钥只存服务器端，不返回浏览器；备份默认排除 |
| DKIM 私钥 | `/etc/opendkim/keys/` | `0640 root:opendkim` | `backend/mailstackctl/core.py` `set_dkim_key_permissions`，签发与轮转路径均调用 |
| 控制台设置 | `/etc/mailstack/settings.json` | `0600` | `backend/mailstackctl/telemetry.py` |
| 安装参数 | `/etc/mailstack/install-args.conf` | `0640 root:mailstack-admin` | 仅含访问模式/域名/端口/管理员**用户名**等部署参数，**不含密码**（`deploy/install.sh`） |
| 备份归档与元数据 | `/var/backups/mailstack/` | `0600` | 默认排除凭据类文件；可选 GPG AES256 加密（`backend/mailstackctl/backup.py`） |
| RPC 审计日志 | `/var/log/mailstack-rpc-audit.log` | `0600` | 每次写入后强制 `chmod 0600`（`backend/mailstackctl/core.py` `audit`） |
| 管理员会话 | 仅管理进程内存 | 不落盘 | 会话表含 IP 与截断至 512 字符的 User-Agent；进程重启即失效（`backend/server.production.ts`） |
| Webmail 会话失效标记 | `/var/lib/mailstack/webmail-session-epoch.json` | `0640 root:mailstack-webmail` | 仅含 unix 时间戳，用于改密/锁账号时踢下线（`webmail/server.mjs`） |
| 邮箱注册表 | `/var/lib/mailstack/managed-mailboxes.json` | `0640 root:mailstack-webmail` | 修复后迁至该目录，webmail 才可读 |
| 遥测指标 | 管理进程内存 | 不落盘、不外发 | `/api/metrics/*` 实时生成；系统日志只读取本机既有日志文件展示（`backend/mailstackctl/telemetry.py`） |
| 特权 helper socket | `/run/mailstack/helper.sock` | `0660 root:mailstack-admin`（目录 `0750`） | 仅管理控制台服务所在组可连（`backend/mailstackctl/daemon.py`） |
| Dovecot 认证 socket | `/var/run/dovecot/auth-client` | `0660` | webmail 登录唯一认证通道（`webmail/dovecot-auth.mjs`） |
| 发布签名信任锚 | `/etc/mailstack/release-allowed-signers` | root 可读 | 公钥文件，不含秘密（`deploy/install.sh`） |

**不离开主机的承诺**：本项目无遥测上报、无外部回连；唯一主动出站的网络请求是
管理员**显式配置**的 AI 接口与 ACME/证书签发，且 AI 出站经 SSRF 筛查
（`backend/mailstackctl/ai.py` `is_ip_restricted`，含 CGNAT 与 IPv4-mapped 解包）。

## 2. 日志红线（什么绝不允许进日志与 argv）

### 2.1 审计日志只记白名单字段

特权操作审计（`core.py` `audit()`）是事实来源：

- 每条记录仅含 6 个字段：`time`、`uid`、`action`、`target`、`ok`、`error`。
- `target` **只从固定的 7 个字段中按序提取第一个存在的值**：
  `domain` → `username` → `address` → `ip` → `service` → `queueId` → `filename`，
  并截断至 120 字符；`error` 截断至 500 字符。
- 口令、恢复码、TOTP secret、API Key 等字段名不在提取列表中，**没有进入审计日志的途径**；
  审计文件本身 `0600`，写入失败只向 stderr 报告，不降级为宽松落盘。

### 2.2 秘密不进进程参数（argv）与日志

| 秘密 | 保护方式 | 出处 |
|---|---|---|
| 邮箱登录口令 | 不再经 `doveadm auth test user pass`（会暴露在 `/proc/*/cmdline`），改走 Dovecot auth-client socket，密码只在 socket 负载内；失败关闭且与错密码在 HTTP 层不可区分 | `webmail/dovecot-auth.mjs`、`webmail/server.mjs` |
| 管理员口令 | 安装可经 `--admin-password-stdin`（stdin）；运行时经 JSON 请求体；不落 argv、不进日志 | `README.md` 非交互安装、`backend/server.production.ts` |
| 备份加密口令 | `gpg --batch --pinentry-mode loopback --passphrase-fd 0`，口令仅经 stdin；加密失败连明文归档一并删除，不产生“明文残留+日志痕迹” | `backend/mailstackctl/backup.py` `_encrypt_archive` / 恢复解密分支 |
| TOTP secret | 仅在绑定（`begin`）时返回一次；`GET /api/admin/2fa` 只回启用状态与剩余恢复码数 | `backend/mailstackctl/totp.py`、`backend/server.production.ts` |
| 恢复码 | 明文仅在启用（`enable`）时返回一次；落盘只存 SHA256 哈希；消费在文件锁内一次性完成 | `backend/mailstackctl/totp.py` |
| 发布签名私钥 | 存放在仓库与发行归档之外（仅维护者/CI Secret 持有）；仓库只含公钥与信任锚；`deploy/privacy-audit.sh` 拦截私钥块入库 | `deploy/mailstack-release.pub`、`deploy/privacy-audit.sh` |
| 登录失败信息 | 401 一律 `INVALID_CREDENTIALS`，不含剩余次数、不区分“用户不存在/密码错” | `backend/server.production.ts` |

### 2.3 仓库侧自检：`deploy/privacy-audit.sh`

- 用法：`bash deploy/privacy-audit.sh [仓库根目录]`（默认脚本上一级目录）。
- 检查三类模式并**失败即非零退出**（CI 门禁）：私有身份值残留、OCI 凭据材料、
  私钥块（`BEGIN ... PRIVATE KEY`）。
- 提交前本地跑一次，可拦截“把真实凭据/私钥提交进仓库”这类事故；
  它同时排除了 `node_modules`、`dist` 等目录，只审计源码树。

## 3. 与备份/恢复相关的隐私要点

- 默认备份**不含**凭据类文件（`admin.json`、`ai.json`、`ai-provider.json`、`sasl_passwd(.db)`）；
  只有显式 `includeSecrets=true` 才纳入——即“含秘密的备份”是显式选择而非默认。
- 含邮件数据需显式 `--include-mails`；异地保管此类归档时按邮件密级对待，建议启用加密备份。
- 恢复路径的成员白名单与完整性校验见 [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md)。

## 4. 关联文档

- [`SECURITY.md`](../SECURITY.md) —— 资产分级与加固保证清单
- [`THREAT_MODEL.md`](THREAT_MODEL.md) —— 信息泄露（STRIDE-I）条目
- [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) —— 备份/恢复操作手册
