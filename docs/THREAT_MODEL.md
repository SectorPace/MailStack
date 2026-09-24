# MailStack 威胁模型（STRIDE 深化）

> 本文是 [`SECURITY.md`](../SECURITY.md) 中 **Threat Model** 段的增量深化：
> 资产分级、信任边界与非目标（non-goals）以 `SECURITY.md` 为准，本文不重复，
> 只按 STRIDE 六类威胁逐项展开 rc5 已落地的缓解措施与残余风险。
> 所有缓解措施均给出代码/脚本出处，可直接核对实现。

适用版本：v0.5.2-rc.5。

## 资产清单（回顾）

按敏感度从高到低（与 `SECURITY.md` 一致）：

1. **主机 root** —— 特权 helper（`mailstack-helper.service` 长驻 daemon 与一次性 sudo 包装器）以 root 运行。
2. **邮件内容** —— Maildir（`/var/vmail`、`/home/<托管用户>/Maildir`）。
3. **静态凭据** —— 管理员凭据、SMTP relay 口令、DKIM 私钥、AI Key、备份归档。
4. **会话** —— 管理控制台与 webmail 的登录会话。

本文额外覆盖以下运行时资产：**管理员控制台**（`mailstack-web`）、**webmail**（`mailstack-webmail`）、
**SMTP/IMAP 认证面**（Postfix SASL / Dovecot）、**特权 helper socket**（`/run/mailstack/helper.sock`）、
**升级通道**（`ms upgrade`）、**备份文件**（`/var/backups/mailstack/`）、**DNS 记录**（MX/SPF/DKIM/DMARC）。

---

## S — Spoofing（仿冒）

| 攻击面 | 威胁 | rc5 缓解 | 出处 |
|---|---|---|---|
| 管理员控制台登录 | 凭据爆破、撞库 | 三层固定窗口限流：全局 500 次/分钟、每 IP 30 次/15 分钟、每账号 10 次/15 分钟；叠加 5 次失败锁定 5 分钟；401 一律返回无差别的 `INVALID_CREDENTIALS`（不含剩余次数） | `backend/server.production.ts`（`consumeRate`、`/api/auth/login`） |
| 管理员控制台登录 | 单因子被盗即接管 | TOTP 2FA（RFC 6238，HMAC-SHA1/6 位/30 秒步长/±1 窗口）；登录时代码在 Node 进程本地验证并带**防重放**（每个步长对每个账号至多接受一次）；恢复码一次性消费（见 T） | `backend/server.production.ts`（`verifyTotp`、`totpLastAcceptedCounter`）、`backend/mailstackctl/totp.py` |
| 管理员控制台会话 | CSRF / 会话劫持 | 会话 Cookie `HttpOnly; SameSite=Strict`（HTTPS 下加 `Secure`）；非 GET/HEAD 请求强制校验 `x-csrf-token`（登录时随会话下发）；滑动 8 小时 + 7 天绝对上限；另有每请求唯一 `X-Request-Id` 便于日志关联 | `backend/server.production.ts`（`auth`、`Set-Cookie`） |
| Webmail 登录 | 口令被同机进程窥探后仿冒 | 登录走 Dovecot `auth-client` unix socket（socket 权限 0660），密码只存在于 socket 负载，**不进入任何进程 argv**；失败关闭（任何 socket 异常与错误密码在 HTTP 层不可区分） | `webmail/dovecot-auth.mjs`、`webmail/server.mjs` |
| SMTP/IMAP 认证 | SASL/IMAP 暴力破解 | 安装器写入 fail2ban jail 配置（`postfix-sasl` + `dovecot`），`ms doctor` 用 TEST-NET-1 探针做 ban/unban 往返，不动作即判 FAIL | `deploy/install-mail-stack.sh`（`configure_fail2ban`）、`backend/mailstackctl/security.py`（`fail2ban_jail_operational`） |
| 特权 helper socket | 非授权进程连接并下发 RPC | B1 双 socket：只读面 `/run/mailstack/helper-ro.sock` `0660 root:mailstack-admin`（Node 直连，仅放行 `ALLOWED_ACTIONS_RO`；变更 action 抵达即拒绝并审计 `ro_channel_violation`）；变更面 `/run/mailstack/helper.sock` `0600 root:root`（Node 连不上，变更动作恒经单条 sudoers 规则的包装器 `--rw-forward` 转发，daemon 侧 SO_PEERCRED 复核 uid==0）；目录 `0750` | `backend/mailstackctl/daemon.py`、`backend/server.production.ts`（`ctl`） |
| 升级通道 | 伪造仓库/中间人投递恶意包 | `ms upgrade` 默认只接受官方 GitHub Release 三件套，`ssh-keygen -Y verify`（identity `mailstack-release`、namespace `file`）验签失败即退出；非官方 `MAILSTACK_REPO_URL` 直接拒绝 | `mailstack.sh`（`update_from_signed_release`、`update_cmd`） |
| 管理员密码变更 | 旧会话残留被复用 | 管理员改密（`admin.set`）与 2FA 启用/禁用都会清空全部会话；webmail 侧有会话 epoch（改密/锁账号即失效全部 webmail 会话） | `backend/server.production.ts`、`webmail/server.mjs` |

**残余风险**：拥有 `mailstack-admin` 组成员身份的账号本身即控制平面（`SECURITY.md` 非目标）；钓鱼/键盘记录不在用户态防御范围。

---

## T — Tampering（篡改）

| 攻击面 | 威胁 | rc5 缓解 | 出处 |
|---|---|---|---|
| 特权 RPC | 通过 API 注入任意命令/配置 | `ALLOWED_ACTIONS` 闭合白名单（约 50 个 action，其余一律拒绝）；能到达 shell 或配置文件的输入全部过允许列表正则（`DOMAIN_RE`/`USER_RE`/`ADDRESS_RE`/`QUEUE_RE`/`ADMIN_RE`）；`domains.delete`/`users.delete`/`backup.delete` 等破坏性动作要求显式 `confirm`，API 层绝不代为制造同意 | `backend/mailstackctl/core.py`、`backend/mailstackctl/dispatcher.py`、`backend/server.production.ts`（`confirmRequested`） |
| Caddy/安装注入面 | 域名/邮箱里夹带换行注入配置 | `DOMAIN_RE`/`EMAIL_RE` 在**参数解析后、任何副作用前**校验，交互补录值写 Caddyfile 前再校一次；有专门的注入门禁脚本 | `deploy/install.sh`、`scripts/ci_domain_injection_test.sh` |
| 备份恢复 | 恶意归档路径穿越/覆盖任意文件 | 恢复只接受本地且文件名匹配 `BACKUP_FILENAME_RE` 的归档；成员路径必须在允许前缀内（`etc/mailstack`、`etc/postfix`、`etc/dovecot`、`etc/opendkim`、`var/vmail`、`var/lib/mailstack`、`root/Maildir`、仅托管用户的 `home/`）；拒绝符号链接/硬链接/设备文件/特殊权限位；先做元数据 SHA256 完整性校验 | `backend/mailstackctl/backup.py`（`_normalized_member`、`validate_tar_safe`、`backup_restore`） |
| 2FA 状态文件 | 并发恢复码“双花” | `admin.totp.*` 全部动作在 `locked(ADMIN_CONFIG)` 文件锁内完成 读-改-写，消费即从哈希列表删除；`atomic()` 写盘 | `backend/mailstackctl/totp.py`（`_consume_recovery`）、`backend/mailstackctl/core.py`（`locked`、`atomic`） |
| 供应链安装器 | “下载即执行”被投毒 | Node.js 官方 tarball 以 SHA256 常量钉扎；Caddy 仓库先验 GPG 指纹；acme.sh 钉版本 3.1.4 tarball + SHA256；任何不匹配 fail-closed | `deploy/install.sh` |
| 升级资产 | Release 资产被篡改 | 先验 `SHA256SUMS.sig` 分离签名，再对归档做 `sha256sum -c`；资产结构异常（非单顶层目录、缺 `deploy/install.sh`）即中止 | `mailstack.sh` |
| 引导安装脚本 | `curl`/`wget` 单文件获取的 `deploy/install.sh` 被替换，或经中间人投递 | 引导段不含任何安装逻辑，只做「取回官方 Release 三件套 → `ssh-keygen -Y verify` 分离签名 → `sha256sum -c` → 解压到 `/opt/mailstack-source` → `exec` 真正安装器」；验签或校验和不通过即中止，未验签内容绝不执行。推荐的 `bash <(curl …)` 进程替换形态不占用 stdin（交互问答与 `--admin-password-stdin` 正常）；残留的管道形态下 stdin 即脚本正文，有控制终端时接回 `/dev/tty`，无终端则明确失败，避免 `read` 退化为空值后在密码重试循环里空转。注意 `sudo bash <(curl …)` 不可用：sudo 关闭 3 号以上 fd，进程替换必须由执行脚本的 shell 自己完成 | `deploy/install.sh`（`bootstrap_from_signed_release`） |
| 管理员配置 | 部分写入导致损坏 | `admin.json`/`settings.json` 等一律经 `atomic()` 临时文件+rename 写入 | `backend/mailstackctl/core.py` |

**残余风险**：已持有主机 root 者当然可改一切（非目标）；归档内容本身（邮件正文）在允许前缀内可被备份/恢复流程覆盖——这正是恢复前自动生成快照（见 `docs/DISASTER_RECOVERY.md`）的原因。引导安装脚本与它的信任锚取自同一 HTTPS 来源（`raw.githubusercontent.com` 同一仓库），因此该来源本身不可作为信任依据——防篡改控制落在 Release 资产的分离签名上（锚是公钥，签名由仓库外的发布私钥产生）；能篡改 `raw.githubusercontent.com` 内容的攻击者同时也能替换引导脚本，这一层退化为与「直接下载 tar.gz」等价。

---

## R — Repudiation（抵赖）

| 机制 | 说明 | 出处 |
|---|---|---|
| 特权操作审计日志 | 每次 RPC（含 daemon 与一次性入口）追加一行 JSON 到 `/var/log/mailstack-rpc-audit.log`（`0600`）：`time`、`uid`、`action`、`target`、`ok`、`error`。`target` **只从白名单字段提取**（`domain`/`username`/`address`/`ip`/`service`/`queueId`/`filename`），截断 120 字符；`error` 截断 500 字符。口令等敏感值没有进入字段的途径 | `backend/mailstackctl/core.py`（`audit`） |
| 审计防篡改与外送 | 本机 root 删改/截尾审计掩盖痕迹 | B3：审计逐条携带 `prev_hash` 哈希链（链首创世值）+ 旁挂 `.head` 锚检测截尾；每条镜像外送 syslog `AUTHPRIV`（外送失败降级不阻塞落盘）；`ms audit-verify` 校验链完整性并以非零退出码供监控 | `backend/mailstackctl/core.py`（`audit`、`_audit_syslog`、`audit_verify`） |
| 会话可见与吊销 | 管理员可列出活跃会话（以 `sha256(sid)` 前 16 位指纹标识，不暴露会话 ID 与 CSRF token）、单个吊销或一键吊销其余全部 | `backend/server.production.ts`（`/api/auth/sessions`、`/api/auth/sessions/revoke`） |
| 登录失败痕迹 | 失败计数与锁定记录在进程内按 `IP:账号` 维护，服务日志可溯源；401 响应体对外保持无差别 | `backend/server.production.ts` |
| 备份/恢复留痕 | 备份与恢复均为审计 action；恢复前自动生成 `mailstack-backup-*-pre-restore.tar.gz` 快照，可作为“恢复前状态”的抗抵赖证据 | `backend/mailstackctl/backup.py` |

**残余风险**：日志保存在本机，主机 root 可篡改日志（非目标）；审计日志轮转依赖系统 `logrotate`（`deploy/mailstack.logrotate`）。

---

## I — Information Disclosure（信息泄露）

| 数据 | 威胁 | rc5 缓解 | 出处 |
|---|---|---|---|
| 管理员/邮箱口令 | 经进程参数泄露（`/proc/*/cmdline`） | webmail 改 Dovecot auth-client socket 认证；管理员口令只经 stdin/JSON 传递；备份加密口令经 `gpg --passphrase-fd 0`（stdin） | `webmail/dovecot-auth.mjs`、`backend/mailstackctl/backup.py` |
| 管理员凭据文件 | 静态泄露 | `admin.json` `0640 root:mailstack-admin`，仅存 PBKDF2-SHA256（310000 次）哈希；Node 管理进程只读不写 | `backend/mailstackctl/core.py`（`password_record`、`admin_set`） |
| TOTP 秘密与恢复码 | 泄露即绕过 2FA | TOTP secret 仅在 `begin` 时返回一次；恢复码明文仅在 `enable` 时返回一次，落盘为 **SHA256 哈希**；`GET /api/admin/2fa` 只返回启用状态与剩余数量 | `backend/mailstackctl/totp.py`、`backend/server.production.ts` |
| 备份归档 | 含凭据的备份外泄 | 归档与元数据均 `0600`；默认**排除** `admin.json`/`ai.json`/`ai-provider.json`/`sasl_passwd(.db)`（仅 `includeSecrets` 时纳入）；可选 GPG 对称加密（AES256），加密失败时连明文一并删除，绝不静默降级 | `backend/mailstackctl/backup.py`（`backup_create`、`_encrypt_archive`） |
| 备份归档（公网门） | 公网模式产出无口令明文归档 | B2：公网模式（caddy/direct/high）`backup.create` 无 passphrase 在打 tar 前 fail-closed 拒绝；恢复同样强制口令；`ms doctor` 对公网模式下未加密归档判 FAIL（metadata 缺失按未加密计） | `backend/mailstackctl/backup.py`（`backup_create`、`plaintext_backup_scan`）、`telemetry.py`（doctor） |
| 静态密钥 | 权限过宽 | `sasl_passwd` `0600`；`settings.json` `0600`；DKIM 私钥经 `set_dkim_key_permissions` 收敛为 `root:opendkim 0640`；`/etc/mailstack` `0750` | `backend/mailstackctl/core.py`、`network.py`、`certs.py` |
| AI 出站请求 | SSRF 探测内网 | 解析后的所有地址（含 `ipv4_mapped`/`sixtofour`/`teredo` 解包、CGNAT）先筛查，命中即拒；连接钉在具体地址上 | `backend/mailstackctl/ai.py`（`is_ip_restricted`） |
| AI 出站开关 | 公网默认暴露 SSRF/出站面 | B5：公网模式 AI 出站动作（`ai.test`/`ai.chat`/`ai.diagnose`/`ai.parse`/`ai.models.list`）默认拒绝（fail-closed，需显式开关）；密钥/凭证文件权限 doctor 全表断言（FAIL 级） | `backend/mailstackctl/dispatcher.py`（`AI_OUTBOUND_ACTIONS` 门）、`telemetry.py`（密钥政策全表扫描） |
| 响应面 | 错误信息成为枚举弹药 | 登录 401 不含 `remainingAttempts`；会话列表不含原始 sid；所有安全响应头（CSP、`nosniff`、`DENY`、`no-referrer`）统一注入 | `backend/server.production.ts` |

**残余风险**：邮件正文本身经管理员控制台不可见（管理进程无邮箱读权限），但备份 `--include-mails` 后归档内含邮件——因此备份口令与归档权限是保护重点。

---

## D — Denial of Service（拒绝服务）

| 攻击面 | 缓解 | 出处 |
|---|---|---|
| 登录/认证洪泛 | 管理员登录三层限流（见 S）；webmail 登录同口径限流；AI 诊断接口每 IP 20 次/分钟 | `backend/server.production.ts`、`webmail/server.mjs` |
| API 洪泛 | 请求体上限 256 KB（超限 413）；会话表上限 `MAX_SESSIONS`（默认 5000），满员先清扫过期再驱逐最近过期者 | `backend/server.production.ts` |
| helper daemon 资源耗尽 | 并发上限 8；单请求 ≤1 MB、单响应 ≤16 MB；读取超时 30 秒 | `backend/mailstackctl/daemon.py` |
| 备份/恢复炸弹 | 归档 ≤5 GB、成员数 ≤100 000、解压后 ≤50 GB，任一超限即拒绝 | `backend/mailstackctl/backup.py` |
| SMTP/IMAP 洪泛 | **非目标**（见 `SECURITY.md`）：MTA 层洪泛属运维范畴，fail2ban 只覆盖认证爆破 | `SECURITY.md` |

---

## E — Elevation of Privilege（提权）

| 攻击面 | 威胁 | rc5 缓解 | 出处 |
|---|---|---|---|
| sudo 通道 | 宽泛的 sudo 规则成为第二 root 入口 | sudoers **只有一条**规则（`/etc/sudoers.d/mailstack-web` → `/usr/local/libexec/mailstack-privileged`，无参数通配）；旧的 `mailstack-web-ctl` 规则由安装器删除；`HELPER_PATH` 恒定，绝不回退到原始 python 入口 | `deploy/install.sh`、`backend/server.production.ts`（`ctlViaSudo`） |
| 服务账号提权 | 管理进程改写自身或后端代码 | `/opt/mailstack` 归 root 所有，服务账号不可写；B4 后 `mailstack-web` 单元 `ProtectSystem=strict`（全文件系统只读，`admin.json`/`settings.json` 写路径全走 helper 经 rw socket 转发；因 sudo 提权所需，该单元不带 `NoNewPrivileges`/`RestrictSUIDSGID`，边界由 sudoers 单条 + `helper.sock` 0600 + daemon 双通道门禁承担）；helper 单元 `ProtectSystem=full` + 显式 `ReadWritePaths` 白名单并叠加固指令（`RestrictSUIDSGID`/`LockPersonality`/`SystemCallFilter=@system-service`）；`mailstack-webmail` 单元同为 strict + `ReadWritePaths=-/home -/var/vmail` | `deploy/install.sh` |
| webmail 横向移动 | webmail 被攻破后动控制平面 | `mailstack-webmail` 独立 no-login 用户、无 sudo、无法连接特权 socket（socket 属组是 `mailstack-admin`） | `deploy/install.sh`、`backend/mailstackctl/daemon.py` |
| 恢复通道写任意路径 | 恶意备份覆盖 `.ssh/authorized_keys` 等 | 恢复允许前缀白名单；`home/` 仅限当前托管邮箱用户；拒绝链接/设备/特殊位（见 T） | `backend/mailstackctl/backup.py` |
| RPC 面越权 | 调用白名单外动作 | 未知 action 一律拒绝；一次性入口与长驻 daemon 共用同一 `ALLOWED_ACTIONS` | `backend/mailstackctl/core.py`、`daemon.py` |

**残余风险**：Postfix/Dovecot/OpenDKIM/Caddy 自身漏洞由发行版负责跟进（`SECURITY.md` 非目标）；物理访问与恶意内核不在防御范围。B4 不假装收窄 `/home`：webmail 单元因投递邮件所必需仍保留 `ReadWritePaths=-/home`（`ProtectHome=read-only` 只对非 `ReadWritePaths` 覆盖部分生效），webmail 进程对其可写范围内邮件的机密性/完整性损失与投递面（Postfix 等同）同权；管理面 `mailstack-web` B4 后无任何写路径。

---

## 关联文档

- [`SECURITY.md`](../SECURITY.md) —— 威胁模型总纲、支持版本、报告渠道、加固保证清单
- [`VULNERABILITY_RESPONSE.md`](VULNERABILITY_RESPONSE.md) —— 漏洞响应 SLA 与 VEX
- [`DATA_PRIVACY.md`](DATA_PRIVACY.md) —— 数据停留与日志红线
- [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) —— 备份/恢复/回滚操作手册
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) —— 签名发布流程
