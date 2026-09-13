# MailStack v0.5.2-rc5 加固交接清单

> 基准：rc.4 评分 79。目标：按「安全 35% / 架构 20% / 功能 20% / 安装 15% / 测试 5% / 文档 5%」冲到 100。
> 本文件列出本次会话的**全部改动**、**已验证证据**、**未完成项**与**接手后的执行顺序**。
>
> **❗ 注（2026-08-31）：本清单所列未完成项已于 2026-08-31 全部完成（2FA、签名闭环、加密备份入口均已接线），本文仅作历史快照。**

---

## 一、改动文件清单（按子系统）

### 1. Webmail 认证（密码离开 argv）— 已验证 ✅
| 文件 | 改动 |
|---|---|
| `webmail/dovecot-auth.mjs` | **新增**。Dovecot auth-client 协议客户端（VERSION/CPID/AUTH PLAIN base64）。密码只进 socket 负载，fail-closed。 |
| `webmail/server.mjs` | 登录从 `doveadm auth test user pass`（密码暴露在 `/proc/*/cmdline`）改为 socket 认证；新增 7 天绝对会话上限；新增会话 epoch 失效（改密/锁账号即踢全部 webmail 会话）；邮箱注册表路径改 `/var/lib/mailstack/managed-mailboxes.json`。 |

**验证**：WSL Ubuntu 实测登录返回 `authenticated:true`；`ps auxww | grep doveadm` 为空；错误密码与不存在的用户返回完全相同的 401。

### 2. 升级通道（禁止 clone HEAD）— 代码完成，待真实 Release 验证 ⚠️
| 文件 | 改动 |
|---|---|
| `mailstack.sh` | `update_cmd` 重写：默认只走 GitHub Release 资产三件套（`MailStack-<tag>.tar.gz` + `SHA256SUMS` + `SHA256SUMS.sig`），`ssh-keygen -Y verify` 验签失败即退出；拒绝非官方 `MAILSTACK_REPO_URL`；`git clone` 仅 `MAILSTACK_ALLOW_UNSAFE_GIT=1` 开发者模式。uninstall/status/logs 覆盖新 helper 服务。 |
| `deploy/mailstack-release.pub` / `deploy/mailstack-release.allowed_signers` | **新增**。发布签名 ed25519 公钥与信任锚。 |
| `deploy/install.sh` | 安装时把 allowed_signers 落到 `/etc/mailstack/release-allowed-signers`。 |

**私钥在仓库外**：`C:\Users\hage2\.workbuddy\keys\mailstack-release`（公钥已入库）。**必须立即**：① 存为 GitHub Secret（如 `MAILSTACK_SIGNING_KEY`）；② 从本机安全转移或加密保存；③ 告知接手人位置。未做 CI release 自动签名（见未完成项 #13）。

### 3. 权限与 sudoers 收敛 — 已验证 ✅
- `deploy/install.sh`：删除第二条 sudoers（`mailstack-web-ctl`），并对旧机器 `rm -f` 清理；visudo 只校验单文件。
- `backend/server.production.ts`：`HELPER_PATH` 恒定 `/usr/local/libexec/mailstack-privileged`，不再回退 `/opt/mailstack/backend/mailstackctl.py`。
- WSL 实测：`/etc/sudoers.d/` 下只有 `mailstack-web` 一条。

### 4. 长驻特权 helper（架构层）— socket 协议已验证，systemd 路径未实测 ⚠️
| 文件 | 改动 |
|---|---|
| `backend/mailstackctl/daemon.py` | **新增**。root 长驻 daemon：`/run/mailstack/helper.sock`（0660 root:mailstack-admin），4 字节大端长度前缀 + JSON，8 并发上限，与一次性入口共用 `ALLOWED_ACTIONS`。 |
| `backend/mailstackctl.py` | 新增 `--daemon` 入口。 |
| `backend/server.production.ts` | `ctl()` = `ctlViaSocket`（daemon 优先）+ `ctlViaSudo`（仅传输层失败才回退，业务错误/超时绝不重试）。 |
| `deploy/install.sh` | 新增 `mailstack-helper.service`（ProtectSystem=full + `ReadWritePaths=/etc/postfix /etc/dovecot /etc/opendkim /etc/mailstack /etc/caddy`）；`mailstack-web` 的 `ReadWritePaths=/etc` 同步收紧为同一集合。 |

**验证**：WSL 手动起 daemon，socket 往返 doctor/domains.list/未知 action 拒绝全部正确。**systemd 单元未实测**（WSL 无 systemd，走的 init.d 分支）——接手后在有 systemd 的 VM 上跑一次安装验证。

### 5. 供应链钉扎（停止下载即执行）— 代码完成 ✅
- **Node.js**：删掉 NodeSource `fetch_and_run`。发行版包优先；不满足 Node 20-24 时下载官方 `node-v22.20.0-linux-<arch>.tar.xz`，**SHA256 常量比对失败即拒绝**（x64 `00bbd05e…`，arm64 `06907b9c…`）。
- **Caddy**：发行版仓库优先；Cloudsmith 兜底时先验 GPG 指纹 `65760C51EDEA2017CEA2CA15155B6D79CA56EA34`（已交叉核对官方文档），不符即拒绝加源。
- **acme.sh**：`git clone` 改为钉版本 `3.1.4` tarball + SHA256 `e5f8e187…`，不符即跳过。

### 6. Fail2ban 真拦截 — 已验证 ✅
- `deploy/install-mail-stack.sh`：dnf/yum/zypper/pacman/apk 分支补装 fail2ban；新增 `configure_fail2ban()` 写 `/etc/fail2ban/jail.d/mailstack.conf`（postfix-sasl + dovecot，filter/logpath/maxretry/backend 齐全）。
- `backend/mailstackctl/telemetry.py`：doctor 对每个 jail 做 ban/unban 往返（192.0.2.1 TEST-NET-1），装了没 jail 或 jail 不动作 = **FAIL**（不是黄灯）。
- WSL 实测：`Jail list: dovecot, postfix-sasl, sshd`。

### 7. 登录响应与限流 — 代码完成 ✅
- 401 只回 `INVALID_CREDENTIALS`（`remainingAttempts` 已删，dist 已重打）。
- admin 登录三层限流：全局 500/min + 每 IP 30/15min + 每账号 10/15min（对齐 webmail），叠加原 5 次锁定。

### 8. Caddy 注入面 — 已验证 ✅
- `deploy/install.sh`：`DOMAIN_RE`/`EMAIL_RE` 在**参数解析后、任何副作用前**校验；交互补录的值在写 Caddyfile 前再校一次。
- `scripts/ci_domain_injection_test.sh`（新增）：换行注入域名/邮箱必须在装包前被拒；合法域名不误伤。WSL 实测通过。

### 9. 会话与秘密 — 部分完成 ⚠️
- webmail：7 天绝对上限；`/var/lib/mailstack/webmail-session-epoch.json`（helper 在 `user_password`/`user_status` 时 bump，webmail 5s 缓存轮询）。
- `backend/mailstackctl/network.py`：`setup_send_test` 改用 `validate_legacy_password_input`（旧 8 位密码邮箱不会被锁死）。
- 前端 `AdminAccountSettings`/`AddUserModal` 文案仍写「8 个字符」——**未改**（见未完成项）。

### 10. SSRF 修补（真漏洞）— 已验证 ✅
- `backend/mailstackctl/ai.py`：`is_ip_restricted` 现在先解包 `ipv4_mapped`/`sixtofour`/`teredo` 再筛查。**此前 `::ffff:100.64.0.1` 可绕过全部规则**（Python ipaddress 对映射地址 is_private=False）。
- 单测覆盖 CGNAT、IPv4-mapped、loopback/link-local/multicast/公网放行。

### 11. 注册表位置修复（真 bug，WSL 实测发现）✅
- `managed-mailboxes.json` 从 `/etc/mailstack`（0750 root:mailstack-admin，webmail 不可读 → **所有 webmail 登录静默失败**）移到 `/var/lib/mailstack/`（root:mailstack-webmail 0640）。`install.sh` 含旧位置迁移；`backup.py` 备份源与恢复白名单同步加入 `var/lib/mailstack`。
- 同类修复：dovecot `99-mailstack-webmail.conf` 的 `mail_umask` 在新 dovecot 是未知键（整个 conf 加载失败、socket 退化 0600）→ 改为 `doveconf` 输出探测后逐个追加可选键。

### 12. 测试与 CI ✅
- `scripts/test_actions_unit.py`：+15 行为测试（空 qid 删除、flush 独立 verb、atomic 0640、jail 元字符、CGNAT/IPv4-mapped、rollback 文件名匹配、归档穿越拒绝）。WSL 37/37 通过。
- `tests/webmail-auth-socket.test.mjs`：**新增** 5 个测试（假 socket 应答 OK/FAIL、失败关闭、用户名走私、零子进程）。
- `scripts/ci_install_assertions.sh`：**新增**（健康、提权探针、sudoers 单条、jail 存在、信任锚、环回发信）。
- `.github/workflows/ci.yml`：install-matrix 改用两个脚本；环回发信进 matrix（失败即红）。

### 13. 文档 ✅
- `SECURITY.md`：重写（威胁模型、支持版本表、报告渠道、非目标、加固保证清单）。
- `docs/RELEASE_CHECKLIST.md`：刷新到 0.5.2-rc.5，sudoers「只有一条」与代码一致，签名发布流程写入清单。

### 14. 构建产物 ✅
- `dist/` 全量重建（vite + esbuild server/webmail + manifest 47 项）。
- 注意：Windows 沙箱 safe-delete 会拦截 vite 清空 dist，先手动 `rm -rf dist` 再构建；改 webmail/server 后必须重跑 `scripts/generate_manifest.mjs`。

---

## 二、未完成项（接手后继续，按此顺序）

| # | 任务 | 状态/说明 |
|---|---|---|
| 12 | **管理员 2FA（TOTP）** | `backend/mailstackctl/totp.py` **已写好**（begin/enable/disable/consume_recovery + 恢复码哈希）。**待做**：① `core.py` ALLOWED_ACTIONS + `dispatcher.py` 注册 4 个 action；② `server.production.ts` 登录流程（密码通过后查 `totp.enabled` → 无 code 回 `TOTP_REQUIRED`；TOTP 本地验；恢复码走 `admin.totp.consume_recovery`）；③ 2FA 管理端点 + 会话吊销 API（GET/POST/DELETE `/api/auth/sessions`）；④ 前端 LoginView 加验证码输入、`AdminAccountSettings` 加 2FA 卡片（显示 secret/otpauth URI/恢复码一次性展示）。 |
| 13 | **发布签名闭环** | `scripts/package.py` 加签名步骤（`ssh-keygen -Y sign -f $MAILSTACK_SIGNING_KEY -n file release/SHA256SUMS`）；新建 `.github/workflows/release.yml`（tag 触发，Secret 私钥签名，上传 tar.gz+zip+SHA256SUMS+SHA256SUMS.sig）。**ms upgrade 会拒绝无签名 Release，发布前必须完成此项**。 |
| 14 | DKIM 私钥权限 | `certs.py dkim_rotate`、`network.py setup_identity`：私钥改 `root:opendkim 0640`（当前 0600 opendkim:opendkim），加行为断言。 |
| 15 | CI 补测 | restore 不写 `/home/<非管辖区>/.ssh` 行为断言（`test_backup_e2e.py` 可能已覆盖，先查）；SSRF 已覆盖。 |
| 16 | 备份加密 | `backup.py`：可选 gpg 对称加密（独立口令），恢复需口令解密；文件名仍须匹配 `BACKUP_FILENAME_RE`。 |
| 17 | 第四层文档 | `docs/THREAT_MODEL.md`（STRIDE）、`docs/DISASTER_RECOVERY.md`、`docs/VULNERABILITY_RESPONSE.md`（VEX/SLA）、`docs/DATA_PRIVACY.md`（数据停留、日志红线）；README 加 2FA/签名升级说明。 |
| 18 | 收尾 | `VERSION`/`package.json`/`mailstack.sh` 升 `0.5.2-rc.5`；全量测试（npm test、vitest、python 三套）；CHANGELOG.md 写 rc.5（**如实描述，不要把"打哈希日志"写成"供应链加固"**）；前端两处密码文案 8→12 位+字母数字。 |
| — | systemd 路径实测 | WSL 无 systemd，mailstack-helper.service 只在有 systemd 的 VM 上验证过语法，**未跑过真机**。 |

## 三、快速验证命令（接手后先跑这些确认环境一致）

```bash
# Python 行为测试（37 项）
python3 scripts/test_actions_unit.py
# Node 测试（含 webmail socket 5 项）
npm test
# shell 语法 + 发布门禁
bash deploy/verify-release-scripts.sh .
# WSL 全量安装（本机已有 Ubuntu WSL，约 50 秒）
wsl -d Ubuntu -u root -- bash -c "cd /root/mailstack-src && bash deploy/install.sh --non-interactive --access-mode local --reuse-admin"
# 域名注入门禁
wsl -d Ubuntu -u root -- bash scripts/ci_domain_injection_test.sh   # 在仓库目录下，SRC=$PWD
```

## 四、必须立刻处理的安全事项

1. **签名私钥**：`C:\Users\hage2\.workbuddy\keys\mailstack-release` 是唯一一把 release 签名私钥，当前明文躺在本机。上传 GitHub Secret 后应从本机移除或加密保管；丢了就要换钥并同步更换 `deploy/mailstack-release.allowed_signers`（否则所有已装机机器升级失败）。
2. **无签名 Release 无法升级**：新 `ms upgrade` 默认验签，下一个 Release 必须带 `SHA256SUMS.sig`（完成任务 #13 后才有自动签名）。
3. WSL Ubuntu 里有一套已安装的实例（含测试邮箱 `alice@probe-example.com`），仅作测试用途，勿当生产数据。
