# 安全策略（Security Policy）

MailStack 是一个自托管的邮件服务器（SMTP / IMAP / POP3 / ManageSieve / 管理台 / Webmail），
部署位置通常直接面向公网。我们欢迎安全研究者按本文件的方式报告问题。

## 支持版本

| 版本 | 状态 | 说明 |
|---|---|---|
| `1.0.x` | ✅ 支持 | v1.0.0 起的 Rust 全栈版本；安全修复进入 1.0.x |
| `< 1.0.0`（legacy `v0.8.0-beta.10` 及更早的 Node/Python 栈） | ❌ 停止支持 | 已被 v1.0.0 取代，不再接受安全修复；请升级 |

只对**最新 1.0.x** 提供安全修复。升级方式见 [`docs/INSTALL.md`](docs/INSTALL.md)。

## 私有披露流程

**请不要在公开 issue / PR / 社交平台披露未修复的漏洞细节或可用的利用代码。**

首选渠道：在仓库的 **Security → Report a vulnerability**（GitHub 私有安全公告/Advisory）提交报告。
如果无法使用该渠道，请通过仓库维护者的公开联系方式先建立私下沟通，再发送细节。

请在报告中尽量给出：

- 受影响版本（`mailstackd --version` 等输出）与组件（crate / 二进制）；
- 部署形态：是否公网、是否经反向代理终结 TLS、是否启用 2FA、`ACCESS_MODE`；
- 可复现的最小步骤或 PoC（本地/容器环境优先，勿打真实第三方系统）；
- 影响评估（远程/本地、是否需要认证、是否可持久化）；
- 你希望的署名方式（默认不公开致谢，除非你同意）。

我们的处理方式：

1. 确认收到后会复现并给出严重度判断；
2. 修复进入 1.0.x，必要时先给出临时缓解（配置/部署层）；
3. 修复发布后再与你协商公告与致谢；目标是在 90 天内发布修复或缓解措施，
   具体时间取决于严重度与影响面；
4. 同一问题若已在上游依赖（如 `rustls` / `mail-auth`）修复，我们会跟进升级并注明。

## 请勿附带的内容

为保护生产数据与凭据，**报告中不要附带**以下材料；如有必要，请提供脱敏后的最小片段：

- 真实用户口令、TOTP 种子、恢复码、会话 Cookie / CSRF token；
- `totp.key`、`admin.json`、DKIM 私钥、TLS 私钥、中继凭据（`relay.json`）；
- 完整备份归档（`backup.create` 产物）与完整 Maildir/邮件正文；
- 未脱敏的生产日志（含邮箱地址、IP、正文）和第三方用户数据；
- 真实公网目标的扫描结果与流量抓包（请在自己的环境中复现）。

## 范围

**在范围内**：`crates/*`、`bin/*`、`webui/`、`deploy/` 中的安装与发布脚本；
SMTP/TLS/SASL、SPF/DKIM/DMARC/ARC 判定、队列与 DSN、IMAP/POP3/ManageSieve、
管理 API、特权边界、Webmail、备份/恢复、安装器与 systemd unit。

**不在范围内**（通常按部署问题处理，不视为产品漏洞）：

- 未按文档部署导致的暴露：把 `mailstack-web` / `mailstack-webmail` 绑到 `0.0.0.0`
  又不在前面加 TLS 反向代理（本栈不内建这两个面 TLS 终止，见
  [`docs/WEBMAIL.md`](docs/WEBMAIL.md) 与 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)）；
- 弱口令、被攻陷的操作系统账号、主机层 root 权限滥用；
- 第三方依赖自身缺陷（请直接报给上游；我们会跟进升级）；
- 机会式 TLS 直投缺失（已在 `CHANGELOG.md` 的已知限制中登记）；
- 邮件内容层的钓鱼/垃圾邮件（属内容治理，另行处理）。

## 部署加固清单

上线前逐项确认（命令与文件位置见 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)）：

- [ ] **管理面/Webmail 只绑回环**：`127.0.0.1:8443` / `127.0.0.1:8444`，
      对外只经 TLS 反向代理或 SSH 隧道；
- [ ] **SMTP/IMAP/POP3 的 TLS 证书就位**，`mailstack-imap` 不给证书应拒绝启动；
- [ ] **启用 2FA**（TOTP + 恢复码），恢复码离线保存；管理员口令符合口令策略；
- [ ] **备份加密**（`backup.create` 带口令）并异地保存；恢复流程演练过；
- [ ] **文件权限**符合契约：`/etc/mailstack` `0750 root:mailstack-admin`、
      密钥/凭据 `0600`、`admin.json` `0640`、`totp.key` `0600 root:root`；
- [ ] **特权包装器**指向本仓库的 `mailstackctl --privileged-stdin`，
      sudoers 仅授权 `/usr/local/libexec/mailstack-privileged`；
- [ ] **审计哈希链**（`/var/log/mailstack-rpc-audit.log` + `.head`）权限 `0600`，
      并纳入监控；
- [ ] **出站 25 端口**可用，或显式配置中继；直投为明文，敏感场景请用中继；
- [ ] **依赖门禁**通过：`cargo deny check` / `cargo audit`（CI 已接线）；
- [ ] **fail-closed 检查**：`mailstackd` 缺 `setup.json`/证书/域名表时应拒绝启动，
      而不是带病运行。

## 安全设计要点（摘要）

- **特权边界**：只读动作直连 `/run/mailstack/helper-ro.sock`（`0660 root:mailstack-admin`）；
  变更动作恒经 `sudo /usr/local/libexec/mailstack-privileged`（`helper.sock` 为 `0600 root:root`，
  Web 进程连不上）。未登记动作默认走只读面并被拒绝；破坏性动作强制 `confirm: true`；
  助手不可达一律 `503`，绝不降级为无特权执行。
- **动作名编译期绑定**：处理器不从请求体读取动作名，白名单不可被请求体绕过。
- **审计哈希链**：每条特权动作记录进哈希链，`.head` 锚文件可检测截尾。
- **2FA**：TOTP secret 以 AES-256-GCM 信封落盘，主密钥 `0600 root:root`；
  动态码按 RFC 6238（HMAC-SHA1 / 6 位 / 30 秒 / ±1 步）校验并记账防重放；
  恢复码只以 SHA-256 落盘、持锁一次性消费。
- **会话**：Cookie 带 `__Host-` 前缀（HTTPS 模式）+ `HttpOnly` + `SameSite=Strict`；
  CSRF token 与会话绑定；改密/2FA 变更按用户全量吊销会话（会话纪元）。
- **Webmail**：服务端 HTML allowlist 消毒 + 前端 sandbox iframe 展示 + 远程图片默认阻断
  + CSRF + 会话纪元；发送只入出站队列，DKIM 由队列统一签名。
- **SSRF 防线**：直投 MX 与 AI 出站都走地址策略白名单（私网/环回/link-local/
  IPv6 内嵌 IPv4 一律拒绝），AI 端点强制 HTTPS。
- **供应链**：`Cargo.lock` 提交、`cargo-deny` + `cargo audit` 在 CI 强制；
  v1.0.0 发布前修掉了 7 条 RUSTSEC 通告（见 `CHANGELOG.md`）。

## 披露历史

| 日期 | 版本 | 内容 |
|---|---|---|
| 2026-11-03 | v1.0.0 | 发布前完成 7 份独立代码审查（144 条发现）并修复关键项；修复 7 条依赖 RUSTSEC 通告。详见 `CHANGELOG.md` 与 `docs/REVIEW_FIXES.md` |
