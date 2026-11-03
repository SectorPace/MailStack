# Webmail（`mailstack-webmail`）

> v1.0.0 新增：Rust 全栈版首次自带 Webmail。**独立进程、独立端口、独立会话体系**，
> 与管理台 `mailstack-web` 完全隔离。
> 接口契约的冻结版见仓库审查材料 `review/WEBMAIL_CONTRACT.md`（实现与前端共同遵守的唯一接口真相源）；
> 本文是面向使用者与运维的说明。

## 1. 定位

- Webmail 是**给邮箱用户**的 Web 客户端，登录名是**完整邮箱地址**（如 `alice@example.com`），
  口令来自 `/etc/mailstack/mailbox-passwords.json`（与 IMAP/POP3/提交端口是同一份 PBKDF2 记录）。
- 不是管理台的一部分：管理台登录是管理员，Webmail 登录是邮箱用户；两者进程、端口、
  Cookie 名、会话表、CSRF 域全部独立。
- 默认监听 `127.0.0.1:8444`，**只绑回环**；TLS 终止交给反向代理 / SSH 隧道（与管理台同策略）。
- 与管理台共用同一份前端构建产物 `webui/dist`：入口 `mail.html`（管理台入口是 `index.html`，
  两者同一次 `npm run build` 产出）。

## 2. 功能清单

对齐 Gmail / Outlook / Apple Mail / QQ 邮箱的公共能力：

| 能力 | 说明 |
|---|---|
| 文件夹树 | 特殊文件夹（INBOX / Sent / Drafts / Trash / Junk / Archive）+ 自定义文件夹；未读徽标；存储配额条 |
| 邮件列表 | 发件人、主题、摘要、智能时间格式、未读加粗 + 圆点、星标、附件图标、多选 / 全选、批量操作（已读/未读/星标/移动/删除） |
| 阅读窗格 | 标题、发件人详情、收件人折叠、日期、回复/全部回复/转发/星标/删除/移动/打印；消毒 HTML 在 **sandbox iframe** 中展示；纯文本回退；「显示远程图片」开关；附件下载；引用原文折叠 |
| 写信 | 浮层/全屏；To/Cc/Bcc 芯片输入 + 地址校验；主题；富文本工具栏（粗体/斜体/下划线/列表/引用/链接/清除格式）；附件上传；发送 / 存草稿 / 丢弃；`Ctrl+Enter` 发送 |
| 搜索 | 顶栏搜索（300ms 防抖），跨主题/发件人/收件人/抄送/正文 |
| 设置 | 显示名、签名（纯文本）、每页条数、阅读密度、默认是否加载远程图片（**仅存 localStorage**，不建后端接口） |
| 快捷键 | `c` 写信、`r` 回复、`a` 全部回复、`f` 转发、`j/k` 上一封/下一封、`u` 未读、`s` 星标、`e` 归档、`#`/`Delete` 删除、`/` 搜索、`Esc` 关闭；输入框内不触发 |
| 响应式 | 桌面三栏、移动端单栏 + 返回导航；空态、加载骨架、错误横幅、未读计数标题 `(3) Inbox` |
| 国际化 / 主题 | 中英双语完整覆盖；明暗主题跟随 `data-theme` |
| 会话 | 过期自动跳登录；发送成功 toast + 「查看已发送」 |

## 3. 架构

```
浏览器 ──HTTPS──▶ 反向代理（TLS 终止） ──HTTP──▶ mailstack-webmail 127.0.0.1:8444
                                                   ├── 静态产物 webui/dist/mail.html + assets
                                                   └── /mail/api/*  （认证 / 会话 / 邮件 API）
                                                          ├── /etc/mailstack/mailbox-passwords.json（PBKDF2）
                                                          ├── /var/lib/mailstack/managed-mailboxes.json（账号解析）
                                                          ├── /etc/passwd → 家目录 → ~/Maildir（读写）
                                                          └── 出站队列（发信入队，DKIM 由队列统一签名）
```

- **进程与库**：`bin/mailstack-webmail`（进程入口）+ `crates/webmail`（库：认证、会话、
  Maildir 服务、MIME 视图、HTML 消毒、写信/发送入队）。
- **权限前提**：进程需要读 `/etc/mailstack/mailbox-passwords.json`（`0600 root:root`）与各账号
  `~/Maildir`，因此与 `mailstack-imap` 一样以 root 运行（systemd `User=root`），只绑回环。
  这是**已登记的设计前提**，不是遗漏。
- **会话**：服务端内存表（token 为 32 字节随机 hex 的 SHA-256 存储），滑动 8 小时 / 绝对 7 天上限，
  服务端总量上限 4096。
- **会话纪元**：登录时记录 `/var/lib/mailstack/webmail-session-epoch.json` 中该用户的值；
  每次请求校验当前值是否变大（改密/锁定会 bump），变大立即 `401` 并删除会话。
- **Maildir 同步 I/O**：所有 Maildir 调用走 `tokio::task::spawn_blocking`，不阻塞 async worker。

### 命令行

```text
mailstack-webmail [--bind 127.0.0.1:8444] [--dist DIR] [--config-dir DIR]
                  [--passwd-root DIR] [--maildir NAME] [--log LEVEL]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--bind` | `127.0.0.1:8444` | 监听地址（建议保持回环） |
| `--dist` | 无 | 前端产物目录；省略时页面请求 503，API 仍可用 |
| `--config-dir` | 生产路径 | 把 `/etc/mailstack`、`/var/lib/mailstack` 视作 `<DIR>/etc/mailstack` 等（测试/旁路部署） |
| `--passwd-root` | `/etc` | `passwd` 所在目录（测试可指向临时根） |
| `--maildir` | `Maildir` | 家目录下的 Maildir 目录名 |
| `--log` | `info` | 日志级别；`RUST_LOG` 优先 |

> 以 `mailstack-webmail --help` 的最终输出为准；绑定失败会打印具体地址与原因并以非零码退出。

## 4. HTTP API 摘要

所有 API 前缀为 `/mail/api`；JSON；错误模型 `{"error":{"code","message"}}`。
除 `POST /mail/api/session`（登录）外，所有 `POST/PATCH/PUT/DELETE` 必须带
`x-csrf-token`（缺失/不匹配 → `403 CSRF_REJECTED`）。

### 4.1 认证与会话

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/mail/api/session` | `{"login":"alice@example.com","password":"…"}` → `200 {user,csrfToken,expiresInSeconds}` + `Set-Cookie` |
| GET | `/mail/api/session` | 当前会话（含 csrfToken）；未认证 `401 UNAUTHORIZED` |
| DELETE | `/mail/api/session` | 注销，清 Cookie |

- Cookie：HTTPS/公网模式 `__Host-mailstack_mail=<session>`，HTTP 默认 `mailstack_mail=<session>`；
  `HttpOnly; SameSite=Strict; Path=/`（`Secure` 按部署模式判定）。
- 失败统一 `401 INVALID_CREDENTIALS`（**不区分**用户不存在/口令错/邮箱未建）；
  超限 `429 TOO_MANY_ATTEMPTS`（每 IP + 每登录名失败计数、指数退避窗口）。
- 登录请求若带 `Origin` 头，其 host:port 必须匹配 `Host`，否则 403。

### 4.2 邮件

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/mail/api/folders` | 文件夹列表（特殊用途、订阅、总数、未读数） |
| POST | `/mail/api/folders` | 新建文件夹 |
| PATCH | `/mail/api/folders/{folder}` | 重命名 |
| DELETE | `/mail/api/folders/{folder}` | 删除（**仅空文件夹**；非空 → `409 FOLDER_NOT_EMPTY`） |
| GET | `/mail/api/messages?folder=INBOX&limit=50&offset=0&q=&unread=1&flagged=1&sort=date_desc` | 列表（分页/过滤/排序） |
| GET | `/mail/api/messages/{folder}/{uid}` | 单封详情（头、正文 text/html、附件、被阻断远程图片数） |
| GET | `/mail/api/messages/{folder}/{uid}/raw` | RFC822 原文下载 |
| GET | `/mail/api/messages/{folder}/{uid}/parts/{partId}` | 附件/内嵌资源下载（`?download=1` 强制附件） |
| PATCH | `/mail/api/messages/{folder}/{uid}` | 只改给出的 flags（`seen`/`flagged`/`answered`） |
| POST | `/mail/api/messages/{folder}/{uid}/move` | 移动/复制 |
| DELETE | `/mail/api/messages/{folder}/{uid}` | 永久删除（expunge 该 uid） |
| POST | `/mail/api/messages/batch` | 批量（move/copy/delete/mark_seen/mark_unseen/flag/unflag） |
| GET | `/mail/api/search?q=…&folder=INBOX&limit=50` | 搜索（主题/发件人/收件人/抄送 + 正文前 256KB，大小写不敏感） |
| GET | `/mail/api/quota` | 邮件数 / 存储字节 / 上限 |
| POST | `/mail/api/messages` | 保存草稿（`mailbox` 仅允许 `Drafts`） |
| POST | `/mail/api/send` | 发送：入出站队列 + 保存 `Sent` 副本 → `202 {queued,queueId,sentUid}` |

路径参数 `folder` 为 URL 编码的 Maildir 文件夹名，服务端用 `normalize_folder_name` 校验，
拒绝 `..`、NUL 与绝对路径；`uid` 为十进制 u32，由文件夹元数据定位，不接受任意路径。

## 5. 安全模型

| 面 | 措施 |
|---|---|
| HTML 正文 | **服务端 allowlist 消毒**（不可信输入）：允许常用排版/表格/图片标签，`script/style/iframe/form/object/svg/…` 连同内容丢弃；属性白名单（所有 `on*`、`srcset`、`background`、`formaction` 丢弃）；URL 仅 `http/https/mailto/cid`，`javascript:`/`vbscript:`/`data:text/html` 一律剥离；`<a>` 加 `rel="noopener noreferrer nofollow" target="_blank"` |
| 渲染隔离 | 前端用 `sandbox=""` iframe + `srcdoc` 展示消毒后的 HTML，内部 meta CSP；外层响应带 `frame-ancestors 'none'` |
| 远程图片 | 默认阻断：`<img src="http(s)://…">` 改写为 `data-blocked-src` 并删除 `src`，返回 `remoteImagesBlocked` 计数；用户显式「显示图片」后才加载 |
| CSRF | 所有写请求校验 `x-csrf-token`（与会话绑定）；登录做同源检查 |
| 会话 | `HttpOnly` + `SameSite=Strict`；HTTPS 模式 `__Host-` 前缀 + `Secure`；会话纪元让改密/锁定即时踢下线 |
| 路径穿越 | 文件夹名归一化校验；附件/原文按文件夹内元数据定位；静态服务拒绝 `..` 与符号链接逃逸 |
| 附件 | 单封附件总量上限 25 MiB（解码后）；文件名清洗（去 `/\` 与控制字符，限长 200）；不可内联渲染的 Content-Type 强制 attachment |
| 请求体 | compose/send/draft 32 MiB；其它 JSON 256 KiB（双重上限） |
| 头注入 | 主题拒绝 CR/LF；地址校验简化 RFC 5321（无 CR/LF/NUL、含 `@`、≤320）；MIME 边界随机 |
| 日志 | 不记录口令、正文、附件内容、session token；只记录 email/account/uid/folder/动作 |
| 响应头 | `nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、CSP（见契约 §3） |

发送路径：`POST /mail/api/send` → `QueueStore::enqueue_new`（outbound）→ `MailStore::append("Sent")`。
**DKIM 由队列 runner 出站前统一签名**，Webmail 不签名、不直连外域。队列成功、Sent 失败时返回
`202` + warning + `sentUid: null`，不回滚已入队邮件。

## 6. 运维

### systemd

安装器会生成 unit（示例，最终以 `deploy/install.sh` 落盘的 unit 为准）：

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
# 只绑回环；TLS 终止交给反向代理 / SSH 隧道。
# 前端产物与管理台同一份 webui/dist（入口 mail.html）。
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

> Webmail 直接读写 Maildir 并经队列落盘投递，**不依赖 `mailstackd` 是否已启动**；
> 与管理台是两个进程、两套会话（同一份前端产物、不同进程与端口）。
> 因此它也是**独立重启**的：重启 Webmail 不影响收信与投递。

```bash
systemctl status mailstack-webmail
journalctl -u mailstack-webmail -f
```

### 反向代理

对外暴露必须由反向代理终止 TLS（示例 nginx）：

```nginx
server {
    listen 443 ssl;
    server_name webmail.example.com;
    ssl_certificate     /etc/letsencrypt/live/webmail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/webmail.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8444;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

> 若部署在 HTTPS 反代之后，Cookie 是否带 `Secure`/`__Host-` 前缀由部署模式（`ACCESS_MODE`）
> 决定，与管理台同一判定逻辑；把 `--bind` 改成 `0.0.0.0` 而无反代 = 明文暴露。

### 故障排查

| 现象 | 排查方向 |
|---|---|
| 页面 503 `frontend is not available` | `--dist` 未给或目录里没有 `mail.html`；重新 `cd webui && npm run build` |
| 登录 401 但口令确认无误 | 账号是否在 `managed-mailboxes.json`；家目录/`Maildir` 是否存在（登录 fail-closed，不会自动创建）；口令记录是否更新 |
| 所有请求 401 并跳登录 | 会话过期（滑动 8h/绝对 7d），或管理员改密/锁定触发了会话纪元 bump |
| 写操作 403 `CSRF_REJECTED` | 前端未带 `x-csrf-token`，或反代重写了 `Host`/`Origin` |
| 发信成功但「已发送」里没有 | 队列成功、`Sent` 追加失败（响应带 warning）；查日志与 Maildir 权限 |
| 邮件显示为纯文本 | 原邮件没有 HTML 部分，或 HTML 全被消毒为不可呈现内容（此时回退纯文本） |
| 远程图片不显示 | 默认阻断；点「显示图片」后仍不显示则可能是 `http(s)` 之外的 URL（`cid:` 已改写为本地附件路径） |

## 7. 已知限制

- **不内建 TLS 终止**：只绑回环，不支持在进程内配证书；公网访问必须经反代/隧道。
- **无 OAuth / 外部身份**：只支持本机口令库（PBKDF2）；无 Gmail 式「授权第三方」。
- **设置仅本地**：签名/每页条数/阅读密度/远程图片偏好只存浏览器 localStorage，不跨设备同步。
- **不做服务端规则/过滤器管理**：Sieve 由 ManageSieve（4190）客户端或管理台维护，Webmail 不提供规则编辑。
- **搜索范围**：主题/收发件人/抄送 + 正文前 256KB，非全文索引。
