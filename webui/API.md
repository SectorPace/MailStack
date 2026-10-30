# MailStack 前端 → 后端 交接文档（API 契约 v1）

> 后端实现：`crates/web`（crate 名 `mailstack-web`，axum）。
> **契约的唯一真相源**是 `crates/web/src/contract.rs` 的契约表（方法 / 路径 / 动作名）
> 与 `crates/web/src/lib.rs` 的路由注册；本文档是人类可读版 + 传输层语义。
> `src/api/client.ts` 的 `mockDispatch()` 只是**开发构建**的演示分支，不再是契约依据
> （生产构建会把整个 mock 块剔除）。

---

## 1. 前端形态（部署即用，无需后端配合）

- `dist/` 纯静态产物，`base: './'`（相对路径），**hash 路由**（`#/dashboard`）→ axum 挂载到任意路径都无需 SPA fallback：

```rust
Router::new()
    .nest_service("/api", api_router)
    .fallback_service(ServeDir::new("dist").fallback(ServeFile::new("dist/index.html")))
```

- 开发期：`npm run dev`（Vite 5173，`/api` 代理到 `ADMIN_API` 环境变量，默认 `http://127.0.0.1:8080`）。

## 2. 双传输层（启动时自动探测）

前端启动时 `GET /api/setup/status`：

| 结果 | 传输层 | 说明 |
|---|---|---|
| 200 / 401 等 | **REST**（对齐原版 MailStack beta.10 admin-web） | 全部走下表 REST 端点，写操作带 `x-csrf-token` |
| 404 / 405 / 网络错误 | **RPC 桥** | `POST /api/rpc`，帧协议透传 helper socket |

REST 未映射的动作自动回退 RPC 桥 —— 因此后端**最小实现只需 §4 的 P0 项**即可点亮全部页面。

## 3. 认证 / CSRF / 错误语义

- `POST /api/auth/login` `{ username, password, code? }` → `200 { ok, csrf, username }` 并下发
  HttpOnly 会话 Cookie；失败 `401 { error: { code, message } }`；**`code === "TOTP_REQUIRED"`**
  时前端切两步验证阶段并重发 `code` 字段。
- `GET /api/auth/session` → `{ ok, csrf, username }`：前端**启动时**用它恢复登录态与 CSRF
  （刷新页面不再强制重登）。CSRF 只存内存，登录/恢复时捕获，注销/401/403 时清空。
- 任何端点 `401` **或 `403`** → 前端清空 CSRF 并弹回登录页（403 通常是 CSRF 失效，
  原先只有 401 才登出，用户会被一句 toast 卡在页面内）。
- 错误体约定：`{ error: { code, message } }` 或 `{ error: string }`，前端展示 `message`。

## 4. REST 端点契约（方法 / 路径 / 请求 / 响应）

> 响应字段结构 = mock 分发器中的同名 case。标注 ★ 的为前端扩展（原版 beta.10 没有的端点，可直接实现或统一走 §5 RPC 桥）。

### 认证与会话
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/auth/login` | POST | `{username, password, code?}` | `{ok, csrf, username}` + Set-Cookie |
| `/api/auth/session` | GET | — | `{ok, csrf, username}` |
| `/api/auth/logout` | POST | — | `{ok}`（服务端删除会话；前端此前从不调用 → 已修） |
| `/api/auth/sessions` | GET | — | `{ok, sessions:[{id(指纹), username, createdAt, lastSeen}]}` |
| `/api/auth/sessions/revoke` | POST | `{id}`（指纹） | `{ok: bool}`；**只认单个 id，`{all:true}` 无效** |
| `/api/auth/sessions` | DELETE | — | `{ok, revoked}`：吊销除当前外的全部会话 |

> ⚠️ 会话列表**没有** `current` / `ip` / `userAgent` / `lastActive` 字段
> （`crates/web/src/session.rs` 的 `list_public`）。前端据此不再假设「当前会话」，
> 也不再靠 `current` 过滤列表 —— 吊销后重新拉取后端列表。

### 管理员
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/admin` | GET | — | `{username, passwordConfigured, twoFactorEnabled, recoveryCodesRemaining}` |
| `/api/admin` | POST | `{username, password?}` | 助手返回值 + `{revokedSessions: number, reauthenticate: true}`；**总是**吊销全部会话（含当前） |
| `/api/admin/2fa` | GET | — | `{enabled, state, recoveryCodesRemaining, algorithm, digits, period}` |
| `/api/admin/2fa/begin` | POST | `{code:""}` | `{secret, otpauthUrl}` |
| `/api/admin/2fa/enable` | POST | `{code}` | `{recoveryCodes:[8×"xxxxxxxx-xxxxxxxx"], revokedSessions, reauthenticate:true}` |
| `/api/admin/2fa/disable` | POST | `{code}` | `{..., revokedSessions, reauthenticate:true}` |

> 2FA 启用/关闭与改账号成功后会吊销全部会话并下发 `Max-Age=0` Cookie；前端必须处理
> `reauthenticate`（恢复码只显示一次，所以先提示保存、再回登录页）。

### 仪表盘（★ snapshot 扩展字段）
| 端点 | 方法 | 响应 |
|---|---|---|
| `/api/snapshot` | GET | `{health, uptime, domains{total,active,disabled}, users{...}, queue{total,pending,sending,failed,deferred,hold,bounced,delivered}, smtp{running,connections,sentToday,successRate,ports,uptime}, dovecot{...}, latency{points:[{t,v}]}, domainRows[], userRows[], serviceDist{total,running,alert,offline}, resources{cpu,memory,disk}, healthPanel{overall, items:[{key,label,status,value?}]}}` |
| `/api/metrics/realtime` | GET | `{points:[{t,v}], ts}` |
| `/api/metrics/telemetry` | GET | 遥测 |
| `/api/metrics/system` ★ | GET | `{cpu, memory, disk}` |
| `/api/system/doctor` | GET | `[{check, ok, detail}]` |
| `/api/activity` ★ | GET | `[{kind: user\|domain\|queue\|service\|cert, title, sub, time}]` |

### 资源 CRUD
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/domains` | GET | — | 域名数组（或 `{domains:[...]}`） |
| `/api/domains` | POST | `{domain}` | `{domain}` |
| `/api/domains/{domain}` | DELETE | — | `{}` |
| `/api/users` | GET | — | 用户数组 |
| `/api/users` | POST | `{address, name?, quota?}` | `{address}` |
| `/api/users/{address}` | DELETE | — | `{}` |
| `/api/users/status` | POST | `{address, active}` | `{address, active}` |
| `/api/users/password` | POST | `{address, password?}` | `{}` |
| `/api/aliases` | GET | — | 别名数组 |
| `/api/aliases` | POST | `{source, target}` | `{source, target}` |
| `/api/aliases/{source}` | DELETE | — | `{}` |

### 邮件服务
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/certificates` | GET | — | `[{domain, issuer, keySize, notAfter, daysLeft, autoRenew}]` |
| `/api/certificates/renew` | POST | `{domain}` | `{renewed}` |
| `/api/queue/action` | POST | `{id, op: deliver\|release\|hold\|delete}` | `{}` |
| `/api/services/action` | POST | `{key, op: start\|stop\|restart}` | `{running}` |
| `/api/setup/relay/test` | POST | `{relayProvider, relayHost, relayPort, relayAuthUser, ...}` | `{success, latencyMs, message}` |
| `/api/setup/relay/apply` | POST | 同上 | `{applied}` |
| `/api/network/check-port` | POST | `{port, host}` | `{open, latencyMs}` |
| `/api/status` | GET | — | 中继运行状态 |

### 初始设置向导
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/setup/status` | GET | — | `{completed: bool, step}` |
| `/api/setup/identity` | POST | `{domain, mailHost, serverIp}` | `{applied}` |
| `/api/setup/dns/verify` | POST | `{domain, mailHost}` | `{verified}` |
| `/api/setup/cert/issue` | POST | `{domain, mailHost}` | `{issued, san[], issuer, algo}` |
| `/api/setup/mail/test` | POST | `{to}` | `{success, queued, message}` |
| `/api/mail/test-loopback` | POST | — | `{success, message}` |

### 安全 / 备份 / DNS
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/security/scan` | **POST** | — | `{ok, scannedAt, scanned, absent, findings:[{path,severity,issue,mode,maxMode,note,detail}], summary, highestSeverity, bannedIps, bannedIpScope}` |
| `/api/security/ban` | POST | `{ip, reason?}` | `{}` |
| `/api/security/unban` | POST | `{ip}` | `{}` |
| `/api/backups` | GET | — | `[{name, size, time, kind}]` |
| `/api/backups/restore` | POST | `{name}` | `{}` |

### AI（原版 DNS 助手端点）
| 端点 | 方法 | 请求 | 响应 |
|---|---|---|---|
| `/api/ai/config` | GET / POST | GET—；POST `{provider, endpoint, apiKey?, model?}` | 配置对象 |
| `/api/ai/models` | GET | — | `[{id, label, context}]` |
| `/api/ai/test` | POST | 配置 | `{ok, latencyMs, models}` |
| `/api/ai/dns-chat` | POST | `{message}` | `{reply}` |
| `/api/ai/diagnose-dns` | POST | `{}` | `{summary, items:[{ok,text}]}` |

## 5. RPC 桥（万能回退，前端已自动使用）

REST 表中没有的动作（`queue.list`、`services.list`、`dkim.keys`、`dkim.rotate`、`dns.records`、`ai.config.get` 在 REST 表有 GET；`backup.create/delete` 等其余全部）会落到：

```
POST /api/rpc
请求体: {"action": string, "data": object}     ← 与 helper socket 帧协议字段一致
响应:   {"ok": true, "data": ...} | {"ok": false, "error": string}
```

实现 = axum handler 校验 action ∈ `crates/core/src/actions.rs` 白名单（HTTP 面可达集由
`crates/web/src/contract.rs` 的 `is_exposed_action` 收窄）→ 写帧到 `helper-ro.sock`（RO）/
`helper.sock`（RW）→ 读回帧原样返回。

> 无页面调用的映射已从 `REST` 表删除（`status.relay`、`metrics.realtime`、
> `metrics.telemetry`、`backups.list`、`backup.restore`）：后端有完整 backup CRUD，
> 但前端还没有备份页面，保留半截映射只会让「改后端契约时没人发现」。

## 6. 后端实现清单（按优先级）

**P0（点亮登录 + 全部页面骨架）**
1. 静态托管 `dist/` + `nest_service("/api")`
2. `POST /api/auth/login`（PBKDF2 + HttpOnly Cookie + csrf 字段 + 401/TOTP_REQUIRED 语义）
3. `GET /api/setup/status`
4. `POST /api/rpc` 桥（helper socket 已实现，粘合即可）

**P1（真实数据）**
5. `GET /api/snapshot`（helper `snapshot` 动作组装）· `/api/settings` GET/POST
6. CRUD：domains / users(+status,password) / aliases / certificates(+renew) / logs
7. `queue/action` · `services/action` · `security/*` · `backups` · `system/doctor` · `metrics/*`

**P2（增强）**
8. `admin` + `admin/2fa/*`（TOTP）+ `auth/sessions*`
9. `setup/identity|dns/verify|relay/*|cert/issue|mail/test`
10. `ai/*`（可选，需外部 LLM 端点）

## 7. 验收方法

1. 后端起在 `127.0.0.1:8080` → 直接打开前端（无参数）→ 探测 `/api/health` 成功 → 走 REST，
   并调用 `GET /api/auth/session` 恢复登录态。
2. 未实现 REST 时：实现 §5 的 `/api/rpc` 桥即可（前端自动回退）。
3. **fail-closed**：探活失败时前端显示「后端不可达 + 重试」错误页，**不会**降级为演示数据。
4. 演示/评审（**仅 `npm run dev` 开发构建**）：`?mock=1`（内置 mock，无需后端）；
   `?mock=1&login=1` 登录页；`?mock=1&setup=1` 向导回放。生产构建中 mock 代码被整块剔除，
   这些参数无效。
5. 任何字段拿不准 → 以 `crates/web/src/contract.rs` 与 `crates/web/src/lib.rs` 为准。
