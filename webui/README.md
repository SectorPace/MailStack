# MailStack Admin Console — Liquid Glass 前端

Apple iOS 27 **Liquid Glass** 设计语言的 MailStack 邮件服务器管理控制台（全新前端）。

React 19 · TypeScript · Vite 7 · Tailwind CSS 4 · Motion 12 · Radix Primitives · 零路由依赖（内置 hash 路由）

![技术栈](https://img.shields.io/badge/react-19-blue) ![tailwind](https://img.shields.io/badge/tailwind-4-38bdf8) ![motion](https://img.shields.io/badge/motion-12-ff0080)

---

## 快速开始

```bash
npm install
npm run dev        # 开发：http://localhost:5173（/api 自动代理到后端）
npm run build      # 产物在 dist/（相对路径 base，可挂在任意路径下）
npm run preview    # 本地预览构建产物
```

- **后端不可达时自动进入 Mock 模式**（演示数据，与产品示意图一致），UI 行为与 live 模式完全相同。
- 强制模式：`?mock=1`（纯演示）/ `?live=1`（强制连后端）。
- 开发代理目标可用环境变量覆盖：`ADMIN_API=http://127.0.0.1:9443 npm run dev`

---

## 与 Rust 后端（crates/admin-web）衔接

前端是纯静态 SPA + JSON API 约定。**支持双传输层**，启动时自动探测（GET `/api/setup/status`）：

- **REST 模式（默认，对齐原版 MailStack beta.10 admin-web）**：CSRF 保护（登录响应 `csrf` → 写操作回传 `x-csrf-token`）
- **RPC 桥模式**：`POST /api/rpc` 原样透传 helper socket 协议（`{action,data}` → `{ok,data|error}`）

REST 端点（与原版一致）：
```
auth:    /api/auth/login · session · logout · sessions · sessions/revoke
admin:   /api/admin (POST 改用户名/密码) · /api/admin/2fa [·begin ·enable ·disable]
数据:    /api/snapshot · domains[/id] · users[/status] · aliases[/id] · certificates[/renew]
         /api/logs · queue/action · services/action · settings · setup/status
```
未映射的动作自动回退 RPC 桥。登录响应的 `csrf` 由前端自动捕获并回传。

### 1. `POST /api/rpc` —— RPC 直通桥

请求体与响应体 **原样透传** 给 helper 的 RPC socket（协议见 `crates/common/src/rpc.rs`）：

```jsonc
// 请求（前端 → admin-web）
{ "action": "domains.list", "data": {} }

// 响应（helper 协议原样返回）
{ "ok": true,  "data": [ ... ] }
{ "ok": false, "error": "invalid domain" }
```

axum 侧参考实现（连接 `helper-ro.sock` / `helper.sock`，按 RO/RW 白名单选通道）：

```rust
async fn rpc_bridge(State(state): State<App>, Json(req): Json<Value>) -> Response {
    // 1. req["action"] 按 common::actions::ALLOWED_ACTIONS_RO / _RW 校验
    // 2. 写帧: u32be(len) + JSON 到对应 socket，读回 {"ok":..} 帧
    // 3. 把 helper 的响应 JSON 原样作为 HTTP 200 返回
}
```

前端 action 名与 `crates/common/src/actions.rs` 白名单一一对应，已接线的动作：

| 页面 | RO | RW |
|---|---|---|
| 仪表盘 | `snapshot` `metrics.realtime` `metrics.system`² `activity.list`² `system.doctor` | — |
| 邮件域名 | `domains.list` | `domains.add` `domains.delete` |
| 邮箱用户 | `users.list`¹ | `users.add` `users.delete` `users.status` `users.password` |
| 地址与别名 | `aliases.list` | `aliases.add` `aliases.delete` |
| 出站中继 | `settings.get` | `relay.test`² `relay.apply`² `settings.set` |
| DKIM 与 DNS | `dkim.keys`² `dns.records`² | `dkim.rotate` |
| TLS 证书 | `certs.list` | `certs.renew` |
| 邮件队列/日志 | `queue.list`² `logs.list` | `queue.action`（op=`deliver/release/hold/delete`） |
| 服务管理 | `services.list`² | `services.action`（op=`start/stop/restart`） |
| 安全中心 | `security.scan` | `security.unban` `security.ban` |
| 系统设置 | `settings.get` | `settings.set` |

> ¹ 白名单暂无 `users.list`，后端可在 `snapshot` 中返回 `users` 数组，或为 admin-web 增加该 RO 动作。
> ² admin-web 聚合层动作：由 admin-web 把 helper 的底层数据组装后返回（前端字段结构见 `src/api/client.ts` 的 mock 分发器，即数据契约）。
>
> 仪表盘扩展契约（`snapshot` 新增字段 + 两个聚合动作，均见于 mock）：
> - `snapshot.serviceDist` `{ total, running, alert, offline }` —— 服务状态分布环形图
> - `snapshot.resources` `{ cpu, memory, disk }` —— 资源使用率（%），也可由 `metrics.system` 返回
> - `snapshot.healthPanel` `{ overall, items:[{ key, label, status, value? }] }` —— 综合健康度环 + 服务清单（disk 项带 value 百分比）
> - `activity.list` → `[{ kind: user|domain|queue|service|cert, title, sub, time }]` —— 最近动态
> - `admin.set` / `admin.2fa.status|begin|enable|disable` / `sessions.list|revoke` —— 管理员账户、TOTP 绑定、会话管理（设置 → 安全策略）
> - `network.check_port` —— 中继端口连通检测（25/465/587）

### 2. `GET /api/health` —— 探活

返回 `200 {"ok": true}`。前端启动时探测：成功 → live 模式；失败/超时 → mock 模式。

### 3. `POST /api/auth/login` —— 会话登录（可选）

live 模式下收到 `401/403` 时前端自动弹出玻璃登录门：

```jsonc
// 请求
{ "username": "admin", "password": "…" }
// 200 表示成功；错误返回 401（沿用既有 PBKDF2 + HttpOnly Session + CSRF 体系）
```

### 4. 静态托管 dist/

`vite.config.ts` 已设 `base: "./"`，产物全部是相对路径资源，axum 一行即可挂载：

```rust
Router::new()
    .nest_service("/api", api_router)
    .fallback_service(ServeDir::new("../mailstack-admin-frontend/dist")
        .fallback(ServeFile::new("../mailstack-admin-frontend/dist/index.html")))
```

前端路由是 hash 路由（`#/dashboard`），**无需** SPA fallback 重写也能直接用。

---

## 目录结构

```
src/
├── main.tsx              入口
├── App.tsx               外壳：侧栏 + 工具栏 + 路由 + 登录门 + 刷新信号
├── router.ts             内置 hash 路由（13 个路由）
├── i18n.ts               中英双语词典（面包屑双标签）
├── index.css             ★ 设计系统：全部玻璃材质 token（唯一玻璃来源）
├── api/client.ts         ★ RPC 客户端 + mock 数据契约（后端字段以 mock 为准）
├── store/settings.tsx    主题/语言/强调色/玻璃透明度/无障碍偏好（localStorage 持久化）
├── components/           Sidebar / Toolbar / CommandPalette / DataTable / LineChart / ui
└── pages/                13 个页面（与侧边栏一一对应）
```

---

## 设计系统要点（验收对照）

- **材质层级**：功能性 chrome / 导航 / 工具栏 / 浮层 = Liquid Glass；高密度表格与日志 = 中性数据表面（`glass--data`），未卡片化。
- **玻璃物理感**：半透明 + backdrop 实时折射活 DOM + 配对边缘高光（内侧镜面高光 + 外侧 1px 轮廓）+ 边缘透镜（`edge-lens` 环形二次折射）。全部经由 `index.css` 的 6 个材质类，无散装 blur。
- **双主题**：Light 画布 `#F2F2F7` + systemBlue `#007AFF`；Dark 画布近黑 `#0B0D12` + systemBlue `#0A84FF`，深色玻璃为**更亮的中调玻璃**，激活导航胶囊**比周边玻璃更深** + 亮色文字。
- **滚动边缘工具栏**：内容滚动后工具栏获得更硬磨砂 + 1px 底部分隔线（`.is-scrolled`）；无底部模糊地平线。
- **语义双编码**：所有状态 = 颜色 + 图标 + 文字（Delivered/Sending/Failed/Pending/Hold/Running/Stopped…）。
- **动效**：Motion spring 按压 / 导航胶囊 `layoutId` 形变 / 页面 spring 入场 / 分段控件滑动；曲线「快 → 柔 → 落定」。
- **可访问性（真实生效）**：`减少透明度`（玻璃→近不透明、关闭折射）、`增加对比度`、`减少动态效果` 三个开关写 `data-*` 到 `<html>` 并被 CSS/Motion 消费；Radix 键盘可达 + focus-visible。
- **Liquid Glass 个性化**：设置 → 外观 中 0%（超清澈）→ 100%（柔和暗色）滑杆实时调节全局玻璃 alpha，附实时预览窗与强调色板（systemBlue/systemPurple/systemGreen/systemRed/systemOrange/systemYellow）。
- **工具栏九要素**：面包屑（EN/中文）· ⌘K 搜索 · 系统状态 · 时间范围 · 刷新 · 通知（角标+下拉）· 主题 · 语言 · 管理员菜单。

## 命令面板

`⌘K / Ctrl+K` 或点击工具栏搜索框 → 玻璃浮层快速跳转 13 个页面（↑↓ / Enter / Esc）。

## 资源致谢

- `public/alpine-lake.png` 背景山湖照片来自 WorkBuddy 参考工程（`C:\Users\hage2\WorkBuddy AI\2026-10-02-01-00-49`，AI 生成图）。
- 折射实现参考：samasante/liquid-glass（backdrop-filter url 活 DOM 位移 + 浏览器降级）、hwyuanzi/LiquidGlass-UI（双层高光、抬升交互）；苹果材质规则见 HIG「Materials / Liquid Glass」。
