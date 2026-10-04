//! 路由处理器。
//!
//! **关键安全设计**：动作名在**路由注册时静态绑定**，处理器从请求体只读取
//! `data` 载荷。若改为「从请求体读取动作名」，请求体就能指定要执行的特权动作，
//! 白名单就形同虚设。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::error::{api_not_found, ApiError};
use crate::ratelimit::{ERR_INVALID_CREDENTIALS, ERR_TOTP_REQUIRED};
use crate::session::{forwarded_proto, session_cookie_secure};
use crate::{AppState, AuthenticatedUser};

/// 为一个特权动作生成处理器函数。
///
/// 用宏而不是「返回闭包」是刻意的：闭包方案需要把
/// `Fn(State, Option<Path>, Option<Json>) -> Pin<Box<dyn Future>>` 写进返回类型，
/// 既触发 `clippy::type_complexity`，也不如真实函数与 Axum 的 `Handler` 契合。
///
/// **动作名在编译期绑定**，处理器只从请求体读 `data` 载荷 —— 请求体无法指定
/// 要执行的特权动作，白名单因此不可被绕过。
macro_rules! action_handlers {
    ($($name:ident => $action:literal),* $(,)?) => {
        $(
            pub async fn $name(
                State(state): State<AppState>,
                path_params: Option<Path<HashMap<String, String>>>,
                body: Option<Json<serde_json::Value>>,
            ) -> Response {
                run_action(&state, $action, path_params, body).await
            }
        )*
    };
}

action_handlers! {
    domains_list            => "domains.list",
    domains_add             => "domains.add",
    domains_delete          => "domains.delete",
    snapshot_get            => "snapshot",
    logs_list               => "logs.list",
    metrics_realtime        => "metrics.realtime",
    check_port              => "network.check_port",
    settings_get            => "settings.get",
    settings_set            => "settings.set",
    admin_get               => "admin.get",
    aliases_add             => "aliases.add",
    aliases_delete          => "aliases.delete",
    dkim_rotate             => "dkim.rotate",
    totp_begin              => "admin.totp.begin",
    system_doctor           => "system.doctor",
    setup_status            => "setup.status",
    ai_config_get           => "ai.config.get",
    queue_action            => "queue.action",
    services_action         => "services.action",
    security_scan           => "security.scan",
    security_ban            => "security.ban",
    security_unban          => "security.unban",
    backup_list             => "backup.list",
    backup_create           => "backup.create",
    backup_restore          => "backup.restore",
    backup_delete           => "backup.delete",
    certs_list              => "certs.list",
    setup_identity          => "setup.identity.apply",
    setup_dns_verify        => "setup.dns.verify",
    setup_relay_test        => "setup.relay.test",
    setup_relay_apply       => "setup.relay.apply",
    setup_mail_test         => "setup.mail.test",
    mail_test_loopback      => "mail.test_loopback",
    users_add               => "users.add",
    users_list              => "users.list",
    users_status            => "users.status",
    users_password          => "users.password",
    users_delete            => "users.delete",
    aliases_list            => "aliases.list",
    certs_renew             => "certs.renew",
    setup_cert_issue        => "setup.cert.issue",
    ai_config_set           => "ai.config.set",
    ai_models_list          => "ai.models.list",
    ai_test                 => "ai.test",
    ai_chat                 => "ai.chat",
    ai_diagnose             => "ai.diagnose",
    ai_parse                => "ai.parse",
    // ── 为管理前端新增的只读列表动作（基线 50 条白名单里没有，属规格外扩展） ──
    // 前端把这 8 个动作当作独立页面/面板的数据源，缺一个对应界面就空转。
    queue_list              => "queue.list",
    services_list           => "services.list",
    dkim_keys               => "dkim.keys",
    dns_records             => "dns.records",
    metrics_system          => "metrics.system",
    activity_list           => "activity.list",
}

async fn run_action(
    state: &AppState,
    action: &'static str,
    path_params: Option<Path<HashMap<String, String>>>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    // 载荷：请求体 + 路径参数（如 :id / :name），语义与原实现一致。
    let mut data = body.map(|Json(v)| v).unwrap_or(serde_json::Value::Null);
    if data.is_null() {
        data = serde_json::json!({});
    }
    if let Some(obj) = data.as_object_mut() {
        if let Some(Path(params)) = path_params {
            for (k, v) in params {
                // 路径参数不覆盖显式提供的请求体字段。
                obj.entry(k).or_insert(serde_json::Value::String(v));
            }
        }
    }

    match state.inner.client.call(action, &data).await {
        Ok(value) => crate::error::ok_json(value),
        Err(e) => e.into_response(),
    }
}

/// `POST /api/admin` —— 改用户名 / 改口令（`admin.set`）。
///
/// ## 为什么这里必须吊销会话
///
/// 改密是事故响应的**第一步**，而在此之前 [`SessionStore::revoke_user`] 是死代码
/// —— 没有任何非测试调用点。于是「我改密码了」与「攻击者的会话失效了」之间
/// 毫无关系：攻击者那 7 天绝对上限内的会话仍然完全可用，第一步形同虚设。
///
/// ## 决策：**连当前会话一起吊销**，并要求重新登录
///
/// 备选方案是「保留当前会话、吊销其余全部」（`revoke_others`）。不选它的理由：
///
/// 1. **无法区分「当前会话」是不是攻击者的**。劫持场景下两种可能各占一半，
///    猜错的那一半等于没做任何事，而这恰恰是事故响应最不能承受的失败模式。
/// 2. **基线也是这么做的**：`server.production.ts` 的 `POST /api/admin` 在
///    `admin.set` 成功后 `sessions.clear()` 并回 `reauthenticate: true`，
///    明确要求重新登录。保持一致也让前端逻辑不必新增分支。
/// 3. 体验代价只有「再输一次口令」，而误判的代价是攻击者全身而退。
///
/// fail-closed 的含义也在这里：**宁可多登出一次**，不可少吊销一个。
///
/// ## 为什么用户名从 `admin.json` 读而不是从请求体取
///
/// 请求体的 `username` 可以是空串（「只改密码」是既有语义），也可能被篡改。
/// 吊销是**按用户维度全量生效**的操作，一旦用户名取错就会「踢光别人、留下自己」
/// —— 恰好与目的相反。以落盘配置为准才是真相源。
pub async fn admin_set(
    State(state): State<AppState>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let payload = json_body(body);

    if let Err(e) = state.inner.client.call("admin.set", &payload).await {
        // 失败**不吊销**：凭据没变，踢下线只会白白让用户重登，
        // 还把「改密失败」这个真正需要看到的事实盖掉。
        return e.into_response();
    }

    let Some(username) = admin_username(&state) else {
        return e500_missing_admin_config();
    };
    let mut response = revoke_sessions(&state, &username, serde_json::json!({ "ok": true }));
    clear_session_cookie(&mut response, &state);
    response
}

/// `POST /api/admin/2fa/enable` —— 启用 2FA。
///
/// 理由与 [`admin_set`] 相同，但要更严：`enable` 之后 2FA 才真正生效，
/// 而**在此之前建立的全部会话**都没有经过第二因子验证 —— 它们是在更弱的
/// 信任边界下拿到的，全部不再可信。
///
/// 响应体必须原样带回助手的 `recoveryCodes`：那是**只此一次**的明文，
/// 丢在这里就等于让用户永远拿不到恢复码（而没有恢复码的 2FA 等于没有）。
///
/// `begin` **不**走这里：它只是把 secret 交给用户，2FA 尚未生效，
/// 若此时踢下线，用户会发现自己刚点「开始绑定」就被登出（基线对此有明确
/// 注释：`wasEnabled` 为真时才清会话，否则每次 begin 都会把会话作废掉）。
pub async fn totp_enable(
    State(state): State<AppState>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let payload = json_body(body);
    match state.inner.client.call("admin.totp.enable", &payload).await {
        Ok(value) => {
            let Some(username) = admin_username(&state) else {
                return e500_missing_admin_config();
            };
            let mut response = revoke_sessions(&state, &username, value);
            clear_session_cookie(&mut response, &state);
            response
        }
        Err(e) => e.into_response(),
    }
}

/// `POST /api/admin/2fa/disable` —— 关 2FA。
///
/// 与 [`totp_enable`] 同一套收尾：2FA 消失之后，旧会话不再受第二因子保护，
/// 全部吊销并要求重新登录。**这里更不能「保留当前会话」** ——
/// 能发起这个请求的会话正是劫持来的。
pub async fn totp_disable(
    State(state): State<AppState>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let payload = json_body(body);
    match state
        .inner
        .client
        .call("admin.totp.disable", &payload)
        .await
    {
        Ok(value) => {
            let Some(username) = admin_username(&state) else {
                return e500_missing_admin_config();
            };
            let mut response = revoke_sessions(&state, &username, value);
            clear_session_cookie(&mut response, &state);
            response
        }
        Err(e) => e.into_response(),
    }
}

/// 请求体归一化：缺体与 `null` 都变成空对象。
fn json_body(body: Option<Json<serde_json::Value>>) -> serde_json::Value {
    match body.map(|Json(v)| v) {
        Some(v) if !v.is_null() => v,
        _ => serde_json::json!({}),
    }
}

/// 读落盘配置里的管理员用户名。
///
/// 读不到就返回 `None`：**吊销是按用户名全量生效的**，拿不到用户名时
/// 宁可显式报错，也不能「吊销 0 个」然后告诉用户「成功」。
fn admin_username(state: &AppState) -> Option<String> {
    mailstack_core::config::read_admin_config(state.paths()).map(|c| c.username)
}

/// 按用户维度**全量**吊销会话，并把助手的返回值原样包进响应。
///
/// 返回值里额外带 `revokedSessions` 与 `reauthenticate`：前者让用户知道
/// 「其它几个设备已登出」，后者告诉前端「请把会话作废并回登录页」。
fn revoke_sessions(state: &AppState, username: &str, mut value: serde_json::Value) -> Response {
    let revoked = state.inner.sessions.revoke_user(username);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("revokedSessions".to_string(), revoked.into());
        obj.insert("reauthenticate".to_string(), true.into());
    }
    crate::error::ok_json(value)
}

/// 下发一个「立即作废」的会话 Cookie。
///
/// `Max-Age=0` 让浏览器马上丢弃；`__Host-` 前缀与 `Secure` 必须与登录时
/// 下发的那一枚**逐字一致** —— 属性不同的同名 Cookie 在浏览器里是两条独立
/// 记录，只清掉一条的话另一条仍会被发回服务端（表现为「登出了但立刻又自动
/// 登录」）。
///
/// ## 为什么这里的 `Secure` 走保守判定
///
/// 本函数在**响应**阶段，没有请求头也没有对端地址可用（处理器已消费掉）。
/// 沿用 [`cookie_secure`] 的同一套判定：读显式配置项，读不到就不加 ——
/// 与登录路径的默认行为一致，因此「下发」与「作废」必然配对。
fn clear_session_cookie(response: &mut Response, state: &AppState) {
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        crate::SESSION_COOKIE,
        "",
    );
    if secure_cookie_from_env(state) {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// 只看显式配置项的 `Secure` 判定（响应阶段没有请求信息可用）。
///
/// **刻意不**在这里推断「当前是不是 https」：作废 Cookie 若与下发时算出的
/// 属性不一致，浏览器就清不掉那一枚 —— 那比多加一次 `Secure` 更糟。
/// 配置项是运维能同时对齐两处的唯一手段。
fn secure_cookie_from_env(state: &AppState) -> bool {
    let env_flag = std::env::var(crate::session::SESSION_COOKIE_SECURE_ENV).ok();
    session_cookie_secure(
        env_flag.as_deref(),
        state.inner.public_mode,
        None,
        &axum::http::HeaderMap::new(),
    )
}

/// `admin.json` 读不到时的 500。
///
/// 走到这里说明「凭据已改但吊销目标不明」，属于**半完成状态**：必须让调用方
/// 看见，而不是静默当作成功。
fn e500_missing_admin_config() -> Response {
    ApiError::new(
        crate::ratelimit::ERR_INTERNAL_ERROR,
        "administrator configuration is unreadable; sessions were not revoked",
    )
    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
    .into_response()
}

/// `POST /api/rpc` —— 管理前端的 RPC 桥。
///
/// 请求体形状：`{ "action": "<动作名>", "data": { ... } }`。
///
/// **这是全仓唯一从请求体读动作名的地方**，与本文件顶部「动作名编译期静态绑定」
/// 的纪律直接冲突。之所以仍要开这个口子：新前端把 RPC 桥当作**兜底传输层**
/// （它的 `restCall` 未命中映射表时回退到这里），没有它前端有一批动作会直接 404。
///
/// 安全性由两点保证，缺一不可：
/// 1. [`crate::contract::is_exposed_action`] —— 只放行**已有专门 HTTP 路由**的动作。
///    该集合是助手白名单的**真子集**，因此只被登录流程内部使用的
///    `admin.totp.verify` / `admin.totp.consume_recovery` 不会经此暴露到 HTTP 面。
/// 2. 破坏性动作的 `confirm: true` 由助手侧 `ActionGate` 强制，请求体绕不过去。
///
/// 响应形状与 REST 路由**相反**：这里必须带 `{ok, data}` 外壳，因为前端 `bridge()`
/// 按 `body.ok` / `body.data` 拆包（见 [`crate::error::rpc_ok_json`]）。
pub async fn rpc_bridge(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if !crate::contract::is_exposed_action(action) {
        // 不区分「动作不存在」与「动作未暴露」—— 否则内部动作名会成为可探测信息。
        return crate::error::rpc_err_json(StatusCode::BAD_REQUEST, "unknown action");
    }

    let data = body.get("data").cloned().unwrap_or(serde_json::Value::Null);
    let data = if data.is_null() {
        serde_json::json!({})
    } else {
        data
    };

    match state.inner.client.call(action, &data).await {
        Ok(value) => crate::error::rpc_ok_json(value),
        // 桥的错误是**字符串**：前端把它直接当消息展示。若沿用 REST 的嵌套形状，
        // 界面只会显示 "HTTP 5xx"，丢掉服务端给出的可读原因。
        Err(e) => crate::error::rpc_err_json(e.status, e.message.clone()),
    }
}

/// 取用于限流的客户端标识。
///
/// ## 为什么不能用 `X-Forwarded-For`
///
/// 本进程**默认只绑回环**（`bin/mailstack-web` 的 `DEFAULT_BIND = 127.0.0.1:8443`），
/// 生产靠反向代理 / SSH 隧道终止 TLS。那种拓扑下对端地址是 `127.0.0.1`，于是
/// per-IP 桶会退化成单桶 —— 原实现正是因此写死了 `let client_ip = "unknown"`。
/// 改成读 `X-Forwarded-For` 看似解决了问题，**却把限流器变成攻击者的工具**：
/// 头是请求体可控的明文，任何人都能每次换一个值，让「per-IP」桶对真正的爆破者
/// 永久失效。fail-closed 优先于「看起来能用」。
///
/// 因此这里只取**传输层真实对端**。反向代理拓扑下需要按跳数配置可信代理白名单，
/// 但那属于部署层决策，且在本进程默认绑回环的前提下没有收益 —— 故不做。
/// 真实来源仍然有效：SSH 隧道 / 本机 curl / 反代不隐藏时都能得到真实 IP，
/// 且**伪造不了**。
fn client_key(peer: Option<&SocketAddr>) -> String {
    match peer {
        Some(addr) => normalize_ip(addr.ip()),
        // 拿不到对端地址（测试里的 `oneshot`、未来的 in-process 调用）：
        // 用一个固定键而不是编造 IP，避免凭空造出「每个请求一个新桶」。
        None => "local".to_string(),
    }
}

/// 归一化 IP 的限流键：IPv4 映射形式折叠到 `::ffff:a.b.c.d` 的 `a.b.c.d`，
/// 去掉 IPv6 的 `%zone` 与大写写法。
fn normalize_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let mut s = v6.to_string();
            if let Some(idx) = s.find('%') {
                s.truncate(idx);
            }
            s.to_ascii_lowercase()
        }
    }
}

/// `POST /api/auth/login`。
///
/// 语义（规格书 §5.2、INV-23）：
/// * 三档限流 + 5 次失败账号锁定
/// * `401 INVALID_CREDENTIALS` **不区分**失败原因（枚举防护）
/// * **唯一例外**：密码正确但已启用 2FA → `401 TOTP_REQUIRED`
///
/// 会话建立后返回 `{ ok, csrf, username }` 并下发 HttpOnly Cookie。
///
/// ## 为什么 cookie 的 `Secure` 要逐请求判定
///
/// `Secure` 一旦加错方向，登录就**开箱即坏**（浏览器不再回传 cookie）。
/// 而「外部是不是 HTTPS」只有本进程能判定，且必须区分「可信来源」与
/// 「任何人可伪造的头」—— 详见 [`session_cookie_secure`]。
pub async fn login(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let code = body
        .get("code")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // 限流：三档桶 + 账号锁定。取**传输层真实对端**，不读 XFF（理由见 `client_key`）。
    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let client_ip = client_key(peer_addr.as_ref());
    match state.inner.login_limiter.check(&client_ip, &username) {
        crate::ratelimit::LimitVerdict::Allow => {}
        crate::ratelimit::LimitVerdict::Limited { retry_after_secs } => {
            return ApiError::rate_limited(retry_after_secs).into_response();
        }
    }

    // 口令校验：与原实现一致，Web 进程自己读 admin.json 做 PBKDF2 校验
    // （admin.json 是 0640 root:mailstack-admin，本进程属该组）。
    // 只有 TOTP 校验必须走助手 —— secret 以 AES-256-GCM 信封存放，
    // 主密钥 /etc/mailstack/totp.key 仅特权助手可读（INV-27、INV-28）。
    let Some(config) = mailstack_core::config::read_admin_config(state.paths()) else {
        // 尚未初始化：与原实现一样按凭证无效处理（不区分原因，防枚举）。
        state.inner.login_limiter.record_failure(&username);
        return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
            .with_status(StatusCode::UNAUTHORIZED)
            .into_response();
    };

    let password_ok = config.username == username
        && mailstack_core::password::verify_password(&config.password_record(), &password);

    if !password_ok {
        state.inner.login_limiter.record_failure(&username);
        return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
            .with_status(StatusCode::UNAUTHORIZED)
            .into_response();
    }

    // 口令正确：若已启用 2FA，则必须校验验证码。
    let two_factor_enabled = config
        .totp
        .as_ref()
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if two_factor_enabled {
        let Some(code) = code.as_deref().filter(|c| !c.is_empty()) else {
            // 唯一文档化的区分：密码正确但需要 2FA（INV-23 的刻意例外）。
            return ApiError::new(ERR_TOTP_REQUIRED, "two-factor code required")
                .with_status(StatusCode::UNAUTHORIZED)
                .into_response();
        };

        // secret 从不离开助手；恢复码消费是 mutation。
        let payload = serde_json::json!({ "username": username, "code": code });
        match state.inner.client.call("admin.totp.verify", &payload).await {
            Ok(result)
                if result
                    .get("valid")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) => {}
            Ok(_) => {
                // 验证码错误与口令错误返回同一响应体（不区分因子）。
                state.inner.login_limiter.record_failure(&username);
                return ApiError::new(ERR_INVALID_CREDENTIALS, "invalid credentials")
                    .with_status(StatusCode::UNAUTHORIZED)
                    .into_response();
            }
            Err(e) => {
                // 助手不可达 → 503，绝不因基础设施故障而放行（INV-8）。
                state.inner.login_limiter.record_failure(&username);
                return e.into_response();
            }
        }
    }

    state.inner.login_limiter.record_success(&username);
    let sid = state.inner.sessions.create(&username);
    let csrf = state
        .inner
        .sessions
        .touch(&sid)
        .map(|s| s.csrf)
        .unwrap_or_default();

    let cookie = build_session_cookie(
        &sid,
        &state,
        peer_addr.as_ref(),
        forwarded_proto(&headers).as_deref(),
    );

    let mut response = Json(serde_json::json!({
        "ok": true,
        "csrf": csrf,
        "username": username,
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// 组装会话 Cookie 的 `Set-Cookie` 值。
///
/// `__Host-` 前缀是常量（见 [`crate::SESSION_COOKIE`]）；`Secure` 由
/// [`session_cookie_secure`] 逐请求判定，理由见那里的注释（默认不加，
/// 以免把「只提供 HTTP」的默认部署弄成登不进去）。
fn build_session_cookie(
    sid: &str,
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> String {
    let mut cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        crate::SESSION_COOKIE,
        sid,
        crate::session::SESSION_TTL_SECONDS
    );
    if cookie_secure(state, peer, forwarded_proto) {
        cookie.push_str("; Secure");
    }
    cookie
}

/// 本次下发是否应带 `Secure`。
fn cookie_secure(
    state: &AppState,
    peer: Option<&SocketAddr>,
    forwarded_proto: Option<&str>,
) -> bool {
    let mut headers = axum::http::HeaderMap::new();
    if let Some(proto) = forwarded_proto {
        if let Ok(value) = HeaderValue::from_str(proto) {
            headers.insert("x-forwarded-proto", value);
        }
    }
    let env_flag = std::env::var(crate::session::SESSION_COOKIE_SECURE_ENV).ok();
    session_cookie_secure(env_flag.as_deref(), state.inner.public_mode, peer, &headers)
}

/// `GET /api/auth/sessions`。
pub async fn list_sessions(State(state): State<AppState>) -> Response {
    let sessions = state
        .inner
        .sessions
        .list_public(time::OffsetDateTime::now_utc());
    Json(serde_json::json!({ "ok": true, "sessions": sessions })).into_response()
}

/// `POST /api/auth/sessions/revoke` —— 体 `{ id }`（id 是**指纹**，不是会话 ID）。
pub async fn revoke_session(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let Some(fingerprint) = body.get("id").and_then(|v| v.as_str()) else {
        return ApiError::new("REQUEST_FAILED", "missing session fingerprint").into_response();
    };
    let revoked = state.inner.sessions.revoke_by_fingerprint(fingerprint);
    Json(serde_json::json!({ "ok": revoked })).into_response()
}

/// `DELETE /api/auth/sessions` —— 吊销除当前外的全部会话。
pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    let revoked = state.inner.sessions.revoke_others(&user.session_id);
    Json(serde_json::json!({ "ok": true, "revoked": revoked })).into_response()
}

/// `GET /api/admin/2fa` —— 由 Web 进程自身应答（契约里 `action` 为 `None`）。
///
/// 只返回**公开**状态：是否启用、还剩几张恢复码、处于 `pending` 还是 `enabled`。
/// secret 本身只存在于助手侧，因此这里不存在「读回 secret」的可能。
pub async fn admin_2fa(State(state): State<AppState>) -> Response {
    let public = mailstack_core::config::admin_public(state.paths());
    Json(serde_json::json!({
        "ok": true,
        "enabled": public.two_factor_enabled,
        "state": mailstack_core::totp::state_at(state.paths()).as_str(),
        "recoveryCodesRemaining": public.recovery_codes_remaining,
        "algorithm": "SHA1",
        "digits": mailstack_core::totp::TOTP_DIGITS,
        "period": mailstack_core::totp::TOTP_PERIOD_SECS,
    }))
    .into_response()
}

/// `GET /api/metrics/telemetry?range=...`。
///
/// 这条路由**不经助手**（契约里 `action` 为 `None`）：采样器就在 Web 进程内，
/// 见 [`crate::telemetry`]。响应是遥测对象本身，**不套 `{ok,data}` 外壳** ——
/// 与基线 `res.json(metricsCollector.getTelemetry(...))` 的形状一致。
pub async fn metrics_telemetry(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let range = params.get("range").map(String::as_str);
    Json(state.inner.telemetry.telemetry(range)).into_response()
}

/// `/api/*` 兜底：**必须**返回 JSON（规格书 §5.1）。
pub async fn api_fallback() -> Response {
    api_not_found()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_router;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use mailstack_core::paths::Paths;
    use tower::ServiceExt;

    fn test_state(tag: &str) -> (std::path::PathBuf, AppState) {
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-routes-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        (root.clone(), AppState::new(Paths::rooted(&root)))
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn session_listing_requires_authentication() {
        let (root, state) = test_state("sesslist");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn session_listing_returns_fingerprints_not_ids() {
        let (root, state) = test_state("sessfp");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/auth/sessions")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let text = serde_json::to_string(&body_json(response).await).unwrap();
        assert!(!text.contains(&sid), "不得暴露原始会话 ID");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn revoke_others_keeps_the_current_session() {
        let (root, state) = test_state("revokeothers");
        let keep = state.inner.sessions.create("admin");
        let csrf = state.inner.sessions.touch(&keep).unwrap().csrf;
        state.inner.sessions.create("admin");
        assert_eq!(state.inner.sessions.len(), 2);

        let app = build_router(state.clone());
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::DELETE)
                    .uri("/api/auth/sessions")
                    .header(header::COOKIE, format!("{}={keep}", crate::SESSION_COOKIE))
                    // DELETE 是变更方法，必须带 CSRF token（INV-6）。
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["revoked"], 1, "应吊销 1 个其它会话");
        assert!(
            state.inner.sessions.touch(&keep).is_some(),
            "当前会话必须保留"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn revoke_session_requires_an_id_field() {
        let (root, state) = test_state("revokenoid");
        let sid = state.inner.sessions.create("admin");
        let app = build_router(state);
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/auth/sessions/revoke")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", "wrong")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        // CSRF 先于业务校验触发。
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn public_mode_reads_never_fall_back_to_sudo() {
        // INV-26：公网模式下 RO socket 是唯一的特权读通道，不得 fallback 到 sudo。
        //
        // 本测试**不**依赖「助手不可达」这一环境假设 —— WSL 里可能恰好装着真实的
        // mailstack-privileged 包装器（本机上就有一个），那样断言会假失败。
        // 改为显式进入公网模式：此时即使 sudo 可用也必须拒绝（503）。
        let mut root = std::env::temp_dir();
        root.push(format!(
            "mailstack-routes-pubmode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let paths = Paths::rooted(&root);
        std::fs::create_dir_all(&paths.etc).unwrap();
        std::fs::write(&paths.install_args_conf, "ACCESS_MODE=direct\n").unwrap();

        let state = AppState::new(paths);
        assert!(state.inner.public_mode, "应判定为公网模式");

        let sid = state.inner.sessions.create("admin");
        let csrf = state.inner.sessions.touch(&sid).unwrap().csrf;
        let app = build_router(state);

        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/domains")
                    .header(header::COOKIE, format!("{}={sid}", crate::SESSION_COOKIE))
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(
            response.status(),
            StatusCode::OK,
            "公网模式 RO 不得经 sudo 成功"
        );
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "应返回 503（助手不可达），实际 {}",
            response.status()
        );
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "PRIVILEGED_HELPER_UNAVAILABLE");
        std::fs::remove_dir_all(&root).ok();
    }

    async fn post_login(app: axum::Router, payload: serde_json::Value) -> Response {
        app.oneshot(
            HttpRequest::builder()
                .method(axum::http::Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn login_with_correct_password_sets_httponly_cookie_and_returns_csrf() {
        let (root, state) = test_state("loginok");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();
        let app = build_router(state.clone());

        let response = post_login(
            app,
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            cookie.starts_with(&format!("{}=", crate::SESSION_COOKIE)),
            "cookie: {cookie}"
        );
        // `__Host-` 前缀是浏览器强制「必须 Secure + 必须 Path=/ + 不得有 Domain」
        // 的那条线，缺了它同站子域就能写同名 cookie 覆盖会话。
        assert!(
            crate::SESSION_COOKIE.starts_with("__Host-"),
            "会话 Cookie 必须带 `__Host-` 前缀，否则同站子域可覆盖它"
        );
        assert!(cookie.contains("HttpOnly"), "会话 Cookie 必须是 HttpOnly");
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        // 注意：默认部署只提供 HTTP，所以**不能**无条件断言 `Secure` ——
        // 加了它浏览器就不回传 cookie，登录会直接坏掉。`Secure` 由
        // `session_cookie_secure()` 判定，其行为由该函数的专属测试覆盖。

        let body = body_json(response).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["username"], "admin");
        assert!(body["csrf"].as_str().unwrap().len() == 64);
        assert_eq!(state.inner.sessions.len(), 1, "应建立一个会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_with_wrong_password_returns_indistinguishable_401() {
        // INV-23 枚举防护：不区分「账号不存在」与「口令错误」。
        let (root, state) = test_state("loginbad");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        let wrong_password = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "admin", "password": "Wr0ngPassword1" }),
        )
        .await;
        let unknown_user = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "nosuchuser", "password": "Tr0ubadour9x" }),
        )
        .await;

        assert_eq!(wrong_password.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unknown_user.status(), StatusCode::UNAUTHORIZED);

        let a = body_json(wrong_password).await;
        let b = body_json(unknown_user).await;
        assert_eq!(a, b, "两种失败必须返回完全相同的响应体");
        assert_eq!(a["error"]["code"], "INVALID_CREDENTIALS");
        // 不得泄露剩余尝试次数或哪个因子失败。
        let text = a.to_string();
        assert!(!text.contains("remaining"));
        assert_eq!(state.inner.sessions.len(), 0, "失败登录不得建立会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_reports_totp_required_when_two_factor_is_enabled() {
        // INV-23 的唯一文档化例外。
        let (root, state) = test_state("login2fa");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        // 注入已启用的 2FA 块。
        let path = &state.paths().admin_config;
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        value["totp"] = serde_json::json!({ "enabled": true, "recovery": [] });
        std::fs::write(path, serde_json::to_string_pretty(&value).unwrap()).unwrap();

        let response = post_login(
            build_router(state.clone()),
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(
            body["error"]["code"], "TOTP_REQUIRED",
            "密码正确但需 2FA 时必须回 TOTP_REQUIRED"
        );
        assert_eq!(state.inner.sessions.len(), 0, "未过 2FA 不得建立会话");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn login_before_initialization_is_indistinguishable_from_bad_credentials() {
        let (root, state) = test_state("loginuninit");
        // 不写 admin.json，直接尝试登录。
        let response = post_login(
            build_router(state),
            serde_json::json!({ "username": "admin", "password": "Tr0ubadour9x" }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = body_json(response).await;
        assert_eq!(body["error"]["code"], "INVALID_CREDENTIALS");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn repeated_failures_lock_the_account() {
        let (root, state) = test_state("loginlock");
        mailstack_core::config::admin_set(state.paths(), "admin", "Tr0ubadour9x").unwrap();

        for _ in 0..crate::ratelimit::FAILURE_LOCKOUT_THRESHOLD {
            let _ = post_login(
                build_router(state.clone()),
                serde_json::json!({ "username": "admin", "password": "Wr0ng1Password" }),
            )
            .await;
        }
        assert!(
            state.inner.login_limiter.is_locked("admin"),
            "连续失败达阈值必须锁定账号"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
