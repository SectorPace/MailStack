// 安全策略 —— 对齐原版 AdminAccountSettings（508 行）功能：
//   1. Web 管理员账户：用户名 + 新密码（更新并注销所有会话）
//   2. 两步验证 TOTP：开始绑定 → Secret/OTPAuth（可复制）→ 6 位验证码启用 → 恢复码（复制全部/我已保存）
//      已启用态：重新绑定（需验证码）/ 关闭两步验证（需验证码）
//   3. 活跃会话：列表 + 当前标记 + 单会话吊销 + 注销其他会话
import { useCallback, useEffect, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc, resetCsrf } from "../api/client";
import { toast } from "./ui";
import { IconCheck, IconKey, IconShield, IconUser } from "./icons";

type TwoFactorStatus = { enabled?: boolean; recoveryCodes?: string[] };
// 后端 admin.totp.begin 返回 otpauthUrl（不是 otpauthUri）；保留旧名作兼容。
type TwoFactorBegin = { secret?: string; otpauthUri?: string; otpauthUrl?: string };
// 后端 sessions.list 每项是 `{ id(指纹), username, createdAt, lastSeen }`
// （crates/web/src/session.rs list_public）——**没有** current/ip/userAgent/lastActive。
type SessionRow = { id: string; username?: string; createdAt?: string; lastSeen?: string };
/** admin.set / admin.totp.enable / disable 成功后会全量吊销会话并带这两个字段。 */
type Revocation = { revokedSessions?: number; reauthenticate?: boolean };

/** 后端在 admin.set / 2FA enable-disable 成功后**总是**吊销全部会话（含当前）。 */
function needsReauth(r: Revocation | undefined): boolean {
  return r?.reauthenticate === true || (r?.revokedSessions ?? 0) > 0;
}

function signOut() {
  resetCsrf();
  window.dispatchEvent(new CustomEvent("mailstack:logout"));
}


export default function AccountSecurity() {
  const { prefs } = useSettings();
  const zh = prefs.lang === "zh";

  /* ---- 1. 管理员账户 ---- */
  const [username, setUsername] = useState("admin");
  const [pass1, setPass1] = useState("");
  const [pass2, setPass2] = useState("");
  const [savingAcct, setSavingAcct] = useState(false);

  useEffect(() => {
    rpc<{ username?: string }>("admin.get").then((r) => {
      if (r.ok && (r.data as { username?: string })?.username) setUsername((r.data as { username?: string }).username!);
    });
  }, []);

  async function saveAccount() {
    if (pass1 && pass1 !== pass2) {
      toast(zh ? "密码不一致" : "Passwords do not match", "err");
      return;
    }
    if (pass1 && pass1.length < 8) {
      toast(zh ? "密码至少 8 位" : "Password must be at least 8 characters", "err");
      return;
    }
    setSavingAcct(true);
    const r = await rpc<Revocation>("admin.set", { username, password: pass1 || undefined });
    setSavingAcct(false);
    if (r.ok) {
      toast(zh ? "管理员账户已更新" : "Administrator updated");
      setPass1("");
      setPass2("");
      // 后端字段是 revokedSessions(number) + reauthenticate(bool)；原实现读 revokeSessions，
      // 条件恒为 false，于是「已注销所有会话」的提示永远不出现，用户带着已死的会话继续操作。
      if (needsReauth(r.data)) {
        toast(zh ? "所有会话已注销，请重新登录" : "All sessions were revoked. Sign in again.", "warn");
        setTimeout(signOut, 1200);
      }
    } else toast(r.error, "err");
  }

  /* ---- 2. 两步验证 ---- */
  const [totpEnabled, setTotpEnabled] = useState<boolean | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [begin, setBegin] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [enrollCode, setEnrollCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  /** 启用 2FA 后会话已被服务端吊销：恢复码必须**先保存**，再回登录页。 */
  const [reauthNeeded, setReauthNeeded] = useState(false);
  const [disableCode, setDisableCode] = useState("");
  const [disabling, setDisabling] = useState(false);

  useEffect(() => {
    rpc<TwoFactorStatus>("admin.2fa.status").then((r) => {
      if (r.ok) setTotpEnabled(!!(r.data as TwoFactorStatus)?.enabled);
    });
  }, []);

  async function beginEnroll() {
    const r = await rpc<TwoFactorBegin>("admin.2fa.begin", {});
    if (r.ok) {
      // 后端字段是 otpauthUrl，mock 是 otpauthUri。
      setBegin({ secret: r.data.secret ?? "", otpauthUri: r.data.otpauthUrl ?? r.data.otpauthUri ?? "" });
      setEnrolling(true);
      toast(zh ? "重新绑定已开始" : "Re-enrollment started");
    } else toast(r.error, "err");
  }

  async function confirmEnable() {
    const r = await rpc<{ recoveryCodes?: string[] } & Revocation>("admin.2fa.enable", { code: enrollCode.trim() });
    if (r.ok) {
      const d = r.data;
      setRecovery(d?.recoveryCodes ?? []);
      setTotpEnabled(true);
      setEnrollCode("");
      // 后端在 enable 成功后吊销**全部**会话并下发 Max-Age=0 cookie（routes.rs totp_enable）。
      // 原实现忽略 reauthenticate：UI 停在「已启用」，下一次写操作才 401 弹回登录页，
      // 且恢复码（只此一次）可能已被那次 401 冲掉。这里改为显式提示 + 保存后再登出。
      if (needsReauth(d)) {
        setReauthNeeded(true);
        toast(
          zh ? "两步验证已启用；所有会话已注销，请先保存恢复码，再重新登录" : "2FA enabled. All sessions were revoked — save the recovery codes, then sign in again.",
          "warn",
        );
      } else {
        toast(zh ? "两步验证已启用" : "2FA enabled");
      }
    } else toast(zh ? "启用失败，验证码不正确" : "Enabling failed, invalid code", "err");
  }

  async function confirmDisable() {
    setDisabling(true);
    const r = await rpc<Revocation>("admin.2fa.disable", { code: disableCode.trim() });
    setDisabling(false);
    if (r.ok) {
      setTotpEnabled(false);
      setEnrolling(false);
      setBegin(null);
      setDisableCode("");
      if (needsReauth(r.data)) {
        toast(zh ? "两步验证已关闭，所有会话已注销，请重新登录" : "2FA disabled. All sessions were revoked — sign in again.", "warn");
        setTimeout(signOut, 1200);
      } else {
        toast(zh ? "两步验证已关闭" : "Two-factor authentication disabled");
      }
    } else toast(zh ? "关闭失败，验证码不正确" : "Disabling failed, invalid code", "err");
  }

  async function copyAllCodes() {
    if (!recovery) return;
    try {
      await navigator.clipboard.writeText(recovery.join("\n"));
      toast(zh ? "恢复码已复制" : "Recovery codes copied");
    } catch {
      toast(zh ? "复制失败" : "Copy failed", "err");
    }
  }

  /* ---- 3. 活跃会话 ---- */
  const [sessions, setSessions] = useState<SessionRow[] | null>(null);

  const loadSessions = useCallback(() => {
    rpc<SessionRow[]>("sessions.list").then((r) => {
      if (r.ok) setSessions(Array.isArray(r.data) ? r.data : []);
    });
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  async function revoke(id: string) {
    const r = await rpc("sessions.revoke", { id });
    if (r.ok) {
      // 吊销后**重新拉取**真实列表，而不是本地猜「哪一行是当前会话」。
      loadSessions();
      toast(zh ? "会话已吊销" : "Session revoked");
    } else toast(r.error, "err");
  }

  async function revokeOthers() {
    // 后端对应的端点是 DELETE /api/auth/sessions（revoke 只认单个 id）。
    const r = await rpc("sessions.revokeOthers", {});
    if (r.ok) {
      // 原实现 `filter(x => x.current)`：后端从不返回 current，一行都删不掉 → UI 谎报成功。
      loadSessions();
      toast(zh ? "其他会话已注销" : "Other sessions revoked");
    } else toast(r.error, "err");
  }

  return (
    <div className="space-y-3">
      {/* 1. 管理员账户 */}
      <CardBlock title={zh ? "Web 管理员账户" : "Web Administrator Account"} icon={<IconUser size={15} />}>
        <FieldRow label={zh ? "管理员用户名" : "Administrator username"} value={username} onChange={setUsername} />
        <FieldRow label={zh ? "新密码，留空仅修改用户名" : "New password (blank to keep)"} value={pass1} onChange={setPass1} type="password" />
        <FieldRow label={zh ? "确认新密码" : "Confirm new password"} value={pass2} onChange={setPass2} type="password" />
        <button className="btn btn-accent mt-1" disabled={savingAcct} onClick={saveAccount}>
          {zh ? "更新并注销会话" : "Update & revoke sessions"}
        </button>
      </CardBlock>

      {/* 2. 两步验证 */}
      <CardBlock title={zh ? "两步验证" : "Two-Factor Authentication"} icon={<IconShield size={15} />} right={
        totpEnabled == null ? null : (
          <span className={`badge ${totpEnabled ? "badge-ok" : "badge-neutral"}`}>
            <span className="dot" />
            {totpEnabled ? (zh ? "已启用" : "Enabled") : zh ? "未启用" : "Disabled"}
          </span>
        )
      }>
        {totpEnabled === null && <div className="skeleton h-16" />}

        {/* 未启用 / 绑定中 */}
        {totpEnabled === false && !enrolling && (
          <button className="btn btn-accent" onClick={beginEnroll}>
            {zh ? "开始绑定" : "Begin setup"}
          </button>
        )}
        {enrolling && begin && !recovery && (
          <div className="space-y-3">
            <div className="glass--well space-y-2 rounded-[12px] p-3.5 text-[12px]">
              <div className="flex items-baseline justify-between gap-3">
                <span className="shrink-0 text-[var(--text-3)]">{zh ? "密钥 (Secret)" : "Secret Key"}</span>
                <span className="mono truncate font-semibold text-[var(--text-1)]">{begin.secret}</span>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <span className="shrink-0 text-[var(--text-3)]">OTPAuth URI</span>
                <span className="mono max-w-[280px] truncate text-[var(--text-2)]" title={begin.otpauthUri}>
                  {begin.otpauthUri}
                </span>
              </div>
              <button
                className="btn glass--control"
                style={{ height: 26, fontSize: 11 }}
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(begin.secret + "\n" + begin.otpauthUri);
                    toast(zh ? "已复制" : "Copied");
                  } catch {
                    toast(zh ? "复制失败" : "Copy failed", "err");
                  }
                }}
              >
                {zh ? "复制密钥与 URI" : "Copy secret & URI"}
              </button>
            </div>
            <FieldRow
              label={zh ? "6 位验证码或恢复码" : "6-digit code or recovery code"}
              value={enrollCode}
              onChange={setEnrollCode}
              mono
              placeholder="123456"
            />
            <div className="flex gap-2">
              <button className="btn btn-accent" disabled={!enrollCode.trim()} onClick={confirmEnable}>
                <IconCheck size={14} /> {zh ? "确认启用" : "Confirm & enable"}
              </button>
              <button className="btn glass--control" onClick={() => { setEnrolling(false); setBegin(null); }}>
                {zh ? "取消" : "Cancel"}
              </button>
            </div>
          </div>
        )}

        {/* 恢复码展示 */}
        {recovery && (
          <div className="space-y-3">
            <div className="rounded-[12px] p-3.5" style={{ background: "rgb(var(--warn-rgb) / 0.1)", boxShadow: "inset 0 0 0 1px rgb(var(--warn-rgb) / 0.3)" }}>
              <div className="text-[12px] font-semibold" style={{ color: "rgb(var(--warn-rgb))" }}>
                {zh ? "请立即保存恢复码（仅显示一次）" : "Save your recovery codes now (shown once)"}
              </div>
              <div className="mono mt-2 grid grid-cols-2 gap-1.5 text-[12px]" style={{ color: "var(--text-1)" }}>
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
              <div className="mt-3 flex gap-2">
                <button className="btn glass--control" style={{ height: 28, fontSize: 12 }} onClick={copyAllCodes}>
                  {zh ? "复制全部恢复码" : "Copy all recovery codes"}
                </button>
                <button
                  className="btn btn-accent"
                  style={{ height: 28, fontSize: 12 }}
                  onClick={() => {
                    setRecovery(null);
                    setEnrolling(false);
                    if (reauthNeeded) {
                      // 会话已在服务端被吊销：保存好恢复码后回登录页（否则下一次请求才 401）
                      signOut();
                      return;
                    }
                    toast(zh ? "绑定完成" : "Setup finished");
                  }}
                >
                  {zh ? "我已保存恢复码，完成绑定" : "I have saved my recovery codes"}
                </button>
              </div>
              {reauthNeeded && (
                <div className="mt-2 text-[11.5px] leading-relaxed" style={{ color: "rgb(var(--warn-rgb))" }}>
                  {zh
                    ? "所有会话已被注销（含当前会话）。请先保存恢复码，再点击完成并重新登录。"
                    : "All sessions were revoked (including this one). Save the recovery codes, then finish and sign in again."}
                </div>
              )}
            </div>
          </div>
        )}

        {/* 已启用 */}
        {totpEnabled && !recovery && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-[12px] text-[var(--text-2)]">
              <IconKey size={13} />
              {zh ? "登录时需要身份验证器的 6 位验证码或恢复码。" : "A 6-digit authenticator code or recovery code is required at sign-in."}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button className="btn glass--control" onClick={beginEnroll}>
                {zh ? "重新绑定" : "Re-enroll"}
              </button>
            </div>
            <FieldRow label={zh ? "关闭两步验证：输入验证码" : "Disable 2FA: enter code"} value={disableCode} onChange={setDisableCode} mono placeholder="123456" />
            <button className="btn" style={{ background: "rgb(var(--err-rgb))", color: "#fff" }} disabled={!disableCode.trim() || disabling} onClick={confirmDisable}>
              {zh ? "关闭两步验证" : "Disable 2FA"}
            </button>
          </div>
        )}
      </CardBlock>

      {/* 3. 活跃会话 */}
      <CardBlock
        title={zh ? "活跃会话" : "Active Sessions"}
        icon={<IconShield size={15} />}
        right={
          sessions && sessions.length > 1 ? (
            <button className="btn glass--control" style={{ height: 26, fontSize: 11 }} onClick={revokeOthers}>
              {zh ? "注销其他会话" : "Sign out other sessions"}
            </button>
          ) : null
        }
      >
        {!sessions && <div className="skeleton h-20" />}
        {sessions && sessions.length === 0 && (
          <div className="text-[12px] text-[var(--text-3)]">{zh ? "暂无会话信息" : "No session information available"}</div>
        )}
        {sessions && sessions.length > 0 && (
          <div className="space-y-2">
            <div className="text-[11px] leading-relaxed text-[var(--text-3)]">
              {zh
                ? "后端只返回 id（指纹）/ 用户名 / 创建时间 / 最近活动，不标记「当前会话」；吊销当前会话会立即登出。"
                : "The backend returns id (fingerprint) / username / createdAt / lastSeen only and does not mark the current session. Revoking your own session signs you out."}
            </div>
            {sessions.map((s) => (
              <div
                key={s.id}
                className="flex items-center justify-between gap-3 rounded-[12px] px-3 py-2.5 text-[12px]"
                style={{ background: "rgb(var(--text-1) / 0.04)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}
              >
                <div className="min-w-0 leading-tight">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium text-[var(--text-1)]">{s.username ?? "—"}</span>
                    <span className="mono shrink-0 text-[10.5px] text-[var(--text-3)]" title={s.id}>
                      {s.id.slice(0, 12)}
                    </span>
                  </div>
                  <div className="truncate text-[11px] text-[var(--text-3)]">
                    {zh ? "最近活动" : "Last seen"} {s.lastSeen || "—"} · {zh ? "创建" : "Created"} {s.createdAt || "—"}
                  </div>
                </div>
                <button className="btn glass--control" style={{ height: 26, fontSize: 11, color: "rgb(var(--err-rgb))" }} onClick={() => revoke(s.id)}>
                  {zh ? "吊销" : "Revoke"}
                </button>
              </div>
            ))}
          </div>
        )}
      </CardBlock>
    </div>
  );
}

/* ---- 小部件 ---- */

function CardBlock({
  title,
  icon,
  right,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass edge-lens rounded-[var(--r-panel)] p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-[13.5px] font-semibold text-[var(--text-1)]">
          <span
            className="flex h-7 w-7 items-center justify-center rounded-[9px]"
            style={{ background: "rgb(var(--accent-rgb) / 0.11)", color: "rgb(var(--accent-rgb))" }}
          >
            {icon}
          </span>
          {title}
        </h3>
        {right}
      </div>
      {children}
    </div>
  );
}

function FieldRow({
  label,
  value,
  onChange,
  type = "text",
  mono,
  placeholder,
  disabled,
}: {
  label: string;
  value: string;
  onChange?: (v: string) => void;
  type?: string;
  mono?: boolean;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <label className="mb-2.5 block">
      <span className="mb-1.5 block text-[11.5px] font-semibold text-[var(--text-2)]">{label}</span>
      <input
        className={"input" + (mono ? " font-mono" : "")}
        type={type}
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        onChange={(e) => onChange?.(e.target.value)}
      />
    </label>
  );
}
