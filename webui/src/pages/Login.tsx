// 登录页 —— 对齐原版 LoginView 功能：用户名/密码（明文切换）、TOTP 两段式登录、
// 保持登录、主机名指示、安全提示、右上角主题/语言快捷切换。Liquid Glass 材质。
import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { getMode, captureCsrf } from "../api/client";
import { rpc } from "../api/client";
import { BrandLogo } from "../components/BrandLogo";
import {
  IconUser,
  IconKey,
  IconEye,
  IconEyeOff,
  IconShield,
  IconSun,
  IconMoon,
  IconGlobe,
  IconChevronRight,
} from "../components/icons";

type LoginError = { code?: string; message?: string };

async function doLogin(username: string, password: string, totp?: string): Promise<void> {
  // mock 分支只存在于开发构建：生产包中该块被 Vite 剔除，因此不存在“任意口令登录”。
  if (import.meta.env.DEV && getMode() === "mock") {
    await new Promise((r) => setTimeout(r, 550));
    // 演示：密码 123456 → 触发两步验证；其他任意密码通过
    if (!totp && password === "123456") throw { code: "TOTP_REQUIRED" } as LoginError;
    if (username.trim().length === 0 || password.length === 0) throw { message: "invalid" } as LoginError;
    return;
  }
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password, ...(totp ? { code: totp } : {}) }),
  });
  if (res.ok) {
    const j = (await res.json().catch(() => ({}))) as { csrf?: string };
    captureCsrf(j.csrf);
    return;
  }
  // 后端失败响应是 { ok:false, error:{ code, message } }（error 是对象）；
  // 这里同时兼容扁平的 { code } / { error:"..." } 形态。
  const body = (await res.json().catch(() => ({}))) as {
    code?: string;
    error?: string | { code?: string; message?: string };
  };
  const errObj = typeof body.error === "object" ? body.error : undefined;
  const errCode =
    body.code ?? errObj?.code ?? (typeof body.error === "string" ? body.error : undefined);
  if (res.status === 401 && errCode === "TOTP_REQUIRED") {
    throw { code: "TOTP_REQUIRED" } as LoginError;
  }
  const msg = typeof body.error === "object" ? errObj?.message : body.error;
  throw { message: msg ?? `HTTP ${res.status}` } as LoginError;
}

export default function Login({ onOk }: { onOk: () => void }) {
  const { t, prefs, resolvedTheme, setTheme, setLang } = useSettings();
  const zh = prefs.lang === "zh";
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [busy, setBusy] = useState(false);
  const [totpStage, setTotpStage] = useState(false);
  const [totp, setTotp] = useState("");
  const [err, setErr] = useState("");
  const [hostname, setHostname] = useState("mail.example.com");

  useEffect(() => {
    rpc<{ hostname?: string }>("settings.get").then((r) => {
      if (r.ok && r.data?.hostname) setHostname(r.data.hostname);
    });
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    let totpStageNeeded = false;
    try {
      await doLogin(username.trim(), password, totpStage ? totp.trim() : undefined);
      setTotpStage(false);
      setTotp("");
      onOk();
    } catch (e2) {
      const le = e2 as LoginError;
      if (le.code === "TOTP_REQUIRED") {
        totpStageNeeded = true;
        setTotpStage(true);
        setTotp("");
        setErr(zh ? "需要两步验证：请输入身份验证器的 6 位验证码或恢复码" : "2FA required: enter the 6-digit code or a recovery code");
      } else {
        setErr(zh ? (totpStage ? "验证码不正确或已失效，请重试" : "登录失败：请检查用户名与密码") : le.message || "Login failed");
      }
    } finally {
      setBusy(false);
      if (!totpStageNeeded && !totpStage) setPassword("");
    }
  }

  const inputCls =
    "input pl-9 font-mono tracking-wide";

  return (
    <div className="relative flex min-h-full items-center justify-center p-4">
      {/* 右上角快捷工具：语言 / 主题（对齐原版） */}
      <div className="absolute right-4 top-4 z-20 flex items-center gap-2">
        <button className="icon-btn glass--control" onClick={() => setLang(zh ? "en" : "zh")} aria-label="Language" title="Language">
          <IconGlobe size={15} />
          <span className="ml-1 text-[10px] font-semibold">{zh ? "EN" : "中"}</span>
        </button>
        <button className="icon-btn glass--control" onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} aria-label={t("theme")} title={t("theme")}>
          {resolvedTheme === "dark" ? <IconSun size={15} /> : <IconMoon size={15} />}
        </button>
      </div>

      <motion.form
        onSubmit={submit}
        initial={{ opacity: 0, y: 14, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", stiffness: 380, damping: 34 }}
        className="glass--clear edge-lens relative w-full max-w-[420px] overflow-hidden rounded-[26px] p-7"
      >
        {/* 顶部柔光 */}
        <div
          aria-hidden
          className="pointer-events-none absolute -left-20 -top-24 h-56 w-56 rounded-full blur-3xl"
          style={{ background: "linear-gradient(135deg, rgb(var(--accent-rgb) / 0.18), transparent 70%)" }}
        />

        {/* Logo + 标题 */}
        <div className="relative flex flex-col items-center">
          <BrandLogo size={56} radius={15} />
          <h1 className="mt-3 text-[17px] font-bold tracking-wide text-[var(--text-1)]">
            {zh ? "登录管理后台" : "Admin Console Login"}
          </h1>
          <div className="mt-0.5 text-[11px] tracking-wider text-[var(--text-3)]">MailStack Admin</div>

          {/* 主机名指示 */}
          <div className="glass--well mt-4 flex items-center gap-2 rounded-full px-3.5 py-1.5 text-[11.5px]" style={{ color: "var(--text-2)" }}>
            <span className="h-2 w-2 rounded-full" style={{ background: "rgb(var(--accent-rgb))", boxShadow: "0 0 8px rgb(var(--accent-rgb) / 0.6)" }} />
            {zh ? "主机名" : "Hostname"}:
            <span className="font-mono font-semibold" style={{ color: "rgb(var(--accent-rgb))" }}>
              {hostname}
            </span>
          </div>
        </div>

        {/* 表单 */}
        <div className="relative mt-6 space-y-4">
          {!totpStage ? (
            <>
              <label className="block">
                <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-[var(--text-2)]">
                  {zh ? "用户名" : "Username"}
                </span>
                <span className="relative block">
                  <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[var(--text-3)]">
                    <IconUser size={15} />
                  </span>
                  <input autoFocus className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" required autoComplete="username" />
                </span>
              </label>

              <label className="block">
                <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-[var(--text-2)]">
                  {zh ? "管理口令" : "Password"}
                </span>
                <span className="relative block">
                  <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[var(--text-3)]">
                    <IconKey size={15} />
                  </span>
                  <input
                    type={showPass ? "text" : "password"}
                    className={inputCls + " pr-9"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    required
                    autoComplete="current-password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass(!showPass)}
                    className="absolute inset-y-0 right-0 flex items-center pr-3 text-[var(--text-3)] transition-colors hover:text-[var(--text-1)]"
                    aria-label={showPass ? "Hide password" : "Show password"}
                  >
                    {showPass ? <IconEyeOff size={15} /> : <IconEye size={15} />}
                  </button>
                </span>
              </label>
            </>
          ) : (
            <>
              <label className="block">
                <span className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-[var(--text-2)]">
                  {zh ? "两步验证码" : "2FA Code"}
                </span>
                <span className="relative block">
                  <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-[var(--text-3)]">
                    <IconShield size={15} />
                  </span>
                  <input
                    autoFocus
                    autoComplete="one-time-code"
                    className={inputCls + " tracking-[0.35em]"}
                    value={totp}
                    onChange={(e) => setTotp(e.target.value)}
                    placeholder="123456"
                    required
                  />
                </span>
              </label>
              <p className="text-[11px] leading-relaxed text-[var(--text-3)]">
                {zh
                  ? "输入身份验证器应用的 6 位验证码，或恢复码（形如 xxxxxxxx-xxxxxxxx）。"
                  : "Enter the 6-digit code from your authenticator app, or a recovery code (xxxxxxxx-xxxxxxxx)."}
              </p>
              <button
                type="button"
                onClick={() => {
                  setTotpStage(false);
                  setTotp("");
                  setPassword("");
                }}
                className="flex items-center gap-1 text-[12px] text-[var(--text-3)] transition-colors hover:text-[var(--accent)]"
              >
                ← {zh ? "返回，重新输入用户名与密码" : "Back, re-enter username & password"}
              </button>
            </>
          )}

          {/* 原先此处有「保持登录」复选框：后端 /api/auth/login 只接受
              username/password/code，会话 TTL 固定（HttpOnly Cookie Max-Age），
              勾选状态不参与任何请求构造 → 纯死控件，已删除。 */}

          {err && (
            <div className="rounded-[10px] px-3 py-2 text-[12px] leading-relaxed" style={{ color: "rgb(var(--err-rgb))", background: "rgb(var(--err-rgb) / 0.08)", boxShadow: "inset 0 0 0 1px rgb(var(--err-rgb) / 0.25)" }}>
              {err}
            </div>
          )}

          {/* 提交 */}
          <button type="submit" disabled={busy} className="btn btn-accent h-11 w-full text-[14px] font-bold" style={{ borderRadius: 12 }}>
            {busy ? (
              <span className="h-4.5 w-4.5 inline-block animate-spin rounded-full border-2 border-white/40 border-t-white" style={{ width: 18, height: 18 }} />
            ) : (
              <>
                {totpStage ? (zh ? "验证" : "Verify") : zh ? "登录" : "Sign In"}
                <IconChevronRight size={15} />
              </>
            )}
          </button>

          {import.meta.env.DEV && getMode() === "mock" && (
            <p className="text-center text-[10.5px] text-[var(--text-3)]">
              {zh ? "演示模式：任意密码可登录；输入 123456 体验两步验证" : "Demo: any password signs in. Use 123456 to try 2FA."}
            </p>
          )}
        </div>

        {/* 安全提示 */}
        <div className="glass--well relative mt-6 flex items-start gap-2.5 rounded-[14px] p-3.5 text-left">
          <IconShield size={16} className="mt-0.5 shrink-0" style={{ color: "rgb(var(--accent-rgb))" }} />
          <div className="space-y-1 text-[11px] leading-relaxed text-[var(--text-2)]">
            <p className="font-medium text-[var(--text-1)]">
              {zh ? "安全提示：建议仅通过 HTTPS、VPN 或 SSH 隧道访问管理后台。" : "Security tip: access the admin panel only via HTTPS, VPN, or SSH tunnel."}
            </p>
            <p className="text-[10px] text-[var(--text-3)]">
              {zh ? "PBKDF2-SHA256 · HttpOnly Session · CSRF Token · 登录限流" : "PBKDF2-SHA256 · HttpOnly session · CSRF token · rate limited"}
            </p>
          </div>
        </div>
      </motion.form>
    </div>
  );
}
