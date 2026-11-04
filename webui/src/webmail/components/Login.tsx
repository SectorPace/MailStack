import { useState, type FormEvent } from "react";
import { ApiError, isDemoMode, login } from "../api";
import type { SessionInfo } from "../types";
import { useMailPrefs } from "../store/prefs";
import { MailBrandLogo, IconGlobe, IconMoon, IconSun, IconUser, IconKey, IconShield, IconChevronRight, IconEye, IconEyeOff } from "./icons";
export function Login({ expired, onLoggedIn }: {
    expired: boolean;
    onLoggedIn: (session: SessionInfo) => void;
}) {
    const { t, prefs, resolvedTheme, setTheme, setLang } = useMailPrefs();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [networkError, setNetworkError] = useState(false);
    const demo = isDemoMode();
    async function submit(e: FormEvent) {
        e.preventDefault();
        if (busy)
            return;
        setError("");
        setNetworkError(false);
        setBusy(true);
        try {
            const session = await login(email.trim(), password);
            onLoggedIn(session);
        }
        catch (err) {
            if (err instanceof ApiError) {
                if (err.network) {
                    setNetworkError(true);
                    setError(t("login_network"));
                }
                else if (err.status === 429 || err.code === "TOO_MANY_ATTEMPTS") {
                    setError(t("login_too_many"));
                }
                else if (err.status === 401 || err.code === "INVALID_CREDENTIALS") {
                    setError(t("login_invalid"));
                }
                else {
                    setError(err.message || t("unexpected_error"));
                }
            }
            else {
                setError(t("unexpected_error"));
            }
        }
        finally {
            setBusy(false);
            setPassword("");
        }
    }
    return (<div className="mail-login">
      <div className="mail-login-tools">
        <button type="button" className="icon-btn glass--control" onClick={() => setLang(prefs.lang === "zh" ? "en" : "zh")} aria-label={t("language")} title={t("language")}>
          <IconGlobe size={15}/>
          <span className="mail-lang-tag">{prefs.lang === "zh" ? "EN" : "中"}</span>
        </button>
        <button type="button" className="icon-btn glass--control" onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} aria-label={t("theme")} title={t("theme")}>
          {resolvedTheme === "dark" ? <IconSun size={15}/> : <IconMoon size={15}/>}
        </button>
      </div>

      <form className="mail-login-card" onSubmit={submit}>
        <div className="mail-login-brand">
          <MailBrandLogo dark={resolvedTheme === "dark"} size={54}/>
          <h1 className="mail-login-title">{t("login_title")}</h1>
          <div className="mail-login-subtitle">MailStack Webmail</div>
          <div className="mail-login-host">{t("login_subtitle")}</div>
        </div>

        {expired && !error && (<div className="mail-login-notice" role="status">
            {t("login_session_expired")}
          </div>)}

        <label className="mail-login-field">
          <span className="mail-login-label">{t("login_email")}</span>
          <span className="mail-login-input-wrap">
            <span className="mail-login-icon" aria-hidden>
              <IconUser size={15}/>
            </span>
            <input className="input mail-login-input" type="email" required autoFocus autoComplete="username" value={email} placeholder={t("login_email_placeholder")} onChange={(e) => setEmail(e.target.value)}/>
          </span>
        </label>

        <label className="mail-login-field">
          <span className="mail-login-label">{t("login_password")}</span>
          <span className="mail-login-input-wrap">
            <span className="mail-login-icon" aria-hidden>
              <IconKey size={15}/>
            </span>
            <input className="input mail-login-input mail-login-input--password" type={showPassword ? "text" : "password"} required autoComplete="current-password" value={password} placeholder="••••••••••••" onChange={(e) => setPassword(e.target.value)}/>
            <button type="button" className="mail-login-eye" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((v) => !v)}>
              {showPassword ? <IconEyeOff size={15}/> : <IconEye size={15}/>}
            </button>
          </span>
        </label>

        {error && (<div className="mail-login-error" role="alert">
            {error}
            {networkError && <div className="mail-login-error-hint">{t("login_network_hint")}</div>}
          </div>)}

        <button type="submit" className="btn btn-accent mail-login-submit" disabled={busy}>
          {busy ? t("login_signing_in") : t("login_sign_in")}
          {!busy && <IconChevronRight size={15}/>}
        </button>

        {demo && <div className="mail-login-demo">{t("demo_hint")}</div>}

        <div className="mail-login-security">
          <IconShield size={15}/>
          <div>
            <div className="mail-login-security-title">{t("login_secure_hint")}</div>
            <div className="mail-login-security-protocol">{t("login_protocol")}</div>
          </div>
        </div>
      </form>
    </div>);
}
