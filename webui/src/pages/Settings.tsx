// 系统设置 —— 展板形态：左侧竖排标签导航（基础/邮件服务/安全策略/通知/外观）+ 右侧内容面板。
// 外观页含：主题三选一、Liquid Glass 透明度滑杆 + 五档预设、强调色、三个真实生效的降级开关、实时预览。
import { useEffect, useState } from "react";
import * as RTabs from "@radix-ui/react-tabs";
import * as RSlider from "@radix-ui/react-slider";
import * as RSwitch from "@radix-ui/react-switch";
import { ACCENTS, useSettings, type Accent, type ThemeMode } from "../store/settings";
import { rpc } from "../api/client";
import { PageHeader, Card, ToggleRow, toast } from "../components/ui";
import { IconMoon, IconSun, IconGear, IconCheck, IconShield, IconBell, IconSparkles, IconMail, IconSend, IconPlus } from "../components/icons";
import { BrandLogo } from "../components/BrandLogo";
import AccountSecurity from "../components/AccountSecurity";
import type { DictKey } from "../i18n";
import type { ReactNode } from "react";

// 后端 settings.get 返回的是 Settings（hostname / adminEmail / timezone /
// maxMessageSizeMb / rateLimitPerHour …），**没有 serverName**；故这里只编辑
// 后端确实支持的字段，settings.set 也只提交白名单内的键（其余键后端会丢弃）。
type ServerSettings = { hostname: string; adminEmail: string };
type ServiceRow = { key: string; running: boolean; detail: string };

const TABS: { v: string; labelKey: DictKey; icon: ReactNode }[] = [
  { v: "general", labelKey: "general", icon: <IconGear size={14} /> },
  { v: "mail", labelKey: "settings_mail", icon: <IconMail size={14} /> },
  { v: "security", labelKey: "security_set", icon: <IconShield size={14} /> },
  { v: "notifications", labelKey: "notifications_set", icon: <IconBell size={14} /> },
  { v: "appearance", labelKey: "appearance", icon: <IconSparkles size={14} /> },
];

export default function Settings() {
  const { t } = useSettings();
  const [tab, setTab] = useState("appearance");

  return (
    <div className="p-4">
      <PageHeader title={t("settings_title")} sub={t("settings_sub")} />

      <RTabs.Root
        value={tab}
        onValueChange={setTab}
        orientation="vertical"
        className="grid grid-cols-1 items-start gap-3 lg:grid-cols-[196px_minmax(0,1fr)]"
      >
        {/* 竖排标签（展板形态：激活项浅蓝胶囊） */}
        <RTabs.List aria-label="settings sections" className="glass edge-lens flex flex-col gap-1 rounded-[var(--r-panel)] p-2">
          {TABS.map((x) => (
            <RTabs.Trigger key={x.v} value={x.v} className="vtab">
              {x.icon}
              {t(x.labelKey)}
            </RTabs.Trigger>
          ))}
          <div className="mt-1 px-3 pb-1 pt-1 text-[10px] text-[var(--text-3)]">MailStack v0.8.0</div>
        </RTabs.List>

        <div className="min-w-0">
          <RTabs.Content value="general" className="focus-visible:outline-none">
            <GeneralTab />
          </RTabs.Content>
          <RTabs.Content value="mail" className="focus-visible:outline-none">
            <MailTab />
          </RTabs.Content>
          <RTabs.Content value="security" className="focus-visible:outline-none">
            <AccountSecurity />
          </RTabs.Content>
          <RTabs.Content value="notifications" className="focus-visible:outline-none">
            <NotificationsTab />
          </RTabs.Content>
          <RTabs.Content value="appearance" className="focus-visible:outline-none">
            <AppearanceTab />
          </RTabs.Content>
        </div>
      </RTabs.Root>
    </div>
  );
}

/* ---------------- 基础设置 ---------------- */

function GeneralTab() {
  const { t } = useSettings();
  const [form, setForm] = useState<ServerSettings | null>(null);

  useEffect(() => {
    rpc<ServerSettings>("settings.get").then((r) => r.ok && setForm(r.data));
  }, []);

  if (!form) return <Card className="h-40">&nbsp;</Card>;

  return (
    <div className="space-y-3">
      <Card>
        <h2 className="mb-3 text-[14px] font-semibold text-[var(--text-1)]">{t("general")}</h2>
        <Field label={t("hostname")} value={form.hostname} onChange={(v) => setForm({ ...form, hostname: v })} />
        <Field label={t("admin_email")} value={form.adminEmail} onChange={(v) => setForm({ ...form, adminEmail: v })} />
        <button
          className="btn btn-accent mt-2"
          onClick={async () => {
            const r = await rpc("settings.set", { ...form });
            toast(r.ok ? t("saved") : r.error, r.ok ? "ok" : "err");
          }}
        >
          {t("save_changes")}
        </button>
      </Card>
      <Card>
        <h2 className="mb-1 text-[14px] font-semibold text-[var(--text-1)]">RPC</h2>
        <p className="mono text-[12px] leading-relaxed text-[var(--text-2)]">
          POST /api/rpc {"{ action, data }"} → {"{ ok, data | error }"}
          <br />
          helper-ro.sock (RO) · helper.sock (RW) · uint32be + JSON
        </p>
      </Card>
    </div>
  );
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="mb-3 block">
      <span className="mb-1.5 block text-[12.5px] font-medium text-[var(--text-2)]">{label}</span>
      <input className="input" value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

/* ---------------- 邮件服务（展板新增标签页） ---------------- */

function MailTab() {
  const { t } = useSettings();
  const [services, setServices] = useState<ServiceRow[] | null>(null);
  const [testOut, setTestOut] = useState("");

  useEffect(() => {
    rpc<ServiceRow[]>("services.list").then((r) => r.ok && setServices(r.data));
  }, []);

  const NAME: Record<string, string> = {
    smtp: "SMTP · Postfix",
    imap: "IMAP / POP3 · Dovecot",
    lmtp: "LMTP · Dovecot",
    dkim: "DKIM · Rspamd",
    webmail: "Webmail",
    admin: "Admin Console",
  };

  return (
    <div className="space-y-3">
      <Card>
        <h2 className="mb-3 text-[14px] font-semibold text-[var(--text-1)]">{t("settings_mail")}</h2>
        <div className="space-y-2">
          {(services ?? []).map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-3 rounded-[12px] px-3 py-2.5 text-[12.5px]" style={{ background: "rgb(var(--text-1) / 0.04)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
              <div className="leading-tight">
                <div className="font-medium text-[var(--text-1)]">{NAME[s.key] ?? s.key}</div>
                <div className="mono text-[11px] text-[var(--text-3)]">{s.detail}</div>
              </div>
              <span className={`badge ${s.running ? "badge-ok" : "badge-err"}`}>
                <span className="dot" />
                {s.running ? t("running") : t("stopped")}
              </span>
            </div>
          ))}
          {!services && <div className="skeleton h-24" />}
        </div>
      </Card>

      <Card>
        <h2 className="mb-2.5 text-[14px] font-semibold text-[var(--text-1)]">Loopback Test</h2>
        <div className="glass--well mono min-h-[72px] rounded-[12px] p-3 text-[12px] leading-relaxed text-[var(--text-2)]">
          {testOut || "$ mailstack mail test-loopback …"}
        </div>
        <button
          className="btn btn-accent mt-3"
          onClick={async () => {
            setTestOut(t("loading"));
            const r = await rpc<{ success: boolean; message: string }>("mail.test_loopback", {});
            setTestOut(r.ok ? `${r.data.success ? "✓" : "✕"} ${r.data.message}` : r.error);
          }}
        >
          <IconSend size={14} /> Test
        </button>
      </Card>
    </div>
  );
}

/* ---------------- 外观设置 ---------------- */

function AppearanceTab() {
  const { t, prefs, setTheme, setAccent, setGlassLevel, setFlag, customBg, setCustomBg } = useSettings();
  const glassLabels = [t("ultra_clear"), t("clear"), t("balanced"), t("dimmed"), t("soft_dark")];
  const PRESETS = [
    { label: t("ultra_clear"), sw: "0.22" },
    { label: t("clear"), sw: "0.38" },
    { label: t("balanced"), sw: "0.55" },
    { label: t("dimmed"), sw: "0.72" },
    { label: t("soft_dark"), sw: "0.88" },
  ];

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,560px)_minmax(0,420px)]">
      {/* 左列 */}
      <Card>
        {/* 主题三选一（蓝描边选项卡，对齐示意图） */}
        <h2 className="text-[13.5px] font-semibold text-[var(--text-1)]">{t("theme_label")}</h2>
        <div className="mt-2.5 flex gap-2">
          {(
            [
              { v: "light", label: t("light"), icon: <IconSun size={15} /> },
              { v: "dark", label: t("dark"), icon: <IconMoon size={15} /> },
              { v: "system", label: t("system"), icon: <IconGear size={15} /> },
            ] as { v: ThemeMode; label: string; icon: ReactNode }[]
          ).map((o) => (
            <button
              key={o.v}
              className="option-card"
              data-active={prefs.theme === o.v}
              aria-pressed={prefs.theme === o.v}
              onClick={() => setTheme(o.v)}
            >
              {o.icon}
              {o.label}
            </button>
          ))}
        </div>

        {/* Liquid Glass 个性化 */}
        <h2 className="mt-6 text-[13.5px] font-semibold text-[var(--text-1)]">{t("glass_personalization")}</h2>
        <p className="mt-0.5 text-[12px] text-[var(--text-2)]">{t("glass_personalization_sub")}</p>

        <div className="mt-4">
          <div className="mb-1 flex items-center justify-between text-[12.5px]">
            <span className="font-medium text-[var(--text-1)]">{t("glass_opacity")}</span>
            <span className="tnum badge badge-neutral">{prefs.glassLevel}%</span>
          </div>
          <RSlider.Root
            className="radix-slider"
            value={[prefs.glassLevel]}
            min={0}
            max={100}
            step={5}
            aria-label={t("glass_opacity")}
            onValueChange={([v]) => setGlassLevel(v)}
          >
            <RSlider.Track className="radix-track">
              <RSlider.Range className="radix-range" />
            </RSlider.Track>
            <RSlider.Thumb className="radix-thumb" aria-label={t("glass_opacity")} />
          </RSlider.Root>
          <div className="mt-1.5 flex justify-between text-[10.5px] text-[var(--text-3)]">
            <span>{t("ultra_clear")} (0%)</span>
            <span>{glassLabels[Math.min(4, Math.floor(prefs.glassLevel / 25))]}</span>
            <span>{t("soft_dark")} (100%)</span>
          </div>
        </div>

        {/* 五档预设（超清澈 0% → 柔和暗色 100%，对齐展板样式） */}
        <div className="preset-row mt-3">
          {PRESETS.map((p, i) => (
            <button
              key={p.label}
              className="preset-box"
              data-active={Math.abs(prefs.glassLevel - i * 25) < 12.5}
              aria-label={`${p.label} ${i * 25}%`}
              onClick={() => setGlassLevel(i * 25)}
            >
              <span className="preset-swatch" style={{ ["--sw" as string]: p.sw }}>
                <i />
              </span>
              <div className="pl">{p.label}</div>
              <div className="pv">({i * 25}%)</div>
            </button>
          ))}
        </div>

        {/* 强调色 */}
        <h2 className="mt-6 text-[13.5px] font-semibold text-[var(--text-1)]">{t("accent_color")}</h2>
        <div className="mt-2.5 flex items-center gap-2.5">
          {(Object.keys(ACCENTS) as Accent[]).map((k) => {
            const a = ACCENTS[k];
            const active = prefs.accent === k;
            return (
              <button
                key={k}
                aria-label={a.label}
                title={a.label}
                onClick={() => setAccent(k)}
                className="relative flex h-8 w-8 items-center justify-center rounded-full transition-transform"
                style={{
                  background: prefs.theme === "dark" ? a.dark : a.light,
                  boxShadow: active
                    ? "0 0 0 2px var(--canvas), 0 0 0 4px rgb(var(--accent-rgb)), inset 0 1px 0 rgba(255,255,255,.4)"
                    : "inset 0 1px 0 rgba(255,255,255,.4), 0 1px 3px rgba(10,22,40,.25)",
                  transform: active ? "scale(1.05)" : undefined,
                }}
              >
                {active && <IconCheck size={14} className="text-white" />}
              </button>
            );
          })}
        </div>

        {/* 自定义背景 */}
        <h2 className="mt-6 text-[13.5px] font-semibold text-[var(--text-1)]">{t("custom_bg")}</h2>
        <p className="mt-0.5 text-[12px] text-[var(--text-2)]">{t("custom_bg_sub")}</p>
        <div className="mt-2.5 flex items-center gap-3">
          <div
            className="h-[44px] w-[72px] shrink-0 overflow-hidden rounded-[10px]"
            style={{
              backgroundImage: "url(" + (customBg ?? "alpine-lake.png") + ")",
              backgroundSize: "cover",
              backgroundPosition: "center 48%",
              boxShadow: "inset 0 0 0 1px var(--hairline)",
            }}
          />
          <label className="btn glass--control cursor-pointer">
            <IconPlus size={14} /> {t("upload_image")}
            <input
              type="file"
              accept="image/*"
              className="hidden!"
              onChange={(e) => {
                const file = e.target.files && e.target.files[0];
                e.target.value = "";
                if (!file) return;
                const reader = new FileReader();
                reader.onload = () => {
                  const img = new Image();
                  img.onload = () => {
                    const max = 1920;
                    const scale = Math.min(1, max / Math.max(img.width, img.height));
                    const canvas = document.createElement("canvas");
                    canvas.width = Math.round(img.width * scale);
                    canvas.height = Math.round(img.height * scale);
                    canvas.getContext("2d")?.drawImage(img, 0, 0, canvas.width, canvas.height);
                    try {
                      setCustomBg(canvas.toDataURL("image/jpeg", 0.85));
                      toast(t("saved"));
                    } catch {
                      toast("storage full", "err");
                    }
                  };
                  img.src = String(reader.result);
                };
                reader.readAsDataURL(file);
              }}
            />
          </label>
          <button
            className="btn glass--control"
            disabled={!customBg}
            style={{ opacity: customBg ? 1 : 0.45 }}
            onClick={() => { setCustomBg(null); toast(t("saved")); }}
          >
            {t("reset_default")}
          </button>
        </div>

        {/* 辅助功能 */}
        <h2 className="mt-6 text-[13.5px] font-semibold text-[var(--text-1)]">{t("accessibility")}</h2>
        <div className="mt-1 flex flex-col gap-1">
          <div className="hairline-b">
            <ToggleRow
              title={t("reduce_transparency")}
              sub={t("reduce_transparency_sub")}
              checked={prefs.reduceTransparency}
              onChange={(v) => setFlag("reduceTransparency", v)}
            />
          </div>
          <div className="hairline-b">
            <ToggleRow
              title={t("increase_contrast")}
              sub={t("increase_contrast_sub")}
              checked={prefs.increaseContrast}
              onChange={(v) => setFlag("increaseContrast", v)}
            />
          </div>
          <ToggleRow
            title={t("reduce_motion")}
            sub={t("reduce_motion_sub")}
            checked={prefs.reduceMotion}
            onChange={(v) => setFlag("reduceMotion", v)}
          />
        </div>
      </Card>

      {/* 右列：实时预览 */}
      <Card>
        <h2 className="mb-3 text-[13.5px] font-semibold text-[var(--text-1)]">{t("live_preview")}</h2>
        <LivePreview />
        <p className="mt-3 text-center text-[11.5px] text-[var(--text-3)]">{t("changes_apply_live")}</p>
      </Card>
    </div>
  );
}

/** 实时预览窗 —— 迷你控制台套在山景光场上方，随全局设置即时变化 */
function LivePreview() {
  const { t, resolvedTheme } = useSettings();
  const dark = resolvedTheme === "dark";
  return (
    <div
      className="relative overflow-hidden rounded-[14px]"
      style={{
        height: 300,
        background: dark
          ? "linear-gradient(180deg, #17233a 0%, #0e1522 55%, #0a0d14 100%)"
          : "linear-gradient(180deg, #a8c8ec 0%, #d8e6f6 45%, #f0e8da 100%)",
      }}
    >
      {/* 山与水面 */}
      <div
        className="absolute inset-x-0 bottom-0"
        style={{
          height: "46%",
          background: dark
            ? "radial-gradient(120% 100% at 30% 100%, rgba(46,76,110,.85) 0%, rgba(28,44,66,.9) 60%)"
            : "radial-gradient(120% 100% at 30% 100%, rgba(120,152,190,.75) 0%, rgba(160,185,210,.8) 60%)",
          clipPath: "polygon(0 68%, 14% 42%, 30% 60%, 46% 30%, 62% 58%, 78% 38%, 100% 64%, 100% 100%, 0 100%)",
        }}
      />
      <div
        className="absolute inset-x-0 bottom-0"
        style={{
          height: "18%",
          background: dark ? "linear-gradient(180deg, rgba(90,130,180,.28), rgba(20,30,45,.9))" : "linear-gradient(180deg, rgba(255,255,255,.5), rgba(190,210,230,.65))",
        }}
      />
      {/* 迷你控制台 */}
      <div className="absolute inset-4 flex gap-2.5">
        <div className="glass edge-lens flex w-[38%] flex-col gap-1.5 rounded-[14px] p-2.5">
          <div className="flex items-center gap-1.5">
            <BrandLogo size={15} radius={5} />
            <span className="text-[10.5px] font-semibold text-[var(--text-1)]">MailStack</span>
          </div>
          <div
            className="mt-1 flex items-center gap-1.5 rounded-full px-2 py-1 text-[9.5px] font-medium"
            style={
              dark
                ? { background: "linear-gradient(180deg, rgba(7,11,18,.86), rgba(9,14,24,.78))", color: "var(--text-1)", boxShadow: "inset 0 1px 0 rgba(255,255,255,.09), 0 0 0 1px rgba(0,0,0,.45)" }
                : { background: "linear-gradient(180deg, rgb(var(--accent-rgb)), rgb(var(--accent-deep-rgb)))", color: "#fff" }
            }
          >
            <IconGear size={10} /> {t("nav_dashboard")}
          </div>
          {[t("nav_domains"), t("nav_users"), t("nav_queue")].map((x) => (
            <div key={x} className="flex items-center gap-1.5 rounded-full px-2 py-1 text-[9.5px] text-[var(--text-2)]">
              <span className="h-2.5 w-2.5 rounded-[4px]" style={{ background: "rgb(var(--text-1) / 0.14)" }} />
              {x}
            </div>
          ))}
        </div>
        <div className="glass edge-lens flex flex-1 flex-col gap-2 rounded-[14px] p-2.5">
          <div className="flex items-center justify-between">
            <span className="text-[10.5px] font-semibold text-[var(--text-1)]">{t("dash_title")}</span>
            <span className="badge badge-ok" style={{ height: 14, fontSize: 8, padding: "0 5px" }}>
              <span className="dot" style={{ width: 4, height: 4 }} /> OK
            </span>
          </div>
          <div className="grid grid-cols-3 gap-1.5">
            {[t("total_domains"), t("mailbox_users"), t("mail_queue")].map((x, i) => (
              <div key={x} className="glass--well rounded-[9px] px-1.5 py-1.5">
                <div className="text-[7.5px] text-[var(--text-2)]">{x}</div>
                <div className="tnum text-[12px] font-semibold text-[var(--text-1)]">{[8, 1248, 23][i]}</div>
              </div>
            ))}
          </div>
          <div className="glass--well flex flex-1 items-center justify-center rounded-[9px]">
            <svg viewBox="0 0 100 36" className="w-full px-2">
              <path d="M2 28 C14 24, 18 14, 30 18 S 48 28, 60 20 S 84 8, 98 12" fill="none" stroke="rgb(var(--accent-rgb))" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </div>
        </div>
      </div>
      {/* 玻璃反光 */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: "linear-gradient(115deg, rgba(255,255,255,.16) 0%, rgba(255,255,255,0) 32%)" }}
      />
    </div>
  );
}

/* ---------------- 通知设置 ---------------- */

function NotificationsTab() {
  const { t } = useSettings();
  const [mail, setMail] = useState(true);
  const [queue, setQueue] = useState(true);
  const [certs, setCerts] = useState(true);
  return (
    <Card className="max-w-[560px]">
      <h2 className="mb-1 text-[14px] font-semibold text-[var(--text-1)]">{t("notifications_set")}</h2>
      <ToggleRow title="SMTP" sub="postfix@mailstack" checked={mail} onChange={setMail} />
      <ToggleRow title={t("mail_queue")} sub="queue.action" checked={queue} onChange={setQueue} />
      <ToggleRow title={t("tls_title")} sub="certs.renew" checked={certs} onChange={setCerts} />
      <div className="mt-4 flex items-center gap-2.5 rounded-[12px] p-3" style={{ background: "rgb(var(--accent-rgb) / 0.08)" }}>
        <RSwitch.Root checked disabled data-checked="true" className="radix-switch" aria-label="system">
          <span className="knob" />
        </RSwitch.Root>
        <span className="text-[12px] text-[var(--text-2)]">System alerts · always on</span>
      </div>
    </Card>
  );
}
