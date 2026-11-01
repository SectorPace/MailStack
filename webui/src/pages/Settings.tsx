// 系统设置 —— macOS System Settings 结构（golden screen）：
// 左侧源列表分组导航（200-240px，sticky；通用/外观/邮件/安全 分组）+
// 右侧内容面板 = 分组表单（inset grouped rows：标签左 / 控件右，行高走
// --control-h-lg，发丝分隔从文本内缩，组容器 = --radius-panel + 发丝描边 +
// --surface 近实心面 —— 不用玻璃，玻璃预算仍归 chrome）。
// 功能与原竖排标签版完全一致：主题 / 强调色 / 透明度 / 背景 / 管理账户 / 2FA /
// 会话 / 邮件服务 / 通知 —— 仅视觉重组。
import { Fragment, useCallback, useEffect, useState, type ReactNode } from "react";
import * as RTabs from "@radix-ui/react-tabs";
import * as RSlider from "@radix-ui/react-slider";
import * as RSwitch from "@radix-ui/react-switch";
import { ACCENTS, useSettings, type Accent, type ThemeMode } from "../store/settings";
import { rpc } from "../api/client";
import { PageHeader, LoadError, StatusBadge, toast } from "../components/ui";
import { cssUrl } from "../lib/format";
import { IconMoon, IconSun, IconGear, IconCheck, IconShield, IconBell, IconSparkles, IconMail, IconSend, IconPlus } from "../components/icons";
import { BrandLogo } from "../components/BrandLogo";
import AccountSecurity from "../components/AccountSecurity";
import type { DictKey } from "../i18n";

// 后端 settings.get 返回的是 Settings（hostname / adminEmail / timezone /
// maxMessageSizeMb / rateLimitPerHour …），**没有 serverName**；故这里只编辑
// 后端确实支持的字段，settings.set 也只提交白名单内的键（其余键后端会丢弃）。
type ServerSettings = { hostname: string; adminEmail: string };
type ServiceRow = { key: string; running: boolean; detail: string };

/** 源列表分组：分组头走 set_group_* 词典键，条目沿用原页签词典。 */
const NAV_GROUPS: { id: string; labelKey: DictKey; items: { v: string; labelKey: DictKey; icon: ReactNode }[] }[] = [
  {
    id: "general",
    labelKey: "set_group_general",
    items: [
      { v: "general", labelKey: "general", icon: <IconGear size={14} /> },
      { v: "notifications", labelKey: "notifications_set", icon: <IconBell size={14} /> },
    ],
  },
  {
    id: "appearance",
    labelKey: "set_group_appearance",
    items: [{ v: "appearance", labelKey: "appearance", icon: <IconSparkles size={14} /> }],
  },
  {
    id: "mail",
    labelKey: "set_group_mail",
    items: [{ v: "mail", labelKey: "settings_mail", icon: <IconMail size={14} /> }],
  },
  {
    id: "security",
    labelKey: "set_group_security",
    items: [{ v: "security", labelKey: "security_set", icon: <IconShield size={14} /> }],
  },
];

export default function Settings() {
  const { t } = useSettings();
  // System Settings 默认落在第一项（通用）
  const [tab, setTab] = useState("general");

  return (
    <div className="p-4 pb-8">
      <PageHeader title={t("settings_title")} sub={t("settings_sub")} />

      <RTabs.Root
        value={tab}
        onValueChange={setTab}
        orientation="vertical"
        className="grid grid-cols-1 items-start gap-5 lg:grid-cols-[224px_minmax(0,1fr)]"
      >
        {/* 源列表：透明底（画布上直接分组），桌面 sticky 跟随滚动 */}
        <RTabs.List aria-label="settings sections" className="flex flex-col gap-4 lg:sticky lg:top-0">
          {NAV_GROUPS.map((g) => (
            <div key={g.id}>
              <div className="mb-1 px-2.5" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
                {t(g.labelKey)}
              </div>
              <div className="flex flex-col gap-0.5">
                {g.items.map((it) => (
                  <RTabs.Trigger key={it.v} value={it.v} className="vtab">
                    {it.icon}
                    {t(it.labelKey)}
                  </RTabs.Trigger>
                ))}
              </div>
            </div>
          ))}
          <div className="px-2.5 pt-1" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            MailStack
          </div>
        </RTabs.List>

        {/* 内容面板：分组表单（近实心 --surface 组容器，非玻璃） */}
        <div className="min-w-0 max-w-[640px]">
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

/* ---------------- 分组表单基元（System Settings inset grouped rows） ---------------- */

/** 组容器：--surface 近实心面 + --radius-panel + 发丝描边；组头 = caption 档灰字 */
function Group({
  title,
  description,
  children,
  className = "",
}: {
  title?: string;
  description?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={className}>
      {title && (
        <h2 className="mb-1.5 px-1 font-medium" style={{ fontSize: "var(--font-caption)", color: "var(--text-2)" }}>
          {title}
        </h2>
      )}
      {description && (
        <p className="mb-2 px-1" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
          {description}
        </p>
      )}
      <div
        className="overflow-hidden"
        style={{ background: "var(--surface)", borderRadius: "var(--radius-panel)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}
      >
        {children}
      </div>
    </section>
  );
}

/** 组内发丝分隔：左右从文本内缩（mx-4 对齐 px-4），不顶到容器边 */
function Sep() {
  return <div className="mx-4 h-px" style={{ background: "var(--hairline)" }} />;
}

/** 设置行：标签（+ 脚注）左、控件右；行高 --control-h-lg（桌面 32 / iOS 44） */
function Row({
  label,
  sub,
  control,
  sep = false,
}: {
  label: ReactNode;
  sub?: string;
  control: ReactNode;
  sep?: boolean;
}) {
  return (
    <div>
      {sep && <Sep />}
      <div className="flex items-center justify-between gap-6 px-4 py-2" style={{ minHeight: "var(--control-h-lg)" }}>
        <div className="min-w-0">
          <div className="font-medium text-[var(--text-1)]" style={{ fontSize: "var(--font-body)" }}>
            {label}
          </div>
          {sub && (
            <div className="mt-0.5" style={{ fontSize: "var(--font-caption)", color: "var(--text-2)" }}>
              {sub}
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">{control}</div>
      </div>
    </div>
  );
}

/** 开关设置行（本页专用 32px 密度；ui.tsx 的 ToggleRow 保留给其他页面） */
function SwitchRow({
  label,
  sub,
  checked,
  onChange,
  disabled,
  sep = false,
}: {
  label: string;
  sub?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  sep?: boolean;
}) {
  return (
    <div>
      {sep && <Sep />}
      <div
        className="flex items-center justify-between gap-6 px-4 py-2"
        style={{ minHeight: "var(--control-h-lg)", opacity: disabled ? 0.6 : undefined }}
      >
        <div className="min-w-0">
          <div className="font-medium text-[var(--text-1)]" style={{ fontSize: "var(--font-body)" }}>
            {label}
          </div>
          {sub && (
            <div className="mt-0.5" style={{ fontSize: "var(--font-caption)", color: "var(--text-2)" }}>
              {sub}
            </div>
          )}
        </div>
        <RSwitch.Root
          checked={checked}
          onCheckedChange={onChange}
          disabled={disabled}
          data-checked={String(checked)}
          className="radix-switch"
          aria-label={label}
        >
          <span className="knob" />
        </RSwitch.Root>
      </div>
    </div>
  );
}

/* ---------------- 通用设置 ---------------- */

function GeneralTab() {
  const { t } = useSettings();
  const [form, setForm] = useState<ServerSettings | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const load = useCallback(() => {
    rpc<ServerSettings>("settings.get").then((r) => {
      // {ok:true} 无载荷时保持 null（骨架屏），不把 undefined 塞进 form；
      // 失败不再静默 —— 原先失败页与加载页无法区分。
      if (r.ok && r.data) {
        setForm(r.data);
        setLoadErr(null);
      } else if (!r.ok) setLoadErr(r.error);
    });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loadErr)
    return (
      <Group>
        <div className="p-3">
          <LoadError message={loadErr} onRetry={load} />
        </div>
      </Group>
    );
  if (!form)
    return (
      <Group>
        <div className="skeleton m-4 h-24" />
      </Group>
    );

  return (
    <div className="space-y-5">
      <Group title={t("general")}>
        <Row
          label={t("hostname")}
          control={
            <input
              className="input"
              style={{ width: 260, maxWidth: "52vw" }}
              value={form.hostname}
              onChange={(e) => setForm({ ...form, hostname: e.target.value })}
            />
          }
        />
        <Row
          sep
          label={t("admin_email")}
          control={
            <input
              className="input"
              style={{ width: 260, maxWidth: "52vw" }}
              value={form.adminEmail}
              onChange={(e) => setForm({ ...form, adminEmail: e.target.value })}
            />
          }
        />
        <Sep />
        <div className="flex justify-end px-4 py-2.5">
          <button
            className="btn btn-accent"
            onClick={async () => {
              const r = await rpc("settings.set", { ...form });
              toast(r.ok ? t("saved") : r.error, r.ok ? "ok" : "err");
            }}
          >
            {t("save_changes")}
          </button>
        </div>
      </Group>

      <Group title="RPC">
        <div className="p-4 pt-3">
          <p className="mono leading-relaxed text-[var(--text-2)]" style={{ fontSize: 12 }}>
            POST /api/rpc {"{ action, data }"} → {"{ ok, data | error }"}
            <br />
            helper-ro.sock (RO) · helper.sock (RW) · uint32be + JSON
          </p>
        </div>
      </Group>
    </div>
  );
}

/* ---------------- 邮件服务 ---------------- */

function MailTab() {
  const { t } = useSettings();
  const [services, setServices] = useState<ServiceRow[] | null>(null);
  const [testOut, setTestOut] = useState("");

  useEffect(() => {
    // {ok:true} 无载荷时保持 null（骨架屏），不把 undefined 塞进 state。
    rpc<ServiceRow[]>("services.list").then((r) => {
      if (r.ok && r.data) setServices(r.data);
    });
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
    <div className="space-y-5">
      <Group title={t("settings_mail")}>
        {(services ?? []).map((s, i) => (
          <Fragment key={s.key}>
            {i > 0 && <Sep />}
            <Row
              label={NAME[s.key] ?? s.key}
              sub={s.detail}
              control={
                <StatusBadge
                  variant="dot"
                  kind={s.running ? "ok" : "err"}
                  label={s.running ? t("running") : t("stopped")}
                />
              }
            />
          </Fragment>
        ))}
        {!services && <div className="skeleton m-4 h-20" />}
      </Group>

      <Group title="Loopback Test">
        <div className="px-4 pt-3">
          <div
            className="glass--well mono min-h-[64px] rounded-[var(--radius-control)] p-3 leading-relaxed text-[var(--text-2)]"
            style={{ fontSize: 12 }}
          >
            {testOut || "$ mailstack mail test-loopback …"}
          </div>
        </div>
        <div className="flex justify-end px-4 py-2.5">
          <button
            className="btn btn-accent"
            onClick={async () => {
              setTestOut(t("loading"));
              const r = await rpc<{ success: boolean; message: string }>("mail.test_loopback", {});
              setTestOut(r.ok ? `${r.data.success ? "✓" : "✕"} ${r.data.message}` : r.error);
            }}
          >
            <IconSend size={14} /> {t("test")}
          </button>
        </div>
      </Group>
    </div>
  );
}

/* ---------------- 外观设置 ---------------- */

function AppearanceTab() {
  const { t, prefs, resolvedTheme, setTheme, setAccent, setGlassLevel, setFlag, customBg, setCustomBg } = useSettings();
  const zh = prefs.lang === "zh";
  const glassLabels = [t("ultra_clear"), t("clear"), t("balanced"), t("dimmed"), t("soft_dark")];
  const PRESETS = [
    { label: t("ultra_clear"), sw: "0.22" },
    { label: t("clear"), sw: "0.38" },
    { label: t("balanced"), sw: "0.55" },
    { label: t("dimmed"), sw: "0.72" },
    { label: t("soft_dark"), sw: "0.88" },
  ];

  return (
    <div className="max-w-[640px] space-y-5">
      {/* 主题三选一（蓝描边选项卡） */}
      <Group>
        <Row
          label={t("theme_label")}
          control={
            <div className="flex w-[300px] max-w-[54vw] gap-2">
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
          }
        />
      </Group>

      {/* Liquid Glass 个性化：滑杆 + 五档预设。
          提示语说明作用域 —— 内容卡片已固定为近实心表面，滑杆只影响侧栏/工具栏等
          chrome 玻璃（glass budget，见 index.css）。 */}
      <Group title={t("glass_personalization")} description={t("glass_personalization_sub")}>
        <Row
          label={t("glass_opacity")}
          sub={t("glass_opacity_hint")}
          control={
            <div className="flex w-[240px] max-w-[54vw] items-center gap-2.5">
              <RSlider.Root
                className="radix-slider flex-1"
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
              <span className="tnum badge badge-neutral">{prefs.glassLevel}%</span>
            </div>
          }
        />
        <Sep />
        <div className="p-4">
          {/* 五档预设（超清澈 0% → 柔和暗色 100%） */}
          <div className="preset-row">
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
          <div className="mt-1.5 text-center" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            {glassLabels[Math.min(4, Math.floor(prefs.glassLevel / 25))]}
          </div>
        </div>
      </Group>

      {/* 强调色（预览色用 resolvedTheme —— 「跟随系统」时取实际解析结果，不是原始偏好） */}
      <Group>
        <Row
          label={t("accent_color")}
          control={
            <div className="flex items-center gap-2.5">
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
                      background: resolvedTheme === "dark" ? a.dark : a.light,
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
          }
        />
      </Group>

      {/* 自定义背景：缩略图 + 上传；恢复默认单列一行 */}
      <Group>
        <Row
          label={t("custom_bg")}
          sub={t("custom_bg_sub")}
          control={
            <div className="flex items-center gap-3">
              <div
                className="h-[44px] w-[72px] shrink-0 overflow-hidden"
                style={{
                  borderRadius: "var(--radius-panel)",
                  // localStorage 里的值可被外部改写：url() 带引号并转义（lib/format.cssUrl）
                  backgroundImage: "url(" + cssUrl(customBg ?? "alpine-lake.png") + ")",
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
                    // 读文件 / 解码图片都可能失败：原先两个回调缺失时按钮点了没任何反馈。
                    reader.onerror = () => {
                      toast(zh ? "图片读取失败，请重试" : "Failed to read the image. Please retry.", "err");
                    };
                    reader.onload = () => {
                      const img = new Image();
                      img.onerror = () => {
                        toast(zh ? "图片解析失败，请换一张图片" : "Could not decode the image. Try another file.", "err");
                      };
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
            </div>
          }
        />
        <Row
          sep
          label={t("reset_default")}
          control={
            <button
              className="btn glass--control"
              disabled={!customBg}
              style={{ opacity: customBg ? 1 : 0.45 }}
              onClick={() => {
                setCustomBg(null);
                toast(t("saved"));
              }}
            >
              {t("reset_default")}
            </button>
          }
        />
      </Group>

      {/* 辅助功能：三个真实生效的降级开关 */}
      <Group title={t("accessibility")}>
        <SwitchRow
          label={t("reduce_transparency")}
          sub={t("reduce_transparency_sub")}
          checked={prefs.reduceTransparency}
          onChange={(v) => setFlag("reduceTransparency", v)}
        />
        <SwitchRow
          sep
          label={t("increase_contrast")}
          sub={t("increase_contrast_sub")}
          checked={prefs.increaseContrast}
          onChange={(v) => setFlag("increaseContrast", v)}
        />
        <SwitchRow
          sep
          label={t("reduce_motion")}
          sub={t("reduce_motion_sub")}
          checked={prefs.reduceMotion}
          onChange={(v) => setFlag("reduceMotion", v)}
        />
      </Group>

      {/* 实时预览 */}
      <Group title={t("live_preview")}>
        <div className="p-4">
          <LivePreview />
          <p className="mt-3 text-center" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            {t("changes_apply_live")}
          </p>
        </div>
      </Group>
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
  // 通知设置尚未在后端实现（settings.get / settings.set 均无对应字段）。原先这里
  // 摆了三个只写本地 useState 的假开关（SMTP / 队列 / 证书），从不持久化、也控制
  // 不了任何行为 —— 纯虚假 UI，已删除（同 Login.tsx 移除「保持登录」的先例）。
  // 待后端补上通知配置字段后再恢复真实开关。
  const { t } = useSettings();
  return (
    <Group title={t("notifications_set")}>
      <SwitchRow label={t("system_alerts_always")} checked disabled onChange={() => {}} />
    </Group>
  );
}
