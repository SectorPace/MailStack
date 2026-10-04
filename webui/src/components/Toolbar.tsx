// 顶部工具栏 —— 九要素：面包屑 / 搜索⌘K / 系统状态 / 时间范围 / 刷新 / 通知 / 主题 / 语言 / 管理员。
// 滚动边缘行为：内容滚动后获得更硬磨砂 + 1px 底部分隔线（.is-scrolled）。
import * as RDropdown from "@radix-ui/react-dropdown-menu";
import { motion, AnimatePresence } from "motion/react";
import { useSettings } from "../store/settings";
import type { RouteKey } from "../router";
import type { DictKey } from "../i18n";
import {
  IconBell,
  IconMenu,
  IconChevronDown,
  IconGlobe,
  IconMoon,
  IconRefresh,
  IconSun,
  IconUser,
} from "./icons";
import { GlassSelect } from "./ui";
import { BrandLogo } from "./BrandLogo";

const CRUMB: Record<RouteKey, { en: string; zhKey: DictKey }> = {
  dashboard: { en: "DASHBOARD", zhKey: "nav_dashboard" },
  ai: { en: "AI SUITE", zhKey: "nav_ai" },
  domains: { en: "DOMAINS", zhKey: "nav_domains" },
  users: { en: "USERS", zhKey: "nav_users" },
  aliases: { en: "ALIASES", zhKey: "nav_aliases" },
  relay: { en: "SMTP RELAY", zhKey: "nav_relay" },
  dkim: { en: "DKIM & DNS", zhKey: "nav_dkim" },
  tls: { en: "TLS CERTS", zhKey: "nav_tls" },
  queue: { en: "MAIL QUEUE", zhKey: "nav_queue" },
  logs: { en: "LOGS", zhKey: "nav_logs" },
  services: { en: "SERVICES", zhKey: "nav_services" },
  security: { en: "SECURITY", zhKey: "nav_security" },
  settings: { en: "SETTINGS", zhKey: "nav_settings" },
};

export type TimeRange = "24h" | "7d" | "30d" | "today";

export function Toolbar({
  route,
  nav,
  scrolled,
  onRefresh,
  range,
  setRange,
  openPalette,
  mode,
  onMenu,
  showMenu,
}: {
  route: RouteKey;
  nav: (r: RouteKey) => void;
  scrolled: boolean;
  onRefresh: () => void;
  range: TimeRange;
  setRange: (r: TimeRange) => void;
  openPalette: () => void;
  mode: "live" | "mock";
  onMenu?: () => void;
  showMenu?: boolean;
}) {
  const { t, prefs, resolvedTheme, setTheme, setLang } = useSettings();

  function cycleTheme() {
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  }
  function cycleLang() {
    setLang(prefs.lang === "zh" ? "en" : "zh");
  }

  const rangeOptions: { value: TimeRange; label: string }[] = [
    { value: "today", label: t("today") },
    { value: "24h", label: t("last_24h") },
    { value: "7d", label: t("last_7d") },
    { value: "30d", label: t("last_30d") },
  ];

  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

  return (
    <div
      className={`glass--toolbar sticky top-0 z-30 flex h-[54px] shrink-0 items-center gap-2 px-3 ${scrolled ? "is-scrolled" : ""}`}
      style={{ borderRadius: "var(--r-panel)" }}
      role="toolbar"
      aria-label="toolbar"
    >
      {/* 0. 汉堡菜单（<1024 抽屉模式） */}
      {showMenu && (
        <motion.button
          whileTap={{ scale: 0.9 }}
          transition={{ type: "spring", stiffness: 600, damping: 28 }}
          className="icon-btn glass--control mr-0.5 shrink-0"
          onClick={onMenu}
          aria-label="Menu"
        >
          <IconMenu size={17} />
        </motion.button>
      )}

      {/* 品牌字标（展板：工具栏左侧 MailStack） */}
      <div className="mr-1 hidden items-center gap-2 pl-1 lg:flex" aria-hidden>
        <BrandLogo size={22} radius={7} />
        <span className="text-[15px] font-semibold tracking-[-0.01em] text-[var(--text-1)]">MailStack</span>
      </div>

      {/* 1. 面包屑：英文大写 + 中文 */}
      <div className="hidden min-w-0 items-center gap-2 pl-1 sm:flex" aria-label="breadcrumb">
        <span className="hidden truncate text-[11px] font-semibold tracking-[0.08em] text-[var(--text-3)] lg:inline">
          {CRUMB[route].en}
        </span>
        <span className="hidden text-[11px] text-[var(--text-3)] lg:inline">/</span>
        <span className="truncate text-[13.5px] font-semibold text-[var(--text-1)]">{t(CRUMB[route].zhKey)}</span>
      </div>

      {/* 数据来源徽标：mock = 演示数据（琥珀），live = 已连接后端（绿） */}
      <span
        className={`badge hidden! xl:inline-flex ${mode === "mock" ? "badge-warn" : "badge-ok"}`}
        title={mode === "mock" ? t("mock_data") : t("live_data")}
      >
        <span className="dot" />
        {mode === "mock" ? t("mock_data") : t("live_data")}
      </span>

      {/* 3. 系统状态徽标 */}
      <span className="badge badge-ok hidden! sm:inline-flex" role="status" title={t("system_healthy")}>
        <span className="dot" />
        <span className="hidden md:inline">{t("system_healthy")}</span>
      </span>

      <div className="ml-auto flex items-center gap-1.5">
        {/* 4. 时间范围选择器（≥md） */}
        <div className="hidden md:block">
          <GlassSelect value={range} onChange={(v) => setRange(v as TimeRange)} options={rangeOptions} ariaLabel={t("last_24h")} width={116} />
        </div>

        {/* 5. 刷新 */}
        <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn hidden! sm:inline-flex" onClick={onRefresh} aria-label={t("refresh")} title={t("refresh")}>
          <IconRefresh size={16} />
        </motion.button>

        {/* 6. 通知（角标 + 下拉） */}
        <RDropdown.Root>
          <RDropdown.Trigger asChild>
            <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn" aria-label={t("notifications")} title={t("notifications")}>
              <IconBell size={16} />
              <span
                className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full"
                style={{ background: "rgb(var(--err-rgb))", boxShadow: "0 0 0 2px rgb(var(--glass-rgb) / 0.9)" }}
              />
            </motion.button>
          </RDropdown.Trigger>
          <RDropdown.Portal>
            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" style={{ width: 300 }}>
              <div className="flex items-center justify-between px-2.5 py-1.5 text-[12px] font-semibold text-[var(--text-2)]">
                {t("notifications")}
                <button className="text-[11.5px] font-normal text-[var(--accent)]">{t("mark_all_read")}</button>
              </div>
              <div className="radix-sep" />
              {[
                { id: "n1", level: "warn", time: "14:22", text: t("cert_expiry_alert") },
                { id: "n2", level: "info", time: "13:35", text: t("mail_queue_alert") },
                { id: "n3", level: "err", time: "13:12", text: t("security_alert") },
              ].map((n) => (
                <div key={n.id} className="radix-item items-start" role="listitem">
                  <span
                    className="mt-1 h-2 w-2 shrink-0 rounded-full"
                    style={{
                      background:
                        n.level === "err" ? "rgb(var(--err-rgb))" : n.level === "warn" ? "rgb(var(--warn-rgb))" : "rgb(var(--accent-rgb))",
                    }}
                  />
                  <div className="min-w-0">
                    <div className="text-[12.5px] leading-snug">{n.text}</div>
                    <div className="text-[11px] text-[var(--text-3)]">{stamp.slice(0, 11)}{n.time}</div>
                  </div>
                </div>
              ))}
            </RDropdown.Content>
          </RDropdown.Portal>
        </RDropdown.Root>

        {/* 7. 主题切换 */}
        <motion.button
          whileTap={{ scale: 0.9 }}
          transition={{ type: "spring", stiffness: 600, damping: 28 }}
          className="icon-btn"
          onClick={cycleTheme}
          aria-label={t("theme")}
          title={t("theme")}
        >
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={resolvedTheme}
              initial={{ rotate: -60, opacity: 0, scale: 0.7 }}
              animate={{ rotate: 0, opacity: 1, scale: 1 }}
              exit={{ rotate: 60, opacity: 0, scale: 0.7 }}
              transition={{ type: "spring", stiffness: 500, damping: 32 }}
              className="flex"
            >
              {resolvedTheme === "dark" ? <IconMoon size={16} /> : <IconSun size={16} />}
            </motion.span>
          </AnimatePresence>
        </motion.button>

        {/* 8. 语言切换 */}
        <motion.button
          whileTap={{ scale: 0.9 }}
          transition={{ type: "spring", stiffness: 600, damping: 28 }}
          className="icon-btn hidden! sm:inline-flex"
          onClick={cycleLang}
          aria-label={t("language")}
          title={t("language")}
        >
          <IconGlobe size={16} />
        </motion.button>

        {/* 9. 管理员菜单 */}
        <RDropdown.Root>
          <RDropdown.Trigger asChild>
            <button className="glass--control flex h-[34px] items-center gap-2 rounded-full py-0 pl-1 pr-2.5" aria-label={t("admin")}>
              <Avatar />
              <span className="hidden text-[13px] font-medium text-[var(--text-1)] sm:inline">admin</span>
              <IconChevronDown size={12} className="text-[var(--text-3)]" />
            </button>
          </RDropdown.Trigger>
          <RDropdown.Portal>
            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" style={{ minWidth: 200 }}>
              <div className="flex items-center gap-2.5 px-2.5 py-2">
                <Avatar size={34} />
                <div>
                  <div className="text-[13px] font-semibold text-[var(--text-1)]">admin</div>
                  <div className="text-[11px] text-[var(--text-3)]">admin@example.com</div>
                </div>
              </div>
              <div className="radix-sep" />
              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                <IconUser size={14} /> {t("admin_profile")}
              </RDropdown.Item>
              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                <BrandLogo size={14} radius={4} /> MailStack {t("settings_title")}
              </RDropdown.Item>
              <div className="radix-sep" />
              <RDropdown.Item className="radix-item" style={{ color: "rgb(var(--err-rgb))" }} onSelect={() => toastLogout()}>
                <IconMoon size={14} /> {t("logout")}
              </RDropdown.Item>
            </RDropdown.Content>
          </RDropdown.Portal>
        </RDropdown.Root>
      </div>
    </div>
  );
}

function toastLogout() {
  window.dispatchEvent(new CustomEvent("mailstack:logout"));
}

function Avatar({ size = 24 }: { size?: number }) {
  return (
    <span
      aria-hidden
      className="flex shrink-0 items-center justify-center rounded-full"
      style={{
        width: size,
        height: size,
        background: "linear-gradient(180deg, rgb(var(--accent-rgb)), rgb(var(--accent-deep-rgb)))",
        color: "#fff",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,.35), 0 0 0 1px rgba(255,255,255,.15)",
      }}
    >
      <IconUser size={size * 0.55} />
    </span>
  );
}
