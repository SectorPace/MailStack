// 侧边栏 —— 13 项导航，顺序/文案固定；三种形态自适应：
//   fixed：桌面（≥1280）固定玻璃层
//   rail：平板横屏（1024–1279）图标窄栏（hover/title 提示）
//   drawer：手机/平板竖屏（<1024）抽屉 + 遮罩
// 标签随界面语言单一显示。
import type { ComponentType } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { DICT, type DictKey } from "../i18n";
import type { RouteKey } from "../router";
import {
  IconAliases,
  IconSearch,
  IconCert,
  IconDashboard,
  IconGear,
  IconGlobe as IconDomains,
  IconKey as IconDKIM,
  IconLogs,
  IconQueue,
  IconRelay,
  IconServices,
  IconShield,
  IconSparkles,
  IconUsers,
} from "./icons";
import { BrandLogo } from "./BrandLogo";

export const NAV: { key: RouteKey; icon: ComponentType<{ size?: number }> }[] = [
  { key: "dashboard", icon: IconDashboard },
  { key: "ai", icon: IconSparkles },
  { key: "domains", icon: IconDomains },
  { key: "users", icon: IconUsers },
  { key: "aliases", icon: IconAliases },
  { key: "relay", icon: IconRelay },
  { key: "dkim", icon: IconDKIM },
  { key: "tls", icon: IconCert },
  { key: "queue", icon: IconQueue },
  { key: "logs", icon: IconLogs },
  { key: "services", icon: IconServices },
  { key: "security", icon: IconShield },
  { key: "settings", icon: IconGear },
];

const NAV_KEYS: Record<RouteKey, DictKey> = {
  dashboard: "nav_dashboard",
  ai: "nav_ai",
  domains: "nav_domains",
  users: "nav_users",
  aliases: "nav_aliases",
  relay: "nav_relay",
  dkim: "nav_dkim",
  tls: "nav_tls",
  queue: "nav_queue",
  logs: "nav_logs",
  services: "nav_services",
  security: "nav_security",
  settings: "nav_settings",
};

export type SidebarVariant = "fixed" | "rail" | "drawer";

export function Sidebar({
  route,
  nav,
  variant = "fixed",
  open = true,
  onClose,
  onSearch,
}: {
  route: RouteKey;
  nav: (r: RouteKey) => void;
  variant?: SidebarVariant;
  open?: boolean;
  onClose?: () => void;
  onSearch?: () => void;
}) {
  const { prefs } = useSettings();
  const zh = prefs.lang === "zh";
  const rail = variant === "rail";
  const drawer = variant === "drawer";
  const searchLabel = zh ? "搜索功能…" : "Search functions…";

  function handleNav(key: RouteKey) {
    nav(key);
    if (drawer) onClose?.();
  }

  return (
    <>
      {/* 抽屉遮罩 */}
      {drawer && (
        <div
          className="fixed inset-0 z-40 transition-opacity duration-300"
          style={{
            background: "rgba(8, 14, 24, 0.42)",
            backdropFilter: "blur(4px)",
            WebkitBackdropFilter: "blur(4px)",
            opacity: open ? 1 : 0,
            pointerEvents: open ? "auto" : "none",
          }}
          onClick={onClose}
          aria-hidden
        />
      )}

      <aside
        className="glass--sidebar edge-lens z-50 flex shrink-0 flex-col"
        style={{
          borderRadius: "var(--r-sidebar)",
          ...(drawer
            ? {
                position: "fixed",
                left: 10,
                top: 10,
                bottom: 10,
                width: 252,
                transform: open ? "translateX(0)" : "translateX(calc(-100% - 24px))",
                transition: "transform .38s cubic-bezier(.32,.72,0,1)",
              }
            : { margin: 10 }),
          ...(rail ? { width: 66, padding: "14px 8px 10px" } : drawer ? { padding: "14px 12px 12px" } : { width: 232, padding: "14px 12px 12px" }),
        }}
        aria-label="primary navigation"
      >
        {/* 品牌行 */}
        <div className={`flex items-center pb-3 pt-1 ${rail ? "justify-center px-0" : "gap-2.5 px-2"}`}>
          <BrandLogo size={26} />
          {!rail && (
            <span className="text-[16.5px] font-semibold tracking-[-0.01em] text-[var(--text-1)]">MailStack</span>
          )}
        </div>

        {/* 搜索入口（展板：侧边栏顶部搜索框 → 打开 ⌘K 命令面板） */}
      {!rail && (
        <button
          onClick={() => {
            onSearch?.();
            if (drawer) onClose?.();
          }}
          className="glass--well mb-2.5 flex h-[34px] w-full items-center gap-2 rounded-[10px] px-3 text-left transition-colors"
          style={{ color: "var(--text-3)" }}
          aria-label={searchLabel}
        >
          <IconSearch size={14} />
          <span className="flex-1 truncate text-[12.5px]">{searchLabel}</span>
          <span className="kbd">⌘K</span>
        </button>
      )}

      <nav className={`flex min-h-0 flex-1 flex-col overflow-y-auto ${rail ? "items-center gap-1" : "gap-0.5"}`}>
          {NAV.map((item) => {
            const active = route === item.key;
            const Icon = item.icon;
            const pair = DICT[NAV_KEYS[item.key] as keyof typeof DICT];
            const primary = zh ? pair[0] : pair[1];
            if (rail) {
              return (
                <button
                  key={item.key}
                  onClick={() => handleNav(item.key)}
                  aria-current={active ? "page" : undefined}
                  title={primary}
                  className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-full outline-none transition-colors"
                  style={{ color: active ? undefined : "var(--text-2)" }}
                >
                  {active && (
                    <motion.span
                      layoutId="nav-capsule"
                      className={`absolute inset-0 ${prefs.theme === "dark" ? "nav-capsule-dark" : "nav-capsule-light"}`}
                      style={{ borderRadius: 999 }}
                      transition={{ type: "spring", stiffness: 500, damping: 40, mass: 0.9 }}
                    />
                  )}
                  <span
                    className="relative z-10 flex"
                    style={{ color: active ? (prefs.theme === "dark" ? "var(--text-1)" : "#fff") : undefined }}
                  >
                    <Icon size={18} />
                  </span>
                </button>
              );
            }
            return (
              <button
                key={item.key}
                onClick={() => handleNav(item.key)}
                aria-current={active ? "page" : undefined}
                className="group relative flex h-[38px] shrink-0 items-center gap-2.5 rounded-full px-3 text-left outline-none transition-colors"
                style={{ color: active ? undefined : "var(--text-2)" }}
              >
                {active && (
                  <motion.span
                    layoutId="nav-capsule"
                    className={`absolute inset-0 ${prefs.theme === "dark" ? "nav-capsule-dark" : "nav-capsule-light"}`}
                    style={{ borderRadius: 999 }}
                    transition={{ type: "spring", stiffness: 500, damping: 40, mass: 0.9 }}
                  />
                )}
                <span
                  className="relative z-10 flex items-center gap-2.5"
                  style={{ color: active ? (prefs.theme === "dark" ? "var(--text-1)" : "#fff") : undefined }}
                >
                  <Icon size={17} />
                  <span className="nav-label min-w-0 flex-1 truncate text-[13.5px] font-medium">{primary}</span>
                </span>
              </button>
            );
          })}
        </nav>

      </aside>
    </>
  );
}
