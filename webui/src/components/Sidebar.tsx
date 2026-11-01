// 侧边栏 —— Golden Gate 源列表形态：
//   桌面（fixed，≥1280）：全高贴边左栏（宽 --sidebar-width，无外边距/圆角），
//                         分组标题（概览/邮件/系统，11px），--control-h 行高（28px），
//                         16px 图标，accent 选中胶囊；可折叠成 56px 图标栏。
//   rail（1024–1279）：强制 56px 图标窄栏（hover/title 提示）。
//   drawer（<1024）：抽屉 + 遮罩，iOS 度量（44px 行高经 --control-h）。
// 标签随界面语言单一显示；分组标签同。
// 折叠持久化：prefs.sidebarCollapsed（store/settings.tsx；旧键
// mailstack.sidebar-collapsed 由 store 的 load() 一次性迁移并删除）。
// 抽屉 aside 挂 id="app-drawer"：Toolbar 汉堡的 aria-controls 指向它。
import { type ComponentType } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { DICT, type DictKey } from "../i18n";
import type { RouteKey } from "../router";
import {
  IconAliases,
  IconChevronRight,
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

export const NAV_KEYS: Record<RouteKey, DictKey> = {
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

/** 源列表分组（Golden Gate）：顺序覆盖 NAV 全部 13 项；标签随界面语言。 */
export const SIDEBAR_SECTIONS: { zh: string; en: string; keys: RouteKey[] }[] = [
  { zh: "概览", en: "Overview", keys: ["dashboard", "ai"] },
  { zh: "邮件", en: "Mail", keys: ["domains", "users", "aliases", "relay", "dkim", "tls", "queue"] },
  { zh: "系统", en: "System", keys: ["logs", "services", "security", "settings"] },
];

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
  const { prefs, setSidebarCollapsed } = useSettings();
  const zh = prefs.lang === "zh";
  const rail = variant === "rail";
  const drawer = variant === "drawer";
  // 折叠态走全局偏好（持久化 / 读写由 store 承担），不再自持 localStorage 键
  const collapsed = prefs.sidebarCollapsed;
  // 图标栏 = 强制窄栏（rail 断点）或桌面手动折叠
  const iconRail = rail || (variant === "fixed" && collapsed);
  const searchLabel = zh ? "搜索功能…" : "Search functions…";
  const collapseLabel = zh ? "折叠侧栏" : "Collapse sidebar";
  const expandLabel = zh ? "展开侧栏" : "Expand sidebar";

  function toggleCollapsed() {
    setSidebarCollapsed(!collapsed);
  }

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
        id="app-drawer"
        className="glass--sidebar edge-lens app-sidebar z-50 flex shrink-0 flex-col"
        data-variant={variant}
        style={{
          ...(drawer
            ? {
                position: "fixed",
                // 抽屉间隙：iOS profile = 10px；桌面断点回落档 --sidebar-inset 为 0，
                // max() 保底 8px，避免圆角纸贴死屏幕边缘
                left: "max(var(--sidebar-inset), 8px)",
                top: "max(var(--sidebar-inset), 8px)",
                bottom: "max(var(--sidebar-inset), 8px)",
                width: "var(--sidebar-width)",
                transform: open ? "translateX(0)" : "translateX(calc(-100% - 24px))",
                transition: "transform .38s cubic-bezier(.32,.72,0,1)",
                padding: "14px 12px 12px",
              }
            : iconRail
              ? { width: "var(--sidebar-rail-width)", padding: "12px 8px 10px" }
              : { width: "var(--sidebar-width)", padding: "12px 10px 12px" }),
        }}
        aria-label="primary navigation"
        aria-hidden={drawer && !open ? true : undefined}
        // 抽屉关闭后整体滑出屏幕，但内部按钮仍可 Tab 聚焦 —— 焦点跑进一个
        // 视觉上不存在的导航（WEBUI_AUDIT §3.2，与 App.tsx ScrollRail 同款处理）。
        // React 19 原生支持布尔 inert。
        inert={drawer && !open}
      >
        {/* 品牌行 */}
        <div className={`flex items-center pb-3 pt-1 ${iconRail ? "justify-center" : "gap-2.5 px-1.5"}`}>
          <BrandLogo size={26} />
          {!iconRail && (
            <span className="min-w-0 flex-1 truncate text-[16px] font-semibold tracking-[-0.01em] text-[var(--text-1)]">
              MailStack
            </span>
          )}
        </div>

        {/* 搜索入口（侧栏顶部搜索框 → 打开 ⌘K 命令面板） */}
        {!iconRail && (
          <button
            onClick={() => {
              onSearch?.();
              if (drawer) onClose?.();
            }}
            className="glass--well mb-2 flex w-full shrink-0 items-center gap-2 rounded-[var(--radius-control)] px-2.5 text-left transition-colors"
            style={{ height: "var(--control-h)", color: "var(--text-3)" }}
            aria-label={searchLabel}
          >
            <IconSearch size={14} />
            <span className="min-w-0 flex-1 truncate" style={{ fontSize: "var(--font-caption)" }}>
              {searchLabel}
            </span>
            <span className="kbd">⌘K</span>
          </button>
        )}

        <nav
          className={`min-h-0 flex-1 overflow-y-auto ${
            iconRail ? "flex flex-col items-center gap-1" : "flex flex-col"
          }`}
        >
          {iconRail
            ? NAV.map((item) => {
                const active = route === item.key;
                const Icon = item.icon;
                const pair = DICT[NAV_KEYS[item.key] as keyof typeof DICT];
                const primary = zh ? pair[0] : pair[1];
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
                      style={{ color: active ? (prefs.theme === "dark" ? "rgb(var(--accent-rgb))" : "#fff") : undefined }}
                    >
                      <Icon size={16} />
                    </span>
                  </button>
                );
              })
            : SIDEBAR_SECTIONS.map((section) => (
                <div key={section.en} className="pb-1">
                  {/* 11px 组头（--font-caption；iOS 13px） */}
                  <div
                    className="px-2.5 pb-1 pt-2.5 font-semibold uppercase tracking-[0.07em]"
                    style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}
                  >
                    {zh ? section.zh : section.en}
                  </div>
                  {section.keys.map((key) => {
                    const item = NAV.find((n) => n.key === key);
                    if (!item) return null;
                    const active = route === item.key;
                    const Icon = item.icon;
                    const pair = DICT[NAV_KEYS[item.key] as keyof typeof DICT];
                    const primary = zh ? pair[0] : pair[1];
                    return (
                      <button
                        key={item.key}
                        onClick={() => handleNav(item.key)}
                        aria-current={active ? "page" : undefined}
                        className="group relative flex h-[var(--control-h)] shrink-0 items-center gap-2 rounded-[var(--radius-control)] px-2.5 text-left outline-none transition-colors"
                        style={{ color: active ? undefined : "var(--text-2)" }}
                      >
                        {active && (
                          <motion.span
                            layoutId="nav-capsule"
                            className={`absolute inset-0 ${prefs.theme === "dark" ? "nav-capsule-dark" : "nav-capsule-light"}`}
                            style={{ borderRadius: "var(--radius-control)" }}
                            transition={{ type: "spring", stiffness: 500, damping: 40, mass: 0.9 }}
                          />
                        )}
                        <span
                          className="relative z-10 flex items-center gap-2"
                          style={{ color: active ? (prefs.theme === "dark" ? "rgb(var(--accent-rgb))" : "#fff") : undefined }}
                        >
                          <Icon size={16} />
                          <span
                            className="nav-label min-w-0 flex-1 truncate font-medium"
                            style={{ fontSize: "var(--font-body)" }}
                          >
                            {primary}
                          </span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              ))}
        </nav>

        {/* 折叠开关（仅 fixed 桌面形态；rail/drawer 的宽度由断点决定） */}
        {variant === "fixed" && (
          <div
            className={`mt-1 flex shrink-0 border-t pt-1.5 ${iconRail ? "justify-center" : "justify-end"}`}
            style={{ borderColor: "var(--hairline)" }}
          >
            <button
              className="icon-btn"
              style={{ width: 26, height: 26 }}
              onClick={toggleCollapsed}
              aria-expanded={!collapsed}
              aria-label={collapsed ? expandLabel : collapseLabel}
              title={collapsed ? expandLabel : collapseLabel}
            >
              <IconChevronRight size={14} className={collapsed ? "" : "rotate-180"} />
            </button>
          </div>
        )}
      </aside>
    </>
  );
}
