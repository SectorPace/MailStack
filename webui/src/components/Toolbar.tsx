// 顶部工具栏 —— 九要素：面包屑 / 搜索⌘K / 系统状态 / 时间范围 / 刷新 / 通知 / 主题 / 语言 / 管理员。
// 滚动边缘行为：内容滚动后获得更硬磨砂 + 1px 底部分隔线（.is-scrolled）。
import * as RDropdown from "@radix-ui/react-dropdown-menu";
import { motion, AnimatePresence } from "motion/react";
import { useEffect, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc, resetCsrf } from "../api/client";
import type { RouteKey } from "../router";
import type { DictKey } from "../i18n";
import { DICT } from "../i18n";
import {
  IconBell,
  IconMenu,
  IconChevronDown,
  IconGlobe,
  IconMoon,
  IconRefresh,
  IconSearch,
  IconSun,
  IconUser,
} from "./icons";
import { GlassSelect, toast } from "./ui";
import { BrandLogo } from "./BrandLogo";
import { formatTime } from "../lib/format";

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

/** 后端 activity.list 的条目（审计日志折成的活动流）。 */
type ActivityItem = { kind?: string; title?: string; sub?: string; time?: string };
type ServiceSnapshot = { services?: { status?: string }[]; serviceDist?: { total?: number; running?: number } };
const NOTIF_READ_KEY = "mailstack:notif-read";

function actText(a: ActivityItem, t: (k: DictKey) => string): string {
  const title = a.title ?? "";
  const label = Object.prototype.hasOwnProperty.call(DICT, title) ? t(title as DictKey) : title || "—";
  return a.sub ? `${label} · ${a.sub}` : label;
}

function actTime(a: ActivityItem): string {
  const raw = a.time ?? "";
  // 后端是 ISO8601（2026-09-29T14:22:10+00:00，UTC）——slice 会把 UTC 当本地时间展示；
  // mock 是 "14:22" 短串，原样返回。ISO 交给共享助手转本地时区。
  return raw.length > 10 ? formatTime(raw) : raw;
}

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
  menuOpen,
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
  /** 抽屉开合态（State 在 App.tsx）：仅用于汉堡的 aria-expanded。 */
  menuOpen?: boolean;
}) {
  const { t, prefs, resolvedTheme, setTheme, setLang } = useSettings();

  /* ---- 真实数据：通知（activity.list）/ 系统状态（snapshot）/ 管理员名（admin.get） ---- */
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [readKeys, setReadKeys] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem(NOTIF_READ_KEY);
      // 上限 200 条（drop-oldest）：读集合无上限会随会话无限增长，localStorage 越写越大。
      return new Set(raw ? (JSON.parse(raw) as string[]).slice(-200) : []);
    } catch {
      return new Set();
    }
  });
  const [health, setHealth] = useState<{ running: number; total: number } | null>(null);
  const [adminName, setAdminName] = useState<string | null>(null);

  const notifKey = (a: ActivityItem) => `${a.title ?? ""}|${a.time ?? ""}|${a.sub ?? ""}`;
  const unreadCount = activity.filter((a) => !readKeys.has(notifKey(a))).length;

  /**
   * 「全部已读」：把当前活动流标记为已读（本地持久化），红点随之熄灭。
   * Set 保持插入序（旧→新），只保留最近 ~200 条，防止无界增长。
   */
  function markAllRead() {
    const next = new Set(readKeys);
    activity.forEach((a) => next.add(notifKey(a)));
    const capped = [...next].slice(-200);
    setReadKeys(new Set(capped));
    try {
      localStorage.setItem(NOTIF_READ_KEY, JSON.stringify(capped));
    } catch {
      /* 存储不可用时仅本会话生效 */
    }
  }

  // 通知与管理员名原先整个会话只拉一次：红点/动态会一直停留在打开页面那一刻。
  // 与下方系统状态徽标一致，用 60s 轻轮询（比 focus 监听更省事，两处行为统一）。
  useEffect(() => {
    let live = true;
    const load = () => {
      rpc<ActivityItem[]>("activity.list").then((r) => {
        if (live && r.ok) setActivity(r.data ?? []);
      });
      rpc<{ username?: string }>("admin.get").then((r) => {
        if (live && r.ok) setAdminName((r.data as { username?: string } | undefined)?.username ?? null);
      });
    };
    load();
    const timer = setInterval(load, 60_000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);

  // 系统状态徽标：读真实服务状态（原先是恒为 badge-ok 的「服务运行正常」）。
  useEffect(() => {
    let live = true;
    async function load() {
      const r = await rpc<ServiceSnapshot>("snapshot");
      if (!live) return;
      const d = (r.ok ? r.data : null) as ServiceSnapshot | null;
      const svcs = d?.services;
      if (Array.isArray(svcs) && svcs.length) {
        setHealth({ running: svcs.filter((s) => s.status === "ACTIVE").length, total: svcs.length });
      } else if (d?.serviceDist && typeof d.serviceDist.total === "number") {
        setHealth({ running: d.serviceDist.running ?? 0, total: d.serviceDist.total });
      } else {
        setHealth(null);
      }
    }
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);

  const healthKind = health == null ? "neutral" : health.running === health.total ? "ok" : health.running > 0 ? "warn" : "err";
  const healthLabel = health == null ? "—" : health.running === health.total ? t("system_healthy") : t("system_degraded");

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

  return (
    <div
      // 全宽贴顶（非浮动胶囊）：高度走 --toolbar-height（48px），底部 0.5px 发丝线
      // 与滚动强化在 index.css 的 .app-toolbar / .app-toolbar.is-scrolled。
      className={`glass--toolbar app-toolbar sticky top-0 z-30 flex h-[var(--toolbar-height)] shrink-0 items-center gap-2 px-3 ${scrolled ? "is-scrolled" : ""}`}
      role="toolbar"
      aria-label="toolbar"
    >
      {/* 0. 汉堡菜单（<1024 抽屉模式）。开合态 menuOpen 由 App 传入（aria-expanded），
          aria-controls 指向 Sidebar 抽屉 aside 的 id="app-drawer"。
          尺寸：.icon-btn = var(--control-h)（iOS 度量档 44px）→ 触控目标已达标。 */}
      {showMenu && (
        <motion.button
          whileTap={{ scale: 0.9 }}
          transition={{ type: "spring", stiffness: 600, damping: 28 }}
          className="icon-btn glass--control mr-0.5 shrink-0"
          onClick={onMenu}
          aria-label="Menu"
          aria-expanded={menuOpen}
          aria-controls="app-drawer"
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

      {/* 2. 搜索（⌘K 命令面板入口；openPalette 此前是未使用的 prop） */}
      <motion.button
        whileTap={{ scale: 0.9 }}
        transition={{ type: "spring", stiffness: 600, damping: 28 }}
        className="icon-btn shrink-0"
        onClick={openPalette}
        aria-label={t("search_placeholder")}
        title={t("search_placeholder")}
      >
        <IconSearch size={16} />
      </motion.button>

      {/* 数据来源徽标：mock = 演示数据（琥珀），live = 已连接后端（绿） */}
      <span
        className={`badge hidden xl:inline-flex ${mode === "mock" ? "badge-warn" : "badge-ok"}`}
        title={mode === "mock" ? t("mock_data") : t("live_data")}
      >
        <span className="dot" />
        {mode === "mock" ? t("mock_data") : t("live_data")}
      </span>

      {/* 3. 系统状态徽标：由 snapshot 的真实服务状态推导；拿不到数据显示 — */}
      <span
        className={`badge badge-${healthKind} hidden sm:inline-flex`}
        role="status"
        title={health ? `${healthLabel} · ${health.running}/${health.total}` : healthLabel}
      >
        <span className="dot" />
        <span className="hidden md:inline">{healthLabel}</span>
      </span>

      <div className="ml-auto flex items-center gap-1.5">
        {/* 4. 时间范围选择器（≥md） */}
        <div className="hidden md:block">
          <GlassSelect value={range} onChange={(v) => setRange(v as TimeRange)} options={rangeOptions} ariaLabel={t("last_24h")} width={116} />
        </div>

        {/* 5. 刷新 */}
        <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn hidden sm:inline-flex" onClick={onRefresh} aria-label={t("refresh")} title={t("refresh")}>
          <IconRefresh size={16} />
        </motion.button>

        {/* 6. 通知（角标 + 下拉） */}
        <RDropdown.Root>
          <RDropdown.Trigger asChild>
            <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn" aria-label={t("notifications")} title={t("notifications")}>
              <IconBell size={16} />
              {unreadCount > 0 && (
                <span
                  className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full"
                  style={{ background: "rgb(var(--err-rgb))", boxShadow: "0 0 0 2px rgb(var(--glass-rgb) / 0.9)" }}
                />
              )}
            </motion.button>
          </RDropdown.Trigger>
          <RDropdown.Portal>
            {/* data-chrome：折射/边缘透镜仅作用于 chrome 浮层（index.css glass budget） */}
            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" data-chrome={true} style={{ width: 300 }}>
              <div className="flex items-center justify-between px-2.5 py-1.5 text-[12px] font-semibold text-[var(--text-2)]">
                {t("notifications")}
                <button className="text-[11.5px] font-normal text-[var(--accent)]" onClick={markAllRead} disabled={unreadCount === 0}>
                  {t("mark_all_read")}
                </button>
              </div>
              <div className="radix-sep" />
              {activity.length === 0 && (
                <div className="px-2.5 py-4 text-center text-[12px] text-[var(--text-3)]">{t("no_notifications")}</div>
              )}
              {activity.slice(0, 5).map((n) => {
                const unread = !readKeys.has(notifKey(n));
                return (
                  <div key={notifKey(n)} className="radix-item items-start" role="listitem">
                    <span
                      className="mt-1 h-2 w-2 shrink-0 rounded-full"
                      style={{ background: unread ? "rgb(var(--accent-rgb))" : "rgb(var(--text-1) / 0.18)" }}
                    />
                    <div className="min-w-0">
                      <div className="text-[12.5px] leading-snug">{actText(n, t)}</div>
                      <div className="text-[11px] text-[var(--text-3)]">{actTime(n)}</div>
                    </div>
                  </div>
                );
              })}
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
          className="icon-btn hidden sm:inline-flex"
          onClick={cycleLang}
          aria-label={t("language")}
          title={t("language")}
        >
          <IconGlobe size={16} />
        </motion.button>

        {/* 9. 管理员菜单 */}
        <RDropdown.Root>
          <RDropdown.Trigger asChild>
            {/* <sm：图标-only 头像钮（名字与箭头折叠，P1 移动溢出修复的一部分） */}
            <button className="glass--control flex h-[var(--control-h)] items-center gap-2 rounded-full py-0 pl-1 pr-1.5 sm:pr-2.5" aria-label={t("admin")}>
              <Avatar />
              <span className="hidden text-[13px] font-medium text-[var(--text-1)] sm:inline">{adminName ?? "—"}</span>
              <IconChevronDown size={12} className="hidden text-[var(--text-3)] sm:block" />
            </button>
          </RDropdown.Trigger>
          <RDropdown.Portal>
            {/* data-chrome：折射/边缘透镜仅作用于 chrome 浮层 */}
            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" data-chrome={true} style={{ minWidth: 200 }}>
              <div className="flex items-center gap-2.5 px-2.5 py-2">
                <Avatar size={34} />
                <div>
                  {/* 管理员名读 admin.get；后端没有 email 字段，故不再硬编码 admin@example.com */}
                  <div className="text-[13px] font-semibold text-[var(--text-1)]">{adminName ?? "—"}</div>
                  <div className="text-[11px] text-[var(--text-3)]">{t("admin")}</div>
                </div>
              </div>
              <div className="radix-sep" />
              {/* Golden Gate 菜单：无逐项图标（无可用快捷键，故不造键位提示） */}
              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                {t("admin_profile")}
              </RDropdown.Item>
              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                MailStack {t("settings_title")}
              </RDropdown.Item>
              <div className="radix-sep" />
              <RDropdown.Item className="radix-item" style={{ color: "rgb(var(--err-rgb))" }} onSelect={() => void toastLogout()}>
                {t("logout")}
              </RDropdown.Item>
            </RDropdown.Content>
          </RDropdown.Portal>
        </RDropdown.Root>
      </div>
    </div>
  );
}

/**
 * 退出登录：**先**让服务端吊销会话，再回登录门。
 *
 * 原实现只 dispatchEvent 做本地跳转：HttpOnly 会话 Cookie（Max-Age 8h）仍然有效，
 * 「退出」并不等于会话失效 —— 拿同一浏览器再进来（或点开 SPA 的登录页刷新）仍是已登录态。
 * rpc 失败时解析成 {ok:false}（不 reject），必须显式检视：登出失败说明会话可能仍
 * 在服务端存活，此时不能清 CSRF / 派发 logout 事件，否则用户以为已退出。
 */
async function toastLogout() {
  const r = await rpc("auth.logout", {});
  if (!r.ok) {
    toast(r.error, "err");
    return;
  }
  resetCsrf();
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
