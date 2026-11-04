import * as RDropdown from "@radix-ui/react-dropdown-menu";
import { motion, AnimatePresence } from "motion/react";
import { useEffect, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc, resetCsrf } from "../api/client";
import type { RouteKey } from "../router";
import type { DictKey } from "../i18n";
import { DICT } from "../i18n";
import { IconBell, IconMenu, IconChevronDown, IconGlobe, IconMoon, IconRefresh, IconSearch, IconSun, IconUser, } from "./icons";
import { GlassSelect, toast } from "./ui";
import { BrandLogo } from "./BrandLogo";
import { formatTime } from "../lib/format";
const CRUMB: Record<RouteKey, {
    en: string;
    zhKey: DictKey;
}> = {
    dashboard: { en: "DASHBOARD", zhKey: "nav_dashboard" },
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
type ActivityItem = {
    kind?: string;
    title?: string;
    sub?: string;
    time?: string;
};
type ServiceSnapshot = {
    services?: {
        status?: string;
    }[];
    serviceDist?: {
        total?: number;
        running?: number;
    };
};
const NOTIF_READ_KEY = "mailstack:notif-read";
function actText(a: ActivityItem, t: (k: DictKey) => string): string {
    const title = a.title ?? "";
    const label = Object.prototype.hasOwnProperty.call(DICT, title) ? t(title as DictKey) : title || "—";
    return a.sub ? `${label} · ${a.sub}` : label;
}
function actTime(a: ActivityItem): string {
    const raw = a.time ?? "";
    return raw.length > 10 ? formatTime(raw) : raw;
}
export function Toolbar({ route, nav, scrolled, onRefresh, range, setRange, openPalette, mode, onMenu, showMenu, menuOpen, }: {
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
    menuOpen?: boolean;
}) {
    const { t, prefs, resolvedTheme, setTheme, setLang } = useSettings();
    const [activity, setActivity] = useState<ActivityItem[]>([]);
    const [readKeys, setReadKeys] = useState<Set<string>>(() => {
        try {
            const raw = localStorage.getItem(NOTIF_READ_KEY);
            return new Set(raw ? (JSON.parse(raw) as string[]).slice(-200) : []);
        }
        catch {
            return new Set();
        }
    });
    const [health, setHealth] = useState<{
        running: number;
        total: number;
    } | null>(null);
    const [adminName, setAdminName] = useState<string | null>(null);
    const notifKey = (a: ActivityItem) => `${a.title ?? ""}|${a.time ?? ""}|${a.sub ?? ""}`;
    const unreadCount = activity.filter((a) => !readKeys.has(notifKey(a))).length;
    function markAllRead() {
        const next = new Set(readKeys);
        activity.forEach((a) => next.add(notifKey(a)));
        const capped = [...next].slice(-200);
        setReadKeys(new Set(capped));
        try {
            localStorage.setItem(NOTIF_READ_KEY, JSON.stringify(capped));
        }
        catch {
        }
    }
    useEffect(() => {
        let live = true;
        const load = () => {
            rpc<ActivityItem[]>("activity.list").then((r) => {
                if (live && r.ok)
                    setActivity(r.data ?? []);
            });
            rpc<{
                username?: string;
            }>("admin.get").then((r) => {
                if (live && r.ok)
                    setAdminName((r.data as {
                        username?: string;
                    } | undefined)?.username ?? null);
            });
        };
        load();
        const timer = setInterval(load, 60000);
        return () => {
            live = false;
            clearInterval(timer);
        };
    }, []);
    useEffect(() => {
        let live = true;
        async function load() {
            const r = await rpc<ServiceSnapshot>("snapshot");
            if (!live)
                return;
            const d = (r.ok ? r.data : null) as ServiceSnapshot | null;
            const svcs = d?.services;
            if (Array.isArray(svcs) && svcs.length) {
                setHealth({ running: svcs.filter((s) => s.status === "ACTIVE").length, total: svcs.length });
            }
            else if (d?.serviceDist && typeof d.serviceDist.total === "number") {
                setHealth({ running: d.serviceDist.running ?? 0, total: d.serviceDist.total });
            }
            else {
                setHealth(null);
            }
        }
        void load();
        const timer = setInterval(() => void load(), 60000);
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
    const rangeOptions: {
        value: TimeRange;
        label: string;
    }[] = [
        { value: "today", label: t("today") },
        { value: "24h", label: t("last_24h") },
        { value: "7d", label: t("last_7d") },
        { value: "30d", label: t("last_30d") },
    ];
    return (<div className={`glass--toolbar app-toolbar sticky top-0 z-30 flex h-[var(--toolbar-height)] shrink-0 items-center gap-2 px-3 ${scrolled ? "is-scrolled" : ""}`} role="toolbar" aria-label="toolbar">

      {showMenu && (<motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn glass--control mr-0.5 shrink-0" onClick={onMenu} aria-label="Menu" aria-expanded={menuOpen} aria-controls="app-drawer">
          <IconMenu size={17}/>
        </motion.button>)}

      <div className="mr-1 hidden items-center gap-2 pl-1 lg:flex" aria-hidden>
        <BrandLogo size={22} radius={7}/>
        <span className="text-[15px] font-semibold tracking-[-0.01em] text-[var(--text-1)]">MailStack</span>
      </div>

      <div className="hidden min-w-0 items-center gap-2 pl-1 sm:flex" aria-label="breadcrumb">
        <span className="hidden truncate text-[11px] font-semibold tracking-[0.08em] text-[var(--text-3)] lg:inline">
          {CRUMB[route].en}
        </span>
        <span className="hidden text-[11px] text-[var(--text-3)] lg:inline">/</span>
        <span className="truncate text-[13.5px] font-semibold text-[var(--text-1)]">{t(CRUMB[route].zhKey)}</span>
      </div>

      <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn shrink-0" onClick={openPalette} aria-label={t("search_placeholder")} title={t("search_placeholder")}>
        <IconSearch size={16}/>
      </motion.button>

      <span className={`badge hidden xl:inline-flex ${mode === "mock" ? "badge-warn" : "badge-ok"}`} title={mode === "mock" ? t("mock_data") : t("live_data")}>
        <span className="dot"/>
        {mode === "mock" ? t("mock_data") : t("live_data")}
      </span>

      <span className={`badge badge-${healthKind} hidden sm:inline-flex`} role="status" title={health ? `${healthLabel} · ${health.running}/${health.total}` : healthLabel}>
        <span className="dot"/>
        <span className="hidden md:inline">{healthLabel}</span>
      </span>

      <div className="ml-auto flex items-center gap-1.5">

        <div className="hidden md:block">
          <GlassSelect value={range} onChange={(v) => setRange(v as TimeRange)} options={rangeOptions} ariaLabel={t("last_24h")} width={116}/>
        </div>

        <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn hidden sm:inline-flex" onClick={onRefresh} aria-label={t("refresh")} title={t("refresh")}>
          <IconRefresh size={16}/>
        </motion.button>

        <RDropdown.Root>
          <RDropdown.Trigger asChild>
            <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn" aria-label={t("notifications")} title={t("notifications")}>
              <IconBell size={16}/>
              {unreadCount > 0 && (<span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full" style={{ background: "rgb(var(--err-rgb))", boxShadow: "0 0 0 2px rgb(var(--glass-rgb) / 0.9)" }}/>)}
            </motion.button>
          </RDropdown.Trigger>
          <RDropdown.Portal>

            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" data-chrome={true} style={{ width: 300 }}>
              <div className="flex items-center justify-between px-2.5 py-1.5 text-[12px] font-semibold text-[var(--text-2)]">
                {t("notifications")}
                <button className="text-[11.5px] font-normal text-[var(--accent)]" onClick={markAllRead} disabled={unreadCount === 0}>
                  {t("mark_all_read")}
                </button>
              </div>
              <div className="radix-sep"/>
              {activity.length === 0 && (<div className="px-2.5 py-4 text-center text-[12px] text-[var(--text-3)]">{t("no_notifications")}</div>)}
              {activity.slice(0, 5).map((n) => {
            const unread = !readKeys.has(notifKey(n));
            return (<div key={notifKey(n)} className="radix-item items-start" role="listitem">
                    <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: unread ? "rgb(var(--accent-rgb))" : "rgb(var(--text-1) / 0.18)" }}/>
                    <div className="min-w-0">
                      <div className="text-[12.5px] leading-snug">{actText(n, t)}</div>
                      <div className="text-[11px] text-[var(--text-3)]">{actTime(n)}</div>
                    </div>
                  </div>);
        })}
            </RDropdown.Content>
          </RDropdown.Portal>
        </RDropdown.Root>

        <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn" onClick={cycleTheme} aria-label={t("theme")} title={t("theme")}>
          <AnimatePresence mode="wait" initial={false}>
            <motion.span key={resolvedTheme} initial={{ rotate: -60, opacity: 0, scale: 0.7 }} animate={{ rotate: 0, opacity: 1, scale: 1 }} exit={{ rotate: 60, opacity: 0, scale: 0.7 }} transition={{ type: "spring", stiffness: 500, damping: 32 }} className="flex">
              {resolvedTheme === "dark" ? <IconMoon size={16}/> : <IconSun size={16}/>}
            </motion.span>
          </AnimatePresence>
        </motion.button>

        <motion.button whileTap={{ scale: 0.9 }} transition={{ type: "spring", stiffness: 600, damping: 28 }} className="icon-btn hidden sm:inline-flex" onClick={cycleLang} aria-label={t("language")} title={t("language")}>
          <IconGlobe size={16}/>
        </motion.button>

        <RDropdown.Root>
          <RDropdown.Trigger asChild>

            <button className="glass--control flex h-[var(--control-h)] items-center gap-2 rounded-full py-0 pl-1 pr-1.5 sm:pr-2.5" aria-label={t("admin")}>
              <Avatar />
              <span className="hidden text-[13px] font-medium text-[var(--text-1)] sm:inline">{adminName ?? "—"}</span>
              <IconChevronDown size={12} className="hidden text-[var(--text-3)] sm:block"/>
            </button>
          </RDropdown.Trigger>
          <RDropdown.Portal>

            <RDropdown.Content align="end" sideOffset={8} className="glass--clear radix-pop edge-lens" data-chrome={true} style={{ minWidth: 200 }}>
              <div className="flex items-center gap-2.5 px-2.5 py-2">
                <Avatar size={34}/>
                <div>

                  <div className="text-[13px] font-semibold text-[var(--text-1)]">{adminName ?? "—"}</div>
                  <div className="text-[11px] text-[var(--text-3)]">{t("admin")}</div>
                </div>
              </div>
              <div className="radix-sep"/>

              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                {t("admin_profile")}
              </RDropdown.Item>
              <RDropdown.Item className="radix-item" onSelect={() => nav("settings")}>
                MailStack {t("settings_title")}
              </RDropdown.Item>
              <div className="radix-sep"/>
              <RDropdown.Item className="radix-item" style={{ color: "rgb(var(--err-rgb))" }} onSelect={() => void toastLogout()}>
                {t("logout")}
              </RDropdown.Item>
            </RDropdown.Content>
          </RDropdown.Portal>
        </RDropdown.Root>
      </div>
    </div>);
}
async function toastLogout() {
    const r = await rpc("auth.logout", {});
    if (!r.ok) {
        toast(r.error, "err");
        return;
    }
    resetCsrf();
    window.dispatchEvent(new CustomEvent("mailstack:logout"));
}
function Avatar({ size = 24 }: {
    size?: number;
}) {
    return (<span aria-hidden className="flex shrink-0 items-center justify-center rounded-full" style={{
            width: size,
            height: size,
            background: "linear-gradient(180deg, rgb(var(--accent-rgb)), rgb(var(--accent-deep-rgb)))",
            color: "#fff",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,.35), 0 0 0 1px rgba(255,255,255,.15)",
        }}>
      <IconUser size={size * 0.55}/>
    </span>);
}
