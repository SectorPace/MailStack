import { createContext, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import { SettingsProvider, useSettings } from "./store/settings";
import { useRoute, type RouteKey } from "./router";
import { useViewport } from "./hooks/useViewport";
import { initApi, getMode, onModeChange, rpc, captureCsrf, type Mode } from "./api/client";
import { cssUrl } from "./lib/format";
import { DICT, type DictKey } from "./i18n";
import { Sidebar } from "./components/Sidebar";
import { Toolbar, type TimeRange } from "./components/Toolbar";
import { TabBar } from "./components/TabBar";
import { useIsMobile } from "./hooks/useIsMobile";
import { CommandPalette } from "./components/CommandPalette";
import { ToastHost } from "./components/ui";
import { IconUser, IconSearch, IconGear, IconChevronDown } from "./components/icons";
const Login = lazy(() => import("./pages/Login"));
const Setup = lazy(() => import("./pages/Setup"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Domains = lazy(() => import("./pages/Domains"));
const Users = lazy(() => import("./pages/Users"));
const Aliases = lazy(() => import("./pages/Aliases"));
const Relay = lazy(() => import("./pages/Relay"));
const DkimDns = lazy(() => import("./pages/DkimDns"));
const TlsCerts = lazy(() => import("./pages/TlsCerts"));
const MailQueue = lazy(() => import("./pages/MailQueue"));
const Logs = lazy(() => import("./pages/Logs"));
const Services = lazy(() => import("./pages/Services"));
const Security = lazy(() => import("./pages/Security"));
const Settings = lazy(() => import("./pages/Settings"));
const PAGE_FOR: Record<RouteKey, React.ComponentType> = {
    dashboard: Dashboard,
    domains: Domains,
    users: Users,
    aliases: Aliases,
    relay: Relay,
    dkim: DkimDns,
    tls: TlsCerts,
    queue: MailQueue,
    logs: Logs,
    services: Services,
    security: Security,
    settings: Settings,
};
export const RefreshContext = createContext<() => void>(() => { });
function makeLensMap(): string {
    const s = 128;
    const c = document.createElement("canvas");
    c.width = c.height = s;
    const ctx = c.getContext("2d");
    if (!ctx)
        return "";
    const img = ctx.createImageData(s, s);
    for (let y = 0; y < s; y++) {
        for (let x = 0; x < s; x++) {
            const i = (y * s + x) * 4;
            img.data[i] = Math.round(255 * (1 - x / (s - 1)));
            img.data[i + 1] = Math.round(255 * (1 - y / (s - 1)));
            img.data[i + 2] = 128;
            img.data[i + 3] = 255;
        }
    }
    ctx.putImageData(img, 0, 0);
    return c.toDataURL("image/png");
}
const LENS_MAP = typeof document !== "undefined" && /Chrom(e|ium)/.test(navigator.userAgent)
    ? makeLensMap()
    : "";
const REFRACT = LENS_MAP !== "";
function useRefreshSignal() {
    const [n, setN] = useState(0);
    return [n, useCallback(() => setN((v) => v + 1), [])] as const;
}
function parseHash(): string {
    return location.hash.replace(/^#\/?/, "").split("?")[0];
}
export default function App() {
    return (<SettingsProvider>
      <Shell />
    </SettingsProvider>);
}
function Shell() {
    const { prefs, customBg, t } = useSettings();
    const [route, nav] = useRoute();
    const [scrolled, setScrolled] = useState(false);
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [range, setRange] = useState<TimeRange>("24h");
    const [refreshN, refresh] = useRefreshSignal();
    const [mode, setMode] = useState<Mode>(getMode());
    const [booted, setBooted] = useState(false);
    const [authed, setAuthed] = useState(false);
    const [setupDone, setSetupDone] = useState<boolean | null>(null);
    const [menuOpen, setMenuOpen] = useState(false);
    const scrollRef = useRef<HTMLDivElement>(null);
    const vp = useViewport();
    const variant: "fixed" | "rail" | "drawer" = vp.isDrawer ? "drawer" : vp.isRail ? "rail" : "fixed";
    const isMobile = useIsMobile();
    const forceLogin = useMemo(() => new URLSearchParams(location.search).get("login") === "1", []);
    useEffect(() => onModeChange(setMode), []);
    const boot = useCallback(async () => {
        setBooted(false);
        const m = await initApi();
        if (m === "unreachable") {
            setBooted(true);
            return;
        }
        if (m === "mock") {
            setAuthed(!forceLogin);
            setBooted(true);
            return;
        }
        const s = await rpc<{
            csrf?: string;
            username?: string;
        }>("auth.session");
        if (s.ok) {
            captureCsrf(((s.data ?? {}) as {
                csrf?: string;
            }).csrf);
            if (!forceLogin)
                setAuthed(true);
        }
        setBooted(true);
    }, [forceLogin]);
    useEffect(() => {
        void boot();
    }, [boot]);
    useEffect(() => {
        if (!authed || !booted)
            return;
        let live = true;
        rpc<{
            completed?: boolean;
            identityConfigured?: boolean;
        }>("setup.status").then((r) => {
            if (!live)
                return;
            const d = r.ok ? (r.data ?? {}) : null;
            const done = d == null
                ? true
                : typeof d.completed === "boolean"
                    ? d.completed
                    : !(d.identityConfigured ?? false);
            setSetupDone(done);
        });
        return () => {
            live = false;
        };
    }, [authed, booted]);
    useEffect(() => {
        document.documentElement.dataset.refract = String(REFRACT);
    }, []);
    useEffect(() => {
        const fn = () => {
            setAuthed(false);
            setSetupDone(null);
        };
        window.addEventListener("mailstack:unauthorized", fn);
        window.addEventListener("mailstack:logout", fn);
        return () => {
            window.removeEventListener("mailstack:unauthorized", fn);
            window.removeEventListener("mailstack:logout", fn);
        };
    }, []);
    const [forceSetup, setForceSetup] = useState(() => parseHash() === "setup");
    useEffect(() => {
        const fn = () => setForceSetup(parseHash() === "setup");
        window.addEventListener("hashchange", fn);
        return () => window.removeEventListener("hashchange", fn);
    }, []);
    useEffect(() => {
        const key = `nav_${route}` as DictKey;
        const name = Object.prototype.hasOwnProperty.call(DICT, key) ? t(key) : "MailStack";
        document.title = `${name} · MailStack`;
    }, [route, t]);
    useEffect(() => {
        scrollRef.current?.scrollTo({ top: 0 });
    }, [route]);
    const handleSetupDone = useCallback(() => {
        setSetupDone(true);
        if (parseHash() === "setup")
            location.hash = "#/dashboard";
    }, []);
    useEffect(() => {
        const fn = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
                e.preventDefault();
                setPaletteOpen((o) => !o);
            }
        };
        window.addEventListener("keydown", fn);
        return () => window.removeEventListener("keydown", fn);
    }, []);
    const Page = PAGE_FOR[route];
    const refreshCtx = useMemo(() => refresh, [refresh]);
    return (<MotionConfig reducedMotion={prefs.reduceMotion ? "always" : "user"}>

      <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden focusable="false">
        <filter id="ms-lens" x="0" y="0" width="100%" height="100%" colorInterpolationFilters="sRGB">
          <feImage href={LENS_MAP} preserveAspectRatio="none"/>

          <feDisplacementMap in="SourceGraphic" scale="28" xChannelSelector="R" yChannelSelector="G"/>
        </filter>
      </svg>
      <div className="relative flex h-full">

      <div className="lightfield" aria-hidden>
        <div className="lf-photo" style={customBg ? { backgroundImage: `url(${cssUrl(customBg)})` } : undefined}/>
        <div className="lf-veil"/>
        <div className="blob b1"/>
      </div>

      {!booted ? (<div className="relative z-10 flex h-full w-full items-center justify-center">
          <PageSkeleton />
        </div>) : mode === "unreachable" ? (<BackendUnreachable onRetry={() => void boot()}/>) : !authed ? (<div className="relative z-10 h-full w-full overflow-y-auto">
          <Suspense fallback={<PageSkeleton />}>
            <Login onOk={() => setAuthed(true)}/>
          </Suspense>
        </div>) : setupDone === false || forceSetup ? (<div className="relative z-10 h-full w-full overflow-y-auto">
          <Suspense fallback={<PageSkeleton />}>
            <Setup onDone={handleSetupDone}/>
          </Suspense>
        </div>) : (<>
      <Sidebar route={route} nav={nav} variant={variant} open={menuOpen} onClose={() => setMenuOpen(false)} onSearch={() => setPaletteOpen(true)}/>

      <main className="relative z-10 flex min-w-0 flex-1 flex-col" style={{
                padding: variant === "drawer" ? 10 : "10px 10px 10px 0",
                paddingBottom: isMobile
                    ? "calc(var(--tabbar-height) + env(safe-area-inset-bottom))"
                    : undefined,
            }}>
        <Toolbar route={route} nav={nav} scrolled={scrolled} onRefresh={refresh} range={range} setRange={setRange} openPalette={() => setPaletteOpen(true)} mode={mode} showMenu={variant === "drawer"} onMenu={() => setMenuOpen((o) => !o)} menuOpen={menuOpen}/>
        <div ref={scrollRef} className="page-scroll mt-2.5 min-h-0 flex-1" onScroll={(e) => setScrolled((e.target as HTMLDivElement).scrollTop > 6)}>
          <RefreshContext.Provider value={refreshCtx}>

            <motion.div key={route} initial={prefs.reduceMotion ? false : { opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ type: "spring", stiffness: 460, damping: 40, mass: 0.7 }}>
              <Suspense fallback={<PageSkeleton />}>
                <Page key={`${route}-${refreshN}`}/>
              </Suspense>
            </motion.div>
          </RefreshContext.Provider>
        </div>
      </main>

      {isMobile && <TabBar route={route} nav={nav}/>}

      </>)}
      {vp.isDesktop && authed && (<ScrollRail visible={scrolled} onSearch={() => setPaletteOpen(true)} nav={nav} onBottom={() => {
                const el = scrollRef.current;
                if (el)
                    el.scrollTo({ top: el.scrollHeight, behavior: prefs.reduceMotion ? "auto" : "smooth" });
            }}/>)}
      {authed && <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} nav={nav}/>}
      <ToastHost />
      </div>
    </MotionConfig>);
}
function ScrollRail({ visible, onSearch, nav, onBottom, }: {
    visible: boolean;
    onSearch: () => void;
    nav: (r: RouteKey) => void;
    onBottom: () => void;
}) {
    const { t } = useSettings();
    return (<motion.div className="glass--clear edge-lens scroll-rail" role="toolbar" aria-label={t("command_hint")} aria-hidden={!visible} inert={!visible} initial={false} animate={visible ? { opacity: 1, x: 0 } : { opacity: 0, x: 16 }} transition={{ type: "spring", stiffness: 420, damping: 34 }} style={{ pointerEvents: visible ? "auto" : "none" }}>
      <button className="rail-btn" onClick={onSearch} aria-label={t("search_placeholder")} title={t("search_placeholder")}>
        <IconSearch size={16}/>
      </button>
      <button className="rail-btn" onClick={() => nav("settings")} aria-label={t("admin_profile")} title={t("admin_profile")}>
        <IconUser size={16}/>
      </button>
      <button className="rail-btn" onClick={() => nav("settings")} aria-label={t("settings_title")} title={t("settings_title")}>
        <IconGear size={16}/>
      </button>
      <span className="rail-sep" aria-hidden/>
      <button className="rail-btn" onClick={onBottom} aria-label="↓" title="↓">
        <IconChevronDown size={16}/>
      </button>
    </motion.div>);
}
function PageSkeleton() {
    return (<div className="p-4">
      <div className="skeleton mb-4 h-8 w-56"/>
      <div className="grid grid-cols-4 gap-3">
        {[0, 1, 2, 3].map((i) => (<div key={i} className="skeleton h-24"/>))}
      </div>
      <div className="skeleton mt-3 h-64"/>
    </div>);
}
function BackendUnreachable({ onRetry }: {
    onRetry: () => void;
}) {
    const { t, prefs } = useSettings();
    return (<div className="relative z-10 flex h-full w-full items-center justify-center overflow-y-auto p-4">
      <div className="glass--clear edge-lens w-full max-w-[460px] rounded-[22px] p-6 text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full" style={{ background: "rgb(var(--err-rgb) / 0.12)", color: "rgb(var(--err-rgb))" }}>
          <IconGear size={22}/>
        </div>
        <h1 className="mt-3 text-[18px] font-semibold text-[var(--text-1)]">{t("error_title")}</h1>
        <p className="mt-2 text-[13px] leading-relaxed text-[var(--text-2)]">{t("backend_unreachable")}</p>
        <p className="mt-1 text-[11.5px] leading-relaxed text-[var(--text-3)]">{t("backend_unreachable_hint")}</p>
        <button className="btn btn-accent mx-auto mt-5" onClick={onRetry}>
          {t("retry_op")}
        </button>
        {import.meta.env.DEV && (<p className="mt-3 text-[10.5px] text-[var(--text-3)]">
            {prefs.lang === "zh" ? "开发构建可用 ?mock=1 进入演示数据。" : "Dev build: append ?mock=1 for demo data."}
          </p>)}
      </div>
    </div>);
}
