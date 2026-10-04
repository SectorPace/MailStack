import { createContext, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { MotionConfig, motion } from "motion/react";
import { SettingsProvider, useSettings } from "./store/settings";
import { useRoute, type RouteKey } from "./router";
import { useViewport } from "./hooks/useViewport";
import { initApi, getMode, onModeChange, rpc } from "./api/client";
import { Sidebar } from "./components/Sidebar";
import { Toolbar, type TimeRange } from "./components/Toolbar";
import { CommandPalette } from "./components/CommandPalette";
import { ToastHost, toast } from "./components/ui";
import { IconUser, IconSearch, IconGear, IconChevronDown } from "./components/icons";
import { BrandLogo } from "./components/BrandLogo";

// 页面按路由分包，首屏只加载 Dashboard
const Login = lazy(() => import("./pages/Login"));
const Setup = lazy(() => import("./pages/Setup"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const AiSuite = lazy(() => import("./pages/AiSuite"));
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
  ai: AiSuite,
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

/** 全局刷新信号：工具栏刷新按钮 → 页面重新拉数据 */
export const RefreshContext = createContext<() => void>(() => {});

/**
 * 折射位移图（Refraction）：R 通道 = 水位 ramp（左 1 → 右 0），G 通道 = 垂直 ramp（上 1 → 下 0）。
   feDisplacementMap 在边缘把背景向内弯折、中心保持中性 —— 展板「Refraction 折射效果」的实现。
 * 仅 Chromium 支持 backdrop-filter: url()；Safari/Firefox 走 CSS 双声明中的基础磨砂（自动降级）。
 */
function makeLensMap(): string {
  const s = 128;
  const c = document.createElement("canvas");
  c.width = c.height = s;
  const ctx = c.getContext("2d");
  if (!ctx) return "";
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
const LENS_MAP =
  typeof document !== "undefined" && /Chrom(e|ium)/.test(navigator.userAgent)
    ? makeLensMap()
    : "";
const REFRACT = LENS_MAP !== "";

function useRefreshSignal() {
  const [n, setN] = useState(0);
  return [n, useCallback(() => setN((v) => v + 1), [])] as const;
}

export default function App() {
  return (
    <SettingsProvider>
      <Shell />
    </SettingsProvider>
  );
}

function Shell() {
  const { prefs, customBg } = useSettings();
  const [route, nav] = useRoute();
  const [scrolled, setScrolled] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [range, setRange] = useState<TimeRange>("24h");
  const [refreshN, refresh] = useRefreshSignal();
  const [mode, setMode] = useState(getMode());
  const [booted, setBooted] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [setupDone, setSetupDone] = useState<boolean | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const vp = useViewport();
  const variant: "fixed" | "rail" | "drawer" = vp.isDrawer ? "drawer" : vp.isRail ? "rail" : "fixed";

  const forceLogin = useMemo(() => new URLSearchParams(location.search).get("login") === "1", []);

  useEffect(() => onModeChange(setMode), []);
  useEffect(() => {
    initApi().then((m) => {
      setBooted(true);
      // mock 模式默认免登录；?login=1 可查看登录页演示
      if (m === "mock") setAuthed(!forceLogin);
    });
  }, []);

  // 登录后检查初次设置是否完成（原版流程：setup.status → 向导 → 控制台）
  useEffect(() => {
    if (!authed || !booted) return;
    let live = true;
    // 后端 setup.status 返回 identityConfigured（是否已写身份），没有 completed；
    // mock 仍回 completed，故两者都兼容，避免真后端下向导永远弹出。
    rpc<{ completed?: boolean; identityConfigured?: boolean }>("setup.status").then((r) => {
      if (!live) return;
      setSetupDone(r.ok ? !!(r.data.identityConfigured ?? r.data.completed) : true);
    });
    return () => {
      live = false;
    };
  }, [authed, booted]);

  // 折射开关落到 <html>，CSS 据此启用 backdrop-filter: url(#ms-lens)
  useEffect(() => {
    document.documentElement.dataset.refract = String(REFRACT);
  }, []);

  // 401 / 注销 → 登录门
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

  // ⌘K 命令面板
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

  return (
    <MotionConfig reducedMotion={prefs.reduceMotion ? "always" : "user"}>
      {/* 折射滤镜定义（feDisplacementMap + 运行时生成的 ramp 位移图） */}
      <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden focusable="false">
        <filter id="ms-lens" x="0" y="0" width="100%" height="100%" colorInterpolationFilters="sRGB">
          <feImage href={LENS_MAP} preserveAspectRatio="none" />
          {/* in2 省略 = 上一原语（feImage 位移图）的结果 */}
          <feDisplacementMap in="SourceGraphic" scale="28" xChannelSelector="R" yChannelSelector="G" />
        </filter>
      </svg>
      <div className="relative flex h-full">
      {/* 背景活动光场 —— 晨光山湖照片 + 主题罩层 + 漂移柔光（玻璃折射的真实内容） */}
      <div className="lightfield" aria-hidden>
        <div className="lf-photo" style={customBg ? { backgroundImage: `url(${customBg})` } : undefined} />
        <div className="lf-veil" />
        <div className="blob b1" />
      </div>

      {!booted ? (
        <div className="relative z-10 flex h-full w-full items-center justify-center">
          <PageSkeleton />
        </div>
      ) : !authed ? (
        <div className="relative z-10 h-full w-full overflow-y-auto">
          <Suspense fallback={<PageSkeleton />}>
            <Login onOk={() => setAuthed(true)} />
          </Suspense>
        </div>
      ) : setupDone === false ? (
        <div className="relative z-10 h-full w-full overflow-y-auto">
          <Suspense fallback={<PageSkeleton />}>
            <Setup onDone={() => setSetupDone(true)} />
          </Suspense>
        </div>
      ) : (
      <>
      <Sidebar
        route={route}
        nav={nav}
        variant={variant}
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
        onSearch={() => setPaletteOpen(true)}
      />

      <main
        className="relative z-10 flex min-w-0 flex-1 flex-col"
        style={{ padding: variant === "drawer" ? 10 : "10px 10px 10px 0" }}
      >
        <Toolbar
          route={route}
          nav={nav}
          scrolled={scrolled}
          onRefresh={refresh}
          range={range}
          setRange={setRange}
          openPalette={() => setPaletteOpen(true)}
          mode={mode}
          showMenu={variant === "drawer"}
          onMenu={() => setMenuOpen((o) => !o)}
        />
        <div
          ref={scrollRef}
          className="page-scroll mt-2.5 min-h-0 flex-1"
          onScroll={(e) => setScrolled((e.target as HTMLDivElement).scrollTop > 6)}
        >
          <RefreshContext.Provider value={refreshCtx}>
            {/* 仅入场动画：路由切换干脆利落，避免快速切换时退出动画互相排队 */}
            <motion.div
              key={route}
              initial={prefs.reduceMotion ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ type: "spring", stiffness: 460, damping: 40, mass: 0.7 }}
            >
              <Suspense fallback={<PageSkeleton />}>
                <Page key={`${route}-${refreshN}`} />
              </Suspense>
            </motion.div>
          </RefreshContext.Provider>
        </div>
      </main>

      </>
      )}
      {vp.isDesktop && authed && (
      <ScrollRail
        visible={scrolled}
        onSearch={() => setPaletteOpen(true)}
        nav={nav}
        onBottom={() => {
          const el = scrollRef.current;
          if (el) el.scrollTo({ top: el.scrollHeight, behavior: prefs.reduceMotion ? "auto" : "smooth" });
        }}
      />
      )}
      {authed && <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} nav={nav} />}
      <ToastHost />
      </div>
    </MotionConfig>
  );
}

/** 滚动边缘工具栏（Scroll-edge toolbar）：内容滚动后自动浮现的竖向玻璃快捷条（对齐展板） */
function ScrollRail({
  visible,
  onSearch,
  nav,
  onBottom,
}: {
  visible: boolean;
  onSearch: () => void;
  nav: (r: RouteKey) => void;
  onBottom: () => void;
}) {
  const { t } = useSettings();
  return (
    <motion.div
      className="glass--clear edge-lens scroll-rail"
      role="toolbar"
      aria-label={t("command_hint")}
      aria-hidden={!visible}
      initial={false}
      animate={visible ? { opacity: 1, x: 0 } : { opacity: 0, x: 16 }}
      transition={{ type: "spring", stiffness: 420, damping: 34 }}
      style={{ pointerEvents: visible ? "auto" : "none" }}
    >
      <button className="rail-btn" onClick={onSearch} aria-label={t("search_placeholder")} title={t("search_placeholder")}>
        <IconSearch size={16} />
      </button>
      <button className="rail-btn" onClick={() => nav("settings")} aria-label={t("admin_profile")} title={t("admin_profile")}>
        <IconUser size={16} />
      </button>
      <button className="rail-btn" onClick={() => nav("settings")} aria-label={t("settings_title")} title={t("settings_title")}>
        <IconGear size={16} />
      </button>
      <span className="rail-sep" aria-hidden />
      <button className="rail-btn" onClick={onBottom} aria-label="↓" title="↓">
        <IconChevronDown size={16} />
      </button>
    </motion.div>
  );
}

function PageSkeleton() {
  return (
    <div className="p-4">
      <div className="skeleton mb-4 h-8 w-56" />
      <div className="grid grid-cols-4 gap-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="skeleton h-24" />
        ))}
      </div>
      <div className="skeleton mt-3 h-64" />
    </div>
  );
}

