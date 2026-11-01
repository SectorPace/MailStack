// 全局偏好：主题 / 语言 / 强调色 / 玻璃透明度 / 三个可访问性降级开关。
// 全部持久化到 localStorage，并落到 <html data-*> 与 CSS 变量上。
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { t as translate, type DictKey, type Lang } from "../i18n";

export type ThemeMode = "light" | "dark" | "system";
export type Accent = "blue" | "purple" | "green" | "red" | "orange" | "yellow";

export const ACCENTS: Record<Accent, { light: string; dark: string; deep: string; label: string }> = {
  blue: { light: "#007AFF", dark: "#0A84FF", deep: "#0064DC", label: "systemBlue" },
  purple: { light: "#AF52DE", dark: "#BF5AF2", deep: "#8E36C4", label: "systemPurple" },
  green: { light: "#34C759", dark: "#30D158", deep: "#248A3D", label: "systemGreen" },
  red: { light: "#FF3B30", dark: "#FF453A", deep: "#D70015", label: "systemRed" },
  orange: { light: "#FF9500", dark: "#FF9F0A", deep: "#C93400", label: "systemOrange" },
  yellow: { light: "#F7CE45", dark: "#FFD60A", deep: "#AA8A1E", label: "systemYellow" },
};

type Prefs = {
  theme: ThemeMode;
  lang: Lang;
  accent: Accent;
  /** 0=超清澈(ultra clear) → 100=柔和暗色(soft dark/tinted) */
  glassLevel: number;
  reduceTransparency: boolean;
  increaseContrast: boolean;
  reduceMotion: boolean;
  /** 桌面全高侧栏折叠为图标栏（Sidebar.tsx 应改为读取该偏好，而不是自己的
      localStorage 键 —— 旧键由 load() 迁移进来并删除，见 LEGACY_COLLAPSE_KEY）。 */
  sidebarCollapsed: boolean;
};

const DEFAULTS: Prefs = {
  theme: "light",
  lang: "zh",
  accent: "blue",
  glassLevel: 50,
  reduceTransparency: false,
  increaseContrast: false,
  reduceMotion: false,
  sidebarCollapsed: false,
};

const STORE_KEY = "mailstack.prefs.v1";
const BG_KEY = "mailstack.customBg";
/** 旧版 Sidebar.tsx 的独立折叠键（components/Sidebar.tsx COLLAPSE_KEY）。 */
const LEGACY_COLLAPSE_KEY = "mailstack.sidebar-collapsed";

function load(): Prefs {
  // 一次性迁移：旧版 Sidebar 的独立键 mailstack.sidebar-collapsed（"0"/"1"）并入
  // 统一 prefs 后删除旧键。Sidebar.tsx 应改为读取 prefs.sidebarCollapsed /
  // setSidebarCollapsed()（本次不改动 Sidebar.tsx —— 它仍写旧键的话，下次加载会
  // 再次迁移，行为收敛一致，无数据丢失）。
  try {
    const legacy = localStorage.getItem(LEGACY_COLLAPSE_KEY);
    if (legacy !== null) {
      localStorage.removeItem(LEGACY_COLLAPSE_KEY);
      try {
        const raw = localStorage.getItem(STORE_KEY);
        const j: Record<string, unknown> = raw ? JSON.parse(raw) : {};
        if (j && typeof j === "object" && j.sidebarCollapsed === undefined) {
          j.sidebarCollapsed = legacy === "1";
          localStorage.setItem(STORE_KEY, JSON.stringify({ ...DEFAULTS, ...j }));
        }
      } catch {
        /* prefs 本体损坏时放弃合并，走下方逐字段校验回落默认值 */
      }
    }
  } catch {
    /* localStorage 不可用（隐私模式等）：跳过迁移 */
  }
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return DEFAULTS;
    // localStorage 可被外部/其他版本改写：原先只 `as Partial<Prefs>` 合并，
    // 坏数据（字符串数字、越界值、错枚举）会直接进城。逐字段校验类型并钳制
    // 取值范围，不合法的键回落默认值。
    const j = JSON.parse(raw) as Record<string, unknown>;
    const bool = (v: unknown, d: boolean): boolean => (typeof v === "boolean" ? v : d);
    return {
      theme:
        j.theme === "light" || j.theme === "dark" || j.theme === "system" ? j.theme : DEFAULTS.theme,
      lang: j.lang === "zh" || j.lang === "en" ? j.lang : DEFAULTS.lang,
      accent:
        typeof j.accent === "string" && (j.accent as string) in ACCENTS
          ? (j.accent as Accent)
          : DEFAULTS.accent,
      glassLevel:
        typeof j.glassLevel === "number" && Number.isFinite(j.glassLevel)
          ? Math.min(100, Math.max(0, Math.round(j.glassLevel)))
          : DEFAULTS.glassLevel,
      reduceTransparency: bool(j.reduceTransparency, DEFAULTS.reduceTransparency),
      increaseContrast: bool(j.increaseContrast, DEFAULTS.increaseContrast),
      reduceMotion: bool(j.reduceMotion, DEFAULTS.reduceMotion),
      sidebarCollapsed: bool(j.sidebarCollapsed, DEFAULTS.sidebarCollapsed),
    };
  } catch {
    return DEFAULTS;
  }
}

function systemDark(): boolean {
  return typeof matchMedia !== "undefined" && matchMedia("(prefers-color-scheme: dark)").matches;
}

type SettingsCtx = {
  prefs: Prefs;
  resolvedTheme: "light" | "dark";
  customBg: string | null;
  setCustomBg: (v: string | null) => void;
  setTheme: (t: ThemeMode) => void;
  setLang: (l: Lang) => void;
  setAccent: (a: Accent) => void;
  setGlassLevel: (n: number) => void;
  setFlag: (k: "reduceTransparency" | "increaseContrast" | "reduceMotion", v: boolean) => void;
  /** Sidebar.tsx 折叠态应迁移到该 setter（替代其本地 localStorage 键）。 */
  setSidebarCollapsed: (v: boolean) => void;
  t: (key: DictKey, params?: Record<string, string | number>) => string;
};

const Ctx = createContext<SettingsCtx | null>(null);

function hexToRgb(hex: string): string {
  const h = hex.replace("#", "");
  const n = parseInt(h, 16);
  return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`;
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState<Prefs>(load);
  const [sysDark, setSysDark] = useState(systemDark);
  const [customBg, setCustomBgState] = useState<string | null>(() => {
    try { return localStorage.getItem(BG_KEY); } catch { return null; }
  });
  const setCustomBg = useCallback((v: string | null) => {
    // 状态先落地（持久化失败时至少当前会话生效），但**不吞** localStorage 的
    // QuotaExceededError：Settings 的调用方包了 try/catch 等 toast「存储已满」，
    // 这里静默会让外层 catch 永远不触发、用户看到的是虚假的「已保存」。
    setCustomBgState(v);
    if (v) localStorage.setItem(BG_KEY, v);
    else localStorage.removeItem(BG_KEY);
  }, []);

  useEffect(() => {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const fn = (e: MediaQueryListEvent) => setSysDark(e.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);

  const resolvedTheme: "light" | "dark" = prefs.theme === "system" ? (sysDark ? "dark" : "light") : prefs.theme;

  // 持久化
  useEffect(() => {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(prefs));
    } catch {
      /* ignore */
    }
  }, [prefs]);

  // 主题 + 玻璃透明度 + 强调色 + a11y → documentElement
  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolvedTheme;
    root.dataset.a11yReducedTransparency = String(prefs.reduceTransparency);
    root.dataset.a11yContrast = String(prefs.increaseContrast);
    root.dataset.a11yReducedMotion = String(prefs.reduceMotion);
    root.lang = prefs.lang === "zh" ? "zh-CN" : "en";

    const dark = resolvedTheme === "dark";
    const accent = ACCENTS[prefs.accent];
    root.style.setProperty("--accent-rgb", hexToRgb(dark ? accent.dark : accent.light));
    root.style.setProperty("--accent-deep-rgb", hexToRgb(accent.deep));

    // Liquid Glass 透明度滑杆：0(超清澈) → 100(柔和暗色)
    const v = prefs.glassLevel / 100;
    if (prefs.reduceTransparency) {
      // 降级开关优先（index.css 内已覆写，这里保持同步以防内联覆盖）
      root.style.removeProperty("--glass-a");
      root.style.removeProperty("--glass-a-top");
      root.style.removeProperty("--toolbar-a");
    } else if (dark) {
      // Dark：更亮的中调玻璃（比背景明显更浅）
      const a = 0.10 + v * 0.26;
      root.style.setProperty("--glass-a", a.toFixed(3));
      root.style.setProperty("--glass-a-top", (a * 0.5).toFixed(3));
      root.style.setProperty("--toolbar-a", (a * 0.72).toFixed(3));
    } else {
      // Light：高通透玻璃（50% ≈ 0.46，对齐展板——卡片透出照片水纹）
      const a = 0.26 + v * 0.4;
      root.style.setProperty("--glass-a", a.toFixed(3));
      root.style.setProperty("--glass-a-top", (a * 0.28).toFixed(3));
      root.style.setProperty("--toolbar-a", (a * 0.6).toFixed(3));
    }
  }, [prefs, resolvedTheme]);

  const set = useCallback(<K extends keyof Prefs>(k: K, v: Prefs[K]) => {
    setPrefs((p) => ({ ...p, [k]: v }));
  }, []);

  const value = useMemo<SettingsCtx>(
    () => ({
      prefs,
      resolvedTheme,
      customBg,
      setCustomBg,
      setTheme: (th) => set("theme", th),
      setLang: (l) => set("lang", l),
      setAccent: (a) => set("accent", a),
      setGlassLevel: (n) => set("glassLevel", n),
      setFlag: (k, v2) => set(k, v2),
      setSidebarCollapsed: (v2) => set("sidebarCollapsed", v2),
      t: (key, params) => translate(prefs.lang, key, params),
    }),
    [prefs, resolvedTheme, customBg, setCustomBg, set],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSettings(): SettingsCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSettings must be used within SettingsProvider");
  return v;
}
