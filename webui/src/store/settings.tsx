import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode, } from "react";
import { t as translate, type DictKey, type Lang } from "../i18n";
export type ThemeMode = "light" | "dark" | "system";
export type Accent = "blue" | "purple" | "green" | "red" | "orange" | "yellow";
export const ACCENTS: Record<Accent, {
    light: string;
    dark: string;
    deep: string;
    label: string;
}> = {
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
    glassLevel: number;
    reduceTransparency: boolean;
    increaseContrast: boolean;
    reduceMotion: boolean;
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
const LEGACY_COLLAPSE_KEY = "mailstack.sidebar-collapsed";
function load(): Prefs {
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
            }
            catch {
            }
        }
    }
    catch {
    }
    try {
        const raw = localStorage.getItem(STORE_KEY);
        if (!raw)
            return DEFAULTS;
        const j = JSON.parse(raw) as Record<string, unknown>;
        const bool = (v: unknown, d: boolean): boolean => (typeof v === "boolean" ? v : d);
        return {
            theme: j.theme === "light" || j.theme === "dark" || j.theme === "system" ? j.theme : DEFAULTS.theme,
            lang: j.lang === "zh" || j.lang === "en" ? j.lang : DEFAULTS.lang,
            accent: typeof j.accent === "string" && (j.accent as string) in ACCENTS
                ? (j.accent as Accent)
                : DEFAULTS.accent,
            glassLevel: typeof j.glassLevel === "number" && Number.isFinite(j.glassLevel)
                ? Math.min(100, Math.max(0, Math.round(j.glassLevel)))
                : DEFAULTS.glassLevel,
            reduceTransparency: bool(j.reduceTransparency, DEFAULTS.reduceTransparency),
            increaseContrast: bool(j.increaseContrast, DEFAULTS.increaseContrast),
            reduceMotion: bool(j.reduceMotion, DEFAULTS.reduceMotion),
            sidebarCollapsed: bool(j.sidebarCollapsed, DEFAULTS.sidebarCollapsed),
        };
    }
    catch {
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
    setSidebarCollapsed: (v: boolean) => void;
    t: (key: DictKey, params?: Record<string, string | number>) => string;
};
const Ctx = createContext<SettingsCtx | null>(null);
function hexToRgb(hex: string): string {
    const h = hex.replace("#", "");
    const n = parseInt(h, 16);
    return `${(n >> 16) & 255} ${(n >> 8) & 255} ${n & 255}`;
}
export function SettingsProvider({ children }: {
    children: ReactNode;
}) {
    const [prefs, setPrefs] = useState<Prefs>(load);
    const [sysDark, setSysDark] = useState(systemDark);
    const [customBg, setCustomBgState] = useState<string | null>(() => {
        try {
            return localStorage.getItem(BG_KEY);
        }
        catch {
            return null;
        }
    });
    const setCustomBg = useCallback((v: string | null) => {
        setCustomBgState(v);
        if (v)
            localStorage.setItem(BG_KEY, v);
        else
            localStorage.removeItem(BG_KEY);
    }, []);
    useEffect(() => {
        const mq = matchMedia("(prefers-color-scheme: dark)");
        const fn = (e: MediaQueryListEvent) => setSysDark(e.matches);
        mq.addEventListener("change", fn);
        return () => mq.removeEventListener("change", fn);
    }, []);
    const resolvedTheme: "light" | "dark" = prefs.theme === "system" ? (sysDark ? "dark" : "light") : prefs.theme;
    useEffect(() => {
        try {
            localStorage.setItem(STORE_KEY, JSON.stringify(prefs));
        }
        catch {
        }
    }, [prefs]);
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
        const v = prefs.glassLevel / 100;
        if (prefs.reduceTransparency) {
            root.style.removeProperty("--glass-a");
            root.style.removeProperty("--glass-a-top");
            root.style.removeProperty("--toolbar-a");
        }
        else if (dark) {
            const a = 0.10 + v * 0.26;
            root.style.setProperty("--glass-a", a.toFixed(3));
            root.style.setProperty("--glass-a-top", (a * 0.5).toFixed(3));
            root.style.setProperty("--toolbar-a", (a * 0.72).toFixed(3));
        }
        else {
            const a = 0.26 + v * 0.4;
            root.style.setProperty("--glass-a", a.toFixed(3));
            root.style.setProperty("--glass-a-top", (a * 0.28).toFixed(3));
            root.style.setProperty("--toolbar-a", (a * 0.6).toFixed(3));
        }
    }, [prefs, resolvedTheme]);
    const set = useCallback(<K extends keyof Prefs>(k: K, v: Prefs[K]) => {
        setPrefs((p) => ({ ...p, [k]: v }));
    }, []);
    const value = useMemo<SettingsCtx>(() => ({
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
    }), [prefs, resolvedTheme, customBg, setCustomBg, set]);
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
export function useSettings(): SettingsCtx {
    const v = useContext(Ctx);
    if (!v)
        throw new Error("useSettings must be used within SettingsProvider");
    return v;
}
