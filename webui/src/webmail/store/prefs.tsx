import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode, } from "react";
import { defaultPrefs, loadPrefs, resolveTheme, savePrefs, type Density, type MailPrefs, type ThemeMode, } from "../lib/prefs";
import { htmlLang, mt, type Lang, type MailKey } from "../i18n";
type MailPrefsContextValue = {
    prefs: MailPrefs;
    resolvedTheme: "light" | "dark";
    setPrefs: (patch: Partial<MailPrefs>) => void;
    setTheme: (theme: ThemeMode) => void;
    setLang: (lang: Lang) => void;
    setDensity: (density: Density) => void;
    t: (key: MailKey, params?: Record<string, string | number>) => string;
};
const MailPrefsContext = createContext<MailPrefsContextValue | null>(null);
function systemPrefersDark(): boolean {
    try {
        return typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
    }
    catch {
        return false;
    }
}
export function MailPrefsProvider({ children }: {
    children: ReactNode;
}) {
    const [prefs, setPrefsState] = useState<MailPrefs>(() => {
        try {
            return loadPrefs();
        }
        catch {
            return defaultPrefs();
        }
    });
    const [systemDark, setSystemDark] = useState<boolean>(systemPrefersDark);
    useEffect(() => {
        let mq: MediaQueryList | null = null;
        try {
            mq = matchMedia("(prefers-color-scheme: dark)");
        }
        catch {
            return;
        }
        const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
        mq.addEventListener("change", onChange);
        return () => mq?.removeEventListener("change", onChange);
    }, []);
    const resolvedTheme: "light" | "dark" = resolveTheme(prefs.theme, prefs.theme === "system" ? systemDark : undefined);
    useEffect(() => {
        savePrefs(prefs);
    }, [prefs]);
    useEffect(() => {
        if (typeof document === "undefined")
            return;
        const root = document.documentElement;
        root.dataset.theme = resolvedTheme;
        root.lang = htmlLang(prefs.lang);
    }, [resolvedTheme, prefs.lang]);
    const setPrefs = useCallback((patch: Partial<MailPrefs>) => {
        setPrefsState((prev) => ({ ...prev, ...patch }));
    }, []);
    const setTheme = useCallback((theme: ThemeMode) => setPrefs({ theme }), [setPrefs]);
    const setLang = useCallback((lang: Lang) => setPrefs({ lang }), [setPrefs]);
    const setDensity = useCallback((density: Density) => setPrefs({ density }), [setPrefs]);
    const value = useMemo<MailPrefsContextValue>(() => ({
        prefs,
        resolvedTheme,
        setPrefs,
        setTheme,
        setLang,
        setDensity,
        t: (key, params) => mt(prefs.lang, key, params),
    }), [prefs, resolvedTheme, setPrefs, setTheme, setLang, setDensity]);
    return <MailPrefsContext.Provider value={value}>{children}</MailPrefsContext.Provider>;
}
export function useMailPrefs(): MailPrefsContextValue {
    const value = useContext(MailPrefsContext);
    if (!value)
        throw new Error("useMailPrefs must be used within MailPrefsProvider");
    return value;
}
