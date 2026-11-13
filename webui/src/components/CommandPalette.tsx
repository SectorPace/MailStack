import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import * as RDialog from "@radix-ui/react-dialog";
import { useSettings } from "../store/settings";
import { NAV, SIDEBAR_SECTIONS } from "./Sidebar";
import type { RouteKey } from "../router";
import type { DictKey } from "../i18n";
import { IconSearch } from "./icons";
type PaletteItem = {
    key: RouteKey;
    label: string;
    en: string;
    icon: ComponentType<{
        size?: number;
    }>;
};
type GroupedPaletteItem = PaletteItem & {
    index: number;
};
export function CommandPalette({ open, onOpenChange, nav, }: {
    open: boolean;
    onOpenChange: (o: boolean) => void;
    nav: (r: RouteKey) => void;
}) {
    const { t, prefs } = useSettings();
    const [q, setQ] = useState("");
    const [idx, setIdx] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);
    const items = useMemo<PaletteItem[]>(() => {
        const all = NAV.map((n) => ({
            key: n.key,
            label: t(`nav_${n.key}` as DictKey),
            en: n.key,
            icon: n.icon,
        }));
        const query = q.trim().toLowerCase();
        if (!query)
            return all;
        return all.filter((x) => x.label.toLowerCase().includes(query) ||
            x.en.toLowerCase().includes(query) ||
            x.key.includes(query));
    }, [q, prefs.lang, t]);
    const groups = useMemo(() => {
        const byKey = new Map(items.map((it) => [it.key, it]));
        let flat = 0;
        return SIDEBAR_SECTIONS.map((s) => ({
            label: prefs.lang === "zh" ? s.zh : s.en,
            items: s.keys
                .map((k) => byKey.get(k))
                .filter((x): x is PaletteItem => x !== undefined)
                .map((it): GroupedPaletteItem => ({ ...it, index: flat++ })),
        })).filter((g) => g.items.length > 0);
    }, [items, prefs.lang]);
    useEffect(() => {
        if (open) {
            setQ("");
            setIdx(0);
            setTimeout(() => inputRef.current?.focus(), 30);
        }
    }, [open]);
    const activeIdx = items.length === 0 ? -1 : Math.min(idx, items.length - 1);
    function go(key: RouteKey) {
        onOpenChange(false);
        nav(key);
    }
    function onKeyDown(e: React.KeyboardEvent) {
        if (e.key === "ArrowDown") {
            e.preventDefault();
            if (items.length > 0)
                setIdx((i) => Math.min(items.length - 1, i + 1));
        }
        else if (e.key === "ArrowUp") {
            e.preventDefault();
            setIdx((i) => Math.max(0, i - 1));
        }
        else if (e.key === "Enter" && activeIdx >= 0) {
            go(items[activeIdx].key);
        }
    }
    return (<RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay"/>

        <RDialog.Content className="glass--clear radix-dialog command-palette edge-lens" data-chrome={true} style={{
            width: "min(620px, calc(100vw - 40px))",
            top: "12vh",
            transform: "translateX(-50%)",
            maxHeight: "min(72vh, 560px)",
            display: "flex",
            flexDirection: "column",
            padding: 0,
            overflow: "hidden",
        }} onKeyDown={onKeyDown}>
          <RDialog.Title className="sr-only">Command palette</RDialog.Title>
          <div className="flex items-center gap-3 border-b px-4" style={{ borderColor: "var(--hairline)", height: 56 }}>
            <IconSearch size={18} className="shrink-0 text-[var(--text-3)]"/>
            <input ref={inputRef} value={q} onChange={(e) => {
            setQ(e.target.value);
            setIdx(0);
        }} placeholder={t("search_placeholder")} className="h-full min-w-0 flex-1 bg-transparent text-[15px] text-[var(--text-1)] outline-none placeholder:text-[var(--text-3)]"/>
            <span className="kbd">esc</span>
          </div>
          <div className="max-h-[min(50vh,360px)] overflow-y-auto p-1.5" style={{ minHeight: 0 }}>
            {items.length === 0 && (<div className="px-3 py-8 text-center text-[13px] text-[var(--text-3)]">{t("no_data")}</div>)}
            {groups.map((g) => (<div key={g.label}>
                <div className="px-2.5 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-[var(--text-3)]">
                  {g.label}
                </div>
                {g.items.map((it) => {
                const Icon = it.icon;
                const active = it.index === activeIdx;
                return (<button key={it.key} onClick={() => go(it.key)} onMouseEnter={() => setIdx(it.index)} className="flex w-full items-center gap-3 rounded-[var(--radius-control)] px-2.5 py-2 text-left" style={{
                        background: active ? "rgb(var(--accent-rgb) / 0.14)" : undefined,
                        boxShadow: active ? "inset 0 0 0 1px rgb(var(--accent-rgb) / 0.25)" : undefined,
                    }}>
                      <span className="flex shrink-0" style={{ color: active ? "var(--accent)" : "var(--text-2)" }}>
                        <Icon size={16}/>
                      </span>
                      <span className="min-w-0 flex-1 truncate text-[13.5px] text-[var(--text-1)]">{it.label}</span>

                      <span className={active ? "kbd" : "kbd hidden"}>↵</span>
                      <span className="text-[11px] uppercase tracking-wide text-[var(--text-3)]">{it.en}</span>
                    </button>);
            })}
              </div>))}
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>);
}
