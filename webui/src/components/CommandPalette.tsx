// ⌘K 命令面板 —— 玻璃浮层，键盘可达（↑↓ 选择 / Enter 跳转 / Esc 关闭）
import { useEffect, useMemo, useRef, useState } from "react";
import * as RDialog from "@radix-ui/react-dialog";
import { useSettings } from "../store/settings";
import { NAV } from "./Sidebar";
import type { RouteKey } from "../router";
import type { DictKey } from "../i18n";
import { IconSearch } from "./icons";

export function CommandPalette({
  open,
  onOpenChange,
  nav,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  nav: (r: RouteKey) => void;
}) {
  const { t, prefs } = useSettings();
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const items = useMemo(() => {
    const all = NAV.map((n) => ({
      key: n.key,
      label: t(`nav_${n.key}` as DictKey),
      en: n.key,
      icon: n.icon,
    }));
    const query = q.trim().toLowerCase();
    if (!query) return all;
    return all.filter(
      (x) =>
        x.label.toLowerCase().includes(query) ||
        x.en.toLowerCase().includes(query) ||
        x.key.includes(query),
    );
  }, [q, prefs.lang, t]);

  useEffect(() => {
    if (open) {
      setQ("");
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  // 列表为空时 idx 会被 ArrowDown 的 `Math.min(-1, i+1)` 写成 -1，`items[-1]` 是
  // undefined → Enter 静默失效。这里统一收敛到一个安全下标。
  const activeIdx = items.length === 0 ? -1 : Math.min(idx, items.length - 1);

  function go(key: RouteKey) {
    onOpenChange(false);
    nav(key);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (items.length > 0) setIdx((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter" && activeIdx >= 0) {
      go(items[activeIdx].key);
    }
  }

  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay" />
        <RDialog.Content
          className="glass--clear radix-dialog edge-lens"
          style={{ width: "min(520px, calc(100vw - 48px))", top: "18%", padding: 0 }}
          onKeyDown={onKeyDown}
        >
          <RDialog.Title className="sr-only">Command palette</RDialog.Title>
          <div className="flex items-center gap-2.5 border-b px-4" style={{ borderColor: "var(--hairline)" }}>
            <IconSearch size={16} className="text-[var(--text-3)]" />
            <input
              ref={inputRef}
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setIdx(0);
              }}
              placeholder={t("search_placeholder")}
              className="h-12 flex-1 bg-transparent text-[14px] text-[var(--text-1)] outline-none placeholder:text-[var(--text-3)]"
            />
            <span className="kbd">esc</span>
          </div>
          <div className="max-h-[320px] overflow-y-auto p-2">
            {items.length === 0 && (
              <div className="px-3 py-8 text-center text-[13px] text-[var(--text-3)]">{t("no_data")}</div>
            )}
            {items.map((it, i) => {
              const Icon = it.icon;
              const active = i === activeIdx;
              return (
                <button
                  key={it.key}
                  onClick={() => go(it.key)}
                  onMouseEnter={() => setIdx(i)}
                  className="flex w-full items-center gap-3 rounded-[10px] px-3 py-2 text-left"
                  style={{
                    background: active ? "rgb(var(--accent-rgb) / 0.14)" : undefined,
                    boxShadow: active ? "inset 0 0 0 1px rgb(var(--accent-rgb) / 0.25)" : undefined,
                  }}
                >
                  <span className="text-[var(--accent)]">
                    <Icon size={16} />
                  </span>
                  <span className="text-[13.5px] text-[var(--text-1)]">{it.label}</span>
                  <span className="ml-auto text-[11px] uppercase tracking-wide text-[var(--text-3)]">{it.en}</span>
                </button>
              );
            })}
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}
