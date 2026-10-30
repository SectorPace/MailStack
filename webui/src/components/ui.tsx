// 共享 UI 元件：状态徽标 / 页头 / 玻璃下拉 / 开关行 / 确认弹窗 / Toast
import { useCallback, useEffect, useState, type ReactNode } from "react";
import * as RSelect from "@radix-ui/react-select";
import * as RDialog from "@radix-ui/react-dialog";
import * as RSwitch from "@radix-ui/react-switch";
import { AnimatePresence, motion } from "motion/react";
import { useSettings } from "../store/settings";
import type { DictKey } from "../i18n";
import {
  IconCheck,
  IconChevronDown,
  IconClock,
  IconInfo,
  IconSend,
  IconWarn,
  IconX,
} from "./icons";

/* ---------------- 状态徽标：颜色 + 图标 + 文字 双编码 ---------------- */

export type StatusKind = "ok" | "warn" | "err" | "info" | "hold" | "neutral";

const STATUS_ICON: Record<StatusKind, ReactNode> = {
  ok: <IconCheck size={12} />,
  warn: <IconWarn size={12} />,
  err: <IconX size={12} />,
  info: <IconSend size={11} />,
  hold: <IconClock size={12} />,
  neutral: <span className="dot" aria-hidden />,
};

export function StatusBadge({ kind, label }: { kind: StatusKind; label: string }) {
  return (
    <span className={`badge badge-${kind}`} role="status">
      {STATUS_ICON[kind]}
      {label}
    </span>
  );
}

/** 队列状态 → 徽标 */
export function QueueStatus({ s }: { s: string }) {
  const { t } = useSettings();
  const map: Record<string, { kind: StatusKind; key: DictKey }> = {
    delivered: { kind: "ok", key: "delivered" },
    sending: { kind: "info", key: "sending" },
    failed: { kind: "err", key: "failed" },
    pending: { kind: "warn", key: "pending" },
    hold: { kind: "hold", key: "hold" },
  };
  const m = map[s] ?? { kind: "neutral" as StatusKind, key: "status" as DictKey };
  return <StatusBadge kind={m.kind} label={t(m.key)} />;
}

/* ---------------- 页头 ---------------- */

export function PageHeader({
  title,
  sub,
  right,
}: {
  title: string;
  sub: string;
  right?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[25px] font-semibold leading-tight tracking-[-0.015em] text-[var(--text-1)]">{title}</h1>
        <p className="mt-1 text-[13.5px] text-[var(--text-2)]">{sub}</p>
      </div>
      {right && <div className="flex items-center gap-2">{right}</div>}
    </div>
  );
}

/* ---------------- 玻璃 Select（Radix） ---------------- */

export function GlassSelect({
  value,
  onChange,
  options,
  ariaLabel,
  width,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  ariaLabel?: string;
  width?: number;
}) {
  const current = options.find((o) => o.value === value);
  return (
    <RSelect.Root value={value} onValueChange={onChange}>
      <RSelect.Trigger
        aria-label={ariaLabel}
        className="btn glass--control"
        style={{ width }}
      >
        <span className="truncate">{current?.label ?? value}</span>
        <RSelect.Icon>
          <IconChevronDown size={13} />
        </RSelect.Icon>
      </RSelect.Trigger>
      <RSelect.Portal>
        <RSelect.Content position="popper" sideOffset={6} className="glass--clear radix-pop edge-lens" style={{ minWidth: "var(--radix-select-trigger-width)" }}>
          <RSelect.Viewport>
            {options.map((o) => (
              <RSelect.Item key={o.value} value={o.value} className="radix-item">
                <RSelect.ItemText>{o.label}</RSelect.ItemText>
                <RSelect.ItemIndicator className="ml-auto text-[var(--accent)]">
                  <IconCheck size={13} />
                </RSelect.ItemIndicator>
              </RSelect.Item>
            ))}
          </RSelect.Viewport>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>
  );
}

/* ---------------- iOS 式 Switch 设置行 ---------------- */

export function ToggleRow({
  title,
  sub,
  checked,
  onChange,
}: {
  title: string;
  sub?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-6 py-3">
      <div>
        <div className="text-[13.5px] font-medium text-[var(--text-1)]">{title}</div>
        {sub && <div className="text-[12px] text-[var(--text-2)]">{sub}</div>}
      </div>
      <RSwitch.Root
        checked={checked}
        onCheckedChange={onChange}
        data-checked={String(checked)}
        className="radix-switch"
        aria-label={title}
      >
        <span className="knob" />
      </RSwitch.Root>
    </div>
  );
}

/* ---------------- 确认弹窗 ---------------- */

export function ConfirmDialog({
  open,
  title,
  body,
  danger,
  onOpenChange,
  onConfirm,
}: {
  open: boolean;
  title: string;
  body?: string;
  danger?: boolean;
  onOpenChange: (o: boolean) => void;
  onConfirm: () => void;
}) {
  const { t } = useSettings();
  return (
    <RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay" />
        <RDialog.Content className="glass--clear radix-dialog edge-lens">
          <RDialog.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</RDialog.Title>
          {body && <RDialog.Description className="mt-2 text-[13px] text-[var(--text-2)]">{body}</RDialog.Description>}
          <div className="mt-5 flex justify-end gap-2">
            <button className="btn glass--control" onClick={() => onOpenChange(false)}>
              {t("cancel")}
            </button>
            <button
              className="btn btn-accent"
              style={danger ? { background: "linear-gradient(180deg, rgb(var(--err-rgb)), rgb(var(--err-rgb) / 0.85))" } : undefined}
              onClick={() => {
                onConfirm();
                onOpenChange(false);
              }}
            >
              {t("confirm")}
            </button>
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}

/* ---------------- Toast ---------------- */

type ToastItem = { id: number; text: string; kind: StatusKind };
let toastSeq = 1;

export type PushToast = (text: string, kind?: StatusKind) => void;

let globalPush: PushToast | null = null;
export const toast: PushToast = (text, kind) => globalPush?.(text, kind);

export function ToastHost() {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push: PushToast = useCallback((text, kind = "ok") => {
    const id = toastSeq++;
    setItems((arr) => [...arr, { id, text, kind }]);
    setTimeout(() => setItems((arr) => arr.filter((x) => x.id !== id)), 3200);
  }, []);
  // 模块级 toast() 的出口必须在 effect 里挂接：渲染期赋值是渲染副作用，
  // StrictMode 双渲染会重复执行（WEBUI_AUDIT §3.3）。
  useEffect(() => {
    globalPush = push;
    return () => {
      if (globalPush === push) globalPush = null;
    };
  }, [push]);
  return (
    <div className="pointer-events-none fixed bottom-6 left-1/2 z-[90] flex -translate-x-1/2 flex-col items-center gap-2">
      <AnimatePresence>
        {items.map((it) => (
          <motion.div
            key={it.id}
            initial={{ opacity: 0, y: 14, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.97 }}
            transition={{ type: "spring", stiffness: 480, damping: 34 }}
            className="glass--clear edge-lens flex items-center gap-2 rounded-full px-4 py-2 text-[13px] text-[var(--text-1)]"
          >
            <span className="text-[var(--accent)]">
              {it.kind === "err" ? <IconX size={13} /> : it.kind === "warn" ? <IconWarn size={13} /> : <IconInfo size={13} />}
            </span>
            {it.text}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

/* ---------------- 卡片容器 ---------------- */

export function Card({
  children,
  className = "",
  padding = true,
}: {
  children: ReactNode;
  className?: string;
  padding?: boolean;
}) {
  return (
    <section className={`glass edge-lens rounded-[var(--r-panel)] ${padding ? "p-4" : ""} ${className}`}>
      {children}
    </section>
  );
}

/** 数据表面容器（表格 / 日志 —— 中性、干脆） */
export function DataPanel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`glass--data rounded-[var(--r-panel)] ${className}`}>{children}</section>;
}
