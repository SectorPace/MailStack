import { useCallback, useEffect, useState, type ReactNode } from "react";
import * as RSelect from "@radix-ui/react-select";
import * as RDialog from "@radix-ui/react-dialog";
import * as RSwitch from "@radix-ui/react-switch";
import { AnimatePresence, motion } from "motion/react";
import { Drawer } from "vaul";
import { useSettings } from "../store/settings";
import { useIsMobile } from "../hooks/useIsMobile";
import type { DictKey } from "../i18n";
import { IconCheck, IconChevronDown, IconClock, IconInfo, IconSend, IconWarn, IconX, } from "./icons";
export type StatusKind = "ok" | "warn" | "err" | "info" | "hold" | "neutral";
const STATUS_ICON: Record<StatusKind, ReactNode> = {
    ok: <IconCheck size={12}/>,
    warn: <IconWarn size={12}/>,
    err: <IconX size={12}/>,
    info: <IconSend size={11}/>,
    hold: <IconClock size={12}/>,
    neutral: <span className="dot" aria-hidden/>,
};
const STATUS_COLOR: Record<StatusKind, string> = {
    ok: "rgb(var(--ok-rgb))",
    warn: "rgb(var(--warn-rgb))",
    err: "rgb(var(--err-rgb))",
    info: "rgb(var(--accent-rgb))",
    hold: "rgb(var(--hold-rgb))",
    neutral: "var(--text-3)",
};
export function StatusBadge({ kind, label, variant = "badge", }: {
    kind: StatusKind;
    label: string;
    variant?: "badge" | "dot";
}) {
    if (variant === "dot") {
        return (<span className="inline-flex items-center gap-1.5 whitespace-nowrap" role="status" style={{ fontSize: "var(--font-caption)", color: "var(--text-2)" }}>
        <span aria-hidden className="inline-block shrink-0 rounded-full" style={{ width: 7, height: 7, background: STATUS_COLOR[kind] }}/>
        {label}
      </span>);
    }
    return (<span className={`badge badge-${kind}`} role="status">
      {STATUS_ICON[kind]}
      {label}
    </span>);
}
export function QueueStatus({ s }: {
    s: string;
}) {
    const { t } = useSettings();
    const map: Record<string, {
        kind: StatusKind;
        key: DictKey;
    }> = {
        delivered: { kind: "ok", key: "delivered" },
        sending: { kind: "info", key: "sending" },
        failed: { kind: "err", key: "failed" },
        pending: { kind: "warn", key: "pending" },
        hold: { kind: "hold", key: "hold" },
    };
    const m = map[s] ?? { kind: "neutral" as StatusKind, key: "status" as DictKey };
    return <StatusBadge kind={m.kind} label={t(m.key)}/>;
}
export function PageHeader({ title, sub, right, }: {
    title: string;
    sub: string;
    right?: ReactNode;
}) {
    const isMobile = useIsMobile();
    return (<div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">

        <h1 className="font-semibold leading-tight tracking-[-0.015em] text-[var(--text-1)]" style={{
            fontSize: isMobile ? 28 : "var(--font-title)",
            fontWeight: isMobile ? 700 : undefined,
        }}>
          {title}
        </h1>
        <p className="mt-0.5 text-[var(--text-2)]" style={{ fontSize: isMobile ? "var(--font-body)" : "var(--font-caption)" }}>
          {sub}
        </p>
      </div>
      {right && <div className="flex items-center gap-2">{right}</div>}
    </div>);
}
export function GlassSelect({ value, onChange, options, ariaLabel, width, }: {
    value: string;
    onChange: (v: string) => void;
    options: {
        value: string;
        label: string;
    }[];
    ariaLabel?: string;
    width?: number;
}) {
    const current = options.find((o) => o.value === value);
    return (<RSelect.Root value={value} onValueChange={onChange}>
      <RSelect.Trigger aria-label={ariaLabel} className="btn glass--control" style={{ width }}>
        <span className="truncate">{current?.label ?? value}</span>
        <RSelect.Icon>
          <IconChevronDown size={13}/>
        </RSelect.Icon>
      </RSelect.Trigger>
      <RSelect.Portal>
        <RSelect.Content position="popper" sideOffset={6} className="glass--clear radix-pop edge-lens" style={{ minWidth: "var(--radix-select-trigger-width)" }}>
          <RSelect.Viewport>
            {options.map((o) => (<RSelect.Item key={o.value} value={o.value} className="radix-item">
                <RSelect.ItemText>{o.label}</RSelect.ItemText>
                <RSelect.ItemIndicator className="ml-auto text-[var(--accent)]">
                  <IconCheck size={13}/>
                </RSelect.ItemIndicator>
              </RSelect.Item>))}
          </RSelect.Viewport>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>);
}
export function ToggleRow({ title, sub, checked, onChange, disabled, }: {
    title: string;
    sub?: string;
    checked: boolean;
    onChange: (v: boolean) => void;
    disabled?: boolean;
}) {
    return (<div className="flex items-center justify-between gap-6 py-3" style={{ opacity: disabled ? 0.6 : undefined }}>
      <div>
        <div className="text-[13.5px] font-medium text-[var(--text-1)]">{title}</div>
        {sub && <div className="text-[12px] text-[var(--text-2)]">{sub}</div>}
      </div>
      <RSwitch.Root checked={checked} onCheckedChange={onChange} disabled={disabled} data-checked={String(checked)} className="radix-switch" aria-label={title}>
        <span className="knob"/>
      </RSwitch.Root>
    </div>);
}
export function ConfirmDialog({ open, title, body, danger, onOpenChange, onConfirm, }: {
    open: boolean;
    title: string;
    body?: string;
    danger?: boolean;
    onOpenChange: (o: boolean) => void;
    onConfirm: () => void;
}) {
    const { t } = useSettings();
    const isMobile = useIsMobile();
    const confirmBtn = (className = "") => (<button className={`btn btn-accent ${className}`} style={danger ? { background: "linear-gradient(180deg, rgb(var(--err-rgb)), rgb(var(--err-rgb) / 0.85))" } : undefined} onClick={() => {
            onConfirm();
            onOpenChange(false);
        }}>
      {t("confirm")}
    </button>);
    if (isMobile) {
        return (<Drawer.Root open={open} onOpenChange={onOpenChange} repositionInputs={false}>
        <Drawer.Portal>
          <Drawer.Overlay className="radix-overlay"/>
          <Drawer.Content className="glass--clear edge-lens fixed inset-x-0 bottom-0 z-[80] mx-auto flex max-h-[92dvh] flex-col overflow-y-auto rounded-t-[var(--radius-sheet)] px-5 pt-2" style={{ paddingBottom: "calc(18px + env(safe-area-inset-bottom))" }}>
            <div aria-hidden className="mx-auto mb-2 h-1 w-9 shrink-0 rounded-full" style={{ background: "var(--hairline-strong)" }}/>
            <Drawer.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</Drawer.Title>
            {body && (<Drawer.Description className="mt-2 text-[13px] leading-relaxed text-[var(--text-2)]">
                {body}
              </Drawer.Description>)}
            <div className="mt-5 flex gap-2">
              <button className="btn glass--control flex-1" onClick={() => onOpenChange(false)}>
                {t("cancel")}
              </button>
              {confirmBtn("flex-1")}
            </div>
          </Drawer.Content>
        </Drawer.Portal>
      </Drawer.Root>);
    }
    return (<RDialog.Root open={open} onOpenChange={onOpenChange}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay"/>
        <RDialog.Content className="glass--clear radix-dialog edge-lens">
          <RDialog.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</RDialog.Title>
          {body && <RDialog.Description className="mt-2 text-[13px] text-[var(--text-2)]">{body}</RDialog.Description>}
          <div className="mt-5 flex justify-end gap-2">
            <button className="btn glass--control" onClick={() => onOpenChange(false)}>
              {t("cancel")}
            </button>
            {confirmBtn()}
          </div>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>);
}
type ToastItem = {
    id: number;
    text: string;
    kind: StatusKind;
};
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
    useEffect(() => {
        globalPush = push;
        return () => {
            if (globalPush === push)
                globalPush = null;
        };
    }, [push]);
    return (<div className="pointer-events-none fixed bottom-6 left-1/2 z-[90] flex -translate-x-1/2 flex-col items-center gap-2" role="status" aria-live="polite">
      <AnimatePresence>
        {items.map((it) => (<motion.div key={it.id} initial={{ opacity: 0, y: 14, scale: 0.96 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8, scale: 0.97 }} transition={{ type: "spring", stiffness: 480, damping: 34 }} className="glass--clear edge-lens flex items-center gap-2 rounded-full px-4 py-2 text-[13px] text-[var(--text-1)]">
            <span className="text-[var(--accent)]">
              {it.kind === "err" ? <IconX size={13}/> : it.kind === "warn" ? <IconWarn size={13}/> : <IconInfo size={13}/>}
            </span>
            {it.text}
          </motion.div>))}
      </AnimatePresence>
    </div>);
}
export function Card({ children, className = "", padding = true, }: {
    children: ReactNode;
    className?: string;
    padding?: boolean;
}) {
    return (<section className={`glass edge-lens rounded-[var(--r-panel)] ${padding ? "p-4" : ""} ${className}`}>
      {children}
    </section>);
}
export function DataPanel({ children, className = "" }: {
    children: ReactNode;
    className?: string;
}) {
    return <section className={`glass--data rounded-[var(--r-panel)] ${className}`}>{children}</section>;
}
export function LoadError({ message, onRetry }: {
    message: string;
    onRetry: () => void;
}) {
    const { t } = useSettings();
    return (<div className="flex items-center justify-between gap-3 rounded-[12px] px-3.5 py-2.5 text-[12.5px]" style={{ background: "rgb(var(--err-rgb) / 0.08)", boxShadow: "inset 0 0 0 1px rgb(var(--err-rgb) / 0.25)", color: "rgb(var(--err-rgb))" }} role="alert">
      <span className="min-w-0 truncate" title={message}>
        {t("load_failed")}：{message}
      </span>
      <button className="btn glass--control shrink-0" style={{ height: 26, fontSize: 11, color: "rgb(var(--err-rgb))" }} onClick={onRetry}>
        {t("retry_op")}
      </button>
    </div>);
}
