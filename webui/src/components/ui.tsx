// 共享 UI 元件：状态徽标 / 页头 / 玻璃下拉 / 开关行 / 确认弹窗 / Toast
import { useCallback, useEffect, useState, type ReactNode } from "react";
import * as RSelect from "@radix-ui/react-select";
import * as RDialog from "@radix-ui/react-dialog";
import * as RSwitch from "@radix-ui/react-switch";
import { AnimatePresence, motion } from "motion/react";
import { Drawer } from "vaul";
import { useSettings } from "../store/settings";
import { useIsMobile } from "../hooks/useIsMobile";
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

/* ---------------- 状态徽标：颜色 + 图标/圆点 + 文字 双编码 ---------------- */

export type StatusKind = "ok" | "warn" | "err" | "info" | "hold" | "neutral";

const STATUS_ICON: Record<StatusKind, ReactNode> = {
  ok: <IconCheck size={12} />,
  warn: <IconWarn size={12} />,
  err: <IconX size={12} />,
  info: <IconSend size={11} />,
  hold: <IconClock size={12} />,
  neutral: <span className="dot" aria-hidden />,
};

/** 纯状态展示（列表行内）用的语义色：圆点着色，文字保持中性可读 */
const STATUS_COLOR: Record<StatusKind, string> = {
  ok: "rgb(var(--ok-rgb))",
  warn: "rgb(var(--warn-rgb))",
  err: "rgb(var(--err-rgb))",
  info: "rgb(var(--accent-rgb))",
  hold: "rgb(var(--hold-rgb))",
  neutral: "var(--text-3)",
};

/**
 * variant="badge"（默认）：胶囊徽标（含图标 + 底色），用于筛选/计数等需要强调的场景；
 * variant="dot"：状态点 + 文本（macOS 源列表行内形态），用于纯状态展示。
 * 两种形态都保留「颜色 + 文字」双编码。
 */
export function StatusBadge({
  kind,
  label,
  variant = "badge",
}: {
  kind: StatusKind;
  label: string;
  variant?: "badge" | "dot";
}) {
  if (variant === "dot") {
    return (
      <span
        className="inline-flex items-center gap-1.5 whitespace-nowrap"
        role="status"
        style={{ fontSize: "var(--font-caption)", color: "var(--text-2)" }}
      >
        <span
          aria-hidden
          className="inline-block shrink-0 rounded-full"
          style={{ width: 7, height: 7, background: STATUS_COLOR[kind] }}
        />
        {label}
      </span>
    );
  }
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
  // 移动端 iOS 大标题（28px bold）：纯组件内实现（媒体断点 hook + 内联样式），
  // 工具栏保持紧凑（48px），大标题随页面内容滚动 —— 与 HIG large title 一致。
  const isMobile = useIsMobile();
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        {/* 度量走平台 token：桌面 16px 标题 / 11px caption；移动 28px 大标题 +
            17px 正文副标题（--font-body 在 iOS 档即 17px），iOS 27 内容设计。 */}
        <h1
          className="font-semibold leading-tight tracking-[-0.015em] text-[var(--text-1)]"
          style={{
            fontSize: isMobile ? 28 : "var(--font-title)",
            fontWeight: isMobile ? 700 : undefined,
          }}
        >
          {title}
        </h1>
        <p
          className="mt-0.5 text-[var(--text-2)]"
          style={{ fontSize: isMobile ? "var(--font-body)" : "var(--font-caption)" }}
        >
          {sub}
        </p>
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
  disabled,
}: {
  title: string;
  sub?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  /** 只读展示用（如 TLS 模式由端口决定的死开关）；禁用时整行降透明度。 */
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-6 py-3" style={{ opacity: disabled ? 0.6 : undefined }}>
      <div>
        <div className="text-[13.5px] font-medium text-[var(--text-1)]">{title}</div>
        {sub && <div className="text-[12px] text-[var(--text-2)]">{sub}</div>}
      </div>
      <RSwitch.Root
        checked={checked}
        onCheckedChange={onChange}
        disabled={disabled}
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
  const isMobile = useIsMobile();

  // 确认按钮的破坏性红渐变两形态共用（danger 语义不因形态改变）；
  // className 参数：移动 Sheet 里补 flex-1 等宽（桌面保持 justify-end 原样）。
  const confirmBtn = (className = "") => (
    <button
      className={`btn btn-accent ${className}`}
      style={danger ? { background: "linear-gradient(180deg, rgb(var(--err-rgb)), rgb(var(--err-rgb) / 0.85))" } : undefined}
      onClick={() => {
        onConfirm();
        onOpenChange(false);
      }}
    >
      {t("confirm")}
    </button>
  );

  if (isMobile) {
    // 移动：vaul 底部 Sheet（单档位 + 下拉关闭；Esc/遮罩点击 → onOpenChange(false)，
    // 焦点陷阱由 Radix 提供 —— vaul 即 Radix Dialog）。按钮横向 flex-1 铺满，
    // 高度 .btn = var(--control-h)（iOS 档 44px）→ 触控目标达标。
    return (
      <Drawer.Root open={open} onOpenChange={onOpenChange} repositionInputs={false}>
        <Drawer.Portal>
          <Drawer.Overlay className="radix-overlay" />
          <Drawer.Content
            className="glass--clear edge-lens fixed inset-x-0 bottom-0 z-[80] mx-auto flex max-h-[92dvh] flex-col overflow-y-auto rounded-t-[var(--radius-sheet)] px-5 pt-2"
            style={{ paddingBottom: "calc(18px + env(safe-area-inset-bottom))" }}
          >
            <div
              aria-hidden
              className="mx-auto mb-2 h-1 w-9 shrink-0 rounded-full"
              style={{ background: "var(--hairline-strong)" }}
            />
            <Drawer.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</Drawer.Title>
            {body && (
              <Drawer.Description className="mt-2 text-[13px] leading-relaxed text-[var(--text-2)]">
                {body}
              </Drawer.Description>
            )}
            <div className="mt-5 flex gap-2">
              <button className="btn glass--control flex-1" onClick={() => onOpenChange(false)}>
                {t("cancel")}
              </button>
              {confirmBtn("flex-1")}
            </div>
          </Drawer.Content>
        </Drawer.Portal>
      </Drawer.Root>
    );
  }

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
            {confirmBtn()}
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
    <div
      className="pointer-events-none fixed bottom-6 left-1/2 z-[90] flex -translate-x-1/2 flex-col items-center gap-2"
      // Toast 是被动通知：polite 播报，不打断正在进行的读屏（WEBUI_AUDIT a11y 债）
      role="status"
      aria-live="polite"
    >
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

/* ---------------- 列表加载失败横幅 ---------------- */

/**
 * 加载失败必须与「暂无数据」可区分（原先 `r.ok && setRows(...)` 没有 else，
 * 失败页跟空列表长得一模一样 —— 虚假 UI）。各列表页共用，message 透传后端错误，
 * onRetry 复用该页的加载函数。
 */
export function LoadError({ message, onRetry }: { message: string; onRetry: () => void }) {
  const { t } = useSettings();
  return (
    <div
      className="flex items-center justify-between gap-3 rounded-[12px] px-3.5 py-2.5 text-[12.5px]"
      style={{ background: "rgb(var(--err-rgb) / 0.08)", boxShadow: "inset 0 0 0 1px rgb(var(--err-rgb) / 0.25)", color: "rgb(var(--err-rgb))" }}
      role="alert"
    >
      <span className="min-w-0 truncate" title={message}>
        {t("load_failed")}：{message}
      </span>
      <button
        className="btn glass--control shrink-0"
        style={{ height: 26, fontSize: 11, color: "rgb(var(--err-rgb))" }}
        onClick={onRetry}
      >
        {t("retry_op")}
      </button>
    </div>
  );
}
