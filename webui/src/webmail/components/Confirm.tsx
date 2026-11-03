// 确认弹窗（删除邮件 / 丢弃草稿 / 注销等破坏性动作）。
// 与管理台 ui.tsx ConfirmDialog 同一视觉语言（玻璃遮罩 + 近实心对话框），但不依赖
// 管理台的 SettingsProvider（Webmail 是独立入口，有自己的偏好与文案）。
import type { ReactNode } from "react";
import { IconWarn } from "./icons";
import { useEscapeKey } from "./Toast";

export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel,
  cancelLabel,
  danger = false,
  busy = false,
  onConfirm,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  body?: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
  children?: ReactNode;
}) {
  useEscapeKey(open, onClose);
  if (!open) return null;
  return (
    <div
      className="mail-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="mail-dialog" role="dialog" aria-modal="true" aria-label={title}>
        <div className="mail-dialog-head">
          {danger && (
            <span className="mail-dialog-badge mail-dialog-badge--danger" aria-hidden>
              <IconWarn size={15} />
            </span>
          )}
          <div className="mail-dialog-title">{title}</div>
        </div>
        {body != null && <div className="mail-dialog-body">{body}</div>}
        {children}
        <div className="mail-dialog-actions">
          <button type="button" className="btn glass--control" onClick={onClose} disabled={busy}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={danger ? "btn mail-btn-danger" : "btn btn-accent"}
            onClick={onConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
