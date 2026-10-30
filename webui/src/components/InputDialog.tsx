// 通用玻璃添加/输入对话框（受控）
//
// 改用 Radix Dialog 承载：焦点陷阱、Esc 关闭、RDialog.Title 与 aria 关联都由 Radix
// 提供。原先是手写 div + role="dialog"：无焦点陷阱、不响应 Esc、无标题关联，
// 与同项目的 ConfirmDialog（Radix）行为不一致（WEBUI_AUDIT §3.2）。
import { useEffect, useRef } from "react";
import * as RDialog from "@radix-ui/react-dialog";
import { useSettings } from "../store/settings";

export function InputDialog({
  open,
  title,
  fields,
  values,
  onChange,
  onSubmit,
  onClose,
}: {
  open: boolean;
  title: string;
  fields: { key: string; label: string; placeholder?: string; type?: string }[];
  values: Record<string, string>;
  onChange: (key: string, v: string) => void;
  onSubmit: () => void;
  onClose: () => void;
}) {
  const { t } = useSettings();
  const first = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) setTimeout(() => first.current?.focus(), 40);
  }, [open]);

  return (
    <RDialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay" />
        <RDialog.Content
          className="glass--clear radix-dialog edge-lens"
          style={{ width: "min(400px, calc(100vw - 48px))" }}
        >
          <RDialog.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</RDialog.Title>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              onSubmit();
            }}
          >
            {fields.map((f, i) => (
              <label key={f.key} className="mt-4 block">
                <span className="mb-1.5 block text-[12.5px] font-medium text-[var(--text-2)]">{f.label}</span>
                <input
                  ref={i === 0 ? first : undefined}
                  className="input"
                  type={f.type ?? "text"}
                  value={values[f.key] ?? ""}
                  placeholder={f.placeholder}
                  onChange={(e) => onChange(f.key, e.target.value)}
                />
              </label>
            ))}
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" className="btn glass--control" onClick={onClose}>
                {t("cancel")}
              </button>
              <button type="submit" className="btn btn-accent">
                {t("confirm")}
              </button>
            </div>
          </form>
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}
