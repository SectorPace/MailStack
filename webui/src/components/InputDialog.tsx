// 通用玻璃添加/输入对话框（受控）
import { useEffect, useRef } from "react";
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

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center" role="dialog" aria-modal="true" aria-label={title}>
      <div className="radix-overlay" onClick={onClose} />
      <form
        className="glass--clear radix-dialog edge-lens relative z-10"
        style={{ width: "min(400px, calc(100vw - 48px))" }}
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
      >
        <h3 className="text-[16px] font-semibold text-[var(--text-1)]">{title}</h3>
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
    </div>
  );
}
