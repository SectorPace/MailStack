// 通用玻璃添加/输入对话框（受控）
//
// 桌面（≥768）：Radix Dialog 承载 —— 焦点陷阱、Esc 关闭、Title 与 aria 关联都由 Radix
// 提供。原先是手写 div + role="dialog"：无焦点陷阱、不响应 Esc、无标题关联，
// 与同项目的 ConfirmDialog（Radix）行为不一致（WEBUI_AUDIT §3.2）。
// 移动（<768）：vaul 底部 Sheet（iOS 27 内容设计）—— 同一表单体、同一行为契约：
// 单档位 + 下拉关闭（不设 snapPoints），Esc 走 Radix 的 onOpenChange(false) → onClose，
// 焦点陷阱同 Radix。repositionInputs={false}：iOS 上键盘弹起不移动整个抽屉
// （vaul 默认会 transform 重排，输入场景抖动明显）。圆角 var(--radius-sheet)
// （iOS 档 26px）；底部 env(safe-area-inset-bottom) 安全区。
import { useEffect, useRef } from "react";
import * as RDialog from "@radix-ui/react-dialog";
import { Drawer } from "vaul";
import { useSettings } from "../store/settings";
import { useIsMobile } from "../hooks/useIsMobile";

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
  fields: { key: string; label: string; placeholder?: string; type?: string; disabled?: boolean; hint?: string }[];
  values: Record<string, string>;
  onChange: (key: string, v: string) => void;
  onSubmit: () => void;
  onClose: () => void;
}) {
  const { t } = useSettings();
  const isMobile = useIsMobile();
  const first = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) setTimeout(() => first.current?.focus(), 40);
  }, [open]);

  // 表单体两形态共用（桌面 Dialog / 移动 Sheet），行为零漂移：校验、hint、
  // disabled、首字段聚焦、Enter 提交全部保留。
  const form = (
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
            className={"input" + (f.disabled ? " opacity-60" : "")}
            type={f.type ?? "text"}
            value={values[f.key] ?? ""}
            placeholder={f.placeholder}
            disabled={f.disabled}
            onChange={(e) => onChange(f.key, e.target.value)}
          />
          {/* 诚实提示位：后端未实现/忽略的字段（如配额）在此说明，而非装作可配置。 */}
          {f.hint && <span className="mt-1 block text-[10.5px] leading-relaxed text-[var(--text-3)]">{f.hint}</span>}
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
  );

  if (isMobile) {
    return (
      <Drawer.Root
        open={open}
        onOpenChange={(o) => {
          if (!o) onClose();
        }}
        repositionInputs={false}
      >
        <Drawer.Portal>
          <Drawer.Overlay className="radix-overlay" />
          <Drawer.Content
            className="glass--clear edge-lens fixed inset-x-0 bottom-0 z-[80] mx-auto flex max-h-[92dvh] flex-col overflow-y-auto rounded-t-[var(--radius-sheet)] px-5 pt-2"
            style={{
              // iOS 底部安全区（Home indicator）：内容层自己加内边距
              paddingBottom: "calc(18px + env(safe-area-inset-bottom))",
            }}
          >
            {/* 抓手（拖拽把手，纯视觉；vaul 的拖拽命中区域是整个 Content） */}
            <div
              aria-hidden
              className="mx-auto mb-2 h-1 w-9 shrink-0 rounded-full"
              style={{ background: "var(--hairline-strong)" }}
            />
            <Drawer.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</Drawer.Title>
            {form}
          </Drawer.Content>
        </Drawer.Portal>
      </Drawer.Root>
    );
  }

  return (
    <RDialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay" />
        <RDialog.Content
          className="glass--clear radix-dialog edge-lens"
          style={{ width: "min(400px, calc(100vw - 48px))" }}
        >
          <RDialog.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</RDialog.Title>
          {form}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>
  );
}
