import { useEffect, useRef } from "react";
import * as RDialog from "@radix-ui/react-dialog";
import { Drawer } from "vaul";
import { useSettings } from "../store/settings";
import { useIsMobile } from "../hooks/useIsMobile";
export function InputDialog({ open, title, fields, values, onChange, onSubmit, onClose, }: {
    open: boolean;
    title: string;
    fields: {
        key: string;
        label: string;
        placeholder?: string;
        type?: string;
        disabled?: boolean;
        hint?: string;
    }[];
    values: Record<string, string>;
    onChange: (key: string, v: string) => void;
    onSubmit: () => void;
    onClose: () => void;
}) {
    const { t } = useSettings();
    const isMobile = useIsMobile();
    const first = useRef<HTMLInputElement>(null);
    useEffect(() => {
        if (open)
            setTimeout(() => first.current?.focus(), 40);
    }, [open]);
    const form = (<form onSubmit={(e) => {
            e.preventDefault();
            onSubmit();
        }}>
      {fields.map((f, i) => (<label key={f.key} className="mt-4 block">
          <span className="mb-1.5 block text-[12.5px] font-medium text-[var(--text-2)]">{f.label}</span>
          <input ref={i === 0 ? first : undefined} className={"input" + (f.disabled ? " opacity-60" : "")} type={f.type ?? "text"} value={values[f.key] ?? ""} placeholder={f.placeholder} disabled={f.disabled} onChange={(e) => onChange(f.key, e.target.value)}/>

          {f.hint && <span className="mt-1 block text-[10.5px] leading-relaxed text-[var(--text-3)]">{f.hint}</span>}
        </label>))}
      <div className="mt-5 flex justify-end gap-2">
        <button type="button" className="btn glass--control" onClick={onClose}>
          {t("cancel")}
        </button>
        <button type="submit" className="btn btn-accent">
          {t("confirm")}
        </button>
      </div>
    </form>);
    if (isMobile) {
        return (<Drawer.Root open={open} onOpenChange={(o) => {
                if (!o)
                    onClose();
            }} repositionInputs={false}>
        <Drawer.Portal>
          <Drawer.Overlay className="radix-overlay"/>
          <Drawer.Content className="glass--clear edge-lens fixed inset-x-0 bottom-0 z-[80] mx-auto flex max-h-[92dvh] flex-col overflow-y-auto rounded-t-[var(--radius-sheet)] px-5 pt-2" style={{
                paddingBottom: "calc(18px + env(safe-area-inset-bottom))",
            }}>

            <div aria-hidden className="mx-auto mb-2 h-1 w-9 shrink-0 rounded-full" style={{ background: "var(--hairline-strong)" }}/>
            <Drawer.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</Drawer.Title>
            {form}
          </Drawer.Content>
        </Drawer.Portal>
      </Drawer.Root>);
    }
    return (<RDialog.Root open={open} onOpenChange={(o) => !o && onClose()}>
      <RDialog.Portal>
        <RDialog.Overlay className="radix-overlay"/>
        <RDialog.Content className="glass--clear radix-dialog edge-lens" style={{ width: "min(400px, calc(100vw - 48px))" }}>
          <RDialog.Title className="text-[16px] font-semibold text-[var(--text-1)]">{title}</RDialog.Title>
          {form}
        </RDialog.Content>
      </RDialog.Portal>
    </RDialog.Root>);
}
