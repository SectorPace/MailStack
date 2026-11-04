import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode, } from "react";
import { IconCheck, IconInfo, IconWarn, IconX } from "./icons";
export type ToastKind = "ok" | "err" | "info" | "warn";
export type ToastAction = {
    label: string;
    onClick: () => void;
};
type ToastItem = {
    id: number;
    text: string;
    kind: ToastKind;
    action?: ToastAction;
};
export type PushToast = (text: string, kind?: ToastKind, action?: ToastAction) => void;
const ToastContext = createContext<PushToast | null>(null);
let toastSeq = 0;
export function ToastProvider({ children }: {
    children: ReactNode;
}) {
    const [items, setItems] = useState<ToastItem[]>([]);
    const push = useCallback<PushToast>((text, kind = "ok", action) => {
        const id = ++toastSeq;
        setItems((list) => [...list.slice(-3), { id, text, kind, action }]);
        window.setTimeout(() => setItems((list) => list.filter((item) => item.id !== id)), action ? 6500 : 3600);
    }, []);
    const value = useMemo(() => push, [push]);
    return (<ToastContext.Provider value={value}>
      {children}
      <div className="mail-toasts" role="status" aria-live="polite">
        {items.map((item) => (<div key={item.id} className={`mail-toast mail-toast--${item.kind}`}>
            <span className="mail-toast-icon" aria-hidden>
              {item.kind === "err" || item.kind === "warn" ? <IconWarn size={13}/> : item.kind === "info" ? <IconInfo size={13}/> : <IconCheck size={13}/>}
            </span>
            <span className="mail-toast-text">{item.text}</span>
            {item.action && (<button type="button" className="mail-toast-action" onClick={() => {
                    setItems((list) => list.filter((x) => x.id !== item.id));
                    item.action?.onClick();
                }}>
                {item.action.label}
              </button>)}
            <button type="button" className="mail-toast-close" aria-label="close" onClick={() => setItems((list) => list.filter((x) => x.id !== item.id))}>
              <IconX size={12}/>
            </button>
          </div>))}
      </div>
    </ToastContext.Provider>);
}
export function useToast(): PushToast {
    const push = useContext(ToastContext);
    if (!push)
        throw new Error("useToast must be used within ToastProvider");
    return push;
}
export function useEscapeKey(open: boolean, onEscape: () => void): void {
    useEffect(() => {
        if (!open)
            return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") {
                e.stopPropagation();
                onEscape();
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [open, onEscape]);
}
