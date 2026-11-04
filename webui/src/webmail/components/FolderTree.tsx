import { useEffect, useState } from "react";
import type { MailFolder, QuotaInfo } from "../types";
import { buildFolderViews, type FolderKind, type FolderView, } from "../lib/folders";
import { formatFileSize } from "../lib/format";
import { useMailPrefs } from "../store/prefs";
import type { MailKey } from "../i18n";
import { ConfirmDialog } from "./Confirm";
import { IconArchive, IconDraft, IconFolder, IconFolderPlus, IconInbox, IconJunk, IconSend, IconStar, IconTrashCan, IconX, } from "./icons";
const LABEL_KEY: Record<Exclude<FolderKind, "custom">, MailKey> = {
    starred: "folder_starred",
    inbox: "folder_inbox",
    sent: "folder_sent",
    drafts: "folder_drafts",
    archive: "folder_archive",
    junk: "folder_junk",
    trash: "folder_trash",
};
function FolderIcon({ kind, size = 15 }: {
    kind: FolderKind;
    size?: number;
}) {
    switch (kind) {
        case "starred":
            return <IconStar size={size}/>;
        case "inbox":
            return <IconInbox size={size}/>;
        case "sent":
            return <IconSend size={size}/>;
        case "drafts":
            return <IconDraft size={size}/>;
        case "archive":
            return <IconArchive size={size}/>;
        case "junk":
            return <IconJunk size={size}/>;
        case "trash":
            return <IconTrashCan size={size}/>;
        case "custom":
        default:
            return <IconFolder size={size}/>;
    }
}
export function folderLabel(view: FolderView, t: (key: MailKey, params?: Record<string, string | number>) => string): string {
    if (view.kind === "custom")
        return view.folder;
    return t(LABEL_KEY[view.kind]);
}
export function QuotaBar({ quota }: {
    quota: QuotaInfo | null;
}) {
    const { t } = useMailPrefs();
    if (!quota)
        return null;
    const used = formatFileSize(quota.storageBytes);
    const limit = quota.limits?.storageBytes ?? null;
    const percent = limit && limit > 0 ? Math.min(100, (quota.storageBytes / limit) * 100) : null;
    const tone = percent == null ? "" : percent >= 90 ? " err" : percent >= 75 ? " warn" : " ok";
    return (<div className="mail-quota">
      <div className="mail-quota-label">
        <span>{t("quota_used", { used, messages: quota.messages })}</span>
        {percent != null && <span className="tnum">{percent.toFixed(0)}%</span>}
      </div>
      {percent != null ? (<div className="bar" role="progressbar" aria-valuenow={Math.round(percent)} aria-valuemin={0} aria-valuemax={100}>
          <i className={tone.trim()} style={{ width: `${percent}%` }}/>
        </div>) : (<div className="mail-quota-unlimited">{t("quota_unlimited")}</div>)}
    </div>);
}
type FolderDialogState = {
    mode: "create";
} | {
    mode: "rename";
    folder: string;
} | {
    mode: "delete";
    folder: string;
    total: number;
} | null;
export function FolderTree({ folders, quota, activeKey, onSelect, onCreate, onRename, onDelete, variant = "pane", onCloseDrawer, }: {
    folders: MailFolder[];
    quota: QuotaInfo | null;
    activeKey: string | null;
    onSelect: (view: FolderView) => void;
    onCreate?: (name: string) => Promise<void>;
    onRename?: (folder: string, name: string) => Promise<void>;
    onDelete?: (folder: string) => Promise<void>;
    variant?: "pane" | "drawer";
    onCloseDrawer?: () => void;
}) {
    const { t } = useMailPrefs();
    const [dialog, setDialog] = useState<FolderDialogState>(null);
    const [name, setName] = useState("");
    const [busy, setBusy] = useState(false);
    const views = buildFolderViews(folders);
    useEffect(() => {
        if (!dialog)
            setName("");
    }, [dialog]);
    const submit = async () => {
        const value = name.trim();
        if (!value || busy)
            return;
        setBusy(true);
        try {
            if (dialog?.mode === "create" && onCreate)
                await onCreate(value);
            if (dialog?.mode === "rename" && onRename)
                await onRename(dialog.folder, value);
            setDialog(null);
        }
        finally {
            setBusy(false);
        }
    };
    return (<aside className={variant === "drawer" ? "mail-folders-panel" : "mail-folders"} aria-label={t("toggle_folders")}>
      {variant === "drawer" && (<div className="mail-drawer-head">
          <span className="mail-drawer-title">{t("toggle_folders")}</span>
          {onCloseDrawer && (<button type="button" className="icon-btn" aria-label={t("close")} onClick={onCloseDrawer}>
              <IconX size={16}/>
            </button>)}
        </div>)}

      <nav className="mail-folder-list">
        {views.map((view) => {
            const active = activeKey === view.key;
            const label = folderLabel(view, t);
            return (<div key={view.key} className="mail-folder-row">
              <button type="button" className={`mail-folder ${active ? "is-active" : ""}`} aria-current={active ? "page" : undefined} title={label} onClick={() => onSelect(view)}>
                <span className="mail-folder-icon" aria-hidden>
                  <FolderIcon kind={view.kind}/>
                </span>
                <span className="mail-folder-name">{label}</span>
                {view.unseen > 0 && <span className="mail-count is-unread tnum">{view.unseen}</span>}
              </button>
              {view.kind === "custom" && (onRename || onDelete) && (<span className="mail-folder-actions">
                  {onRename && (<button type="button" className="mail-folder-action" aria-label={`${t("folder_rename")}: ${view.folder}`} title={t("folder_rename")} onClick={() => setDialog({ mode: "rename", folder: view.folder })}>
                      ✎
                    </button>)}
                  {onDelete && (<button type="button" className="mail-folder-action" aria-label={`${t("folder_delete")}: ${view.folder}`} title={t("folder_delete")} onClick={() => setDialog({ mode: "delete", folder: view.folder, total: view.total })}>
                      ×
                    </button>)}
                </span>)}
            </div>);
        })}
      </nav>

      {onCreate && (<button type="button" className="mail-folder-add" onClick={() => setDialog({ mode: "create" })}>
          <IconFolderPlus size={15}/> {t("folder_new")}
        </button>)}

      <QuotaBar quota={quota}/>

      {dialog && (dialog.mode === "create" || dialog.mode === "rename") && (<div className="mail-overlay" onMouseDown={(e) => e.target === e.currentTarget && setDialog(null)}>
          <div className="mail-dialog mail-dialog--narrow" role="dialog" aria-modal="true" aria-label={t("folder_name")}>
            <div className="mail-dialog-title">
              {dialog.mode === "create" ? t("folder_new") : t("folder_rename")}
            </div>
            <input className="input mail-dialog-input" autoFocus value={name} placeholder={t("folder_name")} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => {
                if (e.key === "Enter")
                    void submit();
                if (e.key === "Escape")
                    setDialog(null);
            }}/>
            <div className="mail-dialog-actions">
              <button type="button" className="btn glass--control" onClick={() => setDialog(null)} disabled={busy}>
                {t("cancel")}
              </button>
              <button type="button" className="btn btn-accent" onClick={() => void submit()} disabled={busy || !name.trim()}>
                {dialog.mode === "create" ? t("folder_create") : t("save")}
              </button>
            </div>
          </div>
        </div>)}

      {dialog?.mode === "delete" && (<ConfirmDialog open danger title={t("folder_delete")} body={<>
              {t("folder_delete_confirm", { name: dialog.folder })}
              {dialog.total > 0 && <div className="mail-dialog-warn">{t("folder_delete_not_empty")}</div>}
            </>} confirmLabel={t("delete")} cancelLabel={t("cancel")} onClose={() => setDialog(null)} onConfirm={() => {
                const target = dialog.folder;
                setDialog(null);
                void onDelete?.(target);
            }}/>)}
    </aside>);
}
