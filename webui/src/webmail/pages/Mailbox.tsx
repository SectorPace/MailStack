import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { MailFolder, MessageDetail, MessageSummary, QuotaInfo } from "../types";
import type { MailRoute, Navigate } from "../router";
import type { BatchAction, BatchRequest, MessageListResult } from "../types";
import { batchMessages, deleteMessage, describeError, getMessage, listMessages, patchFlags, searchMessages, } from "../api";
import type { ReplyKind } from "../lib/reply";
import { buildFolderViews, inboxFolderName, type FolderView } from "../lib/folders";
import { FolderTree, folderLabel } from "../components/FolderTree";
import { MessageList, type MessageListActions } from "../components/MessageList";
import { MessageView, type MessageViewActions } from "../components/MessageView";
import { ConfirmDialog } from "../components/Confirm";
import { EmptyState } from "../components/states";
import { useToast } from "../components/Toast";
import { useMailPrefs } from "../store/prefs";
import { isEditableTarget, resolveShortcut } from "../lib/shortcuts";
import { IconMail } from "../components/icons";
export const STARRED_ROUTE_NAME = "Starred";
type DeleteTarget = {
    uids: number[];
    label: string;
} | null;
export type MailboxProps = {
    route: MailRoute;
    navigate: Navigate;
    folders: MailFolder[];
    quota: QuotaInfo | null;
    reloadFolders: () => void;
    isMobile: boolean;
    foldersOpen: boolean;
    onCloseFolders: () => void;
    refreshToken?: number;
    onComposeDraft: (detail: MessageDetail) => void;
    onReply: (kind: ReplyKind, detail: MessageDetail) => void;
    shortcutsEnabled: boolean;
    onCreateFolder: (name: string) => Promise<void>;
    onRenameFolder: (folder: string, name: string) => Promise<void>;
    onDeleteFolder: (folder: string) => Promise<void>;
};
export function Mailbox(props: MailboxProps) {
    const { route, navigate, folders, quota, reloadFolders, isMobile, foldersOpen, onCloseFolders, refreshToken = 0, onComposeDraft, onReply, shortcutsEnabled, onCreateFolder, onRenameFolder, onDeleteFolder, } = props;
    const { t, prefs } = useMailPrefs();
    const toast = useToast();
    const views = useMemo(() => buildFolderViews(folders), [folders]);
    const inboxView = useMemo(() => views.find((v) => v.kind === "inbox"), [views]);
    const starredView = useMemo(() => views.find((v) => v.kind === "starred"), [views]);
    const specialByKind = useCallback((kind: FolderView["kind"]) => views.find((v) => v.kind === kind), [views]);
    const activeView: FolderView | null = useMemo(() => {
        if (route.name === "search")
            return inboxView ?? null;
        if (route.name === "folder" && route.folder === STARRED_ROUTE_NAME)
            return starredView ?? null;
        const name = route.name === "message" ? route.folder : route.name === "folder" ? route.folder : (inboxView?.folder ?? "INBOX");
        return views.find((v) => v.folder === name && !v.flaggedOnly) ?? (route.name === "inbox" ? (inboxView ?? null) : null);
    }, [route, views, inboxView, starredView]);
    const searchQuery = route.name === "search" ? route.q : null;
    const activeFolder = activeView?.folder ?? inboxFolderName(folders);
    const activeFolderKind = activeView?.kind ?? "inbox";
    const archivedFolder = useMemo(() => specialByKind("archive")?.folder ?? null, [specialByKind]);
    const [messages, setMessages] = useState<MessageSummary[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [loadingMore, setLoadingMore] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selected, setSelected] = useState<Set<number>>(new Set());
    const [cursorUid, setCursorUid] = useState<number | null>(null);
    const [refreshKey, setRefreshKey] = useState(0);
    const [deleteTarget, setDeleteTarget] = useState<DeleteTarget>(null);
    const [deleteBusy, setDeleteBusy] = useState(false);
    const [currentDetail, setCurrentDetail] = useState<MessageDetail | null>(null);
    const seq = useRef(0);
    const activeMessageUid = route.name === "message" ? route.uid : null;
    const pageSize = prefs.pageSize;
    const fetchPage = useCallback(async (offset: number) => {
        const view = activeView;
        if (!view) {
            setMessages([]);
            setTotal(0);
            setLoading(false);
            return;
        }
        const id = ++seq.current;
        if (offset === 0)
            setLoading(true);
        else
            setLoadingMore(true);
        setError(null);
        try {
            let result: MessageListResult;
            if (searchQuery !== null) {
                result = await searchMessages(searchQuery, { folder: view.folder, limit: pageSize });
            }
            else {
                result = await listMessages({
                    folder: view.folder,
                    limit: pageSize,
                    offset,
                    flagged: view.flaggedOnly ? true : undefined,
                    sort: "date_desc",
                });
            }
            if (id !== seq.current)
                return;
            setMessages((prev) => (offset === 0 ? result.messages : [...prev, ...result.messages]));
            setTotal(result.total);
        }
        catch (e) {
            if (id !== seq.current)
                return;
            setError(describeError(e, prefs.lang));
            if (offset === 0) {
                setMessages([]);
                setTotal(0);
            }
        }
        finally {
            if (id === seq.current) {
                setLoading(false);
                setLoadingMore(false);
            }
        }
    }, [activeView, searchQuery, pageSize, prefs.lang]);
    useEffect(() => {
        setSelected(new Set());
        setCursorUid(null);
        void fetchPage(0);
    }, [fetchPage, refreshKey, refreshToken]);
    useEffect(() => {
        if (route.name !== "message")
            setCurrentDetail(null);
    }, [route]);
    const reload = useCallback(() => {
        setRefreshKey((n) => n + 1);
        reloadFolders();
    }, [reloadFolders]);
    const openDraft = useCallback(async (uid: number, folder: string) => {
        try {
            const detail = await getMessage(folder, uid);
            onComposeDraft(detail);
        }
        catch (e) {
            toast(describeError(e, prefs.lang), "err");
        }
    }, [onComposeDraft, prefs.lang, toast]);
    const openMessage = useCallback((message: MessageSummary) => {
        if (activeFolderKind === "drafts") {
            void openDraft(message.uid, activeFolder);
            return;
        }
        navigate({ name: "message", folder: activeFolder, uid: message.uid });
    }, [activeFolder, activeFolderKind, navigate, openDraft]);
    const toggleStar = useCallback(async (message: MessageSummary) => {
        const flagged = message.flags.includes("flagged");
        const optimistic = flagged ? message.flags.filter((f) => f !== "flagged") : [...message.flags, "flagged"];
        setMessages((prev) => prev.map((m) => (m.uid === message.uid ? { ...m, flags: optimistic } : m)));
        try {
            await patchFlags(activeFolder, message.uid, { flagged: !flagged });
            reloadFolders();
        }
        catch (e) {
            setMessages((prev) => prev.map((m) => (m.uid === message.uid ? { ...m, flags: message.flags } : m)));
            toast(describeError(e, prefs.lang), "err");
        }
    }, [activeFolder, prefs.lang, reloadFolders, toast]);
    const runBatch = useCallback(async (action: BatchAction, target?: string): Promise<boolean> => {
        const uids = [...selected];
        if (!uids.length || !activeView)
            return false;
        const request: BatchRequest = { folder: activeFolder, uids, action };
        if (target)
            request.target = target;
        try {
            const result = await batchMessages(request);
            const affected = result.affected || uids.length;
            if (action === "delete")
                toast(t("deleted", { n: affected }), "ok");
            else if (action === "move")
                toast(t("moved", { n: affected }), "ok");
            else if (action === "mark_seen")
                toast(t("marked_read"), "ok");
            else if (action === "mark_unseen")
                toast(t("marked_unread"), "ok");
            else if (action === "flag")
                toast(t("starred"), "ok");
            else if (action === "unflag")
                toast(t("unstarred"), "ok");
            setSelected(new Set());
            reload();
            return true;
        }
        catch (e) {
            toast(describeError(e, prefs.lang), "err");
            return false;
        }
    }, [activeFolder, activeView, reload, selected, t, toast, prefs.lang]);
    const archiveSelected = useCallback(() => {
        if (!archivedFolder) {
            toast(t("archive_unavailable"), "err");
            return;
        }
        void runBatch("move", archivedFolder);
    }, [archivedFolder, runBatch, t, toast]);
    const requestDelete = useCallback((uids: number[], label: string) => {
        if (uids.length)
            setDeleteTarget({ uids, label });
    }, []);
    const confirmDelete = useCallback(async () => {
        if (!deleteTarget)
            return;
        setDeleteBusy(true);
        try {
            for (const uid of deleteTarget.uids) {
                await deleteMessage(activeFolder, uid);
            }
            toast(t("deleted", { n: deleteTarget.uids.length }), "ok");
            setDeleteTarget(null);
            setSelected(new Set());
            if (route.name === "message" && deleteTarget.uids.includes(route.uid)) {
                navigate({ name: "folder", folder: activeFolder });
            }
            reload();
        }
        catch (e) {
            toast(describeError(e, prefs.lang), "err");
        }
        finally {
            setDeleteBusy(false);
        }
    }, [activeFolder, deleteTarget, navigate, reload, route, t, toast, prefs.lang]);
    const moveSelected = useCallback((target: string) => void runBatch("move", target), [runBatch]);
    const listActions: MessageListActions = useMemo(() => ({
        onRefresh: reload,
        onOpen: openMessage,
        onToggleSelect: (uid) => setSelected((prev) => {
            const next = new Set(prev);
            if (next.has(uid))
                next.delete(uid);
            else
                next.add(uid);
            return next;
        }),
        onSelectAll: (checked) => {
            if (!checked) {
                setSelected(new Set());
                return;
            }
            setSelected(new Set(messages.map((m) => m.uid)));
        },
        onStar: (message) => void toggleStar(message),
        onMarkRead: () => void runBatch("mark_seen"),
        onMarkUnread: () => void runBatch("mark_unseen"),
        onFlag: () => void runBatch("flag"),
        onUnflag: () => void runBatch("unflag"),
        onArchive: archiveSelected,
        onDelete: () => requestDelete([...selected], t("delete")),
        onMove: moveSelected,
        onLoadMore: () => void fetchPage(messages.length),
    }), [archiveSelected, fetchPage, messages, moveSelected, openMessage, reload, requestDelete, runBatch, selected, t, toggleStar]);
    const handleFlagsChanged = useCallback((detail: MessageDetail, flags: string[]) => {
        setMessages((prev) => prev.map((m) => (m.uid === detail.uid ? { ...m, flags } : m)));
        setCurrentDetail((prev) => (prev && prev.uid === detail.uid ? { ...prev, flags } : prev));
        reloadFolders();
    }, [reloadFolders]);
    const viewActions: MessageViewActions = useMemo(() => ({
        onBack: () => navigate({ name: "folder", folder: activeFolder }),
        onReply: (kind, detail) => onReply(kind, detail),
        onArchive: (detail) => {
            if (!archivedFolder) {
                toast(t("archive_unavailable"), "err");
                return;
            }
            void batchMessages({ folder: detail.folder, uids: [detail.uid], action: "move", target: archivedFolder })
                .then(() => {
                toast(t("archived"), "ok");
                navigate({ name: "folder", folder: activeFolder });
                reload();
            })
                .catch((e) => toast(describeError(e, prefs.lang), "err"));
        },
        onDelete: (detail) => requestDelete([detail.uid], t("delete")),
        onMove: (detail, target) => {
            void batchMessages({ folder: detail.folder, uids: [detail.uid], action: "move", target })
                .then(() => {
                toast(t("moved", { n: 1 }), "ok");
                navigate({ name: "folder", folder: target });
                reload();
            })
                .catch((e) => toast(describeError(e, prefs.lang), "err"));
        },
        onFlagsChanged: handleFlagsChanged,
        onLoaded: (detail) => setCurrentDetail(detail),
    }), [activeFolder, archivedFolder, handleFlagsChanged, navigate, onReply, prefs.lang, reload, requestDelete, t, toast]);
    const shortcutTarget = useCallback((): MessageSummary | null => {
        if (activeMessageUid != null) {
            return messages.find((m) => m.uid === activeMessageUid) ?? null;
        }
        if (cursorUid != null)
            return messages.find((m) => m.uid === cursorUid) ?? null;
        return null;
    }, [activeMessageUid, cursorUid, messages]);
    const moveCursor = useCallback((delta: number) => {
        if (!messages.length)
            return;
        const currentIndex = activeMessageUid != null ? messages.findIndex((m) => m.uid === activeMessageUid) : cursorUid != null ? messages.findIndex((m) => m.uid === cursorUid) : -1;
        const base = currentIndex >= 0 ? currentIndex : delta > 0 ? -1 : messages.length;
        const nextIndex = Math.min(messages.length - 1, Math.max(0, base + delta));
        const next = messages[nextIndex];
        if (!next)
            return;
        setCursorUid(next.uid);
        if (activeFolderKind === "drafts")
            return;
        navigate({ name: "message", folder: activeFolder, uid: next.uid });
    }, [activeFolder, activeFolderKind, activeMessageUid, cursorUid, messages, navigate]);
    const toggleUnread = useCallback(() => {
        const target = shortcutTarget();
        if (!target)
            return;
        const seen = target.flags.includes("seen");
        setMessages((prev) => prev.map((m) => (m.uid === target.uid ? { ...m, flags: seen ? m.flags.filter((f) => f !== "seen") : [...m.flags, "seen"] } : m)));
        void patchFlags(activeFolder, target.uid, { seen: !seen })
            .then(() => {
            toast(seen ? t("marked_unread") : t("marked_read"), "ok");
            reloadFolders();
        })
            .catch((e) => {
            setMessages((prev) => prev.map((m) => (m.uid === target.uid ? { ...m, flags: target.flags } : m)));
            toast(describeError(e, prefs.lang), "err");
        });
    }, [activeFolder, prefs.lang, reloadFolders, shortcutTarget, t, toast]);
    const shortcutStar = useCallback(() => {
        const target = shortcutTarget();
        if (target)
            void toggleStar(target);
    }, [shortcutTarget, toggleStar]);
    const shortcutArchive = useCallback(() => {
        const target = shortcutTarget();
        if (target) {
            if (!archivedFolder) {
                toast(t("archive_unavailable"), "err");
                return;
            }
            void batchMessages({ folder: activeFolder, uids: [target.uid], action: "move", target: archivedFolder })
                .then(() => {
                toast(t("archived"), "ok");
                if (activeMessageUid != null)
                    navigate({ name: "folder", folder: activeFolder });
                reload();
            })
                .catch((e) => toast(describeError(e, prefs.lang), "err"));
        }
        else if (selected.size) {
            archiveSelected();
        }
    }, [activeFolder, activeMessageUid, archivedFolder, archiveSelected, navigate, prefs.lang, reload, selected.size, t, toast]);
    const shortcutDelete = useCallback(() => {
        const target = shortcutTarget();
        if (target)
            requestDelete([target.uid], t("delete"));
        else if (selected.size)
            requestDelete([...selected], t("delete"));
    }, [requestDelete, selected, shortcutTarget, t]);
    useEffect(() => {
        if (!shortcutsEnabled)
            return;
        const onKeyDown = (e: KeyboardEvent) => {
            if (isEditableTarget(e.target))
                return;
            const action = resolveShortcut(e);
            if (!action)
                return;
            switch (action) {
                case "reply":
                    if (currentDetail) {
                        e.preventDefault();
                        onReply("reply", currentDetail);
                    }
                    break;
                case "replyAll":
                    if (currentDetail) {
                        e.preventDefault();
                        onReply("replyAll", currentDetail);
                    }
                    break;
                case "forward":
                    if (currentDetail) {
                        e.preventDefault();
                        onReply("forward", currentDetail);
                    }
                    break;
                case "next":
                    e.preventDefault();
                    moveCursor(1);
                    break;
                case "prev":
                    e.preventDefault();
                    moveCursor(-1);
                    break;
                case "toggleUnread":
                    e.preventDefault();
                    toggleUnread();
                    break;
                case "toggleStar":
                    e.preventDefault();
                    shortcutStar();
                    break;
                case "archive":
                    e.preventDefault();
                    shortcutArchive();
                    break;
                case "delete":
                    e.preventDefault();
                    shortcutDelete();
                    break;
                case "escape":
                    if (deleteTarget) {
                        setDeleteTarget(null);
                    }
                    else if (selected.size) {
                        setSelected(new Set());
                    }
                    else if (isMobile && route.name === "message") {
                        navigate({ name: "folder", folder: activeFolder });
                    }
                    break;
                default:
                    break;
            }
        };
        window.addEventListener("keydown", onKeyDown);
        return () => window.removeEventListener("keydown", onKeyDown);
    }, [
        activeFolder,
        currentDetail,
        deleteTarget,
        isMobile,
        moveCursor,
        navigate,
        onReply,
        route,
        selected.size,
        shortcutArchive,
        shortcutDelete,
        shortcutStar,
        shortcutsEnabled,
        toggleUnread,
    ]);
    const title = searchQuery !== null ? t("search_results") : activeView ? folderLabel(activeView, t) : t("folder_inbox");
    const emptyTitle = searchQuery !== null ? t("empty_search") : activeFolderKind === "inbox" ? t("empty_inbox") : t("empty_folder");
    const moveTargets = useMemo(() => {
        const seen = new Set<string>();
        const out: {
            name: string;
            label: string;
        }[] = [];
        for (const view of views) {
            if (view.flaggedOnly)
                continue;
            if (view.folder === activeFolder || seen.has(view.folder))
                continue;
            seen.add(view.folder);
            out.push({ name: view.folder, label: folderLabel(view, t) });
        }
        return out;
    }, [activeFolder, t, views]);
    const hasMore = messages.length < total;
    const list = (<MessageList title={title} messages={messages} total={total} loading={loading} loadingMore={loadingMore} error={error} selected={selected} activeUid={activeMessageUid} cursorUid={cursorUid} folderKind={activeFolderKind} isSearch={searchQuery !== null} moveTargets={moveTargets} canArchive={archivedFolder != null} hasMore={hasMore} density={prefs.density} emptyTitle={emptyTitle} emptyHint={searchQuery !== null ? t("search_hint") : undefined} actions={listActions}/>);
    const reader = route.name === "message" ? (<MessageView key={`${route.folder}/${route.uid}/${refreshKey}`} folder={route.folder} uid={route.uid} moveTargets={moveTargets} canArchive={archivedFolder != null} showBack={isMobile} actions={viewActions}/>) : (<section className="mail-reader mail-reader--empty">
        <EmptyState icon={<IconMail size={26}/>} title={t("empty_reader")} hint={t("empty_reader_hint")}/>
      </section>);
    return (<div className="mail-shell" data-view={route.name === "message" ? "reader" : "list"}>

      {!isMobile && (<FolderTree folders={folders} quota={quota} activeKey={activeView?.key ?? null} onSelect={(view) => {
                if (view.kind === "starred")
                    navigate({ name: "folder", folder: STARRED_ROUTE_NAME });
                else
                    navigate({ name: "folder", folder: view.folder });
            }} onCreate={onCreateFolder} onRename={onRenameFolder} onDelete={onDeleteFolder}/>)}

      {isMobile && foldersOpen && (<>
          <div className="mail-drawer-overlay" onClick={onCloseFolders} aria-hidden/>
          <div className="mail-folder-drawer">
            <FolderTree folders={folders} quota={quota} activeKey={activeView?.key ?? null} variant="drawer" onCloseDrawer={onCloseFolders} onSelect={(view) => {
                onCloseFolders();
                if (view.kind === "starred")
                    navigate({ name: "folder", folder: STARRED_ROUTE_NAME });
                else
                    navigate({ name: "folder", folder: view.folder });
            }} onCreate={onCreateFolder} onRename={onRenameFolder} onDelete={onDeleteFolder}/>
          </div>
        </>)}

      {isMobile ? (route.name === "message" ? (<div className="mail-pane mail-mobile-pane">{reader}</div>) : (<div className="mail-pane mail-mobile-pane">{list}</div>)) : (<>
          <div className="mail-pane mail-pane--list">{list}</div>
          <div className="mail-pane mail-pane--reader">{reader}</div>
        </>)}

      <ConfirmDialog open={deleteTarget != null} danger title={t("delete_confirm_title")} body={t("delete_confirm_body", { n: deleteTarget?.uids.length ?? 0 })} confirmLabel={t("delete")} cancelLabel={t("cancel")} busy={deleteBusy} onClose={() => setDeleteTarget(null)} onConfirm={() => void confirmDelete()}/>
    </div>);
}
