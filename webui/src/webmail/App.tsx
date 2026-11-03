// Webmail 应用外壳（mail.html 入口）—— 会话引导、路由守卫、文件夹/配额数据、
// 写信浮层与设置弹层的编排、document.title 未读计数、全局快捷键（c / / / Esc）。
//
// 会话（契约 §1）：`GET /mail/api/session` 恢复；401 → 登录页并提示会话过期；
// 网络失败 → 明确的「无法连接 mailstack-webmail」错误页（fail-closed，绝不降级假数据；
// 开发构建可用 ?mock=1 进入带「演示数据」标识的演示模式）。
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  deleteFolder as apiDeleteFolder,
  createFolder as apiCreateFolder,
  describeError,
  isApiError,
  isDemoMode,
  getQuota,
  getSession,
  listFolders,
  logout as apiLogout,
  onSessionLost,
  renameFolder as apiRenameFolder,
} from "./api";
import type { MailFolder, MessageDetail, QuotaInfo, SendResult, SessionInfo } from "./types";
import { isMailboxRoute, useMailRoute, type MailRoute } from "./router";
import { MailPrefsProvider, useMailPrefs } from "./store/prefs";
import { ToastProvider, useToast } from "./components/Toast";
import { Header } from "./components/Header";
import { Login } from "./components/Login";
import { SettingsDialog } from "./components/SettingsDialog";
import { Compose } from "./components/Compose";
import { Mailbox, STARRED_ROUTE_NAME } from "./pages/Mailbox";
import { EmptyState, ErrorBanner, Spinner } from "./components/states";
import { buildFolderViews, totalUnseen } from "./lib/folders";
import { folderLabel } from "./components/FolderTree";
import { buildDocumentTitle } from "./lib/title";
import {
  buildDraftCompose,
  buildNewCompose,
  buildReplyCompose,
  effectiveDisplayName,
  type ComposeInitial,
} from "./lib/compose";
import type { ReplyKind } from "./lib/reply";
import { isEditableTarget, resolveShortcut } from "./lib/shortcuts";
import { useIsMobile } from "../hooks/useIsMobile";
import { IconCompose, IconRefresh, IconWarn } from "./components/icons";

export default function App() {
  return (
    <MailPrefsProvider>
      <ToastProvider>
        <Shell />
      </ToastProvider>
    </MailPrefsProvider>
  );
}

type ComposeState = { initial: ComposeInitial; fullscreen: boolean; key: number };

function Shell() {
  const { t, prefs } = useMailPrefs();
  const toast = useToast();
  const isMobile = useIsMobile();
  const { route, navigate } = useMailRoute();
  const searchRef = useRef<HTMLInputElement>(null);

  const [session, setSession] = useState<SessionInfo | null>(null);
  const [booting, setBooting] = useState(true);
  const [fatal, setFatal] = useState<"network" | "server" | null>(null);
  const [expired, setExpired] = useState(false);
  const [folders, setFolders] = useState<MailFolder[]>([]);
  const [quota, setQuota] = useState<QuotaInfo | null>(null);
  const [foldersError, setFoldersError] = useState<string | null>(null);
  const [foldersLoading, setFoldersLoading] = useState(false);
  const [foldersOpen, setFoldersOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [compose, setCompose] = useState<ComposeState | null>(null);
  const [mailboxRoute, setMailboxRoute] = useState<MailRoute>({ name: "inbox" });
  const [mailboxRefresh, setMailboxRefresh] = useState(0);
  const composeSeq = useRef(0);
  const demo = isDemoMode();

  /** 写信发送/存草稿/文件夹 CRUD 后，通知已挂载的列表重新拉取（否则列表停在旧快照）。 */
  const bumpMailbox = useCallback(() => setMailboxRefresh((n) => n + 1), []);

  const displayName = session ? effectiveDisplayName(prefs, session.user.displayName) : "";

  /* ---------------- 会话引导 / 失效 ---------------- */

  const boot = useCallback(async () => {
    setBooting(true);
    setFatal(null);
    try {
      const info = await getSession();
      setSession(info);
      setExpired(false);
    } catch (e) {
      if (isApiError(e) && e.network) {
        setFatal("network");
      } else if (isApiError(e) && e.status === 401) {
        setSession(null);
        setExpired(true);
      } else {
        setFatal("server");
      }
    } finally {
      setBooting(false);
    }
  }, []);

  useEffect(() => {
    void boot();
  }, [boot]);

  // 401 / CSRF 失效 → 清会话、回登录门并提示会话过期（服务端已吊销/不可用）。
  useEffect(() => {
    return onSessionLost((reason) => {
      setSession(null);
      setExpired(true);
      setCompose(null);
      setSettingsOpen(false);
      setFoldersOpen(false);
      if (reason === "expired") toast(t("session_expired"), "warn");
      navigate({ name: "login" });
    });
  }, [navigate, t, toast]);

  const loadMailboxMeta = useCallback(async () => {
    if (!session) return;
    setFoldersLoading(true);
    try {
      const [nextFolders, nextQuota] = await Promise.all([listFolders(), getQuota()]);
      setFolders(nextFolders);
      setQuota(nextQuota);
      setFoldersError(null);
    } catch (e) {
      setFoldersError(describeError(e, prefs.lang));
    } finally {
      setFoldersLoading(false);
    }
  }, [session, prefs.lang]);

  useEffect(() => {
    if (session) void loadMailboxMeta();
  }, [session, loadMailboxMeta]);

  const reloadFolders = useCallback(() => {
    void loadMailboxMeta();
  }, [loadMailboxMeta]);

  /* ---------------- 路由守卫 ---------------- */

  useEffect(() => {
    // 启动探测（GET /session）完成前不改写 hash：否则深链接
    // #/mail/message/... 会在 boot 期间被重定向到登录页/收件箱而丢失。
    if (booting) return;
    if (!session) {
      if (route.name !== "login") navigate({ name: "login" });
      return;
    }
    if (route.name === "login") navigate({ name: "inbox" });
  }, [booting, session, route.name, navigate]);

  // 「邮箱页」的最近一次路由：写信/设置弹层关闭后回到它。
  useEffect(() => {
    if (isMailboxRoute(route)) setMailboxRoute(route);
  }, [route]);

  useEffect(() => {
    if (!session) setMailboxRoute({ name: "inbox" });
  }, [session]);

  // #/mail/settings 作为当前路由时打开设置弹层
  useEffect(() => {
    if (session && route.name === "settings") setSettingsOpen(true);
  }, [session, route.name]);

  /* ---------------- 写信 ---------------- */

  const openCompose = useCallback(
    (initial: ComposeInitial) => {
      composeSeq.current += 1;
      setCompose({ initial, fullscreen: isMobile, key: composeSeq.current });
    },
    [isMobile],
  );

  const openComposeNew = useCallback(() => {
    if (!session) return;
    openCompose(buildNewCompose(prefs, session.user.displayName));
  }, [openCompose, prefs, session]);

  const openReply = useCallback(
    (kind: ReplyKind, detail: MessageDetail) => {
      if (!session) return;
      openCompose(
        buildReplyCompose(kind, detail, prefs, {
          self: session.user.email,
          lang: prefs.lang,
          backendName: session.user.displayName,
        }),
      );
    },
    [openCompose, prefs, session],
  );

  const openDraft = useCallback(
    (detail: MessageDetail) => {
      openCompose(buildDraftCompose(detail));
    },
    [openCompose],
  );

  const closeCompose = useCallback(() => {
    setCompose(null);
    if (route.name === "compose") navigate(mailboxRoute.name === "inbox" ? { name: "inbox" } : mailboxRoute);
  }, [mailboxRoute, navigate, route.name]);

  // 直接访问 #/mail/compose（无初始内容）→ 新邮件
  useEffect(() => {
    if (!session || route.name !== "compose" || compose) return;
    openCompose(buildNewCompose(prefs, session.user.displayName));
  }, [session, route.name, compose, openCompose, prefs]);

  const sentFolder = useMemo(() => buildFolderViews(folders).find((v) => v.kind === "sent")?.folder ?? "Sent", [folders]);

  const handleSent = useCallback(
    (result: SendResult) => {
      setCompose(null);
      if (route.name === "compose") navigate(mailboxRoute.name === "inbox" ? { name: "inbox" } : mailboxRoute);
      const base = t("sent_toast");
      const text = result.warning ? `${base} · ${result.warning}` : base;
      toast(
        text,
        result.warning ? "warn" : "ok",
        result.sentUid != null
          ? { label: t("view_sent"), onClick: () => navigate({ name: "folder", folder: sentFolder }) }
          : undefined,
      );
      reloadFolders();
      bumpMailbox();
    },
    [bumpMailbox, mailboxRoute, navigate, reloadFolders, route.name, sentFolder, t, toast],
  );

  const handleDraftSaved = useCallback(() => {
    reloadFolders();
    bumpMailbox();
  }, [bumpMailbox, reloadFolders]);

  const toggleFullscreen = useCallback(() => {
    setCompose((prev) => (prev ? { ...prev, fullscreen: !prev.fullscreen } : prev));
  }, []);

  /* ---------------- 设置 ---------------- */

  const openSettings = useCallback(() => {
    setSettingsOpen(true);
    if (route.name !== "settings") navigate({ name: "settings" });
  }, [navigate, route.name]);

  const closeSettings = useCallback(() => {
    setSettingsOpen(false);
    if (route.name === "settings") navigate(mailboxRoute.name === "inbox" ? { name: "inbox" } : mailboxRoute);
  }, [mailboxRoute, navigate, route.name]);

  /* ---------------- 顶栏搜索 ---------------- */

  const handleSearch = useCallback(
    (q: string) => {
      const trimmed = q.trim();
      if (trimmed) {
        navigate({ name: "search", q: trimmed });
      } else {
        navigate(mailboxRoute.name === "search" ? { name: "inbox" } : mailboxRoute);
      }
    },
    [mailboxRoute, navigate],
  );

  const focusSearch = useCallback(() => {
    searchRef.current?.focus();
    searchRef.current?.select();
  }, []);

  /* ---------------- 退出登录 ---------------- */

  const doLogout = useCallback(async () => {
    try {
      await apiLogout();
    } catch (e) {
      toast(describeError(e, prefs.lang), "err");
      return;
    }
    setSession(null);
    setExpired(false);
    setCompose(null);
    setSettingsOpen(false);
    navigate({ name: "login" });
  }, [navigate, prefs.lang, toast]);

  /* ---------------- 文件夹 CRUD ---------------- */

  const createFolder = useCallback(
    async (name: string) => {
      try {
        await apiCreateFolder(name);
        toast(t("folder_created"), "ok");
        reloadFolders();
        bumpMailbox();
      } catch (e) {
        const message = isApiError(e) && (e.status === 400 || e.status === 409) ? t("folder_invalid") : describeError(e, prefs.lang);
        toast(message, "err");
      }
    },
    [bumpMailbox, prefs.lang, reloadFolders, t, toast],
  );

  const renameFolder = useCallback(
    async (folder: string, name: string) => {
      try {
        await apiRenameFolder(folder, name);
        toast(t("folder_renamed"), "ok");
        reloadFolders();
        bumpMailbox();
      } catch (e) {
        toast(describeError(e, prefs.lang), "err");
      }
    },
    [bumpMailbox, prefs.lang, reloadFolders, t, toast],
  );

  const deleteFolder = useCallback(
    async (folder: string) => {
      try {
        await apiDeleteFolder(folder);
        toast(t("folder_deleted"), "ok");
        reloadFolders();
        bumpMailbox();
      } catch (e) {
        toast(describeError(e, prefs.lang), "err");
      }
    },
    [bumpMailbox, prefs.lang, reloadFolders, t, toast],
  );

  /* ---------------- 全局快捷键（c / / / Esc） ---------------- */

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (isEditableTarget(e.target)) return;
      const action = resolveShortcut(e);
      if (!action) return;
      if (action === "compose") {
        if (!session || compose) return;
        e.preventDefault();
        openComposeNew();
      } else if (action === "search") {
        if (!session) return;
        e.preventDefault();
        focusSearch();
      } else if (action === "escape") {
        if (settingsOpen) {
          closeSettings();
          return;
        }
        // 写信浮层的 Esc 由 Compose 自己处理（需要「有改动先确认」的语义）。
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [closeSettings, compose, focusSearch, openComposeNew, session, settingsOpen]);

  /* ---------------- document.title 未读计数 ---------------- */

  const unreadTotal = useMemo(() => totalUnseen(folders), [folders]);
  const currentFolderLabel = useMemo(() => {
    const views = buildFolderViews(folders);
    if (mailboxRoute.name === "search") return t("search_results");
    if (mailboxRoute.name === "folder" && mailboxRoute.folder === STARRED_ROUTE_NAME) {
      const starred = views.find((v) => v.kind === "starred");
      return starred ? folderLabel(starred, t) : t("folder_starred");
    }
    const name =
      mailboxRoute.name === "message" ? mailboxRoute.folder : mailboxRoute.name === "folder" ? mailboxRoute.folder : undefined;
    const view = name ? views.find((v) => v.folder === name && !v.flaggedOnly) : undefined;
    return view ? folderLabel(view, t) : t("folder_inbox");
  }, [folders, mailboxRoute, t]);

  useEffect(() => {
    document.title = buildDocumentTitle(unreadTotal, currentFolderLabel);
  }, [unreadTotal, currentFolderLabel]);

  /* ---------------- 渲染 ---------------- */

  if (booting) {
    return (
      <div className="mail-root">
        <div className="mail-boot">
          <Spinner size={22} />
          <span>{t("loading")}</span>
        </div>
      </div>
    );
  }

  if (fatal) {
    return (
      <div className="mail-root">
        <div className="mail-fatal">
          <div className="mail-fatal-icon" aria-hidden>
            <IconWarn size={22} />
          </div>
          <h1 className="mail-fatal-title">{t("error_network")}</h1>
          <p className="mail-fatal-body">{fatal === "network" ? t("login_network_hint") : t("server_error", { status: "—" })}</p>
          <button type="button" className="btn btn-accent" onClick={() => void boot()}>
            <IconRefresh size={14} /> {t("retry")}
          </button>
          {demo && <div className="mail-fatal-demo">{t("demo_hint")}</div>}
        </div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="mail-root">
        <Login
          expired={expired}
          onLoggedIn={(info) => {
            setSession(info);
            setExpired(false);
            navigate({ name: "inbox" });
          }}
        />
      </div>
    );
  }

  const state = mailboxRoute;

  return (
    <div className="mail-root">
      <Header
        session={session.user}
        displayName={displayName}
        route={route}
        onSearch={handleSearch}
        onCompose={openComposeNew}
        onOpenSettings={openSettings}
        onOpenFolders={() => setFoldersOpen((v) => !v)}
        onLogout={() => void doLogout()}
        searchRef={searchRef}
        demo={demo}
        showMenu={isMobile}
      />

      {foldersError && (
        <div className="mail-meta-error">
          <ErrorBanner message={`${t("folder_load_failed")}：${foldersError}`} retryLabel={t("retry")} onRetry={reloadFolders} />
        </div>
      )}

      <Mailbox
        route={state}
        navigate={navigate}
        folders={folders}
        quota={quota}
        reloadFolders={reloadFolders}
        isMobile={isMobile}
        foldersOpen={foldersOpen}
        onCloseFolders={() => setFoldersOpen(false)}
        refreshToken={mailboxRefresh}
        onComposeDraft={openDraft}
        onReply={openReply}
        shortcutsEnabled={!compose && !settingsOpen}
        onCreateFolder={createFolder}
        onRenameFolder={renameFolder}
        onDeleteFolder={deleteFolder}
      />

      {foldersLoading && folders.length === 0 && (
        <div className="mail-meta-loading" role="status" aria-live="polite">
          {t("loading")}
        </div>
      )}

      {compose && (
        <Compose
          key={compose.key}
          initial={compose.initial}
          fullscreen={compose.fullscreen || isMobile}
          onToggleFullscreen={toggleFullscreen}
          onClose={closeCompose}
          onSent={handleSent}
          onDraftSaved={handleDraftSaved}
        />
      )}

      <SettingsDialog open={settingsOpen} onClose={closeSettings} />

      {/* 空邮箱提示（无任何文件夹/邮件时的兜底说明，不让界面看起来「坏了」） */}
      {folders.length === 0 && !foldersLoading && !foldersError && (
        <div className="mail-empty-fallback">
          <EmptyState
            icon={<IconCompose size={26} />}
            title={t("empty_inbox")}
            hint={t("empty_reader_hint")}
            action={
              <button type="button" className="btn btn-accent" onClick={openComposeNew}>
                <IconCompose size={14} /> {t("compose")}
              </button>
            }
          />
        </div>
      )}
    </div>
  );
}
