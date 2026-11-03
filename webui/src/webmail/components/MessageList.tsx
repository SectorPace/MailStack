// 邮件列表（契约 §5.2）：发件人 / 主题 / 摘要 / 日期规则 / 未读加粗 + 蓝点 /
// 星标 / 附件图标 / checkbox 多选 + 全选 / 批量工具栏 / 加载更多 / 空态 / 骨架。
//
// 渲染纯受控：所有动作通过 `actions` 抛给页面上层（Mailbox），组件本身不发请求，
// 这样批量操作、确认弹窗、乐观更新只有一份实现。
import type { MessageSummary } from "../types";
import { formatListDate, senderName } from "../lib/format";
import type { FolderKind } from "../lib/folders";
import { useMailPrefs } from "../store/prefs";
import { EmptyState, ErrorBanner, SkeletonRows } from "./states";
import {
  IconArchive,
  IconCheck,
  IconClock,
  IconInbox,
  IconPaperclip,
  IconRefresh,
  IconSearch,
  IconStar,
  IconTrash,
  IconX,
} from "./icons";

export type MessageListActions = {
  onRefresh: () => void;
  onOpen: (message: MessageSummary) => void;
  onToggleSelect: (uid: number) => void;
  onSelectAll: (checked: boolean) => void;
  onStar: (message: MessageSummary) => void;
  onMarkRead: () => void;
  onMarkUnread: () => void;
  onFlag: () => void;
  onUnflag: () => void;
  onArchive: () => void;
  onDelete: () => void;
  onMove: (target: string) => void;
  onLoadMore: () => void;
};

export type MessageListProps = {
  title: string;
  messages: MessageSummary[];
  total: number;
  loading: boolean;
  loadingMore: boolean;
  error: string | null;
  selected: ReadonlySet<number>;
  activeUid: number | null;
  cursorUid: number | null;
  folderKind: FolderKind;
  isSearch: boolean;
  moveTargets: { name: string; label: string }[];
  canArchive: boolean;
  hasMore: boolean;
  density: "comfortable" | "compact";
  emptyTitle: string;
  emptyHint?: string;
  actions: MessageListActions;
};

/** 列表行左侧显示谁：普通文件夹显示发件人；已发送/草稿显示收件人。 */
export function rowParty(message: MessageSummary, folderKind: FolderKind, noRecipients: string, unknownSender: string): string {
  if (folderKind === "sent" || folderKind === "drafts") {
    const to = Array.isArray(message.to) ? message.to : [];
    if (!to.length) return noRecipients;
    const first = senderName(to[0]) || noRecipients;
    return to.length > 1 ? `${first} +${to.length - 1}` : first;
  }
  return senderName(message.from) || (message.from?.address ?? "") || unknownSender;
}

function isUnread(message: MessageSummary): boolean {
  return !(Array.isArray(message.flags) && message.flags.includes("seen"));
}

function isFlagged(message: MessageSummary): boolean {
  return Array.isArray(message.flags) && message.flags.includes("flagged");
}

export function MessageList(props: MessageListProps) {
  const {
    title,
    messages,
    total,
    loading,
    loadingMore,
    error,
    selected,
    activeUid,
    cursorUid,
    folderKind,
    isSearch,
    moveTargets,
    canArchive,
    hasMore,
    density,
    emptyTitle,
    emptyHint,
    actions,
  } = props;
  const { t, prefs } = useMailPrefs();
  const lang = prefs.lang;
  const hasSelection = selected.size > 0;
  const allSelected = messages.length > 0 && messages.every((m) => selected.has(m.uid));
  const moveValue = "";

  return (
    <section className="mail-list" aria-label={title}>
      <div className="mail-list-head">
        <div className="mail-list-title-row">
          <h2 className="mail-list-title">
            {isSearch ? <IconSearch size={15} /> : <IconInbox size={15} />}
            <span className="mail-list-title-text">{title}</span>
            <span className="mail-list-count tnum">{t("message_count", { n: total })}</span>
          </h2>
          <button
            type="button"
            className="icon-btn mail-list-refresh"
            onClick={actions.onRefresh}
            aria-label={t("refresh")}
            title={t("refresh")}
          >
            <IconRefresh size={15} />
          </button>
        </div>

        {/* 批量工具栏 */}
        <div className="mail-toolbar" role="toolbar" aria-label={t("settings")}>
          <label className="mail-select-all" title={t("select_all")}>
            <input
              type="checkbox"
              className="mail-check"
              checked={allSelected}
              onChange={(e) => actions.onSelectAll(e.target.checked)}
              aria-label={t("select_all")}
              ref={(el) => {
                if (el) el.indeterminate = hasSelection && !allSelected;
              }}
            />
          </label>
          <span className="mail-selected-count tnum">
            {hasSelection ? t("selected_count", { n: selected.size }) : ""}
          </span>
          <div className="mail-toolbar-group">
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onMarkRead}
              disabled={!hasSelection}
              aria-label={t("mark_read")}
              title={t("mark_read")}
            >
              <IconCheck size={15} />
            </button>
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onMarkUnread}
              disabled={!hasSelection}
              aria-label={t("mark_unread")}
              title={t("mark_unread")}
            >
              <IconClock size={15} />
            </button>
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onFlag}
              disabled={!hasSelection}
              aria-label={t("star")}
              title={t("star")}
            >
              <IconStar size={15} />
            </button>
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onUnflag}
              disabled={!hasSelection}
              aria-label={t("unstar")}
              title={t("unstar")}
            >
              <IconStar size={15} filled />
            </button>
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onArchive}
              disabled={!hasSelection || !canArchive}
              aria-label={t("archive")}
              title={canArchive ? t("archive") : t("archive_unavailable")}
            >
              <IconArchive size={15} />
            </button>
            <button
              type="button"
              className="icon-btn mail-tool-btn"
              onClick={actions.onDelete}
              disabled={!hasSelection}
              aria-label={t("delete")}
              title={t("delete")}
            >
              <IconTrash size={15} />
            </button>
            <select
              className="mail-move-select"
              aria-label={t("move_to")}
              title={t("move_to")}
              value={moveValue}
              disabled={!hasSelection || moveTargets.length === 0}
              onChange={(e) => {
                const target = e.target.value;
                if (target) actions.onMove(target);
              }}
            >
              <option value="">{t("move_to")}…</option>
              {moveTargets.map((target) => (
                <option key={target.name} value={target.name}>
                  {target.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="mail-list-error">
          <ErrorBanner message={error} retryLabel={t("retry")} onRetry={actions.onRefresh} />
        </div>
      )}

      <div className={`mail-list-scroll ${density === "compact" ? "mail-list--compact" : ""}`}>
        {loading ? (
          <SkeletonRows count={7} />
        ) : messages.length === 0 && !error ? (
          <EmptyState
            icon={isSearch ? <IconSearch size={26} /> : <IconInbox size={26} />}
            title={emptyTitle}
            hint={emptyHint}
          />
        ) : (
          <ul className="mail-rows" role="list">
            {messages.map((message) => {
              const unread = isUnread(message);
              const flagged = isFlagged(message);
              const active = activeUid === message.uid;
              const cursor = cursorUid === message.uid;
              return (
                <li key={`${message.uid}`} role="listitem">
                  <div
                    className={`mail-row ${unread ? "is-unread" : ""} ${active ? "is-active" : ""} ${
                      cursor ? "is-cursor" : ""
                    } ${selected.has(message.uid) ? "is-selected" : ""}`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${rowParty(message, folderKind, t("no_recipients"), t("unknown_sender"))} — ${
                      message.subject || t("no_subject")
                    }`}
                    onClick={() => actions.onOpen(message)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        actions.onOpen(message);
                      }
                    }}
                  >
                    <input
                      type="checkbox"
                      className="mail-check mail-row-check"
                      checked={selected.has(message.uid)}
                      aria-label={t("select_message")}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => actions.onToggleSelect(message.uid)}
                    />
                    <button
                      type="button"
                      className={`mail-star ${flagged ? "is-on" : ""}`}
                      aria-pressed={flagged}
                      aria-label={flagged ? t("unstar") : t("star")}
                      title={flagged ? t("unstar") : t("star")}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.onStar(message);
                      }}
                    >
                      <IconStar size={15} filled={flagged} />
                    </button>
                    {unread && <span className="mail-unread-dot" aria-hidden />}
                    <div className="mail-row-main">
                      <div className="mail-row-top">
                        <span className="mail-sender">
                          {rowParty(message, folderKind, t("no_recipients"), t("unknown_sender"))}
                        </span>
                        {message.hasAttachments && (
                          <span className="mail-attach-dot" title={t("has_attachment")} aria-label={t("has_attachment")}>
                            <IconPaperclip size={12} />
                          </span>
                        )}
                        <span className="mail-row-date tnum">{formatListDate(message.date, lang)}</span>
                      </div>
                      <div className="mail-subject">{message.subject || t("no_subject")}</div>
                      <div className="mail-snippet">{message.snippet}</div>
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        {hasMore && !loading && (
          <div className="mail-load-more">
            <button type="button" className="btn glass--control" onClick={actions.onLoadMore} disabled={loadingMore}>
              {loadingMore ? t("loading_more") : t("load_more")}
            </button>
          </div>
        )}
      </div>

      {hasSelection && (
        <div className="mail-list-foot">
          <span className="tnum">{t("selected_count", { n: selected.size })}</span>
          <button
            type="button"
            className="mail-clear-selection"
            onClick={() => actions.onSelectAll(false)}
            aria-label={t("close")}
          >
            <IconX size={12} />
          </button>
        </div>
      )}
    </section>
  );
}
