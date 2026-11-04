import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { MailPrefsProvider } from "../store/prefs";
import { MessageList, type MessageListActions, type MessageListProps } from "./MessageList";
import { makeSummary } from "../test-utils";
function setZhPrefs() {
    window.localStorage.setItem("mailstack.mail.prefs.v1", JSON.stringify({ lang: "zh", theme: "light", pageSize: 50, density: "comfortable" }));
}
function makeActions(): MessageListActions {
    return {
        onRefresh: vi.fn(),
        onOpen: vi.fn(),
        onToggleSelect: vi.fn(),
        onSelectAll: vi.fn(),
        onStar: vi.fn(),
        onMarkRead: vi.fn(),
        onMarkUnread: vi.fn(),
        onFlag: vi.fn(),
        onUnflag: vi.fn(),
        onArchive: vi.fn(),
        onDelete: vi.fn(),
        onMove: vi.fn(),
        onLoadMore: vi.fn(),
    };
}
const NOW_ISO = new Date().toISOString();
const MESSAGES = [
    makeSummary({
        uid: 11,
        flags: [],
        from: { name: "Alice Chen", address: "alice@example.com" },
        subject: "未读会议纪要",
        snippet: "这是一段摘要",
        date: NOW_ISO,
    }),
    makeSummary({
        uid: 12,
        flags: ["seen", "flagged"],
        from: { name: "Bob", address: "bob@example.com" },
        subject: "很久以前的邮件",
        snippet: "旧摘要",
        date: "2020-05-06T00:00:00Z",
        hasAttachments: true,
    }),
];
function wrapper({ children }: {
    children: ReactNode;
}) {
    return <MailPrefsProvider>{children}</MailPrefsProvider>;
}
function renderList(over: Partial<MessageListProps> = {}) {
    const actions = makeActions();
    const props: MessageListProps = {
        title: "收件箱",
        messages: MESSAGES,
        total: MESSAGES.length,
        loading: false,
        loadingMore: false,
        error: null,
        selected: new Set<number>(),
        activeUid: null,
        cursorUid: null,
        folderKind: "inbox",
        isSearch: false,
        moveTargets: [{ name: "Archive", label: "归档" }],
        canArchive: true,
        hasMore: false,
        density: "comfortable",
        emptyTitle: "收件箱是空的",
        emptyHint: "没有新邮件",
        actions,
        ...over,
    };
    const view = render(<MessageList {...props}/>, { wrapper });
    return { ...view, actions, props };
}
beforeEach(() => {
    window.localStorage.clear();
    setZhPrefs();
});
describe("MessageList 渲染", () => {
    it("renders senders, subjects, snippets and the unread dot", () => {
        renderList();
        expect(screen.getByText("Alice Chen")).toBeInTheDocument();
        expect(screen.getByText("未读会议纪要")).toBeInTheDocument();
        expect(screen.getByText("这是一段摘要")).toBeInTheDocument();
        expect(screen.getByText("Bob")).toBeInTheDocument();
        const unreadRow = screen.getByText("Alice Chen").closest(".mail-row");
        expect(unreadRow).not.toBeNull();
        expect(unreadRow?.className).toContain("is-unread");
        expect(unreadRow?.querySelector(".mail-unread-dot")).not.toBeNull();
        const seenRow = screen.getByText("Bob").closest(".mail-row");
        expect(seenRow?.className).not.toContain("is-unread");
        expect(seenRow?.querySelector(".mail-unread-dot")).toBeNull();
    });
    it("formats today as HH:mm and older dates as YYYY-MM-DD (contract §5.2)", () => {
        renderList();
        const unreadRow = screen.getByText("Alice Chen").closest(".mail-row") as HTMLElement;
        const seenRow = screen.getByText("Bob").closest(".mail-row") as HTMLElement;
        const today = unreadRow.querySelector(".mail-row-date")?.textContent ?? "";
        expect(today).toMatch(/^\d{2}:\d{2}$/);
        expect(seenRow.querySelector(".mail-row-date")?.textContent).toBe("2020-05-06");
    });
    it("shows the attachment indicator and star state", () => {
        renderList();
        const seenRow = screen.getByText("Bob").closest(".mail-row") as HTMLElement;
        expect(seenRow.querySelector(".mail-attach-dot")).not.toBeNull();
        const starBtn = within(seenRow).getByRole("button", { name: "取消星标" });
        expect(starBtn).toHaveAttribute("aria-pressed", "true");
    });
    it("clicking the star toggles via action without opening the message", () => {
        const { actions } = renderList();
        const unreadRow = screen.getByText("Alice Chen").closest(".mail-row") as HTMLElement;
        fireEvent.click(within(unreadRow).getByRole("button", { name: "星标" }));
        const onStar = vi.mocked(actions.onStar);
        expect(onStar).toHaveBeenCalledTimes(1);
        expect(onStar.mock.calls[0][0].uid).toBe(11);
        expect(actions.onOpen).not.toHaveBeenCalled();
    });
    it("clicking a row opens the message", () => {
        const { actions } = renderList();
        fireEvent.click(screen.getByText("Alice Chen"));
        const onOpen = vi.mocked(actions.onOpen);
        expect(onOpen).toHaveBeenCalledTimes(1);
        expect(onOpen.mock.calls[0][0].uid).toBe(11);
    });
    it("checkbox toggles selection and select-all reports checked state", () => {
        const { actions } = renderList();
        const checkboxes = screen.getAllByRole("checkbox");
        fireEvent.click(checkboxes[0]);
        expect(actions.onSelectAll).toHaveBeenCalledWith(true);
        fireEvent.click(checkboxes[1]);
        expect(actions.onToggleSelect).toHaveBeenCalledWith(11);
    });
    it("toolbar batch actions are disabled until something is selected", () => {
        renderList();
        expect(screen.getByRole("button", { name: "标为已读" })).toBeDisabled();
        expect(screen.getByRole("button", { name: "删除" })).toBeDisabled();
    });
    it("shows selection count and enables toolbar when selected", () => {
        renderList({ selected: new Set([12]) });
        expect(screen.getAllByText("已选 1 封").length).toBeGreaterThanOrEqual(1);
        expect(screen.getByRole("button", { name: "标为已读" })).toBeEnabled();
        expect(screen.getByRole("button", { name: "删除" })).toBeEnabled();
    });
});
describe("MessageList 状态", () => {
    it("renders the empty state (distinct from loading)", () => {
        renderList({ messages: [], total: 0, emptyTitle: "收件箱是空的" });
        expect(screen.getByText("收件箱是空的")).toBeInTheDocument();
    });
    it("renders the load-more button and triggers it", () => {
        const { actions } = renderList({ hasMore: true });
        fireEvent.click(screen.getByRole("button", { name: "加载更多" }));
        expect(actions.onLoadMore).toHaveBeenCalledTimes(1);
    });
    it("renders an error banner with retry", () => {
        const { actions } = renderList({ error: "无法连接 mailstack-webmail", messages: [], total: 0 });
        expect(screen.getByRole("alert")).toHaveTextContent("无法连接 mailstack-webmail");
        fireEvent.click(screen.getByRole("button", { name: /重试/ }));
        expect(actions.onRefresh).toHaveBeenCalled();
    });
});
