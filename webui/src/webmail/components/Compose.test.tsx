import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { MailPrefsProvider } from "../store/prefs";
import { ToastProvider } from "./Toast";
import { Compose } from "./Compose";
import type { ComposeInitial } from "../lib/compose";
vi.mock("../api", () => ({
    sendMessage: vi.fn(async () => ({ queued: true, queueId: "q-1", sentUid: 42 })),
    saveDraft: vi.fn(async () => ({ uid: 7, folder: "Drafts" })),
    deleteMessage: vi.fn(async () => undefined),
    describeError: (error: unknown) => (error instanceof Error ? error.message : String(error)),
}));
import { deleteMessage, sendMessage } from "../api";
const sendMock = vi.mocked(sendMessage);
const deleteMock = vi.mocked(deleteMessage);
function setZhPrefs() {
    window.localStorage.setItem("mailstack.mail.prefs.v1", JSON.stringify({ lang: "zh", theme: "light", displayName: "Alice", signature: "Alice Chen" }));
}
const INITIAL: ComposeInitial = {
    kind: "new",
    to: [],
    cc: [],
    bcc: [],
    subject: "",
    text: "",
    html: "<p><br></p>",
    references: [],
    draftUid: null,
};
function wrapper({ children }: {
    children: ReactNode;
}) {
    return (<MailPrefsProvider>
      <ToastProvider>{children}</ToastProvider>
    </MailPrefsProvider>);
}
function renderCompose(over: Partial<ComposeInitial> = {}, onClose = vi.fn(), onSent = vi.fn()) {
    const initial = { ...INITIAL, ...over };
    render(<Compose initial={initial} fullscreen={false} onToggleFullscreen={vi.fn()} onClose={onClose} onSent={onSent} onDraftSaved={vi.fn()}/>, { wrapper });
    return { onClose, onSent };
}
function toInput() {
    return screen.getByLabelText("收件人") as HTMLInputElement;
}
beforeEach(() => {
    window.localStorage.clear();
    setZhPrefs();
    sendMock.mockClear();
    deleteMock.mockClear();
});
describe("Compose 收件人校验", () => {
    it("blocks send when there is no recipient", () => {
        renderCompose();
        fireEvent.click(screen.getByRole("button", { name: "发送" }));
        expect(screen.getByRole("alert")).toHaveTextContent("请至少填写一个收件人");
        expect(sendMock).not.toHaveBeenCalled();
    });
    it("rejects invalid addresses in the chip input", () => {
        renderCompose();
        const input = toInput();
        fireEvent.change(input, { target: { value: "not-an-address" } });
        fireEvent.keyDown(input, { key: "Enter" });
        expect(screen.getByRole("alert")).toHaveTextContent("无效的地址");
        expect(input).toHaveValue("");
    });
    it("adds valid addresses on Enter and sends the payload", async () => {
        const { onSent } = renderCompose();
        const input = toInput();
        fireEvent.change(input, { target: { value: "bob@example.com" } });
        fireEvent.keyDown(input, { key: "Enter" });
        expect(screen.getByText("bob@example.com")).toBeInTheDocument();
        fireEvent.change(screen.getByLabelText("主题"), { target: { value: "你好" } });
        fireEvent.click(screen.getByRole("button", { name: "发送" }));
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(1));
        const payload = sendMock.mock.calls[0][0] as {
            to: string[];
            subject: string;
        };
        expect(payload.to).toEqual(["bob@example.com"]);
        expect(payload.subject).toBe("你好");
        await waitFor(() => expect(onSent).toHaveBeenCalled());
    });
    it("sends on Ctrl+Enter", async () => {
        renderCompose();
        const input = toInput();
        fireEvent.change(input, { target: { value: "bob@example.com" } });
        fireEvent.keyDown(input, { key: "Enter" });
        const editor = screen.getByRole("textbox", { name: "正文" });
        fireEvent.keyDown(editor, { key: "Enter", ctrlKey: true });
        await waitFor(() => expect(sendMock).toHaveBeenCalledTimes(1));
    });
});
describe("Compose 关闭 / 丢弃", () => {
    it("closes immediately when nothing was composed", () => {
        const { onClose } = renderCompose();
        fireEvent.click(screen.getByRole("button", { name: "关闭" }));
        expect(onClose).toHaveBeenCalledTimes(1);
    });
    it("asks for confirmation before discarding edits", () => {
        const { onClose } = renderCompose();
        fireEvent.change(screen.getByLabelText("主题"), { target: { value: "草稿内容" } });
        fireEvent.click(screen.getByRole("button", { name: "关闭" }));
        const dialog = screen.getByRole("dialog", { name: "丢弃这封邮件？" });
        expect(dialog).toHaveTextContent("丢弃这封邮件？");
        expect(onClose).not.toHaveBeenCalled();
        fireEvent.click(within(dialog).getByRole("button", { name: "丢弃" }));
        expect(onClose).toHaveBeenCalledTimes(1);
    });
    it("deletes the existing draft on discard", async () => {
        const { onClose } = renderCompose({ kind: "draft", draftUid: 33, to: ["bob@example.com"] });
        fireEvent.click(screen.getByRole("button", { name: "丢弃" }));
        const dialog = screen.getByRole("dialog", { name: "丢弃这封邮件？" });
        fireEvent.click(within(dialog).getByRole("button", { name: "丢弃" }));
        await waitFor(() => expect(deleteMock).toHaveBeenCalledWith("Drafts", 33));
        await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
    });
});
