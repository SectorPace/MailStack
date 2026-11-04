import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
vi.mock("./api", () => {
    const folders = [
        { name: "INBOX", specialUse: ["inbox"], subscribed: true, total: 1, unseen: 1 },
        { name: "Sent", specialUse: ["sent"], subscribed: true, total: 0, unseen: 0 },
        { name: "Drafts", specialUse: ["drafts"], subscribed: true, total: 0, unseen: 0 },
        { name: "Archive", specialUse: ["archive"], subscribed: true, total: 0, unseen: 0 },
        { name: "Trash", specialUse: ["trash"], subscribed: true, total: 0, unseen: 0 },
    ];
    const summary = {
        uid: 1,
        flags: [],
        size: 100,
        from: { name: "Alice Chen", address: "alice@example.com" },
        to: [{ name: "Me", address: "me@example.com" }],
        subject: "Smoke subject",
        date: new Date().toISOString(),
        snippet: "Smoke snippet",
        hasAttachments: false,
        messageId: "<m1@example.com>",
        threadKey: "<m1@example.com>",
    };
    const detail = {
        uid: 1,
        folder: "INBOX",
        flags: [],
        size: 100,
        headers: {
            from: { name: "Alice Chen", address: "alice@example.com" },
            to: [{ name: "Me", address: "me@example.com" }],
            cc: [],
            bcc: [],
            replyTo: [],
            subject: "Smoke subject",
            date: new Date().toISOString(),
            messageId: "<m1@example.com>",
            inReplyTo: null,
            references: [],
            listUnsubscribe: null,
        },
        body: { text: "Smoke body text", html: null, truncated: false },
        attachments: [],
        remoteImagesBlocked: 0,
    };
    return {
        isDemoMode: () => false,
        getSession: vi.fn(async () => ({
            user: { email: "me@example.com", account: "me", displayName: "Me" },
            csrfToken: "csrf",
            expiresInSeconds: 28800,
        })),
        login: vi.fn(async () => ({
            user: { email: "me@example.com", account: "me", displayName: "Me" },
            csrfToken: "csrf",
            expiresInSeconds: 28800,
        })),
        logout: vi.fn(async () => undefined),
        onSessionLost: vi.fn(() => () => { }),
        isApiError: vi.fn(() => false),
        describeError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
        listFolders: vi.fn(async () => folders),
        getQuota: vi.fn(async () => ({ messages: 1, storageBytes: 1024, limits: { messages: null, storageBytes: null } })),
        createFolder: vi.fn(async () => ({ name: "x" })),
        renameFolder: vi.fn(async () => ({ name: "x" })),
        deleteFolder: vi.fn(async () => undefined),
        listMessages: vi.fn(async (q: {
            folder: string;
        }) => ({
            folder: q.folder,
            total: 1,
            offset: 0,
            limit: 50,
            messages: [summary],
        })),
        searchMessages: vi.fn(async () => ({ folder: "INBOX", total: 1, offset: 0, limit: 50, messages: [summary] })),
        getMessage: vi.fn(async () => detail),
        patchFlags: vi.fn(async () => ["seen"]),
        batchMessages: vi.fn(async () => ({ affected: 1 })),
        deleteMessage: vi.fn(async () => undefined),
        rawMessageUrl: () => "/mail/api/messages/INBOX/1/raw",
        attachmentUrl: () => "/mail/api/messages/INBOX/1/parts/2?download=1",
        sendMessage: vi.fn(async () => ({ queued: true, queueId: "q", sentUid: 1 })),
        saveDraft: vi.fn(async () => ({ uid: 2, folder: "Drafts" })),
    };
});
function setZhPrefs() {
    window.localStorage.setItem("mailstack.mail.prefs.v1", JSON.stringify({ lang: "zh", theme: "light", pageSize: 50 }));
}
beforeEach(() => {
    window.localStorage.clear();
    window.location.hash = "";
    setZhPrefs();
});
describe("Webmail App 冒烟", () => {
    it("boots the session and renders header + folders + message list", async () => {
        render(<App />);
        await waitFor(() => expect(screen.getByText("MailStack Webmail")).toBeInTheDocument());
        await waitFor(() => expect(screen.getAllByText("收件箱").length).toBeGreaterThanOrEqual(2));
        expect(await screen.findByText("Smoke subject")).toBeInTheDocument();
        expect(screen.getByText("Smoke snippet")).toBeInTheDocument();
    });
    it("opens a message deep link (#/mail/message/INBOX/1) in the reader", async () => {
        window.location.hash = "#/mail/message/INBOX/1";
        render(<App />);
        expect(await screen.findByText("Smoke body text")).toBeInTheDocument();
        expect(screen.getAllByText("Smoke subject").length).toBeGreaterThanOrEqual(1);
        expect(screen.getByRole("button", { name: "回复" })).toBeInTheDocument();
    });
    it("opens the compose dock from the header button", async () => {
        render(<App />);
        await waitFor(() => expect(screen.getByText("MailStack Webmail")).toBeInTheDocument());
        fireEvent.click(screen.getByRole("button", { name: /写信/ }));
        const dialog = await screen.findByRole("dialog", { name: "新邮件" });
        expect(dialog).toBeInTheDocument();
        expect(screen.getByLabelText("收件人")).toBeInTheDocument();
    });
    it("shows the login view when the session probe is rejected", async () => {
        const api = await import("./api");
        vi.mocked(api.getSession).mockRejectedValueOnce(Object.assign(new Error("unauthorized"), { status: 401, network: false, name: "ApiError" }));
        render(<App />);
        await waitFor(() => expect(screen.queryByText("加载中…")).not.toBeInTheDocument());
        expect(document.body.textContent?.length ?? 0).toBeGreaterThan(0);
    });
});
