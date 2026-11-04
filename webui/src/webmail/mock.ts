import type { ComposeRequest, MailAddress, MailFolder, MessageDetail, MessageSummary, QuotaInfo, SessionInfo, SpecialUse, } from "./types";
const DEMO_USER: SessionInfo["user"] = {
    email: "alice@example.com",
    account: "alice",
    displayName: "Alice Chen",
};
let authenticated = true;
let nextUid = 5000;
type DemoMessage = {
    detail: MessageDetail;
    snippet: string;
};
const addr = (name: string, address: string): MailAddress => ({ name, address });
function baseHeaders(over: Partial<MessageDetail["headers"]>): MessageDetail["headers"] {
    return {
        from: addr("Alice Chen", "alice@example.com"),
        to: [addr("Alice Chen", "alice@example.com")],
        cc: [],
        bcc: [],
        replyTo: [],
        subject: "",
        date: new Date().toISOString(),
        messageId: `<demo-${nextUid}@example.com>`,
        inReplyTo: null,
        references: [],
        listUnsubscribe: null,
        ...over,
    };
}
function makeMessage(folder: string, uid: number, over: {
    from: MailAddress;
    subject: string;
    date: string;
    text?: string;
    html?: string;
    flags?: string[];
    attachments?: MessageDetail["attachments"];
    remoteImages?: number;
    snippet?: string;
}): DemoMessage {
    const headers = baseHeaders({
        from: over.from,
        to: [addr("Alice Chen", "alice@example.com")],
        subject: over.subject,
        date: over.date,
    });
    const text = over.text ?? over.subject;
    const detail: MessageDetail = {
        uid,
        folder,
        flags: over.flags ?? ["seen"],
        size: 4096,
        headers,
        body: { text, html: over.html ?? null, truncated: false },
        attachments: over.attachments ?? [],
        remoteImagesBlocked: over.remoteImages ?? 0,
    };
    return { detail, snippet: over.snippet ?? text.slice(0, 120) };
}
const daysAgo = (n: number, hh = 9, mm = 15): string => {
    const d = new Date();
    d.setDate(d.getDate() - n);
    d.setHours(hh, mm, 0, 0);
    return d.toISOString();
};
const hoursAgo = (n: number): string => new Date(Date.now() - n * 3600000).toISOString();
const htmlMail = (heading: string, paras: string[]): string => [
    `<h2 style="font-size:16px;margin:0 0 8px">${heading}</h2>`,
    ...paras.map((p) => `<p style="margin:0 0 8px">${p}</p>`),
    '<p style="margin:0 0 8px">—— MailStack 演示数据</p>',
].join("");
let messages: DemoMessage[] = [
    makeMessage("INBOX", 4001, {
        from: addr("GitHub", "notifications@github.com"),
        subject: "Security alert: new sign-in to your account",
        date: hoursAgo(1),
        flags: [],
        snippet: "We noticed a new sign-in to your GitHub account from a new device.",
        text: "We noticed a new sign-in to your GitHub account from a new device.\nIf this was you, you can safely ignore this email.",
        html: htmlMail("New sign-in to your account", [
            "We noticed a new sign-in to your <strong>GitHub</strong> account from a new device.",
            "If this was you, you can safely ignore this email.",
        ]),
    }),
    makeMessage("INBOX", 4002, {
        from: addr("Sarah Kim", "sarah.kim@mailstack.io"),
        subject: "Re: Q4 infrastructure review — meeting notes",
        date: hoursAgo(3),
        flags: ["flagged", "seen"],
        snippet: "Thanks for the detailed review. I've added the capacity projections.",
        text: "Thanks for the detailed review. I've added the capacity projections to the shared doc.\n\nLet me know if anything looks off.",
        html: htmlMail("Re: Q4 infrastructure review", [
            "Thanks for the detailed review. I've added the capacity projections to the shared doc.",
            "Let me know if anything looks off.",
        ]),
    }),
    makeMessage("INBOX", 4003, {
        from: addr("MailStack", "no-reply@mailstack.io"),
        subject: "Your weekly deliverability report",
        date: hoursAgo(9),
        flags: [],
        snippet: "98.6% delivered · 0.4% deferred · 0.1% bounced",
        remoteImages: 1,
        text: "Weekly deliverability report: 98.6% delivered, 0.4% deferred, 0.1% bounced.",
        html: '<p style="margin:0 0 8px"><strong>98.6%</strong> delivered · 0.4% deferred · 0.1% bounced</p>' +
            '<p style="margin:0 0 8px"><img src="http://example.com/chart.png" alt="deliverability chart" width="420" height="180"></p>' +
            '<p style="margin:0"><a href="https://mailstack.io/reports">View full report</a></p>',
    }),
    makeMessage("INBOX", 4004, {
        from: addr("", "billing@cloud.example.net"),
        subject: "Invoice #2026-1103 is available",
        date: daysAgo(1, 18, 2),
        flags: [],
        snippet: "Your invoice for October is ready. Amount due: $128.40",
        text: "Your invoice for October is ready. Amount due: $128.40.",
        attachments: [
            {
                partId: "2",
                filename: "invoice-2026-1103.pdf",
                contentType: "application/pdf",
                size: 184320,
                disposition: "attachment",
                inline: false,
                cid: null,
            },
        ],
    }),
    makeMessage("INBOX", 4005, {
        from: addr("DevOps", "ops@mailstack.io"),
        subject: "Maintenance window: Sunday 02:00–04:00 UTC",
        date: daysAgo(2, 11, 40),
        flags: ["seen"],
        snippet: "We will rotate TLS certificates and apply kernel updates.",
        text: "We will rotate TLS certificates and apply kernel updates. Expect brief IMAP reconnects.",
        html: htmlMail("Maintenance window", [
            "We will rotate TLS certificates and apply kernel updates.",
            "Expect brief IMAP reconnects between 02:00 and 04:00 UTC.",
        ]),
    }),
    makeMessage("INBOX", 4006, {
        from: addr("LinkedIn", "messages-noreply@linkedin.com"),
        subject: "You have 3 new messages",
        date: daysAgo(3, 8, 5),
        flags: ["seen"],
        snippet: "See what's new in your network.",
        text: "See what's new in your network.",
    }),
    makeMessage("INBOX", 4007, {
        from: addr("Lena Fischer", "lena@example.org"),
        subject: "Photos from the hike",
        date: daysAgo(5, 20, 30),
        flags: ["flagged"],
        snippet: "Finally uploaded the photos from Saturday. The alpine-lake shots came out great.",
        text: "Finally uploaded the photos from Saturday. The alpine-lake shots came out great.\n\nLena",
    }),
    makeMessage("INBOX", 4008, {
        from: addr("Security", "security@mailstack.io"),
        subject: "Password changed successfully",
        date: daysAgo(6, 7, 12),
        flags: ["seen"],
        snippet: "The password for alice@example.com was changed.",
        text: "The password for alice@example.com was changed. If this wasn't you, contact your administrator.",
    }),
    makeMessage("Sent", 4101, {
        from: addr("Alice Chen", "alice@example.com"),
        subject: "Re: Q4 infrastructure review — meeting notes",
        date: hoursAgo(4),
        flags: ["seen"],
        text: "Looks good, thanks. I'll update the cost section this afternoon.",
    }),
    makeMessage("Sent", 4102, {
        from: addr("Alice Chen", "alice@example.com"),
        subject: "Welcome to MailStack",
        date: daysAgo(4, 10, 0),
        flags: ["seen"],
        text: "Welcome aboard! Your mailbox is ready.",
    }),
    makeMessage("Sent", 4103, {
        from: addr("Alice Chen", "alice@example.com"),
        subject: "Fwd: Photos from the hike",
        date: daysAgo(5, 21, 10),
        flags: ["seen"],
        text: "Sharing these with the team.",
    }),
    makeMessage("Drafts", 4201, {
        from: addr("Alice Chen", "alice@example.com"),
        subject: "Draft: migration checklist",
        date: hoursAgo(2),
        flags: ["draft"],
        text: "TODO: add rollback steps and owner for each item.",
    }),
    makeMessage("Drafts", 4202, {
        from: addr("Alice Chen", "alice@example.com"),
        subject: "Draft: budget follow-up",
        date: daysAgo(2, 15, 22),
        flags: ["draft"],
        text: "Hi team,",
    }),
    makeMessage("Archive", 4301, {
        from: addr("PyCon", "hello@pycon.example.org"),
        subject: "Your talk proposal was accepted",
        date: daysAgo(30, 12, 0),
        flags: ["seen"],
        text: "Congratulations — your talk has been accepted.",
    }),
    makeMessage("Archive", 4302, {
        from: addr("Travel", "trips@travel.example.com"),
        subject: "Itinerary: Berlin → Lisbon",
        date: daysAgo(45, 16, 45),
        flags: ["seen"],
        text: "Your itinerary is attached to this email.",
    }),
    makeMessage("Junk", 4401, {
        from: addr("Lucky Winner", "winner@spam.example.net"),
        subject: "You have won $1,000,000!!!",
        date: daysAgo(1, 3, 33),
        flags: [],
        text: "Claim your prize now by replying with your bank details.",
    }),
    makeMessage("Trash", 4501, {
        from: addr("Newsletter", "digest@news.example.com"),
        subject: "Weekly digest #42",
        date: daysAgo(7, 6, 0),
        flags: ["seen"],
        text: "This week in technology…",
    }),
    makeMessage("Trash", 4502, {
        from: addr("Calendar", "calendar@example.com"),
        subject: "Cancelled: standup",
        date: daysAgo(1, 9, 0),
        flags: ["seen"],
        text: "The standup has been cancelled.",
    }),
];
const SPECIAL: Record<string, SpecialUse[]> = {
    INBOX: ["inbox"],
    Sent: ["sent"],
    Drafts: ["drafts"],
    Archive: ["archive"],
    Junk: ["junk"],
    Trash: ["trash"],
    Projects: [],
};
function folders(): MailFolder[] {
    const names = ["INBOX", "Sent", "Drafts", "Archive", "Junk", "Trash", "Projects"];
    return names.map((name) => {
        const list = messages.filter((m) => m.detail.folder === name);
        const unseen = list.filter((m) => !m.detail.flags.includes("seen")).length;
        return { name, specialUse: SPECIAL[name] ?? [], subscribed: true, total: list.length, unseen };
    });
}
function summaryOf(m: DemoMessage): MessageSummary {
    const d = m.detail;
    return {
        uid: d.uid,
        flags: d.flags,
        size: d.size,
        from: d.headers.from,
        to: d.headers.to,
        subject: d.headers.subject,
        date: d.headers.date,
        snippet: m.snippet,
        hasAttachments: d.attachments.length > 0,
        messageId: d.headers.messageId,
        threadKey: d.headers.messageId,
    };
}
function findMessage(folder: string, uid: number): DemoMessage | undefined {
    return messages.find((m) => m.detail.folder === folder && m.detail.uid === uid);
}
function findAny(uid: number): DemoMessage | undefined {
    return messages.find((m) => m.detail.uid === uid);
}
function moveMessageTo(uid: number, target: string): void {
    const m = findAny(uid);
    if (!m)
        return;
    m.detail.folder = target;
}
function quota(): QuotaInfo {
    const bytes = messages.reduce((sum, m) => sum + m.detail.size, 0);
    return { messages: messages.length, storageBytes: bytes, limits: { messages: null, storageBytes: 1024 * 1024 * 1024 } };
}
function list(folder: string, flagged: boolean, q: string, offset: number, limit: number) {
    let rows = messages.filter((m) => m.detail.folder === folder);
    if (flagged)
        rows = rows.filter((m) => m.detail.flags.includes("flagged"));
    const query = q.trim().toLowerCase();
    if (query) {
        rows = rows.filter((m) => {
            const d = m.detail;
            return (d.headers.subject.toLowerCase().includes(query) ||
                d.headers.from.address.toLowerCase().includes(query) ||
                d.headers.from.name.toLowerCase().includes(query) ||
                (d.body.text ?? "").toLowerCase().includes(query));
        });
    }
    rows = rows.sort((a, b) => Date.parse(b.detail.headers.date) - Date.parse(a.detail.headers.date));
    const total = rows.length;
    const page = rows.slice(offset, offset + limit);
    return { folder, total, offset, limit, messages: page.map(summaryOf) };
}
function ensureSession(): void {
    if (!authenticated) {
        const err = new Error("session expired") as Error & {
            status?: number;
        };
        err.status = 401;
        throw err;
    }
}
export async function mockRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
    await new Promise((resolve) => setTimeout(resolve, 90 + Math.random() * 140));
    const [rawPath, rawQuery = ""] = path.split("?");
    const query = new URLSearchParams(rawQuery);
    const segments = rawPath.split("/").filter(Boolean).map((s) => decodeURIComponent(s));
    const payload = (body ?? {}) as Record<string, unknown>;
    if (segments[0] === "session") {
        if (method === "POST") {
            authenticated = true;
            return {
                user: DEMO_USER,
                csrfToken: "demo-csrf-token",
                expiresInSeconds: 28800,
            } as T;
        }
        if (method === "DELETE") {
            authenticated = false;
            return undefined as T;
        }
        ensureSession();
        return { user: DEMO_USER, csrfToken: "demo-csrf-token", expiresInSeconds: 28800 } as T;
    }
    ensureSession();
    if (segments[0] === "folders") {
        if (method === "GET")
            return { folders: folders() } as T;
        if (method === "POST") {
            const name = String(payload.name ?? "").trim();
            if (!name)
                throw new Error("folder name is required");
            SPECIAL[name] = [];
            return { name } as T;
        }
        if (method === "PATCH") {
            const old = segments[1] ?? "";
            const name = String(payload.name ?? "").trim();
            if (SPECIAL[old]) {
                SPECIAL[name] = SPECIAL[old];
                delete SPECIAL[old];
            }
            messages = messages.map((m) => (m.detail.folder === old ? { ...m, detail: { ...m.detail, folder: name } } : m));
            return { name } as T;
        }
        if (method === "DELETE") {
            const name = segments[1] ?? "";
            messages = messages.filter((m) => m.detail.folder !== name);
            delete SPECIAL[name];
            return undefined as T;
        }
    }
    if (segments[0] === "quota" && method === "GET")
        return quota() as T;
    if (segments[0] === "messages" && method === "GET" && segments.length === 1) {
        return list(query.get("folder") ?? "INBOX", query.get("flagged") === "1" || query.get("flagged") === "true", query.get("q") ?? "", Number.parseInt(query.get("offset") ?? "0", 10) || 0, Number.parseInt(query.get("limit") ?? "50", 10) || 50) as T;
    }
    if (segments[0] === "search" && method === "GET") {
        return list(query.get("folder") ?? "INBOX", false, query.get("q") ?? "", 0, Number.parseInt(query.get("limit") ?? "50", 10) || 50) as T;
    }
    if (segments[0] === "messages" && segments[1] === "batch" && method === "POST") {
        const uids = Array.isArray(payload.uids) ? (payload.uids as number[]) : [];
        const action = String(payload.action ?? "");
        const target = String(payload.target ?? "");
        for (const uid of uids) {
            const m = findAny(uid);
            if (!m)
                continue;
            if (action === "mark_seen" && !m.detail.flags.includes("seen"))
                m.detail.flags.push("seen");
            if (action === "mark_unseen")
                m.detail.flags = m.detail.flags.filter((f) => f !== "seen");
            if (action === "flag" && !m.detail.flags.includes("flagged"))
                m.detail.flags.push("flagged");
            if (action === "unflag")
                m.detail.flags = m.detail.flags.filter((f) => f !== "flagged");
            if ((action === "move" || action === "copy") && target)
                moveMessageTo(uid, target);
        }
        if (action === "delete")
            messages = messages.filter((m) => !uids.includes(m.detail.uid));
        return { affected: uids.length } as T;
    }
    if (segments[0] === "messages" && method === "POST" && segments.length === 1) {
        const uid = nextUid++;
        const compose = payload as unknown as ComposeRequest & {
            draftUid?: number | null;
        };
        const oldUid = typeof payload.draftUid === "number" ? payload.draftUid : null;
        if (oldUid != null)
            messages = messages.filter((m) => m.detail.uid !== oldUid);
        const text = compose.text ?? "";
        const detail: MessageDetail = {
            uid,
            folder: "Drafts",
            flags: ["draft", "seen"],
            size: 2048,
            headers: baseHeaders({
                from: addr("Alice Chen", "alice@example.com"),
                to: (compose.to ?? []).map((a) => addr("", a)),
                cc: (compose.cc ?? []).map((a) => addr("", a)),
                bcc: (compose.bcc ?? []).map((a) => addr("", a)),
                subject: compose.subject ?? "",
                date: new Date().toISOString(),
            }),
            body: { text, html: compose.html ?? null, truncated: false },
            attachments: [],
            remoteImagesBlocked: 0,
        };
        messages = [{ detail, snippet: text.slice(0, 120) }, ...messages];
        return { uid, folder: "Drafts" } as T;
    }
    if (segments[0] === "send" && method === "POST") {
        const compose = payload as unknown as ComposeRequest;
        const sentUid = nextUid++;
        const detail: MessageDetail = {
            uid: sentUid,
            folder: "Sent",
            flags: ["seen"],
            size: 2048,
            headers: baseHeaders({
                from: addr("Alice Chen", "alice@example.com"),
                to: (compose.to ?? []).map((a) => addr("", a)),
                cc: (compose.cc ?? []).map((a) => addr("", a)),
                subject: compose.subject ?? "",
                date: new Date().toISOString(),
            }),
            body: { text: compose.text ?? "", html: compose.html ?? null, truncated: false },
            attachments: [],
            remoteImagesBlocked: 0,
        };
        messages = [{ detail, snippet: (compose.text ?? "").slice(0, 120) }, ...messages];
        return { queued: true, queueId: `demo-${sentUid}`, sentUid } as T;
    }
    if (segments[0] === "messages" && segments.length >= 3) {
        const folder = segments[1];
        const uid = Number.parseInt(segments[2] ?? "", 10);
        const rest = segments[3];
        const found = findMessage(folder, uid) ?? findAny(uid);
        if (method === "GET" && !rest) {
            if (!found)
                throw new Error("message not found");
            const images = query.get("images") === "1";
            return { message: { ...found.detail, remoteImagesBlocked: images ? 0 : found.detail.remoteImagesBlocked } } as T;
        }
        if (method === "PATCH" && !rest) {
            if (!found)
                throw new Error("message not found");
            const patch = (payload.flags ?? {}) as Record<string, boolean>;
            const flags = new Set(found.detail.flags);
            if (patch.seen === true)
                flags.add("seen");
            if (patch.seen === false)
                flags.delete("seen");
            if (patch.flagged === true)
                flags.add("flagged");
            if (patch.flagged === false)
                flags.delete("flagged");
            if (patch.answered === true)
                flags.add("answered");
            found.detail.flags = [...flags];
            return { flags: found.detail.flags } as T;
        }
        if (method === "POST" && rest === "move") {
            moveMessageTo(uid, String(payload.to ?? "INBOX"));
            return { uid, folder: String(payload.to ?? "INBOX") } as T;
        }
        if (method === "DELETE" && !rest) {
            messages = messages.filter((m) => m.detail.uid !== uid);
            return undefined as T;
        }
    }
    throw new Error(`演示数据未实现该请求：${method} ${path}`);
}
