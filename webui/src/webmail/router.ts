import { useCallback, useEffect, useState } from "react";
export type MailRoute = {
    name: "login";
} | {
    name: "inbox";
} | {
    name: "folder";
    folder: string;
} | {
    name: "message";
    folder: string;
    uid: number;
} | {
    name: "compose";
} | {
    name: "settings";
} | {
    name: "search";
    q: string;
};
export function mailHash(route: MailRoute): string {
    switch (route.name) {
        case "login":
            return "#/mail/login";
        case "inbox":
            return "#/mail/inbox";
        case "folder":
            return `#/mail/folder/${encodeURIComponent(route.folder)}`;
        case "message":
            return `#/mail/message/${encodeURIComponent(route.folder)}/${encodeURIComponent(String(route.uid))}`;
        case "compose":
            return "#/mail/compose";
        case "settings":
            return "#/mail/settings";
        case "search":
            return `#/mail/search?q=${encodeURIComponent(route.q)}`;
        default:
            return "#/mail/inbox";
    }
}
export function routeKey(route: MailRoute): string {
    switch (route.name) {
        case "folder":
        case "message":
            return `${route.name}:${route.folder}:${route.name === "message" ? route.uid : ""}`;
        case "search":
            return `search:${route.q}`;
        default:
            return route.name;
    }
}
export function parseMailHash(hash: string): MailRoute {
    const raw = (hash ?? "").replace(/^#\/?/, "");
    const [pathPart, queryPart = ""] = raw.split("?");
    const segments = pathPart.split("/").filter(Boolean);
    if (segments[0] !== "mail")
        return { name: "inbox" };
    const rest = segments.slice(1);
    const head = rest[0];
    if (!head)
        return { name: "inbox" };
    switch (head) {
        case "login":
            return { name: "login" };
        case "inbox":
            return { name: "inbox" };
        case "compose":
            return { name: "compose" };
        case "settings":
            return { name: "settings" };
        case "folder": {
            const folder = decodeSegment(rest[1]);
            return folder ? { name: "folder", folder } : { name: "inbox" };
        }
        case "message": {
            const folder = decodeSegment(rest[1]);
            const rawUid = decodeSegment(rest[2]);
            const uid = Number.parseInt(rawUid, 10);
            if (!folder || !Number.isFinite(uid) || uid <= 0)
                return { name: "inbox" };
            return { name: "message", folder, uid };
        }
        case "search": {
            const q = new URLSearchParams(queryPart).get("q") ?? "";
            return { name: "search", q };
        }
        default:
            return { name: "inbox" };
    }
}
function decodeSegment(segment: string | undefined): string {
    if (!segment)
        return "";
    try {
        return decodeURIComponent(segment);
    }
    catch {
        return segment;
    }
}
export function isMailboxRoute(route: MailRoute): boolean {
    return route.name === "inbox" || route.name === "folder" || route.name === "message" || route.name === "search";
}
export type Navigate = (route: MailRoute) => void;
export function useMailRoute(): {
    route: MailRoute;
    navigate: Navigate;
} {
    const [route, setRoute] = useState<MailRoute>(() => typeof location !== "undefined" ? parseMailHash(location.hash) : { name: "inbox" });
    useEffect(() => {
        const onChange = () => setRoute(typeof location !== "undefined" ? parseMailHash(location.hash) : { name: "inbox" });
        window.addEventListener("hashchange", onChange);
        return () => window.removeEventListener("hashchange", onChange);
    }, []);
    const navigate = useCallback<Navigate>((next) => {
        const hash = mailHash(next);
        if (location.hash === hash) {
            setRoute(parseMailHash(hash));
            return;
        }
        location.hash = hash;
        setRoute(parseMailHash(hash));
    }, []);
    return { route, navigate };
}
