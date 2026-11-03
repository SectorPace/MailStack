// Webmail 的轻量 hash 路由（无第三方依赖）—— 契约 §5.2：
//   `#/mail/login`、`#/mail/inbox`、`#/mail/folder/<name>`、
//   `#/mail/message/<folder>/<uid>`、`#/mail/compose`、`#/mail/settings`、
//   `#/mail/search?q=`。
//
// folder 是 Maildir 名，可能含 `/`：构建 hash 时 encodeURIComponent（`/` → %2F），
// 解析时先按 `/` 分段再 decode，因此编码后的名称不会被错误拆段。

import { useCallback, useEffect, useState } from "react";

export type MailRoute =
  | { name: "login" }
  | { name: "inbox" }
  | { name: "folder"; folder: string }
  | { name: "message"; folder: string; uid: number }
  | { name: "compose" }
  | { name: "settings" }
  | { name: "search"; q: string };

/** 路由 → hash（唯一构造入口；组件里不要手拼 `#/mail/...`）。 */
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

/** 路由稳定 key（useEffect 依赖用，避免对象身份变化导致重复拉取）。 */
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

/** 解析当前 `location.hash`；未匹配/非法一律回落收件箱（不抛错）。 */
export function parseMailHash(hash: string): MailRoute {
  const raw = (hash ?? "").replace(/^#\/?/, "");
  const [pathPart, queryPart = ""] = raw.split("?");
  const segments = pathPart.split("/").filter(Boolean);
  if (segments[0] !== "mail") return { name: "inbox" };
  const rest = segments.slice(1);
  const head = rest[0];
  if (!head) return { name: "inbox" };
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
      if (!folder || !Number.isFinite(uid) || uid <= 0) return { name: "inbox" };
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
  if (!segment) return "";
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** 是否「邮箱页」路由（inbox / folder / message / search）。 */
export function isMailboxRoute(route: MailRoute): boolean {
  return route.name === "inbox" || route.name === "folder" || route.name === "message" || route.name === "search";
}

export type Navigate = (route: MailRoute) => void;

/** hash 路由 hook：读取 + 监听 + 导航（只改 location.hash，不自己造状态源）。 */
export function useMailRoute(): { route: MailRoute; navigate: Navigate } {
  const [route, setRoute] = useState<MailRoute>(() =>
    typeof location !== "undefined" ? parseMailHash(location.hash) : { name: "inbox" },
  );

  useEffect(() => {
    const onChange = () => setRoute(typeof location !== "undefined" ? parseMailHash(location.hash) : { name: "inbox" });
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const navigate = useCallback<Navigate>((next) => {
    const hash = mailHash(next);
    if (location.hash === hash) {
      // hash 相同不会触发 hashchange：手动同步一次，保证首次进入 login/inbox 也有 state。
      setRoute(parseMailHash(hash));
      return;
    }
    location.hash = hash;
    setRoute(parseMailHash(hash));
  }, []);

  return { route, navigate };
}
