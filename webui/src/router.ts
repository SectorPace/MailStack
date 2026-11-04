import { useCallback, useEffect, useState } from "react";
export const ROUTES = [
    "dashboard",
    "domains",
    "users",
    "aliases",
    "relay",
    "dkim",
    "tls",
    "queue",
    "logs",
    "services",
    "security",
    "settings",
] as const;
export type RouteKey = (typeof ROUTES)[number];
function parse(): RouteKey {
    const h = location.hash.replace(/^#\/?/, "").split("?")[0];
    return (ROUTES as readonly string[]).includes(h) ? (h as RouteKey) : "dashboard";
}
export function useRoute(): [
    RouteKey,
    (r: RouteKey) => void
] {
    const [route, setRoute] = useState<RouteKey>(parse);
    useEffect(() => {
        const fn = () => setRoute(parse());
        window.addEventListener("hashchange", fn);
        return () => window.removeEventListener("hashchange", fn);
    }, []);
    const nav = useCallback((r: RouteKey) => {
        location.hash = `#/${r}`;
        setRoute(r);
    }, []);
    useEffect(() => {
        if (!location.hash)
            location.hash = "#/dashboard";
    }, []);
    return [route, nav];
}
