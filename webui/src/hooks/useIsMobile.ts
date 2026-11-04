import { useEffect, useState } from "react";
const QUERY = "(max-width: 767px)";
export function useIsMobile(): boolean {
    const [isMobile, setIsMobile] = useState<boolean>(() => {
        if (typeof window === "undefined" || typeof window.matchMedia !== "function")
            return false;
        return window.matchMedia(QUERY).matches;
    });
    useEffect(() => {
        if (typeof window === "undefined" || typeof window.matchMedia !== "function")
            return;
        const mq = window.matchMedia(QUERY);
        setIsMobile(mq.matches);
        const fn = (e: MediaQueryListEvent) => setIsMobile(e.matches);
        mq.addEventListener("change", fn);
        return () => mq.removeEventListener("change", fn);
    }, []);
    return isMobile;
}
