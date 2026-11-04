import { useEffect, useState } from "react";
export function useViewport() {
    const [width, setWidth] = useState(() => typeof window === "undefined" ? 1500 : window.innerWidth);
    useEffect(() => {
        let raf = 0;
        const fn = () => {
            if (raf)
                return;
            raf = requestAnimationFrame(() => {
                raf = 0;
                setWidth(window.innerWidth);
            });
        };
        window.addEventListener("resize", fn, { passive: true });
        return () => {
            window.removeEventListener("resize", fn);
            if (raf)
                cancelAnimationFrame(raf);
        };
    }, []);
    return {
        width,
        isDesktop: width >= 1280,
        isRail: width >= 1024 && width < 1280,
        isDrawer: width < 1024,
        isMobile: width < 768,
    };
}
