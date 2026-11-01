// 移动断点（<768px）—— 与 index.css 的 @media (max-width: 767px) iOS 度量档同一口径：
// 该档把 --control-h 升到 44px / --font-body 17px / --radius-sheet 26px / --tabbar-height 49px。
// JS 侧用 matchMedia 驱动（而非 useViewport 的 resize+rAF）：跨断点翻转与 CSS 变量
// 换档在同一帧生效，不会出现「样式已升 44px、组件还按桌面渲染」的单帧错位。
// SSR / 无 matchMedia（jsdom 未 mock 时）回落桌面形态 false。
import { useEffect, useState } from "react";

const QUERY = "(max-width: 767px)";

export function useIsMobile(): boolean {
  const [isMobile, setIsMobile] = useState<boolean>(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
    return window.matchMedia(QUERY).matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(QUERY);
    // lazy init 与 effect 之间宽度可能已变化：进 effect 先同步一次真实值
    setIsMobile(mq.matches);
    const fn = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);

  return isMobile;
}
