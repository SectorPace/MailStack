// 视口断点（与 Tailwind 对齐）：
//   ≥1280 桌面（固定侧栏 + 右栏并排）  1024–1279 平板横屏（图标窄栏）  <1024 抽屉侧栏  <768 手机
import { useEffect, useState } from "react";

export function useViewport() {
  const [width, setWidth] = useState(() =>
    typeof window === "undefined" ? 1500 : window.innerWidth,
  );
  useEffect(() => {
    const fn = () => setWidth(window.innerWidth);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);
  return {
    width,
    isDesktop: width >= 1280,
    isRail: width >= 1024 && width < 1280,
    isDrawer: width < 1024,
    isMobile: width < 768,
  };
}
