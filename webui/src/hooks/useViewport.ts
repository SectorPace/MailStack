// 视口断点（与 Tailwind 对齐）：
//   ≥1280 桌面（固定侧栏 + 右栏并排）  1024–1279 平板横屏（图标窄栏）  <1024 抽屉侧栏  <768 手机
//
// resize 事件在拖动窗口时每像素触发；原先直接 setState 会让整棵树逐像素重渲染。
// 这里用 requestAnimationFrame 合并到每帧最多一次（比 setTimeout 节流更贴合绘制节奏）。
import { useEffect, useState } from "react";

export function useViewport() {
  const [width, setWidth] = useState(() =>
    typeof window === "undefined" ? 1500 : window.innerWidth,
  );
  useEffect(() => {
    let raf = 0;
    const fn = () => {
      if (raf) return;
      raf = requestAnimationFrame(() => {
        raf = 0;
        setWidth(window.innerWidth);
      });
    };
    window.addEventListener("resize", fn, { passive: true });
    return () => {
      window.removeEventListener("resize", fn);
      if (raf) cancelAnimationFrame(raf);
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
