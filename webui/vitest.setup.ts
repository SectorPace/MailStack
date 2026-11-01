// Vitest 全局 setup —— 每个测试文件执行前运行一次。
//
// 时区：真正的保证是 vitest.config.ts 的 test.env（worker 进程启动前生效，Date 在
// 进程启动即按 UTC 初始化）；这里再设一次 process.env.TZ 是冗余兜底。注意 import
// 声明会被提升到本赋值之前执行，但 Date 惰性读取时区，运行期赋值同样有效
// （已在 Node 24 / Windows 上实测：getHours() 返回 UTC 钟面）。
process.env.TZ = "UTC";

import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom 不实现 matchMedia；SettingsProvider 挂载时直接调用（prefers-color-scheme 监听）。
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

afterEach(() => {
  // 卸载 RTL 渲染树（含 renderHook 的容器），避免测试间相互污染。
  cleanup();
  // 偏好 / 自定义背景都落在 localStorage，测试间必须清空。
  window.localStorage.clear();
  // 释放 vi.stubGlobal 注入的 fetch 等全局替身。
  vi.unstubAllGlobals();
});
