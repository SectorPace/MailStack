import { defineConfig } from "vitest/config";

// 独立测试配置：存在本文件时 vitest 不再加载 vite.config.ts（无别名/无 define 需要继承）。
//  - environment jsdom：组件测试 + window 事件（mailstack:unauthorized 等）；
//  - test.env { TZ: "UTC" }：在 worker 进程启动前钉住时区 —— formatTime/formatDayTime
//    输出「本地时钟」，时区固定后断言才是确定的（UTC 钟面）；
//  - import.meta.env.DEV 保持 vitest 默认（true）：与开发构建一致，mock 分发器会注册，
//    但 mode 默认 unreachable / initApi 后为 live，rpc() 永远走真实 rest/bridge 传输，
//    fetch 由测试 stub —— 无需 define 覆写；
//  - globals: false：测试文件显式 import { describe, it, expect } from "vitest"。
//  - css: false：样式与断言无关，跳过 CSS 管线。
// 注：本文件位于 tsconfig include(["src"]) 之外，`npx tsc --noEmit` 不覆盖它（可接受，
//     vitest 自身在加载时会解析本文件）。
export default defineConfig({
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    globals: false,
    css: false,
    env: { TZ: "UTC" },
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
