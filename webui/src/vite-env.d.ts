/// <reference types="vite/client" />

// `import.meta.env.DEV` 的类型来自 vite/client；生产构建由 Vite 静态替换为 false，
// 因此 `if (import.meta.env.DEV)` 包裹的整个 mock 块会被剔除（WEBUI_AUDIT §1.1 / §2.8）。
