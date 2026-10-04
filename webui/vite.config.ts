import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// 与 Rust 后端 (crates/admin-web, axum) 衔接：
//   开发期把 /api 代理到本地 admin-web 监听地址（可用环境变量覆盖）。
//   构建产物 base 为相对路径（base: './'），dist/ 可被 axum 直接静态托管在任意挂载点。
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "./",
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.ADMIN_API ?? "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    chunkSizeWarningLimit: 900,
  },
});
