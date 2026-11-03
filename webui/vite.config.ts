import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// 与 Rust 后端衔接：
//   管理台入口 index.html（mailstack-web，默认 127.0.0.1:8443，API /api）；
//   Webmail 入口 mail.html（mailstack-webmail，默认 127.0.0.1:8444，API /mail/api）。
//   构建产物 base 为相对路径（base: './'），dist/ 可被两个 axum 服务直接静态托管。
//   多页入口：rollupOptions.input 显式列出两个 html；管理台产物路径保持不变
//   （dist/index.html + dist/assets/*），Webmail 额外产出 dist/mail.html。
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
      // Webmail dev 代理：本地联调 mailstack-webmail（WSL 127.0.0.1:8444）。
      "/mail/api": {
        target: process.env.MAIL_API ?? "http://127.0.0.1:8444",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        mail: fileURLToPath(new URL("./mail.html", import.meta.url)),
      },
    },
  },
});
