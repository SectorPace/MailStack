// MailStack Webmail 入口（mail.html）—— 与 `src/main.tsx`（管理台）并列的第二个
// Vite 多页入口。首行 import preboot：在 React 渲染前应用 Webmail 自己的主题/语言
// 偏好（管理台的 theme-init.js 读到的是另一套存储键）。
import "./preboot";
import { StrictMode, Component, type ErrorInfo, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "../index.css";
import App from "./App";

/** 顶层错误边界：任何渲染异常都兜底成可读错误页，不白屏。 */
const zhUI = typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("zh");

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[MailStack Webmail] render error:", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="mail-root">
        <div className="mail-fatal" role="alert">
          <h1 className="mail-fatal-title">{zhUI ? "界面出现异常" : "Something went wrong"}</h1>
          <p className="mail-fatal-body">{this.state.error.message}</p>
          <button type="button" className="btn btn-accent" onClick={() => this.setState({ error: null })}>
            {zhUI ? "重试" : "Retry"}
          </button>
          <button type="button" className="btn glass--control" onClick={() => location.reload()}>
            {zhUI ? "刷新页面" : "Reload page"}
          </button>
        </div>
      </div>
    );
  }
}

const rootEl = document.getElementById("root");
if (!rootEl) {
  throw new Error("mail.html is missing #root");
}

createRoot(rootEl).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
