import { StrictMode, Component, type ErrorInfo, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "./index.css";
import App from "./App";

/**
 * 顶层错误边界 —— 页面级守卫（?? [] / ?.）漏掉一处，意外数据就可能让渲染崩溃成
 * 白屏（WEBUI_AUDIT §2.1）。这里兜底成明确的「出错了 + 重试」页并记录日志。
 * 必须放在 App 之外：SettingsProvider（i18n 上下文）可能正是崩溃源，不能依赖它，
 * 文案用 navigator 语言嗅探。
 */
const zhUI = typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("zh");

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 堆栈只进控制台给排障者；用户看到的是可读摘要 + 重试入口。
    console.error("[MailStack] render error:", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#eef2f7] p-4">
        <div className="w-full max-w-[460px] rounded-[18px] bg-white p-6 text-center shadow-[0_8px_30px_rgba(15,30,60,.12)]">
          <h1 className="m-0 text-[18px] font-semibold text-[#1c2733]">{zhUI ? "界面出现异常" : "Something went wrong"}</h1>
          <p className="mt-2 break-words text-[13px] leading-relaxed text-[#5a6b80]">{this.state.error.message}</p>
          <button
            className="mt-4 cursor-pointer rounded-full border-0 bg-[#0A84FF] px-[22px] py-2 text-[13px] font-semibold text-white"
            onClick={() => this.setState({ error: null })}
          >
            {zhUI ? "重试" : "Retry"}
          </button>
          <div>
            <button
              className="mt-2.5 cursor-pointer rounded-full border border-[#cdd7e3] bg-none px-[18px] py-1.5 text-[12px] text-[#5a6b80]"
              onClick={() => location.reload()}
            >
              {zhUI ? "刷新页面" : "Reload page"}
            </button>
          </div>
        </div>
      </div>
    );
  }
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);
