import { StrictMode, Component, type ErrorInfo, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/inter";
import "./index.css";
import App from "./App";
const zhUI = typeof navigator !== "undefined" && navigator.language?.toLowerCase().startsWith("zh");
class ErrorBoundary extends Component<{
    children: ReactNode;
}, {
    error: Error | null;
}> {
    state: {
        error: Error | null;
    } = { error: null };
    static getDerivedStateFromError(error: Error) {
        return { error };
    }
    componentDidCatch(error: Error, info: ErrorInfo) {
        console.error("[MailStack] render error:", error, info.componentStack);
    }
    render() {
        if (!this.state.error)
            return this.props.children;
        return (<div className="flex min-h-screen items-center justify-center bg-[#eef2f7] p-4">
        <div className="w-full max-w-[460px] rounded-[18px] bg-white p-6 text-center shadow-[0_8px_30px_rgba(15,30,60,.12)]">
          <h1 className="m-0 text-[18px] font-semibold text-[#1c2733]">{zhUI ? "界面出现异常" : "Something went wrong"}</h1>
          <p className="mt-2 break-words text-[13px] leading-relaxed text-[#5a6b80]">{this.state.error.message}</p>
          <button className="mt-4 cursor-pointer rounded-full border-0 bg-[#0A84FF] px-[22px] py-2 text-[13px] font-semibold text-white" onClick={() => this.setState({ error: null })}>
            {zhUI ? "重试" : "Retry"}
          </button>
          <div>
            <button className="mt-2.5 cursor-pointer rounded-full border border-[#cdd7e3] bg-none px-[18px] py-1.5 text-[12px] text-[#5a6b80]" onClick={() => location.reload()}>
              {zhUI ? "刷新页面" : "Reload page"}
            </button>
          </div>
        </div>
      </div>);
    }
}
createRoot(document.getElementById("root")!).render(<StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>);
