// iOS 式底部标签栏（<768px 渲染，由 App 控制）—— 主导航 5 定页：
// 仪表盘 / 队列 / 域名 / 服务 / 设置。其余路由走汉堡抽屉（exhaustive nav = 「更多」），
// 因此这里不设独立 More 页签。
// 材质：.glass--toolbar（与顶栏同档的 chrome 玻璃 —— index.css 的 glass budget 中
// chrome 专用档；TabBar 本身就是 chrome，不占内容表面配额）。
// 高度：--tabbar-height(49px) + env(safe-area-inset-bottom) 底部安全区内边距。
// 层级 z-30：高于内容(z-10)，低于抽屉遮罩(z-40)/抽屉(z-50)/Radix 浮层(70/80)。
// 路由：与 Sidebar 同一 nav 机制（hash 路由），图标与 i18n 标签复用 Sidebar 的
// NAV / NAV_KEYS 单一来源，避免两处导航漂移。
import { useSettings } from "../store/settings";
import type { RouteKey } from "../router";
import { NAV, NAV_KEYS } from "./Sidebar";

/** 移动主入口 5 定页（顺序即展示顺序）。 */
const TAB_KEYS: RouteKey[] = ["dashboard", "queue", "domains", "services", "settings"];

type NavItem = (typeof NAV)[number];

export function TabBar({ route, nav }: { route: RouteKey; nav: (r: RouteKey) => void }) {
  const { t } = useSettings();

  // NAV 顺序是桌面侧栏序，这里按 TAB_KEYS 重排；NAV 缺项防御式跳过。
  const tabs = TAB_KEYS.map(
    (key): NavItem | null => NAV.find((n) => n.key === key) ?? null,
  ).filter((n): n is NavItem => n !== null);

  return (
    <nav
      className="glass--toolbar fixed inset-x-0 bottom-0 z-30"
      style={{
        paddingBottom: "env(safe-area-inset-bottom)",
        // 顶栏是 0.5px 底部发丝线（.app-toolbar），标签栏镜像为顶部发丝线
        borderTop: "0.5px solid var(--hairline)",
      }}
      aria-label="primary navigation"
    >
      <div className="flex" style={{ height: "var(--tabbar-height)" }}>
        {tabs.map(({ key, icon: Icon }) => {
          const active = route === key;
          const label = t(NAV_KEYS[key]);
          return (
            <button
              key={key}
              onClick={() => nav(key)}
              aria-current={active ? "page" : undefined}
              aria-label={label}
              className="flex min-w-0 flex-1 flex-col items-center justify-center gap-0.5 outline-none"
              style={{
                color: active ? "rgb(var(--accent-rgb))" : "var(--text-3)",
                WebkitTapHighlightColor: "transparent",
                transition: "color .2s ease",
              }}
            >
              {/* 选中态 = accent 着色 + 轻微放大（filled-feel）；图标描边风格由 icons.tsx 统一 */}
              <span
                className="flex items-center justify-center"
                style={{ transform: active ? "scale(1.08)" : "scale(1)", transition: "transform .2s ease" }}
              >
                <Icon size={22} />
              </span>
              <span className="max-w-full truncate px-1 font-medium" style={{ fontSize: 10, lineHeight: 1.2 }}>
                {label}
              </span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
