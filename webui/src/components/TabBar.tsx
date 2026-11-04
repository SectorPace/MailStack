import { useSettings } from "../store/settings";
import type { RouteKey } from "../router";
import { NAV, NAV_KEYS } from "./Sidebar";
const TAB_KEYS: RouteKey[] = ["dashboard", "queue", "domains", "services", "settings"];
type NavItem = (typeof NAV)[number];
export function TabBar({ route, nav }: {
    route: RouteKey;
    nav: (r: RouteKey) => void;
}) {
    const { t } = useSettings();
    const tabs = TAB_KEYS.map((key): NavItem | null => NAV.find((n) => n.key === key) ?? null).filter((n): n is NavItem => n !== null);
    return (<nav className="glass--toolbar fixed inset-x-0 bottom-0 z-30" style={{
            paddingBottom: "env(safe-area-inset-bottom)",
            borderTop: "0.5px solid var(--hairline)",
        }} aria-label="primary navigation">
      <div className="flex" style={{ height: "var(--tabbar-height)" }}>
        {tabs.map(({ key, icon: Icon }) => {
            const active = route === key;
            const label = t(NAV_KEYS[key]);
            return (<button key={key} onClick={() => nav(key)} aria-current={active ? "page" : undefined} aria-label={label} className="flex min-w-0 flex-1 flex-col items-center justify-center gap-0.5 outline-none" style={{
                    color: active ? "rgb(var(--accent-rgb))" : "var(--text-3)",
                    WebkitTapHighlightColor: "transparent",
                    transition: "color .2s ease",
                }}>

              <span className="flex items-center justify-center" style={{ transform: active ? "scale(1.08)" : "scale(1)", transition: "transform .2s ease" }}>
                <Icon size={22}/>
              </span>
              <span className="max-w-full truncate px-1 font-medium" style={{ fontSize: 10, lineHeight: 1.2 }}>
                {label}
              </span>
            </button>);
        })}
      </div>
    </nav>);
}
