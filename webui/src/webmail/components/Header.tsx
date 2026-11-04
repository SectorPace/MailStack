import { useEffect, useRef, useState, type RefObject } from "react";
import type { MailRoute } from "../router";
import type { MailUser } from "../types";
import { useDebouncedValue } from "../lib/debounce";
import { useMailPrefs } from "../store/prefs";
import { MailAvatar } from "./states";
import { IconChevronDown, IconCompose, IconGear, IconGlobe, IconMail, IconMenu, IconMoon, IconSearch, IconSun, IconUser, IconX, MailBrandLogo, } from "./icons";
export function Header({ session, displayName, route, onSearch, onCompose, onOpenSettings, onOpenFolders, onLogout, searchRef, demo, showMenu, }: {
    session: MailUser;
    displayName: string;
    route: MailRoute;
    onSearch: (q: string) => void;
    onCompose: () => void;
    onOpenSettings: () => void;
    onOpenFolders: () => void;
    onLogout: () => void;
    searchRef: RefObject<HTMLInputElement | null>;
    demo: boolean;
    showMenu: boolean;
}) {
    const { t, prefs, resolvedTheme, setTheme, setLang } = useMailPrefs();
    const routeQuery = route.name === "search" ? route.q : "";
    const [value, setValue] = useState(routeQuery);
    const debounced = useDebouncedValue(value, 300);
    const [menuOpen, setMenuOpen] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        setValue(routeQuery);
    }, [routeQuery]);
    useEffect(() => {
        const q = debounced.trim();
        if (route.name === "search") {
            if (q !== route.q)
                onSearch(q);
            return;
        }
        if (q)
            onSearch(q);
    }, [debounced]);
    useEffect(() => {
        if (!menuOpen)
            return;
        const onDown = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node))
                setMenuOpen(false);
        };
        document.addEventListener("mousedown", onDown);
        return () => document.removeEventListener("mousedown", onDown);
    }, [menuOpen]);
    function submitSearch() {
        const q = value.trim();
        if (q)
            onSearch(q);
        else if (route.name === "search")
            onSearch("");
    }
    return (<header className="mail-header glass--toolbar app-toolbar" role="banner">
      {showMenu && (<button type="button" className="icon-btn mail-header-btn" onClick={onOpenFolders} aria-label={t("toggle_folders")}>
          <IconMenu size={17}/>
        </button>)}

      <div className="mail-brand">
        <MailBrandLogo dark={resolvedTheme === "dark"} size={22}/>
        <span className="mail-brand-name">MailStack Webmail</span>
        {demo && (<span className="badge badge-warn mail-demo-badge" title={t("demo_hint")}>
            <span className="dot"/>
            {t("demo_data")}
          </span>)}
      </div>

      <div className="mail-search" role="search">
        <span className="mail-search-icon" aria-hidden>
          <IconSearch size={14}/>
        </span>
        <input ref={searchRef} className="mail-search-input" type="search" value={value} placeholder={t("search_placeholder")} aria-label={t("search_placeholder")} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                submitSearch();
            }
            else if (e.key === "Escape") {
                setValue("");
                if (route.name === "search")
                    onSearch("");
                (e.target as HTMLInputElement).blur();
            }
        }}/>
        {value && (<button type="button" className="mail-search-clear" aria-label={t("search_clear")} onClick={() => {
                setValue("");
                searchRef.current?.focus();
                if (route.name === "search")
                    onSearch("");
            }}>
            <IconX size={12}/>
          </button>)}
      </div>

      <div className="mail-header-actions">
        <button type="button" className="btn btn-accent mail-compose-btn" onClick={onCompose} title={t("compose")}>
          <IconCompose size={15}/>
          <span className="mail-compose-btn-label">{t("compose")}</span>
        </button>
        <button type="button" className="icon-btn mail-header-btn" onClick={onOpenSettings} aria-label={t("settings")} title={t("settings")}>
          <IconGear size={16}/>
        </button>
        <button type="button" className="icon-btn mail-header-btn" onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} aria-label={t("theme")} title={t("theme")}>
          {resolvedTheme === "dark" ? <IconMoon size={16}/> : <IconSun size={16}/>}
        </button>
        <button type="button" className="icon-btn mail-header-btn" onClick={() => setLang(prefs.lang === "zh" ? "en" : "zh")} aria-label={t("language")} title={t("language")}>
          <IconGlobe size={16}/>
          <span className="mail-lang-tag">{prefs.lang === "zh" ? "EN" : "中"}</span>
        </button>

        <div className="mail-account" ref={menuRef}>
          <button type="button" className="mail-account-btn" aria-haspopup="menu" aria-expanded={menuOpen} onClick={() => setMenuOpen((v) => !v)} title={displayName || session.email}>
            <MailAvatar label={displayName || session.email} size={24}/>
            <span className="mail-account-name">{displayName || session.email}</span>
            <IconChevronDown size={12}/>
          </button>
          {menuOpen && (<div className="mail-menu" role="menu">
              <div className="mail-menu-head">
                <MailAvatar label={displayName || session.email} size={30}/>
                <div className="mail-menu-head-text">
                  <div className="mail-menu-head-name">{displayName || session.account}</div>
                  <div className="mail-menu-head-email">{session.email}</div>
                </div>
              </div>
              <div className="mail-menu-sep"/>
              <button type="button" role="menuitem" className="mail-menu-item" onClick={() => { setMenuOpen(false); onOpenSettings(); }}>
                <IconUser size={14}/> {t("settings")}
              </button>
              <button type="button" role="menuitem" className="mail-menu-item" onClick={() => { setMenuOpen(false); onCompose(); }}>
                <IconMail size={14}/> {t("compose")}
              </button>
              <div className="mail-menu-sep"/>
              <button type="button" role="menuitem" className="mail-menu-item mail-menu-item--danger" onClick={() => {
                setMenuOpen(false);
                onLogout();
            }}>
                {t("logout")}
              </button>
            </div>)}
        </div>
      </div>
    </header>);
}
