// 设置弹层（契约 §5.6）：显示名、签名（纯文本）、每页条数、阅读密度、
// 是否总是加载远程图片、主题、语言 —— 全部只存 localStorage（前缀 mailstack.mail.）。
// 修改即时生效并持久化（无需「保存」按钮），弹层底部明确提示存储位置。
import { useEscapeKey } from "./Toast";
import { useMailPrefs } from "../store/prefs";
import { PAGE_SIZE_OPTIONS } from "../lib/prefs";
import type { MailKey } from "../i18n";
import { IconCheck, IconX } from "./icons";

const THEME_OPTIONS: { value: "light" | "dark" | "system"; key: MailKey }[] = [
  { value: "light", key: "theme_light" },
  { value: "dark", key: "theme_dark" },
  { value: "system", key: "theme_system" },
];

export function SettingsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t, prefs, setPrefs, resolvedTheme, setTheme, setLang } = useMailPrefs();
  useEscapeKey(open, onClose);
  if (!open) return null;

  return (
    <div
      className="mail-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="mail-dialog mail-dialog--wide mail-settings" role="dialog" aria-modal="true" aria-label={t("settings_title")}>
        <div className="mail-dialog-head">
          <div>
            <div className="mail-dialog-title">{t("settings_title")}</div>
            <div className="mail-dialog-subtitle">{t("settings_subtitle")}</div>
          </div>
          <button type="button" className="icon-btn" aria-label={t("close")} onClick={onClose}>
            <IconX size={16} />
          </button>
        </div>

        <div className="mail-settings-group">
          <label className="mail-settings-field">
            <span className="mail-settings-label">{t("settings_display_name")}</span>
            <input
              className="input"
              value={prefs.displayName}
              placeholder={t("settings_display_name")}
              onChange={(e) => setPrefs({ displayName: e.target.value })}
            />
            <span className="mail-settings-hint">{t("settings_display_name_hint")}</span>
          </label>

          <label className="mail-settings-field">
            <span className="mail-settings-label">{t("settings_signature")}</span>
            <textarea
              className="mail-textarea"
              value={prefs.signature}
              placeholder={t("settings_signature")}
              rows={4}
              onChange={(e) => setPrefs({ signature: e.target.value })}
            />
            <span className="mail-settings-hint">{t("settings_signature_hint")}</span>
          </label>
        </div>

        <div className="mail-settings-group">
          <div className="mail-settings-row">
            <span className="mail-settings-label">{t("settings_page_size")}</span>
            <select
              className="mail-settings-select"
              value={prefs.pageSize}
              aria-label={t("settings_page_size")}
              onChange={(e) => setPrefs({ pageSize: Number(e.target.value) || 50 })}
            >
              {PAGE_SIZE_OPTIONS.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </div>

          <div className="mail-settings-row">
            <span className="mail-settings-label">{t("settings_density")}</span>
            <div className="mail-segmented" role="group" aria-label={t("settings_density")}>
              {(["comfortable", "compact"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  className="mail-segmented-btn"
                  data-active={prefs.density === value}
                  onClick={() => setPrefs({ density: value })}
                >
                  {value === "comfortable" ? t("density_comfortable") : t("density_compact")}
                </button>
              ))}
            </div>
          </div>

          <label className="mail-settings-row mail-settings-row--toggle">
            <span>
              <span className="mail-settings-label">{t("settings_remote_images")}</span>
              <span className="mail-settings-hint">{t("settings_remote_images_hint")}</span>
            </span>
            <input
              type="checkbox"
              className="mail-switch"
              checked={prefs.loadRemoteImages}
              aria-label={t("settings_remote_images")}
              onChange={(e) => setPrefs({ loadRemoteImages: e.target.checked })}
            />
          </label>

          <div className="mail-settings-row">
            <span className="mail-settings-label">{t("settings_theme")}</span>
            <div className="mail-segmented" role="group" aria-label={t("settings_theme")}>
              {THEME_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  className="mail-segmented-btn"
                  data-active={prefs.theme === option.value}
                  onClick={() => setTheme(option.value)}
                >
                  {prefs.theme === option.value && <IconCheck size={11} />}
                  {t(option.key)}
                </button>
              ))}
            </div>
          </div>

          <div className="mail-settings-row">
            <span className="mail-settings-label">{t("settings_language")}</span>
            <div className="mail-segmented" role="group" aria-label={t("settings_language")}>
              <button type="button" className="mail-segmented-btn" data-active={prefs.lang === "zh"} onClick={() => setLang("zh")}>
                中文
              </button>
              <button type="button" className="mail-segmented-btn" data-active={prefs.lang === "en"} onClick={() => setLang("en")}>
                English
              </button>
            </div>
          </div>
        </div>

        <div className="mail-settings-note">{t("settings_storage_note")}</div>

        <div className="mail-dialog-actions">
          <span className="mail-settings-live">
            {prefs.theme === "system" ? t("theme_system") : resolvedTheme === "dark" ? t("theme_dark") : t("theme_light")}
            <span className="mail-settings-dot" data-dark={resolvedTheme === "dark"} aria-hidden />
          </span>
          <button type="button" className="btn btn-accent" onClick={onClose}>
            {t("settings_done")}
          </button>
        </div>
      </div>
    </div>
  );
}
