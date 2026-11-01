// 首帧主题 / 平台引导 —— 在 React 加载前同步设置 <html> 属性，避免暗色用户白闪
// （P1）。必须是外部文件：后端 CSP 为 `script-src 'self'`（crates/web/src/lib.rs
// security_headers），内联脚本会被拦截。
//
// 数据源：localStorage `mailstack.prefs.v1`（store/settings.tsx 的存储键，此处只读，
// 不写入）。全程防御：任何一步失败都静默回落到 CSS 默认值（浅色 / 桌面度量），
// React 挂载后 SettingsProvider 会以真实 prefs 覆盖所有属性与内联变量。
(function () {
  try {
    var prefs = JSON.parse(localStorage.getItem("mailstack.prefs.v1") || "{}");
    var root = document.documentElement;

    // 主题：未知/缺失值一律按 light（与 store DEFAULTS 一致）
    var dark =
      prefs.theme === "dark" ||
      (prefs.theme === "system" &&
        window.matchMedia("(prefers-color-scheme: dark)").matches);
    root.dataset.theme = dark ? "dark" : "light";

    // 平台初值（iOS 度量的运行期真源是 index.css 的 ≤767px 媒体查询；
    // 该属性供 JS/组件读取初始档）
    root.dataset.platform = window.matchMedia("(max-width: 767px)").matches
      ? "ios"
      : "macos";

    // 可访问性降级开关：只在为 true 时打标（缺失 = CSS 默认全开）
    if (prefs.reduceTransparency === true) root.dataset.a11yReducedTransparency = "true";
    if (prefs.increaseContrast === true) root.dataset.a11yContrast = "true";
    if (prefs.reduceMotion === true) root.dataset.a11yReducedMotion = "true";

    // 强调色提前上屏（ACCENTS 映射的只读副本：[light, dark, deep] 的 rgb 三元组）
    var ACCENTS = {
      blue: ["0 122 255", "10 132 255", "0 100 220"],
      purple: ["175 82 222", "191 90 242", "142 54 196"],
      green: ["52 199 89", "48 209 88", "36 138 61"],
      red: ["255 59 48", "255 69 58", "215 0 21"],
      orange: ["255 149 0", "255 159 10", "201 52 0"],
      yellow: ["247 206 69", "255 214 10", "170 138 30"],
    };
    var accent = ACCENTS[prefs.accent];
    if (accent) {
      root.style.setProperty("--accent-rgb", dark ? accent[1] : accent[0]);
      root.style.setProperty("--accent-deep-rgb", accent[2]);
    }
  } catch (e) {
    /* 存储不可用 / JSON 损坏：保持 CSS 默认（浅色），不做任何兜底写入 */
  }
})();
