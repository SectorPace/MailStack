// 首帧引导 —— mail.html 的 module 入口第一行 import 本文件，在 React 渲染前把
// Webmail 自己的主题 / 语言偏好写到 `<html>`。
//
// 为什么需要它：`public/theme-init.js`（保留在 mail.html 里）读的是**管理台**的
// 存储键 `mailstack.prefs.v1`；而 Webmail 的主题/语言存在自己的 `mailstack.mail.*`
// 前缀下（契约 §5.6）。没有这一步的话，用户在 Webmail 选了深色/英文，
// 刷新时会先看到管理台的浅色/中文一帧再跳变。
//
// 生产构建下本模块被打进 mail 入口 chunk，仍然是外部脚本（CSP script-src 'self' 允许），
// 执行顺序在 React mount 之前。

import { applyPrefsToDocument, loadPrefs } from "./lib/prefs";

export function preboot(): void {
  try {
    applyPrefsToDocument(loadPrefs());
  } catch {
    /* 隐私模式 / 存储损坏：保持 theme-init.js / CSS 默认值 */
  }
}

preboot();
