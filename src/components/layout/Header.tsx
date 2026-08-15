import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { MailStackLogo } from '../common/MailStackLogo';
import {
  Search,
  RotateCw,
  Bell,
  Sun,
  Moon,
  Download,
  CheckCircle2,
  AlertTriangle,
  X,
  Github,
  Star,
  ExternalLink
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

export const Header: React.FC = () => {
  const {
    currentSection,
    language,
    setLanguage,
    themeMode,
    setThemeMode,
    setIsSearchOpen,
    anomalies,
    showToast,
    t
  } = useApp();

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      showToast('success', language === 'zh' ? '系统数据已刷新' : 'System Refreshed', language === 'zh' ? '所有服务与队列监控指标已同步' : 'All service & queue metrics synced');
    }, 600);
  };

  const getBreadcrumbTitle = () => {
    switch (currentSection) {
      case 'dashboard':
        return language === 'zh' ? 'DASHBOARD > 主控制台' : 'DASHBOARD > Main Console';
      case 'setup_guide':
        return language === 'zh' ? 'WIZARD > 添加配置引导' : 'WIZARD > Configuration Guide';
      case 'ai_suite':
        return language === 'zh' ? 'AI SUITE > AI 智能中心' : 'AI SUITE > AI Intelligence Center';
      case 'ai_diagnostic':
        return language === 'zh' ? 'AI SUITE > 智能 DNS 与发信诊断' : 'AI SUITE > AI Diagnostic';
      case 'ai_assistant':
        return language === 'zh' ? 'AI SUITE > AI 邮件协议顾问' : 'AI SUITE > AI Assistant';
      case 'domains':
        return language === 'zh' ? 'DOMAINS > 邮件域名管理' : 'DOMAINS > Domain Management';
      case 'users':
        return language === 'zh' ? 'USERS > 邮箱用户列表' : 'USERS > Mailbox Users';
      case 'aliases':
        return language === 'zh' ? 'ALIASES > 地址与别名路由' : 'ALIASES > Address & Alias Routing';
      case 'smtp_relay':
        return language === 'zh' ? 'ROUTING > 路由管理 (出站中继)' : 'ROUTING > Outbound SMTP Relay';
      case 'dkim_dns':
        return language === 'zh' ? 'SECURITY > DKIM 密钥与 DNS 解析' : 'SECURITY > DKIM Keys & DNS';
      case 'tls_certs':
        return language === 'zh' ? 'SECURITY > TLS/SSL 证书管理' : 'SECURITY > TLS/SSL Certificates';
      case 'mail_queue':
        return language === 'zh' ? 'MTA > 邮件队列监视' : 'MTA > Mail Queue Monitor';
      case 'logs':
        return language === 'zh' ? 'SYSLOG > 实时日志中心' : 'SYSLOG > Live Log Stream';
      case 'services':
        return language === 'zh' ? 'SYSTEM > 核心守护进程' : 'SYSTEM > Core Daemon Services';
      case 'security':
        return language === 'zh' ? 'SECURITY > 防火墙与安全策略' : 'SECURITY > Firewall & Security';
      case 'settings':
        return language === 'zh' ? 'CONFIG > 系统设置与外观' : 'CONFIG > System Settings';
      default:
        return 'DASHBOARD';
    }
  };

  return (
    <header className="h-16 px-6 liquid-glass sticky top-0 z-30 flex items-center justify-between border-b border-white/10">
      {/* Left Breadcrumb */}
      <div className="flex items-center gap-2.5">
        <MailStackLogo size="xs" />
        <div className="text-xs font-mono tracking-wider text-cyan-400 font-bold drop-shadow-[0_0_8px_rgba(0,242,195,0.4)] uppercase">MAILSTACK</div>
        <span className="text-slate-400 dark:text-slate-500 text-xs">›</span>
        <h1 className="text-sm font-semibold text-slate-800 dark:text-slate-100 tracking-wide flex items-center gap-2">
          {getBreadcrumbTitle()}
        </h1>
      </div>

      {/* Center Search Input & GitHub Icon Button & Dark/Day Mode Switch (with Liquid Glass Effect) */}
      <div className="flex-1 max-w-xl mx-4 hidden md:flex items-center gap-2.5">
        {/* Search Bar - Liquid Glass style */}
        <button
          onClick={() => setIsSearchOpen(true)}
          className="flex-1 min-w-[200px] h-9 px-3.5 liquid-glass-btn rounded-xl text-xs text-slate-700 dark:text-slate-300 flex items-center justify-between transition-all group"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400 group-hover:text-cyan-500 dark:group-hover:text-cyan-300 transition-colors" />
            <span className="truncate text-slate-700 dark:text-slate-300/90 font-medium">{t('nav.search_placeholder')}</span>
          </div>
          <kbd className="text-[10px] font-mono bg-slate-200/70 dark:bg-white/10 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-white/20 shrink-0 shadow-inner">
            ⌘K
          </kbd>
        </button>

        {/* GitHub Button - Pure Icon with Liquid Glass Floating Bubble style */}
        <a
          href="https://github.com"
          target="_blank"
          rel="noreferrer noopener"
          className="w-9 h-9 liquid-glass-btn rounded-xl flex items-center justify-center text-slate-700 dark:text-slate-200 hover:text-cyan-600 dark:hover:text-white transition-all group shrink-0 relative overflow-hidden"
          title={language === 'zh' ? 'GitHub 开源项目 (GitHub Repository)' : 'View GitHub Repository'}
        >
          <Github className="w-4 h-4 text-slate-700 dark:text-slate-300 group-hover:text-cyan-600 dark:group-hover:text-cyan-300 group-hover:scale-110 transition-transform" />
          <span className="sr-only">GitHub</span>
        </a>

        {/* Dark/Day Mode Switch (Pure Icons) - Liquid Glass Segmented Switch */}
        <div className="flex items-center liquid-glass-btn rounded-xl p-0.5 text-xs font-medium shrink-0">
          <button
            onClick={() => setThemeMode('dark')}
            title={language === 'zh' ? '暗黑模式' : 'Dark Mode'}
            className={`w-7 h-7 rounded-lg flex items-center justify-center transition-all ${
              themeMode === 'dark'
                ? 'bg-cyan-400/25 text-cyan-300 shadow-[0_0_12px_rgba(0,242,195,0.25)] border border-cyan-400/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Moon className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setThemeMode('light')}
            title={language === 'zh' ? '白天模式 (纯白界面)' : 'Daylight Mode'}
            className={`w-7 h-7 rounded-lg flex items-center justify-center transition-all ${
              themeMode === 'light'
                ? 'bg-amber-400/25 text-amber-400 shadow-[0_0_12px_rgba(251,191,36,0.25)] border border-amber-400/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sun className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-2.5">
        {/* Refresh Button */}
        <button
          onClick={handleRefresh}
          title={language === 'zh' ? '刷新监控状态' : 'Refresh System'}
          className="w-9 h-9 flex items-center justify-center rounded-xl liquid-glass-btn text-slate-300 hover:text-white transition-all"
        >
          <RotateCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Notifications Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            title={language === 'zh' ? '系统警报' : 'Alerts'}
            className="w-9 h-9 flex items-center justify-center rounded-xl liquid-glass-btn text-slate-300 hover:text-white transition-all relative"
          >
            <Bell className="w-4 h-4" />
            {anomalies.length > 0 && (
              <span className="absolute top-2 right-2 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f2c3]" />
            )}
          </button>

          {/* Notifications Dropdown */}
          <AnimatePresence>
            {showNotifications && (
              <motion.div
                initial={{ opacity: 0, y: 10, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className={`absolute right-0 mt-2 w-80 rounded-2xl shadow-2xl p-3.5 z-50 backdrop-blur-2xl ${
                  themeMode === 'light'
                    ? 'bg-white/95 border border-slate-200 text-slate-900 shadow-[0_12px_36px_rgba(0,0,0,0.12)]'
                    : 'bg-slate-900/95 border border-white/10 text-white shadow-2xl'
                }`}
              >
                <div className={`flex items-center justify-between pb-2 border-b mb-2.5 ${
                  themeMode === 'light' ? 'border-slate-100' : 'border-slate-800'
                }`}>
                  <div className={`text-xs font-semibold flex items-center gap-1.5 ${
                    themeMode === 'light' ? 'text-slate-800' : 'text-white'
                  }`}>
                    <AlertTriangle className="w-3.5 h-3.5 text-cyan-500" />
                    {language === 'zh' ? '近期系统事件' : 'Recent System Events'}
                  </div>
                  <button
                    onClick={() => setShowNotifications(false)}
                    className={`${themeMode === 'light' ? 'text-slate-400 hover:text-slate-700' : 'text-slate-500 hover:text-white'}`}
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {anomalies.map((anom) => (
                    <div
                      key={anom.id}
                      className={`p-2.5 rounded-xl text-xs transition-all border ${
                        themeMode === 'light'
                          ? 'bg-slate-50/90 border-slate-200/90 hover:border-cyan-500/40 shadow-sm'
                          : 'bg-slate-950/80 border-slate-800/80 hover:border-cyan-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                        <span className={`font-semibold ${themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'}`}>{anom.type}</span>
                        <span className={themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}>{anom.timestamp}</span>
                      </div>
                      <p className={`text-[11px] leading-tight ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>{anom.message}</p>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Language Toggle */}
        <div className="flex items-center liquid-glass-btn rounded-xl p-0.5 text-xs font-medium">
          <button
            onClick={() => setLanguage('zh')}
            className={`px-2.5 py-1 rounded-lg transition-all ${
              language === 'zh'
                ? 'bg-cyan-400/25 text-cyan-300 shadow-[0_0_10px_rgba(0,242,195,0.2)] border border-cyan-400/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            中
          </button>
          <button
            onClick={() => setLanguage('en')}
            className={`px-2.5 py-1 rounded-lg transition-all ${
              language === 'en'
                ? 'bg-cyan-400/25 text-cyan-300 shadow-[0_0_10px_rgba(0,242,195,0.2)] border border-cyan-400/30 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            EN
          </button>
        </div>

        {/* Theme Toggle (Mobile icon only) */}
        <button
          onClick={() => setThemeMode(themeMode === 'dark' ? 'light' : 'dark')}
          title={themeMode === 'dark' ? '切换白天模式' : 'Switch to Dark Mode'}
          className="md:hidden w-9 h-9 flex items-center justify-center rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white transition-all"
        >
          {themeMode === 'dark' ? (
            <Moon className="w-4 h-4 text-cyan-300" />
          ) : (
            <Sun className="w-4 h-4 text-amber-400" />
          )}
        </button>

        {/* Top Right Green Pill Button (Apple / HarmonyOS Capsule Style) */}
        <button
          onClick={() =>
            showToast(
              'success',
              language === 'zh' ? '配置文件已导出' : 'Export Ready',
              language === 'zh' ? 'Postfix & Dovecot 当前配置打包已下载' : 'Postfix & Dovecot bundle downloaded'
            )
          }
          className="h-9 px-4 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 text-slate-950 font-bold text-xs rounded-2xl flex items-center gap-1.5 shadow-[0_4px_16px_rgba(0,242,195,0.3)] transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Download className="w-3.5 h-3.5 stroke-[2.5]" />
          <span className="tracking-wide">{t('nav.export_selection')}</span>
        </button>
      </div>
    </header>
  );
};
