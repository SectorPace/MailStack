import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { NavSection } from '../../types';
import { MailStackLogo } from '../common/MailStackLogo';
import { AvatarCustomizerModal } from '../modals/AvatarCustomizerModal';
import { LogoCustomizerModal } from '../modals/LogoCustomizerModal';
import {
  LayoutGrid,
  Globe,
  Users,
  AtSign,
  Send,
  KeyRound,
  ShieldCheck,
  Mail,
  FileText,
  Cpu,
  ShieldAlert,
  Settings,
  LogOut,
  Sparkles,
  Camera,
  Palette,
  Bot,
  Compass,
  Zap
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { currentSection, setCurrentSection, language, queues, setIsLoggedIn, t, adminAvatar, setAdminAvatar, hasCompletedOnboarding } = useApp();
  const [isAvatarModalOpen, setIsAvatarModalOpen] = useState(false);
  const [isLogoModalOpen, setIsLogoModalOpen] = useState(false);

  const navItems: { id: NavSection; labelZh: string; labelEn: string; icon: React.ReactNode; badge?: number; highlight?: boolean }[] = [
    {
      id: 'dashboard',
      labelZh: '仪表盘',
      labelEn: 'Dashboard',
      icon: <LayoutGrid className="w-4 h-4" />,
    },
    ...(!hasCompletedOnboarding
      ? [
          {
            id: 'setup_guide' as NavSection,
            labelZh: '首次配置引导',
            labelEn: 'Setup Wizard',
            icon: <Compass className="w-4 h-4 text-amber-400" />,
            highlight: true,
          },
        ]
      : []),
    {
      id: 'ai_suite',
      labelZh: 'AI 智能中心',
      labelEn: 'AI Suite',
      icon: <Sparkles className="w-4 h-4 text-cyan-400" />,
    },
    {
      id: 'domains',
      labelZh: '邮件域名',
      labelEn: 'Domains',
      icon: <Globe className="w-4 h-4" />,
    },
    {
      id: 'users',
      labelZh: '邮箱用户',
      labelEn: 'Users',
      icon: <Users className="w-4 h-4" />,
    },
    {
      id: 'aliases',
      labelZh: '地址与别名',
      labelEn: 'Aliases',
      icon: <AtSign className="w-4 h-4" />,
    },
    {
      id: 'smtp_relay',
      labelZh: '出站中继',
      labelEn: 'SMTP Relay',
      icon: <Send className="w-4 h-4" />,
    },
    {
      id: 'dkim_dns',
      labelZh: 'DKIM 与 DNS',
      labelEn: 'DKIM & DNS',
      icon: <KeyRound className="w-4 h-4" />,
    },
    {
      id: 'tls_certs',
      labelZh: 'TLS 证书',
      labelEn: 'TLS Certs',
      icon: <ShieldCheck className="w-4 h-4" />,
    },
    {
      id: 'mail_queue',
      labelZh: '邮件队列',
      labelEn: 'Mail Queue',
      icon: <Mail className="w-4 h-4" />,
      badge: queues.length,
    },
    {
      id: 'logs',
      labelZh: '日志中心',
      labelEn: 'Logs',
      icon: <FileText className="w-4 h-4" />,
    },
    {
      id: 'services',
      labelZh: '服务管理',
      labelEn: 'Services',
      icon: <Cpu className="w-4 h-4" />,
    },
    {
      id: 'security',
      labelZh: '安全中心',
      labelEn: 'Security',
      icon: <ShieldAlert className="w-4 h-4" />,
    },
    {
      id: 'settings',
      labelZh: '系统设置',
      labelEn: 'Settings',
      icon: <Settings className="w-4 h-4" />,
    },
  ];

  return (
    <aside className="w-64 border-r border-white/10 liquid-glass flex flex-col justify-between h-screen shrink-0 sticky top-0 select-none z-40">
      {/* Brand Header */}
      <div>
        <div className="p-4 border-b border-white/10 flex items-center justify-between">
          <div
            onClick={() => setIsLogoModalOpen(true)}
            title={language === 'zh' ? '点击定制/更换 Logo 图标' : 'Click to customize/change Logo'}
            className="flex items-center gap-3 cursor-pointer group flex-1 min-w-0"
          >
            <div className="relative">
              <MailStackLogo size="md" showHoverEffect />
              <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-cyan-400 text-slate-950 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity shadow-[0_0_8px_#00f2c3] scale-90">
                <Palette className="w-2.5 h-2.5" />
              </div>
            </div>
            <div className="min-w-0">
              <div className="text-base font-bold tracking-tight flex items-center gap-1.5 text-slate-800 dark:text-white group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                MailStack
              </div>
              <div className="text-[10px] text-slate-500 dark:text-slate-400 tracking-wider flex items-center gap-1.5 font-medium">
                <span className="truncate">{t('nav.mail_center')}</span>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399] shrink-0" />
                <span className="text-[9px] text-emerald-600 dark:text-emerald-400 font-mono shrink-0 font-bold">{t('nav.connected')}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Nav list - Liquid Capsule Dock style */}
        <nav className="p-2.5 space-y-1 overflow-y-auto max-h-[calc(100vh-210px)]">
          {navItems.map((item) => {
            const isActive =
              currentSection === item.id ||
              (item.id === 'ai_suite' &&
                (currentSection === 'ai_suite' ||
                  currentSection === 'ai_diagnostic' ||
                  currentSection === 'ai_assistant'));
            return (
              <button
                key={item.id}
                onClick={() => setCurrentSection(item.id)}
                className={`w-full h-10 px-3.5 rounded-2xl flex items-center justify-between text-xs font-medium transition-all cursor-pointer ${
                  isActive
                    ? 'liquid-glass-btn text-cyan-600 dark:text-cyan-400 font-bold border-cyan-500/40 dark:border-cyan-400/40 shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-black/5 dark:hover:bg-white/5 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-400'} shrink-0`}>
                    {item.icon}
                  </span>
                  <span className="truncate">{language === 'zh' ? item.labelZh : item.labelEn}</span>
                </div>

                {item.highlight && !item.badge && (
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping shadow-[0_0_8px_#fbbf24] shrink-0" />
                )}

                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono shrink-0 ${
                      isActive
                        ? 'bg-cyan-500/15 dark:bg-cyan-400/20 text-cyan-700 dark:text-cyan-400 border border-cyan-400/30 font-bold'
                        : 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-slate-400 border border-slate-300 dark:border-white/10 font-medium'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer OS & User Profile (Apple / HarmonyOS Liquid Floating Pill Card) */}
      <div className="p-3 border-t border-white/10 space-y-2">
        <div className="flex items-center justify-between px-2 text-[10px] font-mono text-slate-500 dark:text-slate-400">
          <span>OS: DEBIAN 12</span>
          <span className="opacity-75">V3.4.2</span>
        </div>

        <div className="p-2 rounded-2xl liquid-glass-card flex items-center justify-between shadow-sm transition-all hover:border-cyan-400/30">
          <div
            onClick={() => setIsAvatarModalOpen(true)}
            title={language === 'zh' ? '点击自定义管理员头像' : 'Click to customize avatar'}
            className="flex items-center gap-2.5 min-w-0 cursor-pointer group flex-1"
          >
            <div className="relative w-8 h-8 rounded-xl overflow-hidden bg-cyan-500/15 border border-cyan-400/30 flex items-center justify-center text-cyan-600 dark:text-cyan-400 font-bold text-xs shrink-0 shadow-inner group-hover:scale-105 transition-transform">
              {adminAvatar ? (
                <img src={adminAvatar} alt="Admin" className="w-full h-full object-cover" referrerPolicy="no-referrer" />
              ) : (
                <span>AL</span>
              )}
              <div className="absolute inset-0 bg-slate-900/60 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity text-white">
                <Camera className="w-3.5 h-3.5" />
              </div>
            </div>
            <div className="min-w-0">
              <div className="text-xs font-semibold truncate text-slate-800 dark:text-slate-100 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                {language === 'zh' ? '管理员 (Admin)' : 'Admin User'}
              </div>
              <div className="text-[10px] text-cyan-700 dark:text-cyan-400 font-mono truncate flex items-center gap-1 font-medium">
                <span>{language === 'zh' ? 'Root 权限' : 'Root Access'}</span>
              </div>
            </div>
          </div>

          <button
            onClick={() => setIsLoggedIn(false)}
            title={language === 'zh' ? '退出并返回登录页' : 'Sign out to Login Screen'}
            className="w-7 h-7 rounded-xl flex items-center justify-center text-slate-500 dark:text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-500/10 transition-all shrink-0 ml-1 cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>

      {isAvatarModalOpen && (
        <AvatarCustomizerModal
          initialName="Alex Lawson"
          initialAvatar={adminAvatar}
          onSave={(url) => setAdminAvatar(url)}
          onClose={() => setIsAvatarModalOpen(false)}
        />
      )}

      {isLogoModalOpen && (
        <LogoCustomizerModal onClose={() => setIsLogoModalOpen(false)} />
      )}
    </aside>
  );
};
