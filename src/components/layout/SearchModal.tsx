import React, { useState, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import { NavSection } from '../../types';
import {
  Search,
  Globe,
  Users,
  Send,
  Mail,
  FileText,
  Cpu,
  ShieldAlert,
  Settings,
  X,
  ArrowRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

export const SearchModal: React.FC = () => {
  const {
    isSearchOpen,
    setIsSearchOpen,
    setCurrentSection,
    domains,
    users,
    relayRoutes,
    language
  } = useApp();

  const [query, setQuery] = useState('');

  useEffect(() => {
    if (isSearchOpen) {
      setQuery('');
    }
  }, [isSearchOpen]);

  if (!isSearchOpen) return null;

  const handleSelectSection = (sec: NavSection) => {
    setCurrentSection(sec);
    setIsSearchOpen(false);
  };

  // Filtered navigation commands
  const commands = [
    { id: 'dashboard' as NavSection, titleZh: '主控制台 (仪表盘)', titleEn: 'Dashboard Overview', category: 'Navigation', icon: <Globe className="w-4 h-4 text-cyan-400" /> },
    { id: 'domains' as NavSection, titleZh: '邮件域名管理与 DNS 验证', titleEn: 'Domains & DNS Verification', category: 'Navigation', icon: <Globe className="w-4 h-4 text-cyan-400" /> },
    { id: 'users' as NavSection, titleZh: '邮箱用户与配额管理', titleEn: 'Mailbox Users & Quotas', category: 'Navigation', icon: <Users className="w-4 h-4 text-cyan-400" /> },
    { id: 'smtp_relay' as NavSection, titleZh: 'SMTP 出站中继与路由策略', titleEn: 'SMTP Outbound Relay & Routing', category: 'Navigation', icon: <Send className="w-4 h-4 text-cyan-400" /> },
    { id: 'mail_queue' as NavSection, titleZh: '邮件投递队列 (Postfix Queue)', titleEn: 'Mail Queue Monitor', category: 'Navigation', icon: <Mail className="w-4 h-4 text-cyan-400" /> },
    { id: 'logs' as NavSection, titleZh: '实时日志中心 (Syslog Console)', titleEn: 'Live Log Stream & Syslog', category: 'Navigation', icon: <FileText className="w-4 h-4 text-cyan-400" /> },
    { id: 'services' as NavSection, titleZh: '系统守护服务 (Postfix, Dovecot, Rspamd)', titleEn: 'System Daemons (Postfix, Dovecot)', category: 'Navigation', icon: <Cpu className="w-4 h-4 text-cyan-400" /> },
    { id: 'security' as NavSection, titleZh: '安全中心与 Fail2ban 防火墙', titleEn: 'Security Center & Fail2ban', category: 'Navigation', icon: <ShieldAlert className="w-4 h-4 text-cyan-400" /> },
    { id: 'settings' as NavSection, titleZh: '系统参数与外观配置', titleEn: 'System Settings & Appearance', category: 'Navigation', icon: <Settings className="w-4 h-4 text-cyan-400" /> },
  ].filter(c =>
    c.titleZh.toLowerCase().includes(query.toLowerCase()) ||
    c.titleEn.toLowerCase().includes(query.toLowerCase())
  );

  const matchedDomains = domains.filter(d => d.name.toLowerCase().includes(query.toLowerCase()));
  const matchedUsers = users.filter(u => u.email.toLowerCase().includes(query.toLowerCase()) || u.displayName.toLowerCase().includes(query.toLowerCase()));
  const matchedRelays = relayRoutes.filter(r => r.relayTarget.toLowerCase().includes(query.toLowerCase()) || r.sourceDomain.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-slate-950/60 backdrop-blur-md">
      <div className="fixed inset-0" onClick={() => setIsSearchOpen(false)} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: -20 }}
        className="w-full max-w-xl liquid-glass rounded-3xl shadow-2xl overflow-hidden relative z-10 border border-white/20"
      >
        {/* Search Input */}
        <div className="p-4 border-b border-white/10 flex items-center gap-3">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={language === 'zh' ? '搜索域名、用户、中继规则、日志或系统功能...' : 'Search domains, users, relays, commands...'}
            className="w-full bg-transparent text-sm placeholder-slate-400 focus:outline-none"
          />
          <button
            onClick={() => setIsSearchOpen(false)}
            className="text-slate-400 hover:text-white p-1 rounded-xl hover:bg-white/10 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-3 space-y-4">
          {/* Quick Navigation Commands */}
          {commands.length > 0 && (
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-1.5">
                {language === 'zh' ? '功能快捷入口' : 'Quick Navigation'}
              </div>
              <div className="space-y-1">
                {commands.slice(0, 5).map((cmd) => (
                  <button
                    key={cmd.id}
                    onClick={() => handleSelectSection(cmd.id)}
                    className="w-full p-2.5 rounded-xl hover:bg-slate-800/80 flex items-center justify-between text-left transition-colors group"
                  >
                    <div className="flex items-center gap-3">
                      {cmd.icon}
                      <span className="text-xs text-slate-200 group-hover:text-white font-medium">
                        {language === 'zh' ? cmd.titleZh : cmd.titleEn}
                      </span>
                    </div>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Matched Domains */}
          {matchedDomains.length > 0 && (
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-1.5">
                {language === 'zh' ? '匹配的域名' : 'Matched Domains'}
              </div>
              <div className="space-y-1">
                {matchedDomains.map((dom) => (
                  <button
                    key={dom.id}
                    onClick={() => handleSelectSection('domains')}
                    className="w-full p-2.5 rounded-xl hover:bg-slate-800/80 flex items-center justify-between text-left transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Globe className="w-4 h-4 text-emerald-400" />
                      <div>
                        <div className="text-xs text-slate-200 font-medium">{dom.name}</div>
                        <div className="text-[10px] text-slate-400">{dom.mailboxesCount} 个邮箱 • {dom.statusTextZh}</div>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                      DNS OK
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Matched Users */}
          {matchedUsers.length > 0 && (
            <div>
              <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3 mb-1.5">
                {language === 'zh' ? '匹配的用户' : 'Matched Users'}
              </div>
              <div className="space-y-1">
                {matchedUsers.map((usr) => (
                  <button
                    key={usr.id}
                    onClick={() => handleSelectSection('users')}
                    className="w-full p-2.5 rounded-xl hover:bg-slate-800/80 flex items-center justify-between text-left transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Users className="w-4 h-4 text-blue-400" />
                      <div>
                        <div className="text-xs text-slate-200 font-medium">{usr.displayName}</div>
                        <div className="text-[10px] text-slate-400">{usr.email}</div>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      {usr.quotaUsedGb} / {usr.quotaMaxGb} GB
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-950 flex items-center justify-between text-[11px] text-slate-500">
          <div className="flex items-center gap-2">
            <kbd className="px-1.5 py-0.5 bg-slate-800 rounded border border-slate-700 text-[10px]">ESC</kbd>
            <span>{language === 'zh' ? '退出搜索' : 'to close'}</span>
          </div>
          <div className="text-cyan-400/80 font-mono text-[10px]">
            MAILSTACK OS SEARCH ENGINE
          </div>
        </div>
      </motion.div>
    </div>
  );
};
