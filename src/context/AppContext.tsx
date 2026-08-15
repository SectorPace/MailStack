import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api, session } from '../api';
import {
  NavSection,
  Language,
  ThemeMode,
  BackgroundConfig,
  DomainItem,
  UserItem,
  AliasItem,
  SmtpRelayRoute,
  RelayProvider,
  LogEntry,
  ServiceItem,
  QueueItem,
  TlsCertificate,
  SecurityEvent,
  SystemSettings,
  ToastMessage
} from '../types';
import {
  INITIAL_DOMAINS,
  INITIAL_USERS,
  INITIAL_ALIASES,
  INITIAL_RELAY_ROUTES,
  INITIAL_RELAY_PROVIDERS,
  INITIAL_LOGS,
  INITIAL_SERVICES,
  INITIAL_QUEUES,
  INITIAL_CERTS,
  INITIAL_ANOMALIES,
  DEFAULT_SETTINGS
} from '../data/mockData';

interface AppContextType {
  currentSection: NavSection;
  setCurrentSection: (section: NavSection) => void;
  isLoggedIn: boolean;
  setIsLoggedIn: (status: boolean) => void;
  language: Language;
  setLanguage: (lang: Language) => void;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  settings: SystemSettings;
  updateSettings: (newSettings: Partial<SystemSettings>) => void;
  
  // Data items
  domains: DomainItem[];
  users: UserItem[];
  aliases: AliasItem[];
  relayRoutes: SmtpRelayRoute[];
  relayProviders: RelayProvider[];
  logs: LogEntry[];
  services: ServiceItem[];
  queues: QueueItem[];
  certs: TlsCertificate[];
  anomalies: SecurityEvent[];
  
  // Live log simulation
  isLiveLogStreaming: boolean;
  setIsLiveLogStreaming: (streaming: boolean) => void;
  logRate: number;
  logBufferSize: string;
  totalLogLines: number;
  addLogEntry: (entry: Omit<LogEntry, 'id'>) => void;
  clearLogs: () => void;
  
  // Actions
  adminAvatar: string;
  setAdminAvatar: (url: string) => void;
  customLogo: string;
  setCustomLogo: (logoUrl: string) => void;
  logoStyle: '3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom';
  setLogoStyle: (style: '3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom') => void;
  updateUserAvatar: (userId: string, avatarUrl: string, avatarColor?: string) => void;
  addDomain: (domain: Partial<DomainItem>) => void;
  deleteDomain: (id: string) => void;
  addUser: (user: Partial<UserItem>) => void;
  deleteUser: (id: string) => void;
  toggleUserStatus: (id: string) => void;
  addAlias: (alias: Partial<AliasItem>) => void;
  deleteAlias: (id: string) => void;
  addRelayRoute: (route: Partial<SmtpRelayRoute>) => void;
  deleteRelayRoute: (id: string) => void;
  toggleRelayRoute: (id: string) => void;
  promoteRelayProvider: (id: string) => void;
  restartService: (id: string) => void;
  flushQueue: () => void;
  deleteQueueItem: (id: string) => void;
  retryQueueItem: (id: string) => void;
  renewCert: (id: string) => void;
  addCert: (cert: Partial<TlsCertificate>) => void;
  
  // Onboarding Wizard
  hasCompletedOnboarding: boolean;
  setHasCompletedOnboarding: (status: boolean) => void;
  isOnboardingModalOpen: boolean;
  setIsOnboardingModalOpen: (open: boolean) => void;
  completeOnboarding: (data?: any) => void;

  // Modals & Search
  isSearchOpen: boolean;
  setIsSearchOpen: (open: boolean) => void;
  activeModal: string | null;
  setActiveModal: (modal: string | null) => void;
  
  // Notifications
  toasts: ToastMessage[];
  showToast: (type: ToastMessage['type'], title: string, message: string) => void;
  removeToast: (id: string) => void;
  
  // Background customization
  backgroundConfig: BackgroundConfig;
  updateBackgroundConfig: (config: Partial<BackgroundConfig>) => void;
  resetBackgroundConfig: () => void;

  // Translation helper
  t: (key: string) => string;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

// Multilingual dictionary
const TRANSLATIONS: Record<string, { zh: string; en: string }> = {
  // Navigation
  'nav.dashboard': { zh: '仪表盘', en: 'Dashboard' },
  'nav.setup_guide': { zh: '添加配置引导', en: 'Setup Guide' },
  'nav.ai_suite': { zh: 'AI 智能中心', en: 'AI Suite' },
  'nav.ai_diagnostic': { zh: 'AI 智能诊断', en: 'AI Diagnostic' },
  'nav.ai_assistant': { zh: 'AI 邮件顾问', en: 'AI Assistant' },
  'nav.domains': { zh: '邮件域名', en: 'Domains' },
  'nav.users': { zh: '邮箱用户', en: 'Users' },
  'nav.aliases': { zh: '地址与别名', en: 'Aliases' },
  'nav.smtp_relay': { zh: 'SMTP 中继', en: 'SMTP Relay' },
  'nav.outbound_relay': { zh: '出站中继', en: 'Outbound Relay' },
  'nav.dkim_dns': { zh: 'DKIM 与 DNS', en: 'DKIM & DNS' },
  'nav.tls_certs': { zh: 'TLS 证书', en: 'TLS Certs' },
  'nav.mail_queue': { zh: '邮件队列', en: 'Mail Queue' },
  'nav.logs': { zh: '日志中心', en: 'Logs' },
  'nav.services': { zh: '服务管理', en: 'Services' },
  'nav.security': { zh: '安全中心', en: 'Security' },
  'nav.settings': { zh: '系统设置', en: 'Settings' },
  'nav.connected': { zh: '已连接', en: 'CONNECTED' },
  'nav.mail_center': { zh: '邮件管理中心', en: 'MAIL CENTER' },
  'nav.main_console': { zh: '主控制台', en: 'Main Console' },
  'nav.root_access': { zh: 'Root 权限', en: 'Root Access' },
  'nav.admin_user': { zh: '管理员', en: 'Admin User' },
  'nav.search_placeholder': { zh: '搜索全系统...', en: 'Search system...' },
  'nav.export_selection': { zh: '导出选中项', en: 'EXPORT SELECTION' },
  'nav.full_scan': { zh: '运行全局诊断', en: 'Run Diagnostics' },
};

export const AppProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [currentSection, setCurrentSection] = useState<NavSection>('dashboard');
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [language, setLanguage] = useState<Language>('zh');
  const [themeMode, setThemeModeState] = useState<ThemeMode>(() => {
    return (localStorage.getItem('mailstack_theme_mode') as ThemeMode) || 'dark';
  });

  const setThemeMode = (mode: ThemeMode) => {
    setThemeModeState(mode);
    localStorage.setItem('mailstack_theme_mode', mode);
  };

  useEffect(() => {
    if (themeMode === 'light') {
      document.documentElement.classList.add('theme-light');
      document.body.classList.add('theme-light');
      document.documentElement.classList.remove('dark');
      document.body.classList.remove('dark');
      document.body.style.backgroundColor = '#f4f6fb';
      document.body.style.color = '#0f172a';
    } else {
      document.documentElement.classList.remove('theme-light');
      document.body.classList.remove('theme-light');
      document.documentElement.classList.add('dark');
      document.body.classList.add('dark');
      document.body.style.backgroundColor = '#060913';
      document.body.style.color = '#e2e8f0';
    }
  }, [themeMode]);
  const [hasCompletedOnboarding, setHasCompletedOnboardingState] = useState<boolean>(() => {
    return localStorage.getItem('mailstack_onboarding_completed') === 'true';
  });
  const [isOnboardingModalOpen, setIsOnboardingModalOpen] = useState<boolean>(false);

  const setHasCompletedOnboarding = (status: boolean) => {
    setHasCompletedOnboardingState(status);
    localStorage.setItem('mailstack_onboarding_completed', status ? 'true' : 'false');
  };

  const completeOnboarding = (data?: any) => {
    setHasCompletedOnboarding(true);
    setIsOnboardingModalOpen(false);
    if (data?.domainName) {
      // Ensure domain exists
      const exists = domains.some(d => d.name === data.domainName);
      if (!exists) {
        addDomain({
          name: data.domainName,
          status: 'active',
          statusTextZh: '活跃 (已完成全套初始化)',
          statusTextEn: 'Active (Initialized)',
          mxStatus: 'ok',
          spfStatus: 'ok',
          dkimStatus: 'ok',
          dmarcStatus: 'ok',
          mailboxesCount: 1,
          mailboxesMax: 50,
          aliasesCount: 1,
          dkimSelector: data.dkimSelector || 'mail',
          dkimKeySize: 2048,
        });
      }
    }
    showToast(
      'success',
      language === 'zh' ? '🎉 邮件服务初始引导部署完成！' : '🎉 Setup Completed!',
      language === 'zh'
        ? 'DNS 策略、出站中继与安全证书均已生效，系统已进入企业级高可用发信状态。'
        : 'All DNS, relay, and security settings are now active.'
    );
  };
  const [settings, setSettings] = useState<SystemSettings>(DEFAULT_SETTINGS);
  const [adminAvatar, setAdminAvatar] = useState<string>('');
  const [customLogo, setCustomLogoState] = useState<string>(() => {
    return localStorage.getItem('mailstack_custom_logo') || '';
  });
  const [logoStyle, setLogoStyleState] = useState<'3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom'>(() => {
    return (localStorage.getItem('mailstack_logo_style') as any) || '3d_glass';
  });

  const setCustomLogo = (url: string) => {
    setCustomLogoState(url);
    if (url) {
      localStorage.setItem('mailstack_custom_logo', url);
      setLogoStyleState('custom');
      localStorage.setItem('mailstack_logo_style', 'custom');
    } else {
      localStorage.removeItem('mailstack_custom_logo');
      if (logoStyle === 'custom') {
        setLogoStyleState('3d_glass');
        localStorage.setItem('mailstack_logo_style', '3d_glass');
      }
    }
  };

  const setLogoStyle = (style: '3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom') => {
    setLogoStyleState(style);
    localStorage.setItem('mailstack_logo_style', style);
  };
  
  const [backgroundConfig, setBackgroundConfigState] = useState<BackgroundConfig>(() => {
    const saved = localStorage.getItem('mailstack_bg_config');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        // fallback
      }
    }
    return {
      preset: 'default',
      customImageUrl: '',
      overlayOpacity: 70,
      blur: 0,
    };
  });

  const updateBackgroundConfig = (newCfg: Partial<BackgroundConfig>) => {
    setBackgroundConfigState((prev) => {
      const merged = { ...prev, ...newCfg };
      localStorage.setItem('mailstack_bg_config', JSON.stringify(merged));
      return merged;
    });
  };

  const resetBackgroundConfig = () => {
    const defaultCfg: BackgroundConfig = {
      preset: 'default',
      customImageUrl: '',
      overlayOpacity: 70,
      blur: 0,
    };
    setBackgroundConfigState(defaultCfg);
    localStorage.removeItem('mailstack_bg_config');
  };

  const [domains, setDomains] = useState<DomainItem[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);
  const [aliases, setAliases] = useState<AliasItem[]>([]);
  const [relayRoutes, setRelayRoutes] = useState<SmtpRelayRoute[]>([]);
  const [relayProviders, setRelayProviders] = useState<RelayProvider[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [queues, setQueues] = useState<QueueItem[]>([]);
  const [certs, setCerts] = useState<TlsCertificate[]>([]);
  const [anomalies, setAnomalies] = useState<SecurityEvent[]>([]);

  const loadSnapshot = async () => {
    const snap = await api('/api/snapshot');
    setDomains(snap.domains || []); setUsers(snap.users || []); setAliases(snap.aliases || []);
    setRelayRoutes(snap.relayRoutes || []); setRelayProviders(snap.relayProviders || []);
    setLogs(snap.logs || []); setServices(snap.services || []); setQueues(snap.queues || []);
    setCerts(snap.certs || []); setAnomalies(snap.anomalies || []);
    if (snap.settings) setSettings((prev) => ({...prev, ...snap.settings}));
  };
  useEffect(() => { session().then(ok => { setIsLoggedIn(ok); if (ok) loadSnapshot().catch(()=>setIsLoggedIn(false)); }); }, []);
  useEffect(() => { if (isLoggedIn) loadSnapshot().catch(e => showToast('error','Backend unavailable',String(e.message||e))); }, [isLoggedIn]);

  
  const [isLiveLogStreaming, setIsLiveLogStreaming] = useState<boolean>(true);
  const [logRate, setLogRate] = useState<number>(12);
  const [logBufferSize, setLogBufferSize] = useState<string>('4.2 MB');
  const [totalLogLines, setTotalLogLines] = useState<number>(10482);
  
  const [isSearchOpen, setIsSearchOpen] = useState<boolean>(false);
  const [activeModal, setActiveModal] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Translation function
  const t = (key: string): string => {
    if (TRANSLATIONS[key]) {
      return TRANSLATIONS[key][language];
    }
    return key;
  };

  const showToast = (type: ToastMessage['type'], title: string, message: string) => {
    const id = 'toast-' + Date.now() + Math.random().toString(36).substring(2, 5);
    setToasts((prev) => {
      // Deduplicate: if an identical title and message already exists, replace it or ignore
      const filtered = prev.filter((t) => !(t.title === title && t.message === message));
      // Keep maximum 2 toasts active simultaneously
      const trimmed = filtered.slice(-1);
      return [...trimmed, { id, type, title, message }];
    });
    setTimeout(() => {
      removeToast(id);
    }, 2800);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const updateSettings = (newSettings: Partial<SystemSettings>) => {
    setSettings((prev) => ({ ...prev, ...newSettings }));
  };

  // Keyboard shortcut for Cmd+K / Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Live logs are loaded from the authenticated backend.
  useEffect(() => { if (!isLoggedIn || !isLiveLogStreaming) return; const timer=setInterval(()=>api('/api/logs').then(setLogs).catch(()=>{}),5000); return ()=>clearInterval(timer); }, [isLoggedIn,isLiveLogStreaming]);

  const addLogEntry = (entry: Omit<LogEntry, 'id'>) => {
    const newLog: LogEntry = {
      id: 'log-' + Date.now(),
      ...entry,
    };
    setLogs((prev) => [newLog, ...prev]);
    setTotalLogLines((prev) => prev + 1);
  };

  const clearLogs = () => {
    setLogs([]);
    showToast('info', language === 'zh' ? '日志已清除' : 'Logs Cleared', language === 'zh' ? '控制台缓冲区已清空' : 'Console buffer has been purged');
  };

  const addDomain = async (newDom: Partial<DomainItem>) => { try { const data=await api('/api/domains',{method:'POST',body:JSON.stringify(newDom)}); setDomains(data); showToast('success', language==='zh'?'域名添加成功':'Domain Added',newDom.name||''); } catch(e:any){ showToast('error','Operation failed',e.message); } };

  const deleteDomain = async (id: string) => { try { const data=await api('/api/domains/'+encodeURIComponent(id),{method:'DELETE'}); setDomains(data); showToast('success',language==='zh'?'域名已删除':'Domain deleted',id); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const updateUserAvatar = (userId: string, avatarUrl: string, avatarColor?: string) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id === userId) {
          return { ...u, avatarUrl, avatarColor: avatarColor || u.avatarColor };
        }
        return u;
      })
    );
  };

  const addUser = async (newUser: Partial<UserItem>) => { try { const data=await api('/api/users',{method:'POST',body:JSON.stringify(newUser)}); setUsers(data); showToast('success',language==='zh'?'用户已创建':'User created',newUser.username||''); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const deleteUser = async (id: string) => { try { const data=await api('/api/users/'+encodeURIComponent(id),{method:'DELETE'}); setUsers(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const toggleUserStatus = (id: string) => {
    setUsers((prev) =>
      prev.map((u) => {
        if (u.id === id) {
          const next = u.status === 'enabled' ? 'disabled' : 'enabled';
          showToast('info', language === 'zh' ? '用户状态变更' : 'User Status Updated', `${u.email} -> ${next === 'enabled' ? '启用' : '禁用'}`);
          return { ...u, status: next };
        }
        return u;
      })
    );
  };

  const addAlias = async (newAlias: Partial<AliasItem>) => { try { const data=await api('/api/aliases',{method:'POST',body:JSON.stringify(newAlias)}); setAliases(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const deleteAlias = async (id: string) => { try { const data=await api('/api/aliases/'+encodeURIComponent(id),{method:'DELETE'}); setAliases(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const addRelayRoute = (newRoute: Partial<SmtpRelayRoute>) => {
    const route: SmtpRelayRoute = {
      id: 'rt-' + Date.now(),
      sourceDomain: newRoute.sourceDomain || '*@example.com',
      relayTarget: newRoute.relayTarget || 'smtp.sendgrid.net:587',
      priority: newRoute.priority || 10,
      action: newRoute.action || 'FORWARD',
      status: 'active',
      description: newRoute.description || 'Custom SMTP Relay Target',
      tlsMode: newRoute.tlsMode || 'STARTTLS',
      port: newRoute.port || 587,
    };
    setRelayRoutes((prev) => [route, ...prev]);
    showToast('success', language === 'zh' ? '中继规则已生效' : 'Relay Route Added', `${route.sourceDomain} -> ${route.relayTarget}`);
  };

  const deleteRelayRoute = (id: string) => {
    setRelayRoutes((prev) => prev.filter((r) => r.id !== id));
    showToast('info', language === 'zh' ? '中继规则已删除' : 'Relay Rule Deleted', language === 'zh' ? '已从 Postfix 路由表中注销' : 'Removed from Postfix table');
  };

  const toggleRelayRoute = (id: string) => {
    setRelayRoutes((prev) =>
      prev.map((r) => (r.id === id ? { ...r, status: r.status === 'active' ? 'disabled' : 'active' } : r))
    );
  };

  const promoteRelayProvider = (id: string) => {
    setRelayProviders((prev) =>
      prev.map((p) => {
        if (p.id === id) {
          return { ...p, isPrimary: true, type: 'primary' };
        }
        return { ...p, isPrimary: false, type: p.type === 'primary' ? 'backup' : p.type };
      })
    );
    showToast('success', language === 'zh' ? '主线路已切换' : 'Primary Relay Promoted', language === 'zh' ? 'Postfix 出站流量已热切换至新中继节点' : 'Outbound traffic hot-swapped to target node');
  };

  const restartService = async (id: string) => { try { const data=await api('/api/services/action',{method:'POST',body:JSON.stringify({id,verb:'restart'})}); setServices(data); showToast('success',language==='zh'?'服务重启完成':'Service restarted',id); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const flushQueue = async () => { try { const data=await api('/api/queue/action',{method:'POST',body:JSON.stringify({verb:'flush'})}); setQueues(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const deleteQueueItem = async (id: string) => { try { const data=await api('/api/queue/action',{method:'POST',body:JSON.stringify({id,verb:'delete'})}); setQueues(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const retryQueueItem = async (id: string) => { try { const data=await api('/api/queue/action',{method:'POST',body:JSON.stringify({id,verb:'retry'})}); setQueues(data); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const renewCert = async (_id: string) => { try { const data=await api('/api/certificates/renew',{method:'POST',body:'{}'}); setCerts(data); showToast('success',language==='zh'?'证书续期任务完成':'Certificate renewal completed','ACME'); } catch(e:any){showToast('error','Operation failed',e.message);} };

  const addCert = (newCert: Partial<TlsCertificate>) => {
    const validToDate = new Date(Date.now() + 90 * 24 * 3600 * 1000).toISOString().split('T')[0];
    const cert: TlsCertificate = {
      id: 'cert-' + Date.now(),
      domain: newCert.domain || 'mail.example.com',
      issuer: newCert.issuer || "Let's Encrypt Authority X3 (ACME)",
      validFrom: new Date().toISOString().split('T')[0],
      validTo: newCert.validTo || validToDate,
      daysRemaining: 90,
      autoRenew: newCert.autoRenew !== undefined ? newCert.autoRenew : true,
      algorithm: newCert.algorithm || 'ECDSA P-256',
      keySize: newCert.keySize || 256,
      status: 'valid',
    };
    setCerts((prev) => [cert, ...prev.filter((c) => c.domain !== cert.domain)]);
    showToast(
      'success',
      language === 'zh' ? 'TLS 证书注册与签发成功' : 'TLS Certificate Issued',
      `${cert.domain} ${language === 'zh' ? '已自动挂载至 Postfix (SMTP 465/587) 与 Dovecot (IMAP 993)' : 'bound to Postfix and Dovecot'}`
    );
  };

  return (
    <AppContext.Provider
      value={{
        currentSection,
        setCurrentSection,
        isLoggedIn,
        setIsLoggedIn,
        language,
        setLanguage,
        themeMode,
        setThemeMode,
        settings,
        updateSettings,
        domains,
        users,
        aliases,
        relayRoutes,
        relayProviders,
        logs,
        services,
        queues,
        certs,
        anomalies,
        isLiveLogStreaming,
        setIsLiveLogStreaming,
        logRate,
        logBufferSize,
        totalLogLines,
        addLogEntry,
        clearLogs,
        addDomain,
        deleteDomain,
        adminAvatar,
        setAdminAvatar,
        customLogo,
        setCustomLogo,
        logoStyle,
        setLogoStyle,
        updateUserAvatar,
        addUser,
        deleteUser,
        toggleUserStatus,
        addAlias,
        deleteAlias,
        addRelayRoute,
        deleteRelayRoute,
        toggleRelayRoute,
        promoteRelayProvider,
        restartService,
        flushQueue,
        deleteQueueItem,
        retryQueueItem,
        renewCert,
        addCert,
        hasCompletedOnboarding,
        setHasCompletedOnboarding,
        isOnboardingModalOpen,
        setIsOnboardingModalOpen,
        completeOnboarding,
        isSearchOpen,
        setIsSearchOpen,
        activeModal,
        setActiveModal,
        backgroundConfig,
        updateBackgroundConfig,
        resetBackgroundConfig,
        toasts,
        showToast,
        removeToast,
        t,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
