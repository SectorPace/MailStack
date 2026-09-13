import React, { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react';
import { api, session } from '../api';
import { getErrorMessage } from '../utils/errors';
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
import { DEFAULT_SETTINGS } from '../config/defaults';

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
  saveSettings: (newSettings?: Partial<SystemSettings>) => Promise<void>;
  logout: () => Promise<void>;
  
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
  restartService: (id: string) => void;
  flushQueue: () => void;
  deleteQueueItem: (id: string) => void;
  retryQueueItem: (id: string) => void;
  renewCert: (id: string) => void;
  
  // Onboarding Wizard
  hasCompletedOnboarding: boolean;
  setHasCompletedOnboarding: (status: boolean) => void;
  isOnboardingModalOpen: boolean;
  setIsOnboardingModalOpen: (open: boolean) => void;
  completeOnboarding: (data?: unknown) => Promise<void>;
  refreshSnapshot: () => Promise<void>;

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
  const logoutTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
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

  const refreshSnapshot = async () => {
    try {
      const snap = await api('/api/snapshot');
      setDomains(snap.domains || []);
      setUsers(snap.users || []);
      setAliases(snap.aliases || []);
      setRelayRoutes(snap.relayRoutes || []);
      setRelayProviders(snap.relayProviders || []);
      setLogs(snap.logs || []);
      setServices(snap.services || []);
      setQueues(snap.queues || []);
      setCerts(snap.certs || []);
      setAnomalies(snap.anomalies || []);
      if (snap.settings) setSettings((prev) => ({ ...prev, ...snap.settings }));
    } catch (e: unknown) {
      console.error('Failed to load snapshot:', e);
      throw e;
    }
  };

  const completeOnboarding = async (_data?: unknown) => {
    try {
      const state = await api<{
        identityConfigured?: boolean;
        postfixActive?: boolean;
        dovecotActive?: boolean;
        dnsVerified?: boolean;
        tlsInstalled?: boolean;
        mailTestQueued?: boolean;
        complete?: boolean;
        pending?: string[];
      }>('/api/setup/status');
      const complete = typeof state.complete === 'boolean'
        ? state.complete
        : Boolean(
          state.identityConfigured &&
          state.postfixActive &&
          state.dovecotActive &&
          state.dnsVerified &&
          state.tlsInstalled &&
          state.mailTestQueued,
        );
      setHasCompletedOnboarding(complete);
      if (complete) setIsOnboardingModalOpen(false);
      await refreshSnapshot();
      showToast(
        complete ? 'success' : 'warning',
        complete
          ? (language === 'zh' ? '服务器验证步骤已完成' : 'Server-verified setup completed')
          : (language === 'zh' ? '配置已保存，仍有待完成项' : 'Configuration saved with pending items'),
        complete ? (language === 'zh' ? '所有必需检查均已通过' : 'All required checks passed') : (state.pending || []).join(', ') || (language === 'zh' ? '请完成剩余服务器检查' : 'Complete the remaining server checks'),
      );
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '无法确认配置状态' : 'Unable to verify setup state', getErrorMessage(e));
      throw e;
    }
  };

  useEffect(() => {
    session().then((ok) => {
      setIsLoggedIn(ok);
      if (ok) refreshSnapshot().catch(() => setIsLoggedIn(false));
    });
  }, []);

  useEffect(() => {
    const handleAuthRequired = () => {
      if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
      setIsLoggedIn(false);
      setIsOnboardingModalOpen(false);
    };
    window.addEventListener('mailstack:auth-required', handleAuthRequired);
    return () => window.removeEventListener('mailstack:auth-required', handleAuthRequired);
  }, []);

  useEffect(() => {
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
    logoutTimerRef.current = null;
    if (isLoggedIn) {
      logoutTimerRef.current = setTimeout(() => {
        setIsLoggedIn(false);
        setCurrentSection('dashboard');
        window.dispatchEvent(new CustomEvent('mailstack:auth-required'));
      }, 8 * 60 * 60 * 1000);
    }
    return () => {
      if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
    };
  }, [isLoggedIn]);

  useEffect(() => {
    if (isLoggedIn) {
      refreshSnapshot().catch((e: unknown) => showToast('error', 'Backend unavailable', getErrorMessage(e)));
      api('/api/setup/status').then((res: any) => {
        if (res && typeof res.complete === 'boolean') {
          setHasCompletedOnboarding(res.complete);
        }
      }).catch(() => {});
    }
  }, [isLoggedIn]);

  
  const [isLiveLogStreaming, setIsLiveLogStreaming] = useState<boolean>(true);
  const [logRate, setLogRate] = useState<number>(12);
  const [logBufferSize, setLogBufferSize] = useState<string>('0 B');
  const [totalLogLines, setTotalLogLines] = useState<number>(0);
  
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

  const saveSettings = async (newSettings?: Partial<SystemSettings>) => {
    const toSave = newSettings ? { ...settings, ...newSettings } : settings;
    const prevSettings = { ...settings };
    setSettings(toSave);
    try {
      const payload = {
        transparency: toSave.transparency,
        backdropBlur: toSave.backdropBlur,
        reducedMotion: toSave.reducedMotion,
        autoUpdate: toSave.autoUpdate,
        adminEmail: toSave.adminEmail,
        maxMessageSizeMb: toSave.maxMessageSizeMb,
        rateLimitPerHour: toSave.rateLimitPerHour,
        spamThreshold: toSave.spamThreshold,
        colorTheme: toSave.colorTheme,
        hostname: toSave.hostname,
        timezone: toSave.timezone,
      };
      const saved = await api<SystemSettings>('/api/settings', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      setSettings((prev) => ({ ...prev, ...saved }));
      showToast('success', language === 'zh' ? '设置已保存' : 'Settings Saved', language === 'zh' ? '系统配置已持久化' : 'System configuration persisted.');
      await refreshSnapshot();
    } catch (e: unknown) {
      setSettings(prevSettings);
      showToast('error', language === 'zh' ? '设置保存失败' : 'Failed to Save Settings', getErrorMessage(e));
      throw e;
    }
  };

  const logout = async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
      setLogs([]);
      setIsLoggedIn(false);
      setCurrentSection('dashboard');
    }
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

  // Live logs are loaded from the authenticated backend with visibility awareness
  useEffect(() => {
    if (!isLoggedIn || !isLiveLogStreaming) return;
    const poll = () => {
      if (document.hidden) return;
      api('/api/logs').then(setLogs).catch(() => {});
    };
    const timer = setInterval(poll, 5000);
    const handleVisibility = () => {
      if (!document.hidden) poll();
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [isLoggedIn, isLiveLogStreaming]);

  const clearLogs = () => {
    setLogs([]);
    showToast('info', language === 'zh' ? '当前视图已清空' : 'Current View Cleared', language === 'zh' ? '仅清空浏览器中的当前日志列表，服务器 journal 未被删除' : 'Only the browser view was cleared; the server journal was not deleted');
  };

  const addDomain = async (newDom: Partial<DomainItem>) => {
    try {
      const data = await api('/api/domains', { method: 'POST', body: JSON.stringify(newDom) });
      setDomains(data);
      showToast('success', language === 'zh' ? '域名添加成功' : 'Domain Added', newDom.name || '');
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const deleteDomain = async (id: string) => {
    try {
      await api('/api/domains/' + encodeURIComponent(id), { method: 'DELETE', body: JSON.stringify({ confirm: true }) });
      const snapshot = await api<{ domains?: DomainItem[] }>('/api/snapshot');
      const serverDomains = snapshot.domains || [];
      if (serverDomains.some((item) => item.id === id || item.name === id)) {
        throw new Error(language === 'zh' ? '服务器仍返回该域名，删除未确认' : 'The server still reports this domain after deletion.');
      }
      setDomains(serverDomains);
      showToast('success', language === 'zh' ? '域名已删除' : 'Domain deleted', id);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
      await refreshSnapshot().catch(() => {});
    }
  };

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

  const addUser = async (newUser: Partial<UserItem>) => {
    try {
      const data = await api('/api/users', { method: 'POST', body: JSON.stringify(newUser) });
      setUsers(data);
      showToast('success', language === 'zh' ? '用户已创建' : 'User created', newUser.username || '');
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const deleteUser = async (id: string) => {
    try {
      const data = await api('/api/users/' + encodeURIComponent(id), { method: 'DELETE', body: JSON.stringify({ confirm: true }) });
      setUsers(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const toggleUserStatus = async (id: string) => {
    const current = users.find(u => u.id === id);
    if (!current) return;
    try {
      const data = await api('/api/users/status', { method: 'POST', body: JSON.stringify({ id, enabled: current.status !== 'enabled' }) });
      setUsers(data);
      showToast('success', language === 'zh' ? '邮箱状态已更新' : 'Mailbox status updated', id);
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '状态更新失败' : 'Status update failed', getErrorMessage(e));
    }
  };

  const addAlias = async (newAlias: Partial<AliasItem>) => {
    try {
      const data = await api('/api/aliases', { method: 'POST', body: JSON.stringify(newAlias) });
      setAliases(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const deleteAlias = async (id: string) => {
    try {
      const data = await api('/api/aliases/' + encodeURIComponent(id), { method: 'DELETE', body: JSON.stringify({ confirm: true }) });
      setAliases(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const restartService = async (id: string) => {
    try {
      const data = await api('/api/services/action', { method: 'POST', body: JSON.stringify({ id, verb: 'restart' }) });
      setServices(data);
      showToast('success', language === 'zh' ? '服务重启完成' : 'Service restarted', id);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const flushQueue = async () => {
    try {
      const data = await api('/api/queue/action', { method: 'POST', body: JSON.stringify({ verb: 'flush' }) });
      setQueues(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const deleteQueueItem = async (id: string) => {
    try {
      const data = await api('/api/queue/action', { method: 'POST', body: JSON.stringify({ id, verb: 'delete' }) });
      setQueues(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const retryQueueItem = async (id: string) => {
    try {
      const data = await api('/api/queue/action', { method: 'POST', body: JSON.stringify({ id, verb: 'retry' }) });
      setQueues(data);
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
  };

  const renewCert = async (id: string) => {
    try {
      const targets = id === 'all'
        ? [...new Set(certs.map((cert) => cert.domain).filter(Boolean))]
        : certs.filter((cert) => cert.id === id || cert.domain === id).map((cert) => cert.domain);
      if (!targets.length) throw new Error(language === 'zh' ? '没有可续期的证书域名' : 'No certificate domain is available for renewal');
      for (const domain of targets) {
        const result = await api<{ status?: string; error?: string }>('/api/certificates/renew', {
          method: 'POST',
          body: JSON.stringify({ domain })
        });
        if (result.status !== 'ok') throw new Error(result.error || `Certificate renewal failed: ${domain}`);
      }
      const updated = await api<TlsCertificate[]>('/api/certificates');
      setCerts(updated);
      showToast('success', language === 'zh' ? '证书续期任务完成' : 'Certificate renewal completed', targets.join(', '));
    } catch (e: unknown) {
      showToast('error', 'Operation failed', getErrorMessage(e));
    }
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
    saveSettings,
    logout,
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
        restartService,
        flushQueue,
        deleteQueueItem,
        retryQueueItem,
        renewCert,
        hasCompletedOnboarding,
        setHasCompletedOnboarding,
        isOnboardingModalOpen,
        setIsOnboardingModalOpen,
        completeOnboarding,
        refreshSnapshot,
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
