export type NavSection =
  | 'dashboard'
  | 'setup_guide'
  | 'ai_suite'
  | 'ai_diagnostic'
  | 'ai_assistant'
  | 'domains'
  | 'users'
  | 'aliases'
  | 'smtp_relay'
  | 'dkim_dns'
  | 'tls_certs'
  | 'mail_queue'
  | 'logs'
  | 'services'
  | 'security'
  | 'settings';

export type Language = 'zh' | 'en';
export type ThemeMode = 'dark' | 'light';

export type BackgroundPreset =
  | 'default'
  | 'aurora_cyan'
  | 'purple_velvet'
  | 'warm_pearl'
  | 'minimal_slate'
  | 'matrix_cyber'
  | 'custom_image';

export interface BackgroundConfig {
  preset: BackgroundPreset;
  customImageUrl?: string;
  overlayOpacity: number; // 0 - 100
  blur: number; // 0 - 20 px
}

export interface DomainItem {
  id: string;
  name: string;
  createdAt: string;
  mxStatus: 'ok' | 'error' | 'pending';
  spfStatus: 'ok' | 'error' | 'pending';
  dkimStatus: 'ok' | 'error' | 'pending';
  dmarcStatus: 'ok' | 'error' | 'pending';
  mailboxesCount: number;
  mailboxesMax: number;
  status: 'active' | 'spf_failed' | 'unconfigured' | 'warning' | 'pending';
  statusTextZh: string;
  statusTextEn: string;
  aliasesCount: number;
  dkimSelector: string;
  dkimKeySize: number;
}

export interface UserItem {
  id: string;
  username: string;
  displayName: string;
  email: string;
  domain: string;
  aliasesCount: number;
  quotaUsedGb: number;
  quotaMaxGb: number;
  lastLoginTime: string;
  lastLoginIp: string;
  status: 'enabled' | 'disabled';
  role: 'admin' | 'user' | 'manager';
  avatarUrl?: string;
  avatarColor?: string;
}

export interface AliasItem {
  id: string;
  source: string;
  domain: string;
  destinations: string[];
  description: string;
  enabled: boolean;
  createdAt: string;
}

export interface SmtpRelayRoute {
  id: string;
  sourceDomain: string;
  relayTarget: string;
  priority: number;
  action: 'FORWARD' | 'DROP' | 'REJECT';
  status: 'active' | 'disabled';
  description?: string;
  tlsMode: 'STARTTLS' | 'SSL/TLS' | 'NONE';
  port: number;
}

export interface RelayProvider {
  id: string;
  name: string;
  host: string;
  provider: string;
  region: string;
  port: number;
  security: string;
  lastSuccess: string;
  status: 'healthy' | 'warning' | 'error';
  isPrimary: boolean;
  type: 'primary' | 'backup' | 'last_resort';
}

export interface LogEntry {
  id: string;
  timestamp: string;
  service: 'postfix/smtpd' | 'dovecot' | 'postfix/cleanup' | 'postfix/qmgr' | 'postfix/smtp' | 'rspamd' | 'clamav';
  level: 'INFO' | 'SUCC' | 'ERR' | 'WARN';
  processId: number;
  details: string;
  clientIp?: string;
  messageId?: string;
}

export interface ServiceItem {
  id: string;
  name: string;
  description: string;
  type: string;
  pid: number;
  uptime: string;
  memoryMb: number;
  cpuPercent: number;
  status: 'ACTIVE' | 'STOPPED' | 'WARNING' | 'RESTARTING';
  ports: number[];
}

export interface QueueItem {
  id: string;
  queueId: string;
  sender: string;
  recipient: string;
  sizeBytes: number;
  arrivalDate: string;
  status: 'deferred' | 'active' | 'hold' | 'incoming';
  errorReason?: string;
  retryCount: number;
}

export interface TlsCertificate {
  id: string;
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  autoRenew: boolean;
  algorithm: string;
  keySize: number;
  status: 'valid' | 'expiring' | 'expired';
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'QUEUE_TIMEOUT' | 'DNS_WARN' | 'AUTH_FAIL' | 'RATE_LIMIT' | 'SPAM_BLOCKED';
  message: string;
  ip?: string;
  severity: 'high' | 'medium' | 'low';
}

export interface SystemSettings {
  transparency: number;
  backdropBlur: number;
  reducedMotion: boolean;
  autoUpdate: boolean;
  version: string;
  hostname: string;
  adminEmail: string;
  timezone: string;
  maxMessageSizeMb: number;
  relayConcurrency: number;
  rateLimitPerHour: number;
  spamThreshold: number;
  colorTheme: 'cyan' | 'blue' | 'emerald' | 'purple';
  customLogo?: string;
  logoStyle?: '3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom';
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message: string;
}
