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
  dkimPublicKey?: string;
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
  password?: string;
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
  relay?: string;
  customLogo?: string;
  logoStyle?: '3d_glass' | 'neon_cyber' | 'isometric_origami' | 'minimal_clean' | 'custom';
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  title: string;
  message: string;
}

export type TelemetryTimeframe = '1m' | '5m' | '30m' | '1h' | '6h' | '24h' | '3d';

export interface DaemonMetric {
  id: string;
  name: string;
  pid: number;
  memoryMb: number;
  cpuPercent: number;
  status: 'ACTIVE' | 'STOPPED';
  uptime?: string;
}

export interface TelemetryPoint {
  timestamp: string;
  cpuPercent: number;
  memoryMb: number; // total daemon memory MB
  systemMemoryPercent: number;
  systemMemoryUsedMb: number;
  systemMemoryTotalMb: number;
  load1: number;
  load5: number;
  load15: number;
  queueTotal: number;
  queueDeferred: number;
  daemons: Record<string, { memoryMb: number; cpuPercent: number; status: string }>;
}

export interface TelemetrySummary {
  avgCpu: number;
  maxCpu: number;
  currentCpu: number;
  avgMemoryMb: number;
  maxMemoryMb: number;
  currentMemoryMb: number;
  avgSystemMemPercent: number;
  maxSystemMemPercent: number;
  currentSystemMemPercent: number;
  currentLoad: [number, number, number];
}

export interface TelemetryResponse {
  timeframe: TelemetryTimeframe;
  intervalMs: number;
  samplingCount: number;
  current: {
    cpuPercent: number;
    totalDaemonMemoryMb: number;
    systemMemoryUsedMb: number;
    systemMemoryTotalMb: number;
    systemMemoryPercent: number;
    loadAvg: [number, number, number];
    uptimeSec: number;
    daemons: DaemonMetric[];
    cores: number;
    hostname: string;
    diskTotalGb?: number;
    diskUsedGb?: number;
    diskUsagePercent?: number;
  };
  summary: TelemetrySummary;
  points: TelemetryPoint[];
}

export interface TwoFactorStatus {
  enabled: boolean;
  recoveryCodesRemaining: number;
}

export interface TwoFactorBeginResult {
  secret: string;
  uri: string;
  enabled: false;
  /** Present (true) when this begin was a re-enrollment over an enabled 2FA:
   * every session has been revoked and the user must sign in again. */
  reauthenticate?: boolean;
}

export interface TwoFactorEnableResult {
  enabled: true;
  recoveryCodes: string[];
}

export interface TwoFactorDisableResult {
  enabled: false;
  reauthenticate: boolean;
}

export interface SessionInfo {
  id: string;
  createdAt: string;
  ip: string;
  userAgent: string;
  current: boolean;
}

export interface SystemRealtimeMetrics {
  timestamp: string;
  cpuPercent: number;
  cores: number;
  coreUsage?: number[];
  systemMemoryUsedMb: number;
  systemMemoryTotalMb: number;
  systemMemoryPercent: number;
  systemMemoryFreeMb: number;
  systemMemoryCachedMb: number;
  loadAvg: [number, number, number];
  uptimeSec: number;
  daemons: DaemonMetric[];
  diskTotalGb: number;
  diskUsedGb: number;
  diskUsagePercent: number;
}

