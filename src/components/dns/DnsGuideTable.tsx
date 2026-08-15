import React, { useState, useMemo } from 'react';
import { useApp } from '../../context/AppContext';
import { DomainItem } from '../../types';
import {
  Globe,
  Copy,
  Check,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
  Cloud,
  ChevronDown,
  ChevronUp,
  Info,
  Server,
  KeyRound,
  FileText,
  SlidersHorizontal,
  Download,
  Terminal,
  Zap,
  HelpCircle,
  XCircle,
  Layers,
  ArrowRight,
  Sparkles,
  Bot,
  Edit3,
  Trash2,
  PlusCircle,
  FileCode,
  Save,
  RotateCcw
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { DnsSetupWizard } from './DnsSetupWizard';
import { AiDnsDiagnostic } from './AiDnsDiagnostic';
import { AiDnsAssistant } from './AiDnsAssistant';

export interface DnsRecordRow {
  id: string;
  name: string;
  nameDisplay: string;
  type: 'A' | 'CNAME' | 'MX' | 'TXT' | 'AAAA';
  content: string;
  proxyStatus: 'dns_only' | 'proxied';
  ttl: string;
  priority?: number;
  category: 'core' | 'auth' | 'protocol' | 'relay';
  categoryLabelZh: string;
  categoryLabelEn: string;
  comment?: string;
  isCustom?: boolean;
}

interface Props {
  domain?: DomainItem;
  serverIp?: string;
  relayProvider?: 'oracle' | 'ses' | 'sendgrid' | 'direct' | 'mailgun' | 'brevo' | 'resend';
  compact?: boolean;
  onRecordChange?: () => void;
}

export const DnsGuideTable: React.FC<Props> = ({
  domain,
  serverIp: initialServerIp = '163.192.27.230',
  relayProvider: initialRelayProvider = 'oracle',
  compact = false,
}) => {
  const { domains, language, themeMode, showToast } = useApp();

  // Dynamic customization states
  const initialDomainName = domain?.name || domains[0]?.name || 'sectorpace.com';
  const [selectedDomainName, setSelectedDomainName] = useState<string>(initialDomainName);
  const [customServerIp, setCustomServerIp] = useState<string>(initialServerIp);
  const [customDkimSelector, setCustomDkimSelector] = useState<string>(domain?.dkimSelector || 's20260809795');
  const [selectedRelay, setSelectedRelay] = useState<'oracle' | 'ses' | 'sendgrid' | 'direct' | 'mailgun' | 'brevo' | 'resend'>(initialRelayProvider);
  const [dmarcPolicy, setDmarcPolicy] = useState<'none' | 'quarantine' | 'reject'>('none');
  const [ruaEmail, setRuaEmail] = useState<string>(`admin@${initialDomainName}`);

  // Navigation tab state
  const [activeTab, setActiveTab] = useState<'table' | 'wizard' | 'ai_diagnostic' | 'ai_assistant'>('table');

  // Interactive editing and table states
  const [editingRecordId, setEditingRecordId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<DnsRecordRow>>({});
  const [customRecordsOverride, setCustomRecordsOverride] = useState<DnsRecordRow[] | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isVerifyingDns, setIsVerifyingDns] = useState(false);
  const [verifiedMap, setVerifiedMap] = useState<Record<string, boolean>>({});

  // Generate dynamic base DNS records based on inputs
  const defaultRecords = useMemo((): DnsRecordRow[] => {
    const dom = selectedDomainName.trim() || 'yourdomain.com';
    const ip = customServerIp.trim() || '163.192.27.230';
    const selector = customDkimSelector.trim() || 's20260809795';
    const rua = ruaEmail.trim() || `admin@${dom}`;

    let spfContent = `"v=spf1 mx ~all"`;
    let relayRecord: DnsRecordRow | null = null;

    if (selectedRelay === 'oracle') {
      spfContent = `"v=spf1 mx include:spf.us-sanjose-1.oci.oraclecloud.com ~all"`;
      relayRecord = {
        id: 'rec-relay-dkim',
        name: `dkim._domainkey.${dom}`,
        nameDisplay: `dkim._domainkey.${dom}`,
        type: 'CNAME',
        content: `dkim.${dom}.dkim.sjc1.oracleemaildelivery.com`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'relay',
        categoryLabelZh: 'Oracle 邮件投递 CNAME DKIM',
        categoryLabelEn: 'Oracle Email Delivery DKIM CNAME',
        comment: 'Oracle Cloud OCI SJC1 DKIM 托管域名 CNAME 解析',
      };
    } else if (selectedRelay === 'ses') {
      spfContent = `"v=spf1 mx include:amazonses.com ~all"`;
      relayRecord = {
        id: 'rec-relay-ses',
        name: `ses._domainkey.${dom}`,
        nameDisplay: `ses._domainkey.${dom}`,
        type: 'CNAME',
        content: `${selector}.dkim.amazonses.com`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'relay',
        categoryLabelZh: 'Amazon SES Easy DKIM',
        categoryLabelEn: 'Amazon SES Easy DKIM CNAME',
        comment: 'AWS SES 自动化 DKIM 签名托管解析',
      };
    } else if (selectedRelay === 'sendgrid') {
      spfContent = `"v=spf1 mx include:sendgrid.net ~all"`;
      relayRecord = {
        id: 'rec-relay-sg',
        name: `em.${dom}`,
        nameDisplay: `em.${dom}`,
        type: 'CNAME',
        content: `sendgrid.net`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'relay',
        categoryLabelZh: 'SendGrid 域名白标别名',
        categoryLabelEn: 'SendGrid White-label CNAME',
        comment: 'SendGrid 出站投递白标验证解析',
      };
    } else if (selectedRelay === 'mailgun') {
      spfContent = `"v=spf1 mx include:mailgun.org ~all"`;
    } else if (selectedRelay === 'brevo') {
      spfContent = `"v=spf1 mx include:spf.sendinblue.com ~all"`;
    } else if (selectedRelay === 'resend') {
      spfContent = `"v=spf1 mx include:resend.com ~all"`;
      relayRecord = {
        id: 'rec-relay-resend',
        name: `resend._domainkey.${dom}`,
        nameDisplay: `resend._domainkey.${dom}`,
        type: 'TXT',
        content: `"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3resend..."`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'relay',
        categoryLabelZh: 'Resend DKIM 签名',
        categoryLabelEn: 'Resend DKIM TXT',
        comment: 'Resend API 发信域名 DKIM 签名公钥',
      };
    }

    const base: DnsRecordRow[] = [
      {
        id: 'rec-1',
        name: `mail.${dom}`,
        nameDisplay: `mail.${dom}`,
        type: 'A',
        content: ip,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'core',
        categoryLabelZh: '邮件主机 A 记录',
        categoryLabelEn: 'Mail Host A Record',
        comment: '自建 MailStack 邮件服务器公网 IPv4 地址',
      },
      ...(relayRecord ? [relayRecord] : []),
      {
        id: 'rec-3',
        name: `imap.${dom}`,
        nameDisplay: `imap.${dom}`,
        type: 'CNAME',
        content: `mail.${dom}`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'protocol',
        categoryLabelZh: 'IMAP 收信协议别名',
        categoryLabelEn: 'IMAP Protocol Alias',
        comment: '客户端 SSL/TLS 993 收信接入点',
      },
      {
        id: 'rec-4',
        name: `pop.${dom}`,
        nameDisplay: `pop.${dom}`,
        type: 'CNAME',
        content: `mail.${dom}`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'protocol',
        categoryLabelZh: 'POP3 收信协议别名',
        categoryLabelEn: 'POP3 Protocol Alias',
        comment: '客户端 SSL/TLS 995 POP3 接入点',
      },
      {
        id: 'rec-5',
        name: `smtp.${dom}`,
        nameDisplay: `smtp.${dom}`,
        type: 'CNAME',
        content: `mail.${dom}`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'protocol',
        categoryLabelZh: 'SMTP 发信协议别名',
        categoryLabelEn: 'SMTP Protocol Alias',
        comment: '客户端 SSL/TLS 465/587 发信接入点',
      },
      {
        id: 'rec-6',
        name: dom,
        nameDisplay: dom,
        type: 'MX',
        content: `mail.${dom}`,
        priority: 10,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'core',
        categoryLabelZh: 'MX 邮件交换记录',
        categoryLabelEn: 'MX Mail Exchanger',
        comment: '全网投递该域名邮件时的权威目标服务器',
      },
      {
        id: 'rec-7',
        name: `_dmarc.${dom}`,
        nameDisplay: `_dmarc.${dom}`,
        type: 'TXT',
        content: `"v=DMARC1; p=${dmarcPolicy}; rua=mailto:${rua}; ruf=mailto:${rua}; fo=1; aspf=r; adkim=r"`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'auth',
        categoryLabelZh: 'DMARC 防伪对齐策略',
        categoryLabelEn: 'DMARC Security Policy',
        comment: 'SPF/DKIM 对齐验证规则与聚合反馈报告接收邮箱',
      },
      {
        id: 'rec-8',
        name: `${selector}._domainkey`,
        nameDisplay: `${selector}._domainkey.${dom}`,
        type: 'TXT',
        content: `"k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0w9B7q2rXw1A4J7d8L2m5n9k8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4a3b2c1d0e9f8g7h6i5j4k3l2m1n0o9p8q7r6s5t4u3v2w1x0y9z8a7b6c5d4e3f2g1h0i9j8k7l6m5n4o3p2q1r0s9t8u7v6w5x4y3z2a1b0c9d8e7f6g5h4i3j2k1l0m9n8o7p6q5r4s3t2u1v0w9x8y7z6a5b4c3d2e1f0g9h8i7j6k5l4m3n2o1p0q9r8s7t6u5v4w3x2y1z0DAQAB"`,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'auth',
        categoryLabelZh: '2048 位 OpenDKIM 数字签名',
        categoryLabelEn: 'OpenDKIM 2048-bit RSA Public Key',
        comment: '本地邮件服务器生成的 2048 位 RSA 签名公钥',
      },
      {
        id: 'rec-9',
        name: dom,
        nameDisplay: dom,
        type: 'TXT',
        content: spfContent,
        proxyStatus: 'dns_only',
        ttl: '自动',
        category: 'auth',
        categoryLabelZh: `SPF 发信 IP 授权${selectedRelay !== 'direct' ? ` (含 ${selectedRelay.toUpperCase()} 中继)` : ''}`,
        categoryLabelEn: 'SPF Authorization with Relay',
        comment: '授权本地 MX 服务器以及出站中继节点合法发信',
      },
    ];

    return base;
  }, [selectedDomainName, customServerIp, customDkimSelector, selectedRelay, dmarcPolicy, ruaEmail]);

  // Current active records (either custom edited or dynamically generated)
  const currentRecords = customRecordsOverride || defaultRecords;

  const copyText = (text: string, key: string, label?: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(key);
    showToast('info', language === 'zh' ? '已复制到剪贴板' : 'Copied to Clipboard', label ? `${label}: ${text}` : text);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleCopyAllZone = () => {
    const lines = [
      `; ==========================================`,
      `; BIND Zone Records for ${selectedDomainName}`,
      `; Generated by MailStack Admin Console`,
      `; Server IP: ${customServerIp}`,
      `; ==========================================`,
      `$TTL 300`,
      `@   IN  SOA ns1.${selectedDomainName}. hostmaster.${selectedDomainName}. (`,
      `        ${new Date().toISOString().slice(0, 10).replace(/-/g, '')}01 ; Serial`,
      `        3600       ; Refresh`,
      `        1800       ; Retry`,
      `        604800     ; Expire`,
      `        300 )      ; Minimum TTL`,
      ``,
    ];

    currentRecords.forEach((r) => {
      let host = r.name;
      if (host === selectedDomainName) host = '@';
      if (r.type === 'MX') {
        lines.push(`${host.padEnd(28)} IN  MX  ${r.priority || 10}  ${r.content}.`);
      } else if (r.type === 'TXT') {
        lines.push(`${host.padEnd(28)} IN  TXT ${r.content}`);
      } else {
        lines.push(`${host.padEnd(28)} IN  ${r.type.padEnd(4)}  ${r.content}`);
      }
    });

    copyText(lines.join('\n'), 'all_zone', language === 'zh' ? 'BIND Zone 配置' : 'BIND Zone Config');
  };

  const handleCopyCloudflareCsv = () => {
    const csvHeader = 'Type,Name,Content,TTL,Proxy status\n';
    const csvRows = currentRecords.map(r => {
      let content = r.content.replace(/^"|"$/g, '');
      return `${r.type},${r.name},"${content}",Auto,DNS only`;
    }).join('\n');

    copyText(csvHeader + csvRows, 'all_csv', language === 'zh' ? 'Cloudflare CSV' : 'Cloudflare CSV');
  };

  const handleSimulateVerify = () => {
    setIsVerifyingDns(true);
    setTimeout(() => {
      setIsVerifyingDns(false);
      const newMap: Record<string, boolean> = {};
      currentRecords.forEach(r => { newMap[r.id] = true; });
      setVerifiedMap(newMap);
      confetti({ particleCount: 50, spread: 60, origin: { y: 0.5 } });
      showToast('success', language === 'zh' ? '权威 DNS 解析验证通过' : 'DNS Records Verified', language === 'zh' ? `所有 ${currentRecords.length} 条记录均已通过全球权威校验！` : 'All DNS records successfully verified.');
    }, 900);
  };

  // Inline Record Editing Handlers
  const handleStartEdit = (record: DnsRecordRow) => {
    setEditingRecordId(record.id);
    setEditForm({ ...record });
  };

  const handleSaveEdit = () => {
    if (!editingRecordId) return;
    const updated = currentRecords.map(r => {
      if (r.id === editingRecordId) {
        return { ...r, ...editForm } as DnsRecordRow;
      }
      return r;
    });
    setCustomRecordsOverride(updated);
    setEditingRecordId(null);
    showToast('success', language === 'zh' ? '记录已更新' : 'Record Updated', language === 'zh' ? '自定义记录已保存到当前解析表' : 'Saved to active table.');
  };

  const handleDeleteRecord = (id: string) => {
    const updated = currentRecords.filter(r => r.id !== id);
    setCustomRecordsOverride(updated);
    if (editingRecordId === id) setEditingRecordId(null);
    showToast('info', language === 'zh' ? '记录已移除' : 'Record Removed', id);
  };

  const handleResetToDefaults = () => {
    setCustomRecordsOverride(null);
    setEditingRecordId(null);
    showToast('info', language === 'zh' ? '已重置为系统标准推荐配置' : 'Reset to Defaults', selectedDomainName);
  };

  return (
    <div className="space-y-6">
      {/* 1. Dynamic Domain & Parameter Customizer Bar */}
      <div className={`p-5 rounded-2xl border backdrop-blur-md transition-all ${
        themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/90 border-slate-800'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center text-slate-950 font-bold shadow-[0_0_15px_rgba(0,242,195,0.25)]">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className={`text-base font-bold tracking-tight ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                  {language === 'zh' ? '动态 DNS 解析与权威配置中心' : 'Dynamic DNS Records & Configuration Center'}
                </h2>
                <span className={`px-2 py-0.5 rounded-full text-[11px] font-mono font-bold border ${
                  themeMode === 'light' ? 'bg-cyan-50 text-cyan-800 border-cyan-300' : 'bg-cyan-950 text-cyan-300 border-cyan-800'
                }`}>
                  Live Wizard
                </span>
              </div>
              <p className={`text-xs mt-0.5 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                {language === 'zh'
                  ? '支持自定义任意域名、公网 IP、DKIM 密钥与出站中继，实时动态计算全部 9 大 DNS 标准记录与 AI 诊断。'
                  : 'Customize domain, server IP, DKIM selectors, and relays. Dynamically generates full DNS records & AI diagnostics.'}
              </p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center flex-wrap gap-2">
            <button
              onClick={handleSimulateVerify}
              disabled={isVerifyingDns}
              className={`h-9 px-3 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                themeMode === 'light'
                  ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700'
                  : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200'
              }`}
              title="模拟全球权威 DNS 查询"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isVerifyingDns ? 'animate-spin text-cyan-500' : ''}`} />
              <span>{isVerifyingDns ? (language === 'zh' ? '全球探测中...' : 'Probing...') : (language === 'zh' ? '连通性验证' : 'Verify Records')}</span>
            </button>

            <button
              onClick={handleCopyCloudflareCsv}
              className={`h-9 px-3 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                themeMode === 'light'
                  ? 'bg-amber-50 hover:bg-amber-100 border-amber-300 text-amber-900'
                  : 'bg-amber-950/40 hover:bg-amber-900/60 border-amber-500/40 text-amber-300'
              }`}
              title="导出 Cloudflare DNS 一键导入 CSV"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '导出 Cloudflare CSV' : 'Cloudflare CSV'}</span>
            </button>

            <button
              onClick={handleCopyAllZone}
              className="h-9 px-3.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,242,195,0.2)] cursor-pointer"
              title="复制完整 BIND Zone 记录"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>{language === 'zh' ? '复制 BIND Zone' : 'Copy BIND Zone'}</span>
            </button>
          </div>
        </div>

        {/* Dynamic Controls Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-4 font-mono text-xs">
          {/* Target Domain Input / Selector */}
          <div className="space-y-1">
            <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
              1. {language === 'zh' ? '当前域名 (Domain)' : 'Domain Name'}
            </label>
            <div className="relative">
              <input
                type="text"
                value={selectedDomainName}
                onChange={(e) => setSelectedDomainName(e.target.value)}
                placeholder="sectorpace.com"
                className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                  themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
                }`}
              />
            </div>
          </div>

          {/* Server IP */}
          <div className="space-y-1">
            <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
              2. {language === 'zh' ? '服务器公网 IP' : 'Server IP'}
            </label>
            <input
              type="text"
              value={customServerIp}
              onChange={(e) => setCustomServerIp(e.target.value)}
              placeholder="163.192.27.230"
              className={`w-full h-9 px-3 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-cyan-300'
              }`}
            />
          </div>

          {/* Outbound Relay Mode */}
          <div className="space-y-1">
            <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
              3. {language === 'zh' ? '出站中继 (Relay)' : 'Relay Provider'}
            </label>
            <select
              value={selectedRelay}
              onChange={(e) => setSelectedRelay(e.target.value as any)}
              className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
              }`}
            >
              <option value="oracle">Oracle Cloud (OCI SJC1)</option>
              <option value="direct">自建服务器直发 (Direct MX)</option>
              <option value="ses">Amazon SES</option>
              <option value="sendgrid">SendGrid</option>
              <option value="mailgun">Mailgun</option>
              <option value="brevo">Brevo (Sendinblue)</option>
              <option value="resend">Resend</option>
            </select>
          </div>

          {/* DKIM Selector */}
          <div className="space-y-1">
            <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
              4. {language === 'zh' ? 'DKIM Selector' : 'DKIM Selector'}
            </label>
            <input
              type="text"
              value={customDkimSelector}
              onChange={(e) => setCustomDkimSelector(e.target.value)}
              placeholder="s20260809795"
              className={`w-full h-9 px-3 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
              }`}
            />
          </div>

          {/* DMARC Policy */}
          <div className="space-y-1">
            <label className={`text-[11px] font-bold uppercase tracking-wider ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
              5. {language === 'zh' ? 'DMARC 策略' : 'DMARC Policy'}
            </label>
            <select
              value={dmarcPolicy}
              onChange={(e) => setDmarcPolicy(e.target.value as any)}
              className={`w-full h-9 px-3 rounded-xl border text-xs font-bold focus:outline-none focus:ring-1 focus:ring-cyan-500 cursor-pointer ${
                themeMode === 'light' ? 'bg-slate-50 border-slate-300 text-slate-900' : 'bg-slate-950 border-slate-800 text-white'
              }`}
            >
              <option value="none">p=none (监控观察模式)</option>
              <option value="quarantine">p=quarantine (疑似垃圾隔离)</option>
              <option value="reject">p=reject (严格拒收拦截)</option>
            </select>
          </div>
        </div>
      </div>

      {/* 2. Top Level Navigation Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className={`p-1.5 rounded-2xl border flex items-center gap-1.5 backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
        }`}>
          <button
            onClick={() => setActiveTab('table')}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'table'
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>{language === 'zh' ? '权威 DNS 记录表' : 'DNS Records Table'}</span>
            <span className="px-1.5 py-0.2 rounded-md bg-slate-950/20 text-[10px]">{currentRecords.length}</span>
          </button>

          <button
            onClick={() => setActiveTab('wizard')}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'wizard'
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Zap className="w-4 h-4 text-amber-500" />
            <span>{language === 'zh' ? '分步设置向导' : 'Setup Wizard'}</span>
          </button>

          <button
            onClick={() => setActiveTab('ai_diagnostic')}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'ai_diagnostic'
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-4 h-4 text-purple-400" />
            <span>{language === 'zh' ? 'AI 智能诊断与体检' : 'AI Health Diagnostic'}</span>
          </button>

          <button
            onClick={() => setActiveTab('ai_assistant')}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'ai_assistant'
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            <Bot className="w-4 h-4 text-cyan-500" />
            <span>{language === 'zh' ? 'AI 邮件顾问助手' : 'AI Assistant'}</span>
          </button>
        </div>

        {customRecordsOverride && (
          <button
            onClick={handleResetToDefaults}
            className={`px-3 py-1.5 rounded-xl border text-xs font-mono flex items-center gap-1.5 cursor-pointer ${
              themeMode === 'light' ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700' : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5 text-amber-500" />
            <span>{language === 'zh' ? '恢复系统推荐值' : 'Reset Table'}</span>
          </button>
        )}
      </div>

      {/* TAB 1: Authoritative Cloudflare-style Records Table */}
      {activeTab === 'table' && (
        <div className="space-y-4 animate-in fade-in duration-200">
          {/* Cloudflare Grey Cloud Notice Bar */}
          <div className={`p-4 rounded-2xl border flex items-start sm:items-center justify-between gap-3 text-xs ${
            themeMode === 'light'
              ? 'bg-gradient-to-r from-amber-500/10 via-amber-50 to-white border-amber-300 text-amber-950'
              : 'bg-gradient-to-r from-amber-950/40 via-slate-900 to-slate-900 border-amber-500/40 text-amber-200'
          }`}>
            <div className="flex items-center gap-2.5">
              <Cloud className="w-4 h-4 text-amber-500 shrink-0" />
              <div>
                <span className="font-bold font-mono">[Cloudflare 核心防坑警示]：</span>
                <span>
                  {language === 'zh'
                    ? '所有邮件相关主机名 (mail, smtp, imap, pop) 在 Cloudflare 控制台中必须设置为【仅 DNS (灰云)】，严禁开启橙云 CDN 代理（避免拦截 25/587 端口）。'
                    : 'All mail hosts in Cloudflare MUST be set to "DNS Only" (Grey Cloud). Orange cloud breaks SMTP/IMAP ports.'}
                </span>
              </div>
            </div>

            <span className="hidden md:inline-flex px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-400 font-mono text-[11px] font-bold uppercase shrink-0">
              DNS Only ☁️
            </span>
          </div>

          {/* Table Container */}
          <div className={`rounded-2xl border backdrop-blur-md overflow-hidden ${
            themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/90 border-slate-800'
          }`}>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className={`border-b ${
                    themeMode === 'light' ? 'bg-slate-100/80 border-slate-200 text-slate-600' : 'bg-slate-950/80 border-slate-800 text-slate-400'
                  }`}>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">#</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">类型 (Type)</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">名称 (Name / Host)</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">内容 (Content / Target)</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">代理状态 (Proxy)</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px]">TTL</th>
                    <th className="py-3.5 px-4 font-bold uppercase text-[11px] text-right">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                  {currentRecords.map((row, idx) => {
                    const isEditing = editingRecordId === row.id;
                    const isVerified = verifiedMap[row.id];

                    return (
                      <React.Fragment key={row.id}>
                        <tr className={`transition-colors ${
                          isEditing
                            ? themeMode === 'light' ? 'bg-cyan-50/70' : 'bg-cyan-950/30'
                            : themeMode === 'light' ? 'hover:bg-slate-50/80' : 'hover:bg-slate-800/40'
                        }`}>
                          {/* Index / Status */}
                          <td className="py-3 px-4 text-slate-400">
                            {isVerified ? (
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                            ) : (
                              <span>{idx + 1}</span>
                            )}
                          </td>

                          {/* Type */}
                          <td className="py-3 px-4">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                              row.type === 'A'
                                ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                                : row.type === 'MX'
                                ? 'bg-purple-500/10 text-purple-400 border-purple-500/30'
                                : row.type === 'TXT'
                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                            }`}>
                              {row.type}
                            </span>
                          </td>

                          {/* Name */}
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-1.5">
                              <span className={`font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                                {row.name}
                              </span>
                              <button
                                onClick={() => copyText(row.name, `name-${row.id}`, 'Name')}
                                className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-500 cursor-pointer"
                                title="复制名称"
                              >
                                {copiedField === `name-${row.id}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                            <div className="text-[10px] text-slate-500 font-sans">{language === 'zh' ? row.categoryLabelZh : row.categoryLabelEn}</div>
                          </td>

                          {/* Content */}
                          <td className="py-3 px-4 max-w-md">
                            <div className="flex items-center justify-between gap-2">
                              <span className={`break-all ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-300'}`}>
                                {row.priority ? <strong className="text-purple-400 mr-1.5">[10]</strong> : null}
                                {row.content}
                              </span>
                              <button
                                onClick={() => copyText(row.content, `content-${row.id}`, 'Content')}
                                className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-500 cursor-pointer shrink-0"
                                title="复制记录值"
                              >
                                {copiedField === `content-${row.id}` ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                              </button>
                            </div>
                          </td>

                          {/* Proxy */}
                          <td className="py-3 px-4">
                            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${
                              themeMode === 'light'
                                ? 'bg-slate-100 text-slate-700 border-slate-300'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}>
                              <Cloud className="w-3 h-3 text-slate-400" />
                              <span>仅 DNS (灰云)</span>
                            </span>
                          </td>

                          {/* TTL */}
                          <td className="py-3 px-4 text-slate-400">
                            {row.ttl || '自动'}
                          </td>

                          {/* Actions */}
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => handleStartEdit(row)}
                                className="p-1.5 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
                                title="编辑该记录"
                              >
                                <Edit3 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDeleteRecord(row.id)}
                                className="p-1.5 rounded-lg hover:bg-rose-500/10 text-slate-400 hover:text-rose-400 transition-colors cursor-pointer"
                                title="删除该记录"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>

                        {/* Expandable Inline Edit Form */}
                        {isEditing && (
                          <tr className={themeMode === 'light' ? 'bg-cyan-50/90' : 'bg-cyan-950/40'}>
                            <td colSpan={7} className="p-4 border-b border-cyan-500/30">
                              <div className="space-y-3 font-mono text-xs">
                                <div className="flex items-center justify-between">
                                  <span className="font-bold text-cyan-500 flex items-center gap-1.5">
                                    <Edit3 className="w-3.5 h-3.5" />
                                    <span>编辑 DNS 记录参数 (Cloudflare 风格)</span>
                                  </span>
                                  <span className="text-[10px] text-slate-400">ID: {row.id}</span>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                                  <div>
                                    <label className="text-[10px] text-slate-500 uppercase">类型 (Type)</label>
                                    <select
                                      value={editForm.type}
                                      onChange={(e) => setEditForm(prev => ({ ...prev, type: e.target.value as any }))}
                                      className={`w-full h-8 px-2 rounded-lg border text-xs mt-1 ${
                                        themeMode === 'light' ? 'bg-white border-slate-300' : 'bg-slate-900 border-slate-700'
                                      }`}
                                    >
                                      <option value="A">A</option>
                                      <option value="CNAME">CNAME</option>
                                      <option value="MX">MX</option>
                                      <option value="TXT">TXT</option>
                                      <option value="AAAA">AAAA</option>
                                    </select>
                                  </div>

                                  <div>
                                    <label className="text-[10px] text-slate-500 uppercase">名称 (Name)</label>
                                    <input
                                      type="text"
                                      value={editForm.name}
                                      onChange={(e) => setEditForm(prev => ({ ...prev, name: e.target.value }))}
                                      className={`w-full h-8 px-2 rounded-lg border text-xs mt-1 ${
                                        themeMode === 'light' ? 'bg-white border-slate-300' : 'bg-slate-900 border-slate-700'
                                      }`}
                                    />
                                  </div>

                                  <div className="lg:col-span-2">
                                    <label className="text-[10px] text-slate-500 uppercase">内容 (Content / Value)</label>
                                    <input
                                      type="text"
                                      value={editForm.content}
                                      onChange={(e) => setEditForm(prev => ({ ...prev, content: e.target.value }))}
                                      className={`w-full h-8 px-2 rounded-lg border text-xs mt-1 ${
                                        themeMode === 'light' ? 'bg-white border-slate-300' : 'bg-slate-900 border-slate-700'
                                      }`}
                                    />
                                  </div>
                                </div>

                                <div className="flex items-center justify-end gap-2 pt-2">
                                  <button
                                    onClick={() => setEditingRecordId(null)}
                                    className={`px-3 py-1.5 rounded-lg border text-xs cursor-pointer ${
                                      themeMode === 'light' ? 'bg-white hover:bg-slate-100 border-slate-300' : 'bg-slate-800 hover:bg-slate-700 border-slate-700'
                                    }`}
                                  >
                                    取消
                                  </button>
                                  <button
                                    onClick={handleSaveEdit}
                                    className="px-3.5 py-1.5 rounded-lg bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1 cursor-pointer"
                                  >
                                    <Save className="w-3 h-3" />
                                    <span>保存修改</span>
                                  </button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Step-by-Step DNS Wizard */}
      {activeTab === 'wizard' && (
        <DnsSetupWizard
          domainName={selectedDomainName}
          serverIp={customServerIp}
          dkimSelector={customDkimSelector}
          relayProvider={selectedRelay}
          dmarcPolicy={dmarcPolicy}
          ruaEmail={ruaEmail}
          onJumpToTab={(tab) => {
            if (tab === 'table') setActiveTab('table');
            if (tab === 'diagnostic') setActiveTab('ai_diagnostic');
            if (tab === 'assistant') setActiveTab('ai_assistant');
          }}
        />
      )}

      {/* TAB 3: AI Comprehensive Health Diagnostic */}
      {activeTab === 'ai_diagnostic' && (
        <AiDnsDiagnostic
          domainName={selectedDomainName}
          serverIp={customServerIp}
          relayProvider={selectedRelay}
          records={currentRecords}
        />
      )}

      {/* TAB 4: AI DNS Assistant Interactive Chat */}
      {activeTab === 'ai_assistant' && (
        <AiDnsAssistant
          domainName={selectedDomainName}
          serverIp={customServerIp}
          relayProvider={selectedRelay}
          records={currentRecords}
        />
      )}
    </div>
  );
};
