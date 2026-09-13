import React, { useState, useMemo } from 'react';
import { useApp } from '../../context/AppContext';
import { DomainItem } from '../../types';
import {
  Layers,
  Zap,
  Sparkles,
  Bot,
  Cloud,
  Edit3,
  Save,
  CheckCircle2,
  Copy,
  Check,
  Trash2,
  Plus,
  AlertCircle,
  HelpCircle,
} from '@/lib/icons';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import { DnsSetupWizard } from './DnsSetupWizard';
import { AiDnsDiagnostic } from './AiDnsDiagnostic';
import { AiDnsAssistant } from './AiDnsAssistant';
import { DnsToolbar } from './DnsToolbar';
import { DnsRecordRowComponent } from './DnsRecordRowComponent';

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
  serverIp: initialServerIp = '',
  relayProvider: initialRelayProvider = 'oracle',
}) => {
  const { domains, language, themeMode, showToast } = useApp();

  const initialDomainName = domain?.name || domains[0]?.name || '';
  const [selectedDomainName, setSelectedDomainName] = useState<string>(initialDomainName);
  const [customServerIp, setCustomServerIp] = useState<string>(initialServerIp);
  const [customDkimSelector, setCustomDkimSelector] = useState<string>(domain?.dkimSelector || 'mail');
  const [selectedRelay, setSelectedRelay] = useState<string>(initialRelayProvider);
  const [dmarcPolicy, setDmarcPolicy] = useState<'none' | 'quarantine' | 'reject'>('none');
  const ruaEmail = selectedDomainName ? `postmaster@${selectedDomainName}` : '';

  const [activeTab, setActiveTab] = useState<'table' | 'wizard'>('table');
  const [editingRecordId, setEditingRecordId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<DnsRecordRow>>({});
  const [customRecordsOverride, setCustomRecordsOverride] = useState<DnsRecordRow[] | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [isVerifyingDns, setIsVerifyingDns] = useState(false);
  const [verifiedMap, setVerifiedMap] = useState<Record<string, boolean>>({});

  const defaultRecords = useMemo((): DnsRecordRow[] => {
    const dom = selectedDomainName.trim();
    if (!dom) return [];
    const ip = customServerIp.trim();
    const selector = customDkimSelector.trim() || 'mail';
    const rua = ruaEmail.trim() || `admin@${dom}`;
    const selectedDomain = domains.find((item) => item.name === dom);
    const dkimPublicKey = selectedDomain?.dkimPublicKey?.trim();

    let spfContent = `"v=spf1 mx ~all"`;

    if (selectedRelay === 'ses') {
      spfContent = `"v=spf1 mx include:amazonses.com ~all"`;
    } else if (selectedRelay === 'sendgrid') {
      spfContent = `"v=spf1 mx include:sendgrid.net ~all"`;
    } else if (selectedRelay === 'mailgun') {
      spfContent = `"v=spf1 mx include:mailgun.org ~all"`;
    } else if (selectedRelay === 'brevo') {
      spfContent = `"v=spf1 mx include:spf.sendinblue.com ~all"`;
    } else if (selectedRelay === 'resend') {
      // Resend DKIM values are account-specific; never invent a publishable key.
      spfContent = `"v=spf1 mx include:resend.com ~all"`;
    }

    const base: DnsRecordRow[] = [
      ...(ip ? [{
        id: 'rec-1',
        name: `mail.${dom}`,
        nameDisplay: `mail.${dom}`,
        type: 'A' as const,
        content: ip,
        proxyStatus: 'dns_only' as const,
        ttl: '自动',
        category: 'core' as const,
        categoryLabelZh: '邮件主机 A 记录',
        categoryLabelEn: 'Mail Host A Record',
        comment: '自建 MailStack 邮件服务器公网 IPv4 地址',
      }] : []),
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
      ...(dkimPublicKey ? [{
        id: 'rec-8',
        name: `${selector}._domainkey`,
        nameDisplay: `${selector}._domainkey.${dom}`,
        type: 'TXT' as const,
        content: `"v=DKIM1; k=rsa; p=${dkimPublicKey.replace(/^v=DKIM1;\s*k=rsa;\s*p=/i, '').replace(/\s+/g, '')}"`,
        proxyStatus: 'dns_only' as const,
        ttl: '自动',
        category: 'auth' as const,
        categoryLabelZh: 'OpenDKIM 数字签名',
        categoryLabelEn: 'OpenDKIM Public Key',
        comment: '从服务器读取的 DKIM 公钥',
      }] : []),
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
  }, [selectedDomainName, customServerIp, customDkimSelector, selectedRelay, dmarcPolicy, ruaEmail, domains]);

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
      const content = r.content.replace(/^"|"$/g, '');
      return `${r.type},${r.name},"${content}",Auto,DNS only`;
    }).join('\n');

    copyText(csvHeader + csvRows, 'all_csv', language === 'zh' ? 'Cloudflare CSV' : 'Cloudflare CSV');
  };

  const handleDnsVerify = async () => {
    if (!selectedDomainName || !customServerIp) {
      showToast(
        'warning',
        language === 'zh' ? 'DNS 验证条件不完整' : 'DNS verification is not ready',
        language === 'zh' ? '请选择真实域名并填写服务器公网 IP。' : 'Select a real domain and provide the public server IP.',
      );
      return;
    }
    setIsVerifyingDns(true);
    try {
      const expectedSpf = currentRecords.find(r => r.type === 'TXT' && r.content.includes('v=spf1'))?.content.replace(/^"|"$/g, '') || '';
      const result: any = await api('/api/setup/dns/verify', {
        method: 'POST',
        body: JSON.stringify({
          domain: selectedDomainName,
          mailHost: `mail.${selectedDomainName}`,
          serverIp: customServerIp,
          dkimSelector: customDkimSelector,
          expectedSpf,
          selectedRelay,
        }),
      });
      const map: Record<string, boolean> = {};
      currentRecords.forEach(r => {
        map[r.id] = r.type === 'A'
          ? !!result.checks?.a
          : r.type === 'MX'
          ? !!result.checks?.mx
          : r.content.includes('v=spf1')
          ? !!result.checks?.spfSingle && !!result.checks?.spfExpected
          : r.name.includes('._domainkey.')
          ? !!result.checks?.dkim
          : r.name.startsWith('_dmarc.')
          ? !!result.checks?.dmarc
          : false;
      });
      setVerifiedMap(map);
      showToast(
        result.verified ? 'success' : 'warning',
        result.verified ? (language === 'zh' ? '权威 DNS 验证通过' : 'DNS verified') : (language === 'zh' ? 'DNS 验证未完成' : 'DNS incomplete'),
        JSON.stringify(result.checks)
      );
    } catch (e: unknown) {
      setVerifiedMap({});
      showToast('error', language === 'zh' ? 'DNS 查询失败' : 'DNS query failed', getErrorMessage(e));
    } finally {
      setIsVerifyingDns(false);
    }
  };

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
      <DnsToolbar
        themeMode={themeMode}
        language={language}
        selectedDomainName={selectedDomainName}
        setSelectedDomainName={setSelectedDomainName}
        customServerIp={customServerIp}
        setCustomServerIp={setCustomServerIp}
        selectedRelay={selectedRelay}
        setSelectedRelay={setSelectedRelay}
        customDkimSelector={customDkimSelector}
        setCustomDkimSelector={setCustomDkimSelector}
        dmarcPolicy={dmarcPolicy}
        setDmarcPolicy={setDmarcPolicy}
        isVerifyingDns={isVerifyingDns}
        onVerify={handleDnsVerify}
        onCopyCsv={handleCopyCloudflareCsv}
        onCopyZone={handleCopyAllZone}
        onReset={handleResetToDefaults}
      />

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
            <span>{language === 'zh' ? '分步解析指引' : 'Setup Steps'}</span>
          </button>
        </div>
      </div>

      {activeTab === 'table' && (
        <div className="space-y-4">
          <div className={`p-4 rounded-2xl border backdrop-blur-md flex flex-wrap items-center justify-between gap-4 ${
            themeMode === 'light' ? 'bg-white/70 border-slate-200 shadow-sm' : 'bg-slate-900/40 border-slate-800'
          }`}>
            <div className="flex items-center gap-3">
              <span className={`w-3 h-3 rounded-full ${themeMode === 'light' ? 'bg-cyan-500' : 'bg-cyan-400'} animate-pulse`} />
              <span className={`text-xs font-mono font-semibold ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-200'}`}>
                {language === 'zh' ? '当前配置域名:' : 'Active Domain:'} <span className="text-cyan-400 font-bold">{selectedDomainName || (language === 'zh' ? '未选择' : 'Not selected')}</span>
              </span>
              <span className={`text-xs font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                ({customRecordsOverride ? (language === 'zh' ? '包含手动自定义覆盖记录' : 'Custom overrides active') : (language === 'zh' ? '系统推荐配置' : 'Standard recommended configuration')})
              </span>
            </div>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => {}}
                className={`px-3.5 py-2 rounded-xl border text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                  themeMode === 'light'
                    ? 'bg-cyan-500/10 border-cyan-300 text-cyan-800 hover:bg-cyan-500/20'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20'
                }`}
              >
                <Plus className="w-4 h-4" />
                <span>{language === 'zh' ? '添加自定义记录' : 'Add Custom Record'}</span>
              </button>
            </div>
          </div>

          {(!selectedDomainName || !customServerIp || !domains.find((item) => item.name === selectedDomainName)?.dkimPublicKey) && (
            <div className={`p-3 rounded-xl border text-xs flex items-start gap-2 ${
              themeMode === 'light' ? 'bg-amber-50 border-amber-200 text-amber-900' : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
            }`} role="status">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                {!selectedDomainName
                  ? (language === 'zh' ? '请先添加一个真实域名。' : 'Add a real domain before generating DNS records.')
                  : !customServerIp
                    ? (language === 'zh' ? '尚未取得服务器公网 IP，A 记录不会生成。' : 'No public server IP is available; the A record is omitted.')
                    : (language === 'zh' ? '尚未从服务器取得 DKIM 公钥，DKIM 记录不会生成。' : 'No server DKIM public key is available; the DKIM record is omitted.')}
              </span>
            </div>
          )}

          <div className={`rounded-2xl border overflow-hidden backdrop-blur-md ${
            themeMode === 'light' ? 'bg-white/80 border-slate-200 shadow-sm' : 'bg-slate-950/60 border-slate-800'
          }`}>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className={`border-b font-mono ${
                    themeMode === 'light' ? 'bg-slate-50/90 text-slate-600 border-slate-200' : 'bg-slate-900/60 text-slate-400 border-slate-800'
                  }`}>
                    <th className="p-3.5 pl-4">{language === 'zh' ? '记录类型' : 'Type'}</th>
                    <th className="p-3.5">{language === 'zh' ? '主机记录 / 名称 (Name)' : 'Host / Name'}</th>
                    <th className="p-3.5 min-w-[320px]">{language === 'zh' ? '记录值 / 内容 (Value/Content)' : 'Value / Content'}</th>
                    <th className="p-3.5">{language === 'zh' ? '代理 / TTL' : 'Proxy / TTL'}</th>
                    <th className="p-3.5">{language === 'zh' ? '作用说明' : 'Purpose'}</th>
                    <th className="p-3.5">{language === 'zh' ? '状态' : 'Status'}</th>
                    <th className="p-3.5 pr-4 text-right">{language === 'zh' ? '操作' : 'Actions'}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {!currentRecords.length && (
                    <tr>
                      <td colSpan={7} className="p-8 text-center text-sm text-slate-500">
                        {language === 'zh' ? '没有可发布的 DNS 记录' : 'No publishable DNS records'}
                      </td>
                    </tr>
                  )}
                  {currentRecords.map((r) => {
                    const isEditing = editingRecordId === r.id;
                    const isVerified = verifiedMap[r.id];

                    return (
                      <React.Fragment key={r.id}>
                        <tr className={`transition-colors font-mono ${
                          themeMode === 'light' ? 'hover:bg-cyan-50/50' : 'hover:bg-cyan-950/10'
                        } ${isEditing ? (themeMode === 'light' ? 'bg-cyan-50/80' : 'bg-cyan-950/30') : ''}`}>
                          <td className="p-3.5 pl-4">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                              r.type === 'A' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30' :
                              r.type === 'MX' ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30' :
                              r.type === 'TXT' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' :
                              'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                            }`}>
                              {r.type}
                            </span>
                          </td>
                          <td className="p-3.5">
                            <div className="flex items-center gap-1.5 group">
                              <span className={`font-semibold ${themeMode === 'light' ? 'text-slate-900' : 'text-slate-100'}`}>
                                {r.nameDisplay}
                              </span>
                              <button
                                onClick={() => copyText(r.nameDisplay, `name-${r.id}`)}
                                title={language === 'zh' ? '复制主机记录' : 'Copy Host'}
                                className="opacity-0 group-hover:opacity-100 p-1 hover:text-cyan-400 transition-opacity cursor-pointer"
                              >
                                {copiedField === `name-${r.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                              </button>
                            </div>
                          </td>
                          <td className="p-3.5 max-w-md">
                            <div className="flex items-center gap-1.5 group">
                              <span className={`font-mono text-xs break-all ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
                                {r.content}
                              </span>
                              <button
                                onClick={() => copyText(r.content, `content-${r.id}`)}
                                title={language === 'zh' ? '复制记录值' : 'Copy Content'}
                                className="opacity-0 group-hover:opacity-100 p-1 hover:text-cyan-400 transition-opacity cursor-pointer shrink-0"
                              >
                                {copiedField === `content-${r.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                              </button>
                            </div>
                          </td>
                          <td className="p-3.5">
                            <div className="flex flex-col gap-1">
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">
                                <AlertCircle className="w-3 h-3" /> 仅 DNS (灰云)
                              </span>
                              <span className="text-[10px] text-slate-500">TTL: {r.ttl}</span>
                            </div>
                          </td>
                          <td className="p-3.5">
                            <div className="flex flex-col gap-0.5">
                              <span className={`text-xs font-medium ${themeMode === 'light' ? 'text-slate-900' : 'text-slate-200'}`}>
                                {language === 'zh' ? r.categoryLabelZh : r.categoryLabelEn}
                              </span>
                              <span className="text-[11px] text-slate-500 line-clamp-1">{r.comment}</span>
                            </div>
                          </td>
                          <td className="p-3.5">
                            {isVerified ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                <CheckCircle2 className="w-3 h-3" /> {language === 'zh' ? '解析正常' : 'Active'}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/10 text-slate-400 border border-slate-500/20">
                                <HelpCircle className="w-3 h-3" /> {language === 'zh' ? '未体检' : 'Untested'}
                              </span>
                            )}
                          </td>
                          <td className="p-3.5 pr-4 text-right">
                            <div className="flex items-center justify-end gap-1">
                              <button
                                onClick={() => handleStartEdit(r)}
                                className={`p-1.5 rounded-lg border text-xs cursor-pointer ${
                                  themeMode === 'light' ? 'hover:bg-slate-100 text-slate-600 border-slate-300' : 'hover:bg-slate-800 text-slate-300 border-slate-700'
                                }`}
                                title={language === 'zh' ? '编辑记录' : 'Edit'}
                              >
                                <Edit3 className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDeleteRecord(r.id)}
                                className="p-1.5 rounded-lg border border-red-500/30 text-red-400 hover:bg-red-500/10 text-xs cursor-pointer"
                                title={language === 'zh' ? '删除记录' : 'Delete'}
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>

                        {isEditing && (
                          <tr className={themeMode === 'light' ? 'bg-cyan-50/90' : 'bg-slate-900/90'}>
                            <td colSpan={7} className="p-4 border-b border-cyan-500/30">
                              <div className="space-y-3 font-sans">
                                <div className="flex items-center justify-between">
                                  <h4 className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                                    <Edit3 className="w-3.5 h-3.5" />
                                    <span>编辑记录: {r.type} {r.nameDisplay}</span>
                                  </h4>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                                  <div>
                                    <label className="block mb-1 text-slate-400">记录类型 (Type)</label>
                                    <select
                                      value={editForm.type || 'TXT'}
                                      onChange={(e) => setEditForm({ ...editForm, type: e.target.value as any })}
                                      className="w-full px-3 py-1.5 rounded-lg border bg-slate-950 border-slate-700 text-white font-mono"
                                    >
                                      {['TXT', 'MX', 'A', 'AAAA', 'CNAME', 'PTR'].map((t) => (
                                        <option key={t} value={t}>{t}</option>
                                      ))}
                                    </select>
                                  </div>
                                  <div>
                                    <label className="block mb-1 text-slate-400">主机记录 (Host / Name)</label>
                                    <input
                                      type="text"
                                      value={editForm.nameDisplay || ''}
                                      onChange={(e) => setEditForm({ ...editForm, nameDisplay: e.target.value, name: e.target.value })}
                                      className="w-full px-3 py-1.5 rounded-lg border bg-slate-950 border-slate-700 text-white font-mono"
                                    />
                                  </div>
                                  <div>
                                    <label className="block mb-1 text-slate-400">记录值 / 内容 (Content)</label>
                                    <input
                                      type="text"
                                      value={editForm.content || ''}
                                      onChange={(e) => setEditForm({ ...editForm, content: e.target.value })}
                                      className="w-full px-3 py-1.5 rounded-lg border bg-slate-950 border-slate-700 text-white font-mono"
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

      {activeTab === 'wizard' && (
        <DnsSetupWizard
          domainName={selectedDomainName}
          serverIp={customServerIp}
          dkimSelector={customDkimSelector}
          dkimPublicKey={domains.find((item) => item.name === selectedDomainName)?.dkimPublicKey || ''}
          relayProvider={selectedRelay}
          dmarcPolicy={dmarcPolicy}
          ruaEmail={ruaEmail}
          onJumpToTab={(tab) => {
            if (tab === 'table') setActiveTab('table');
          }}
        />
      )}
    </div>
  );
};
