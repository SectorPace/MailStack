import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import {
  Lock,
  Plus,
  RefreshCw,
  ShieldCheck,
  AlertCircle,
  FileText,
  KeyRound,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  Server,
  Layers,
  Zap,
  Globe,
  Sliders,
  Calendar,
  Clock,
  ArrowRight
} from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';
import { IssueCertModal } from '../modals/IssueCertModal';

export const CertificatesView: React.FC = () => {
  const { certs, renewCert, language, themeMode, showToast } = useApp();
  const [activeTab, setActiveTab] = useState<'inventory' | 'acme' | 'custom' | 'security'>('inventory');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [renewBusy, setRenewBusy] = useState(false);

  // Custom PEM Import state
  const [customDomain, setCustomDomain] = useState('');
  const [customCertPem, setCustomCertPem] = useState('');
  const [customKeyPem, setCustomKeyPem] = useState('');
  const [importBusy, setImportBusy] = useState(false);

  const isLight = themeMode === 'light';

  const handleRenewAll = async () => {
    setRenewBusy(true);
    try {
      await renewCert('all');
      showToast('success', language === 'zh' ? 'TLS 证书续期成功' : 'Certificates Renewed', 'All managed PEM certs renewed');
    } catch (e) {
      showToast('error', language === 'zh' ? '续期失败' : 'Renewal Failed', getErrorMessage(e));
    } finally {
      setRenewBusy(false);
    }
  };

  const handleImportCustom = async () => {
    if (!customDomain || !customCertPem || !customKeyPem) {
      showToast('error', language === 'zh' ? '请填写完整参数' : 'Incomplete Form', 'Domain, Full Chain PEM and Private Key are required');
      return;
    }
    setImportBusy(true);
    try {
      await api('/api/setup/cert/issue', {
        method: 'POST',
        body: JSON.stringify({
          mailHost: customDomain.trim(),
          customCertPem,
          customKeyPem,
          method: 'custom',
        }),
      });
      showToast('success', language === 'zh' ? '自定义证书导入成功' : 'Custom Certificate Imported', customDomain);
      setCustomCertPem('');
      setCustomKeyPem('');
      location.reload();
    } catch (e) {
      showToast('error', language === 'zh' ? '导入失败' : 'Import Failed', getErrorMessage(e));
    } finally {
      setImportBusy(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Header Card */}
      <LiquidGlass variant="panel" glowColor="cyan" className="p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-400 to-blue-500 text-slate-950 flex items-center justify-center font-bold shadow-[0_0_20px_rgba(0,242,195,0.3)]">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                  {language === 'zh' ? 'TLS / SSL 安全证书管理' : 'TLS Certificates & Cryptography'}
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {certs.length} {language === 'zh' ? '张托管证书' : 'CERTIFICATES'}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {language === 'zh'
                  ? '管理 Postfix (SMTP / SMTPS / Submission) 与 Dovecot (IMAP / IMAPS / POP3 / POP3S) 的双向 TLSv1.3 加密通信证书。'
                  : 'Manage PEM certificates for Postfix (SMTP/SMTPS/Submission) and Dovecot (IMAP/IMAPS/POP3S) daemons.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleRenewAll}
              disabled={renewBusy || certs.length === 0}
              className={`px-3.5 py-2 rounded-xl border text-xs font-mono font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isLight ? 'bg-white hover:bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${renewBusy ? 'animate-spin' : ''}`} />
              <span>{language === 'zh' ? '执行全部续期' : 'Renew All'}</span>
            </button>

            <button
              onClick={() => setIsModalOpen(true)}
              className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow-md"
            >
              <Plus className="w-4 h-4" />
              <span>{language === 'zh' ? '签发 ACME 证书' : 'Issue Certificate'}</span>
            </button>
          </div>
        </div>
      </LiquidGlass>

      {/* Secondary Submenu Navigation Tabs */}
      <div className={`p-1.5 rounded-2xl border flex items-center gap-1.5 backdrop-blur-md overflow-x-auto ${
        isLight ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
      }`}>
        {[
          { id: 'inventory', labelZh: '证书资产与健康度', labelEn: 'Certificate Inventory', icon: <Layers className="w-4 h-4" /> },
          { id: 'acme', labelZh: 'ACME 自动化签发', labelEn: 'ACME Automation', icon: <Zap className="w-4 h-4" /> },
          { id: 'custom', labelZh: '自定义证书导入', labelEn: 'Custom PEM Import', icon: <FileText className="w-4 h-4" /> },
          { id: 'security', labelZh: 'TLS 协议与加密套件', labelEn: 'Security & Ciphers', icon: <ShieldCheck className="w-4 h-4" /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-2 rounded-xl text-xs font-bold font-mono flex items-center gap-2 transition-all cursor-pointer shrink-0 ${
              activeTab === tab.id
                ? 'bg-cyan-400 text-slate-950 shadow-sm'
                : isLight ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
            }`}
          >
            {tab.icon}
            <span>{language === 'zh' ? tab.labelZh : tab.labelEn}</span>
          </button>
        ))}
      </div>

      {/* Tab 1: Certificate Inventory */}
      {activeTab === 'inventory' && (
        <div className="space-y-6 animate-in fade-in">
          {certs.length === 0 ? (
            <div className={`p-8 rounded-2xl border text-center space-y-3 ${
              isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'
            }`}>
              <Lock className="w-10 h-10 mx-auto text-amber-400" />
              <h4 className="text-sm font-bold text-slate-200">
                {language === 'zh' ? '尚未检测到已部署的 TLS PEM 证书' : 'No TLS PEM Certificates Found'}
              </h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                {language === 'zh'
                  ? '当前系统正在使用安装时自动生成的自签名证书。为了防止邮件客户端（Outlook / Thunderbird / Apple Mail）连接时弹出证书不信任告警，请立即签发 Let\'s Encrypt 证书或导入自定义 PEM 证书。'
                  : 'Self-signed certificates are in use. Please issue a Let\'s Encrypt certificate or import custom PEM certs to avoid client trust warnings.'}
              </p>
              <div className="flex items-center justify-center gap-3 pt-2">
                <button
                  onClick={() => setIsModalOpen(true)}
                  className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 cursor-pointer shadow-md"
                >
                  <Zap className="w-4 h-4" />
                  <span>{language === 'zh' ? '签发 Let\'s Encrypt 证书' : 'Issue with Let\'s Encrypt'}</span>
                </button>
                <button
                  onClick={() => setActiveTab('custom')}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-bold text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <FileText className="w-4 h-4" />
                  <span>{language === 'zh' ? '导入 PEM 证书' : 'Import Custom PEM'}</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {certs.map((c) => {
                const daysLeft = c.daysRemaining || 90;
                const isExpiringSoon = daysLeft < 15;
                return (
                  <div
                    key={c.id}
                    className={`p-5 rounded-2xl border flex flex-col justify-between space-y-4 transition-all ${
                      isLight ? 'bg-white/90 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800 hover:border-cyan-500/30 shadow-md'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                            isExpiringSoon ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            <Lock className="w-4 h-4" />
                          </div>
                          <div>
                            <h4 className="font-bold text-sm text-slate-100 font-mono">{c.domain}</h4>
                            <div className="text-[11px] text-slate-400">{c.issuer || 'Let\'s Encrypt Authority X3'}</div>
                          </div>
                        </div>

                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${
                          isExpiringSoon
                            ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                            : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                        }`}>
                          {isExpiringSoon ? `${daysLeft} DAYS LEFT` : 'VALID'}
                        </span>
                      </div>

                      {/* Expiry Progress Bar */}
                      <div className="mt-4 space-y-1.5">
                        <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                          <span>{c.validFrom || '2026-01-01'}</span>
                          <span className="font-bold text-cyan-400">{daysLeft} {language === 'zh' ? '天剩余' : 'days remaining'}</span>
                          <span>{c.validTo || '2026-04-01'}</span>
                        </div>
                        <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all duration-500 ${
                              isExpiringSoon ? 'bg-amber-400' : 'bg-gradient-to-r from-cyan-400 to-emerald-400'
                            }`}
                            style={{ width: `${Math.min(100, Math.max(5, (daysLeft / 90) * 100))}%` }}
                          />
                        </div>
                      </div>

                      <div className="mt-4 p-3 rounded-xl bg-slate-950/70 border border-slate-800 font-mono text-[11px] space-y-1 text-slate-400">
                        <div className="flex justify-between">
                          <span>Algorithm:</span>
                          <span className="text-slate-200">RSA 2048 / SHA256withRSA</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Services Bound:</span>
                          <span className="text-cyan-400">Postfix (25/465/587/2525) + Dovecot (143/993/110/995)</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                      <button
                        onClick={handleRenewAll}
                        disabled={renewBusy}
                        className="px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 font-bold text-xs flex items-center gap-1 cursor-pointer transition-all"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${renewBusy ? 'animate-spin' : ''}`} />
                        <span>{language === 'zh' ? '强制续期' : 'Force Renew'}</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: ACME Automation */}
      {activeTab === 'acme' && (
        <div className="space-y-6 animate-in fade-in">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <LiquidGlass variant="card" className="p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold">
                  <Zap className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-slate-100">HTTP-01 Standalone 自动签发</h4>
                  <p className="text-xs text-slate-400">零依赖内置 ACME 引擎，自动监听 80 端口完成验证</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                适用于邮件主机已配置 A 记录且宿主机 80 端口未被其他反代占用的环境。MailStack 将自动启闭临时 HTTP 服务应答 Let's Encrypt 挑战。
              </p>
              <button
                onClick={() => setIsModalOpen(true)}
                className="w-full py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 cursor-pointer shadow-md"
              >
                <span>立即启动 HTTP-01 签发向导</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </LiquidGlass>

            <LiquidGlass variant="card" className="p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold">
                  <Globe className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-bold text-sm text-slate-100">DNS-01 泛域名证书签发 (*.domain)</h4>
                  <p className="text-xs text-slate-400">通过 Cloudflare / 权威 DNS API 自动写入 TXT 记录</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                无需开放 80 端口，可同时签发根域名、mail 子域与通配符泛域名证书，抗端口封锁能力极佳。
              </p>
              <button
                onClick={() => {
                  showToast('info', 'Cloudflare DNS-01', '请在首次配置引导中配置 API Token');
                  setIsModalOpen(true);
                }}
                className="w-full py-2.5 rounded-xl bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/30 font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
              >
                <span>配置 DNS-01 泛域名签发</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </LiquidGlass>
          </div>
        </div>
      )}

      {/* Tab 3: Custom PEM Import */}
      {activeTab === 'custom' && (
        <div className="space-y-6 animate-in fade-in">
          <LiquidGlass variant="card" className="p-6 space-y-5">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <span>{language === 'zh' ? '导入自定义 PEM 证书与私钥' : 'Import Custom PEM Certificate & Key'}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                支持导入由第三方 CA (DigiCert / Sectigo / ZeroSSL) 签发的文件。系统会自动校验 PEM 模数并应用至 Postfix 和 Dovecot。
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">{language === 'zh' ? '绑定域名 (Common Name / SAN)' : 'Domain Name'}</label>
                <input
                  type="text"
                  value={customDomain}
                  onChange={(e) => setCustomDomain(e.target.value)}
                  placeholder="mail.yourdomain.com"
                  className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-white font-mono text-xs focus:border-cyan-400 focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">
                    {language === 'zh' ? '完整证书链 (Full Chain PEM)' : 'Certificate Fullchain PEM'}
                  </label>
                  <textarea
                    rows={8}
                    value={customCertPem}
                    onChange={(e) => setCustomCertPem(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-cyan-300 font-mono text-[11px] focus:border-cyan-400 focus:outline-none leading-relaxed"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-bold text-slate-400 mb-1.5">
                    {language === 'zh' ? '私钥内容 (Private Key PEM - RSA/ECDSA)' : 'Private Key PEM'}
                  </label>
                  <textarea
                    rows={8}
                    value={customKeyPem}
                    onChange={(e) => setCustomKeyPem(e.target.value)}
                    placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                    className="w-full px-3.5 py-2 rounded-xl border bg-slate-950 border-slate-700 text-amber-300 font-mono text-[11px] focus:border-cyan-400 focus:outline-none leading-relaxed"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={handleImportCustom}
                disabled={importBusy || !customDomain || !customCertPem || !customKeyPem}
                className="px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-50"
              >
                <Lock className="w-4 h-4" />
                <span>{importBusy ? (language === 'zh' ? '正在安装并重载服务...' : 'Installing...') : (language === 'zh' ? '校验并安装证书' : 'Verify & Install PEM')}</span>
              </button>
            </div>
          </LiquidGlass>
        </div>
      )}

      {/* Tab 4: Security & Ciphers */}
      {activeTab === 'security' && (
        <div className="space-y-4 animate-in fade-in">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-400 font-mono">TLSv1.3 & TLSv1.2</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">强制已启用</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">现代传输层加密协议</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                彻底禁用存在已知漏洞的不安全旧协议（SSLv2, SSLv3, TLSv1.0, TLSv1.1），仅允许安全现代化密码套件。
              </p>
            </div>

            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cyan-400 font-mono">PFS (前向安全性)</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">ECDHE 启用</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">椭圆曲线 Diffie-Hellman</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                每次会话动态协商会话密钥，即使私钥在未来泄露，过去的通信记录也无法被解密。
              </p>
            </div>

            <div className={`p-5 rounded-2xl border space-y-2 ${isLight ? 'bg-white/80 border-slate-200' : 'bg-slate-900/60 border-slate-800'}`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-purple-400 font-mono">HSTS & DANE</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">TLSA 就绪</span>
              </div>
              <h5 className="font-bold text-sm text-slate-200">DANE / TLSA 密码学对齐</h5>
              <p className="text-xs text-slate-400 leading-relaxed">
                支持通过 DNSSEC 权威发布 TLSA 证书指纹，杜绝任何中间人伪造 CA 证书拦截邮件通信。
              </p>
            </div>
          </div>
        </div>
      )}

      {isModalOpen && <IssueCertModal onClose={() => setIsModalOpen(false)} />}
    </div>
  );
};
