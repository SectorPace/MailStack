import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { ShieldCheck, Plus, RefreshCw, AlertTriangle, Lock, KeyRound, CheckCircle2, XCircle, ShieldAlert, Calendar, Zap } from 'lucide-react';
import confetti from 'canvas-confetti';
import { IssueCertModal } from '../modals/IssueCertModal';

export const CertificatesView: React.FC = () => {
  const { certs, renewCert, language, themeMode, showToast } = useApp();
  const [isApplying, setIsApplying] = useState(false);
  const [isIssueModalOpen, setIsIssueModalOpen] = useState(false);
  const [filterMode, setFilterMode] = useState<'all' | 'valid' | 'expiring' | 'expired'>('all');

  const handleRenewAll = () => {
    setIsApplying(true);
    setTimeout(() => {
      setIsApplying(false);
      certs.forEach(c => renewCert(c.id));
      confetti({ particleCount: 30, spread: 50 });
      showToast('success', language === 'zh' ? '所有证书已更新' : 'All Certificates Renewed', language === 'zh' ? 'Let\'s Encrypt 自动化 ACME 验证均已通过' : 'ACME challenges completed');
    }, 1200);
  };

  const handleRenewSingle = (id: string, domain: string) => {
    renewCert(id);
    confetti({ particleCount: 25, spread: 45 });
    showToast('success', language === 'zh' ? '证书续签成功' : 'Certificate Renewed', `${domain} ${language === 'zh' ? '已颁发新证书，有效期延长 90 天' : 'extended by 90 days'}`);
  };

  const validCount = certs.filter(c => c.daysRemaining >= 15 && c.status !== 'expired').length;
  const expiringCount = certs.filter(c => c.daysRemaining > 0 && c.daysRemaining < 15).length;
  const expiredCount = certs.filter(c => c.daysRemaining <= 0 || c.status === 'expired').length;

  const filteredCerts = certs.filter(cert => {
    const isExp = cert.daysRemaining > 0 && cert.daysRemaining < 15;
    const isExpir = cert.daysRemaining <= 0 || cert.status === 'expired';
    if (filterMode === 'valid') return !isExp && !isExpir;
    if (filterMode === 'expiring') return isExp;
    if (filterMode === 'expired') return isExpir;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Action Bar & Stat Summary */}
      <div className={`p-5 rounded-2xl border backdrop-blur-md space-y-4 ${
        themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
      }`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl border flex items-center justify-center ${
              themeMode === 'light' ? 'bg-cyan-50 border-cyan-200 text-cyan-700 shadow-sm' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className={`text-base font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? 'TLS / SSL 传输加密证书' : 'TLS / SSL Encryption Certificates'}
              </h3>
              <p className={`text-xs font-mono ${themeMode === 'light' ? 'text-slate-500 font-medium' : 'text-slate-400'}`}>
                Postfix SMTP (25/465/587) &amp; Dovecot IMAP/POP3 (993/995)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsIssueModalOpen(true)}
              className="h-10 px-4 rounded-xl bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer hover:scale-[1.02]"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>{language === 'zh' ? '一键申请/注册 TLS 证书 (ACME)' : 'Issue TLS Cert (ACME)'}</span>
            </button>

            <button
              onClick={handleRenewAll}
              disabled={isApplying}
              className={`h-10 px-3.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
                themeMode === 'light'
                  ? 'bg-white hover:bg-slate-50 text-slate-700 border-slate-300 shadow-sm'
                  : 'bg-slate-800 hover:bg-slate-700 text-cyan-300 border-slate-700'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isApplying ? 'animate-spin text-cyan-500' : ''}`} />
              <span>{isApplying ? (language === 'zh' ? 'ACME 申请中...' : 'Renewing...') : (language === 'zh' ? '批量续签所有证书' : 'Renew All')}</span>
            </button>
          </div>
        </div>

        {/* Filter Badges & Status Summary */}
        <div className={`pt-3 border-t flex flex-wrap items-center justify-between gap-2 text-xs font-mono ${
          themeMode === 'light' ? 'border-slate-200' : 'border-slate-800'
        }`}>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${
                filterMode === 'all'
                  ? themeMode === 'light'
                    ? 'bg-slate-800 text-white font-bold'
                    : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
              }`}
            >
              {language === 'zh' ? '全部证书' : 'All'} ({certs.length})
            </button>
            <button
              onClick={() => setFilterMode('valid')}
              className={`px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 ${
                filterMode === 'valid'
                  ? themeMode === 'light'
                    ? 'bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold'
                    : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40 font-bold'
                  : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
              <span>{language === 'zh' ? '有效' : 'Valid'} ({validCount})</span>
            </button>
            <button
              onClick={() => setFilterMode('expiring')}
              className={`px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 ${
                filterMode === 'expiring'
                  ? themeMode === 'light'
                    ? 'bg-amber-100 text-amber-800 border border-amber-300 font-bold'
                    : 'bg-amber-950 text-amber-300 border border-amber-500/40 font-bold'
                  : themeMode === 'light' ? 'text-slate-600 hover:bg-slate-100' : 'text-slate-400 hover:bg-slate-800'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
              <span>{language === 'zh' ? '即将到期' : 'Expiring'} ({expiringCount})</span>
            </button>
            {expiredCount > 0 && (
              <button
                onClick={() => setFilterMode('expired')}
                className={`px-3 py-1 rounded-lg transition-all cursor-pointer flex items-center gap-1.5 ${
                  filterMode === 'expired'
                    ? 'bg-rose-100 text-rose-800 border border-rose-300 font-bold'
                    : 'text-rose-500 hover:bg-rose-500/10'
                }`}
              >
                <XCircle className="w-3.5 h-3.5 text-rose-500" />
                <span>{language === 'zh' ? '已失效' : 'Expired'} ({expiredCount})</span>
              </button>
            )}
          </div>

          <div className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>
            ACME v2 RFC 8555 / Let's Encrypt / ZeroSSL
          </div>
        </div>
      </div>

      {/* Cert Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredCerts.map((cert) => {
          const isExpiring = cert.daysRemaining > 0 && cert.daysRemaining < 15;
          const isExpired = cert.daysRemaining <= 0 || cert.status === 'expired';

          return (
            <div
              key={cert.id}
              className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 relative overflow-hidden transition-all ${
                isExpired
                  ? themeMode === 'light'
                    ? 'bg-rose-50/70 border-rose-300 shadow-sm'
                    : 'bg-slate-900/70 border-rose-500/50 shadow-[0_0_20px_rgba(244,63,94,0.15)]'
                  : isExpiring
                  ? themeMode === 'light'
                    ? 'bg-amber-50/70 border-amber-300 shadow-sm'
                    : 'bg-slate-900/70 border-amber-500/50 shadow-[0_0_20px_rgba(245,158,11,0.15)]'
                  : themeMode === 'light'
                  ? 'bg-white/90 border-slate-200 shadow-sm hover:border-cyan-300'
                  : 'bg-slate-900/70 border-slate-800/90 hover:border-cyan-500/40'
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className={`text-sm font-bold font-mono ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                    {cert.domain}
                  </h4>
                  <div className={`text-xs mt-0.5 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                    {cert.issuer}
                  </div>
                </div>

                {/* Valid / Expiring / Expired Badge */}
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border flex items-center gap-1 ${
                    isExpired
                      ? themeMode === 'light'
                        ? 'bg-rose-100 text-rose-800 border-rose-300'
                        : 'bg-rose-950 text-rose-300 border-rose-500/40'
                      : isExpiring
                      ? themeMode === 'light'
                        ? 'bg-amber-100 text-amber-800 border-amber-300'
                        : 'bg-amber-950 text-amber-300 border-amber-500/40'
                      : themeMode === 'light'
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-300'
                      : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    isExpired ? 'bg-rose-500' : isExpiring ? 'bg-amber-500' : 'bg-emerald-500'
                  }`} />
                  {isExpired
                    ? (language === 'zh' ? '已失效' : 'EXPIRED')
                    : isExpiring
                    ? (language === 'zh' ? '即将到期' : 'EXPIRING')
                    : (language === 'zh' ? '有效' : 'VALID')}
                </span>
              </div>

              {/* Specs Box */}
              <div className={`space-y-2 p-3.5 rounded-xl border text-xs font-mono ${
                themeMode === 'light'
                  ? 'bg-slate-50/90 border-slate-200'
                  : 'bg-slate-950/80 border-slate-800/80'
              }`}>
                <div className="flex justify-between">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>剩余天数 (Days):</span>
                  <span className={`font-bold ${
                    isExpired
                      ? 'text-rose-500'
                      : isExpiring
                      ? 'text-amber-500'
                      : themeMode === 'light' ? 'text-emerald-700' : 'text-emerald-400'
                  }`}>
                    {cert.daysRemaining} 天 (Days)
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>有效期至 (Expiry):</span>
                  <span className={`font-medium ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}`}>{cert.validTo}</span>
                </div>
                <div className="flex justify-between">
                  <span className={themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}>加密算法 (Cipher):</span>
                  <span className={`font-semibold ${themeMode === 'light' ? 'text-cyan-800' : 'text-cyan-300'}`}>{cert.algorithm}</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-between pt-1">
                <span className={`text-[11px] font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
                  自动续签: {cert.autoRenew ? '已启用 (ACME)' : '手动'}
                </span>
                <button
                  onClick={() => handleRenewSingle(cert.id, cert.domain)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    isExpiring || isExpired
                      ? 'bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400 shadow-sm'
                      : themeMode === 'light'
                      ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200'
                      : 'bg-slate-800 hover:bg-slate-700 text-cyan-300'
                  }`}
                >
                  {language === 'zh' ? '立即续签' : 'Renew'}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* ACME Issue Cert Modal */}
      {isIssueModalOpen && <IssueCertModal onClose={() => setIsIssueModalOpen(false)} />}
    </div>
  );
};
