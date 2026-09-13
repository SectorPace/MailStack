import React from 'react';
import { ShieldCheck, RefreshCw, ArrowLeft, ArrowRight } from '@/lib/icons';
import { LiquidGlass } from '../common/LiquidGlass';

interface Props {
  language: string;
  mailHost: string;
  domainName: string;
  isIssuingCert: boolean;
  certIssued: boolean;
  onIssueCert: () => void;
  onPrev: () => void;
  onNext: () => void;
}

export const SetupTlsStep: React.FC<Props> = ({
  language,
  mailHost,
  domainName,
  isIssuingCert,
  certIssued,
  onIssueCert,
  onPrev,
  onNext,
}) => {
  return (
    <LiquidGlass variant="card" className="p-6 space-y-6 animate-in fade-in">
      <div className="flex items-center justify-between border-b border-white/10 pb-4">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>4. {language === 'zh' ? 'TLS 安全证书自动签发与加密套件' : 'TLS Certificates & Encryption'}</span>
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {language === 'zh'
              ? "自动申请 Let's Encrypt ECC 256 位 TLS 证书，为 Postfix (SMTP 465/587) 与 Dovecot (IMAP 993) 提供 TLS 1.3 传输加密。"
              : "Automated Let's Encrypt certificate issuance and TLS 1.3 encryption."}
          </p>
        </div>

        <button
          onClick={onIssueCert}
          disabled={isIssuingCert}
          className="px-3.5 py-1.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 font-bold text-xs flex items-center gap-1.5 cursor-pointer transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isIssuingCert ? 'animate-spin' : ''}`} />
          <span>{isIssuingCert ? 'ACME 握手签发中...' : certIssued ? '✓ 证书已有效挂载' : '一键签发证书'}</span>
        </button>
      </div>

      <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02] space-y-3 font-mono text-xs">
        <div className="flex items-center justify-between">
          <span className="text-slate-400">证书域名 (SAN):</span>
          <span className="font-bold text-slate-200">{mailHost}, smtp.{domainName}, imap.{domainName}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">签发机构 (CA):</span>
          <span className="text-cyan-400 font-semibold">{"Let's Encrypt Authority X3 (ACME v2)"}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">加密算法 & 秘钥长度:</span>
          <span className="text-emerald-400 font-semibold">ECDSA P-256 (TLS 1.3 极速握手)</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-slate-400">自动续期策略:</span>
          <span className="text-slate-300">到期前 30 天自动 Certbot ACME 续签并热重载 Postfix</span>
        </div>
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-white/10">
        <button
          onClick={onPrev}
          className="px-4 py-2.5 rounded-xl border border-white/10 text-slate-300 hover:bg-white/5 text-xs font-semibold flex items-center gap-2 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>上一步</span>
        </button>

        <button
          onClick={onNext}
          disabled={!certIssued}
          className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(0,242,195,0.25)] cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <span>下一步：创建管理员并进行发信测试</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </LiquidGlass>
  );
};
