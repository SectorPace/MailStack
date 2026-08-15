import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { DomainItem } from '../../types';
import {
  X,
  Globe,
  Copy,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  Table,
  BookOpen
} from 'lucide-react';
import { motion } from 'motion/react';
import { DnsGuideTable } from '../dns/DnsGuideTable';

interface Props {
  domain: DomainItem;
  onClose: () => void;
}

export const DnsCheckModal: React.FC<Props> = ({ domain, onClose }) => {
  const { language, themeMode, showToast } = useApp();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-slate-950/70 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className={`w-full max-w-5xl border rounded-3xl shadow-2xl overflow-hidden relative z-10 flex flex-col max-h-[92vh] font-sans ${
          themeMode === 'light'
            ? 'bg-white border-slate-200 text-slate-900'
            : 'bg-slate-900 border-slate-700/80 text-white'
        }`}
      >
        {/* Header */}
        <div className={`px-6 py-4 border-b flex items-center justify-between shrink-0 ${
          themeMode === 'light' ? 'border-slate-200 bg-slate-50' : 'border-slate-800 bg-slate-950/80'
        }`}>
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${
              themeMode === 'light' ? 'bg-cyan-50 border-cyan-200 text-cyan-700' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className={`text-base font-bold flex items-center gap-2 ${
                themeMode === 'light' ? 'text-slate-900' : 'text-white'
              }`}>
                <span>{domain.name}</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                  themeMode === 'light'
                    ? 'bg-cyan-100 text-cyan-800 border-cyan-300 font-semibold'
                    : 'bg-slate-800 text-cyan-300 border-slate-700'
                }`}>
                  DNS CONFIG & RELAY GUIDE
                </span>
              </h3>
              <p className={`text-xs ${
                themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
              }`}>
                {language === 'zh' ? '9 条核心记录配置对照表（支持 Cloudflare、阿里云、DNSPod 与 Oracle 中继）' : 'Authoritative 9-Record DNS Mapping & SMTP Relay Guides'}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className={`p-1.5 rounded-xl transition-colors cursor-pointer border ${
              themeMode === 'light' ? 'text-slate-500 hover:text-slate-900 hover:bg-slate-200 border-slate-200' : 'text-slate-400 hover:text-white border-slate-800 hover:bg-slate-800'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body: Embedded DnsGuideTable */}
        <div className="p-4 sm:p-6 overflow-y-auto flex-1">
          <DnsGuideTable domain={domain} serverIp="163.192.27.230" relayProvider="oracle" />
        </div>
      </motion.div>
    </div>
  );
};
