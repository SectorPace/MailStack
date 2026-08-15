import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { Globe, X, Plus, KeyRound, ShieldCheck } from 'lucide-react';
import { motion } from 'motion/react';

interface Props {
  onClose: () => void;
}

export const AddDomainModal: React.FC<Props> = ({ onClose }) => {
  const { addDomain, language, themeMode } = useApp();
  const [domainName, setDomainName] = useState('');
  const [mailboxesMax, setMailboxesMax] = useState(50);
  const [dkimSelector, setDkimSelector] = useState('mail');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainName.trim()) return;
    addDomain({
      name: domainName.toLowerCase().trim(),
      mailboxesMax,
      dkimSelector,
    });
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className={`w-full max-w-md border rounded-3xl shadow-2xl overflow-hidden relative z-10 font-sans ${
          themeMode === 'light'
            ? 'bg-white border-slate-200 text-slate-900'
            : 'bg-slate-900 border-slate-700/80 text-white'
        }`}
      >
        <div className={`px-6 py-4 border-b flex items-center justify-between ${
          themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'border-slate-800 bg-slate-950/80'
        }`}>
          <h3 className={`text-base font-bold flex items-center gap-2 ${
            themeMode === 'light' ? 'text-slate-900' : 'text-white'
          }`}>
            <Globe className="w-5 h-5 text-cyan-500" />
            <span>{language === 'zh' ? '添加新邮件域名' : 'Add New Mail Domain'}</span>
          </h3>
          <button
            onClick={onClose}
            className={`p-1 rounded-lg transition-colors cursor-pointer ${
              themeMode === 'light' ? 'text-slate-400 hover:text-slate-700 hover:bg-slate-200' : 'text-slate-400 hover:text-white'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-xs font-mono">
          <div>
            <label className={`block uppercase tracking-wider mb-1.5 ${
              themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
            }`}>
              {language === 'zh' ? '域名地址 (DOMAIN NAME)' : 'DOMAIN NAME'}
            </label>
            <input
              type="text"
              required
              placeholder="example.com"
              value={domainName}
              onChange={(e) => setDomainName(e.target.value)}
              className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-950 border-slate-800 text-white placeholder-slate-600 focus:border-cyan-400'
              }`}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? '邮箱上限' : 'MAX MAILBOXES'}
              </label>
              <input
                type="number"
                value={mailboxesMax}
                onChange={(e) => setMailboxesMax(Number(e.target.value))}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              />
            </div>

            <div>
              <label className={`block uppercase tracking-wider mb-1.5 ${
                themeMode === 'light' ? 'text-slate-700 font-semibold' : 'text-slate-300'
              }`}>
                {language === 'zh' ? 'DKIM 选择器' : 'DKIM SELECTOR'}
              </label>
              <input
                type="text"
                value={dkimSelector}
                onChange={(e) => setDkimSelector(e.target.value)}
                className={`w-full px-3.5 py-2.5 rounded-xl border focus:outline-none transition-colors ${
                  themeMode === 'light'
                    ? 'bg-white border-slate-200 text-slate-900 focus:border-cyan-500 shadow-sm'
                    : 'bg-slate-950 border-slate-800 text-white focus:border-cyan-400'
                }`}
              />
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="w-full py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer font-sans"
            >
              <Plus className="w-4 h-4" />
              <span>{language === 'zh' ? '创建并生成 DKIM 密钥' : 'Create & Generate DKIM Keys'}</span>
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
};
