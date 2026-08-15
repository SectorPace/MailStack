import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { Sparkles, Bot, Stethoscope, MessageSquareCode, ShieldCheck, Zap } from 'lucide-react';
import { LiquidGlass } from '../common/LiquidGlass';
import { AiDiagnosticView } from './AiDiagnosticView';
import { AiAssistantView } from './AiAssistantView';
import { AiProviderSettings } from './AiProviderSettings';

export const AiSuiteView: React.FC<{ initialTab?: 'diagnostic' | 'assistant' }> = ({
  initialTab = 'diagnostic',
}) => {
  const { language, themeMode } = useApp();
  const [activeTab, setActiveTab] = useState<'diagnostic' | 'assistant' | 'provider'>(initialTab);
  const isLight = themeMode === 'light';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top Suite Bar & Tab Switcher */}
      <LiquidGlass
        variant="panel"
        glowColor="cyan"
        className="p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-2xl bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center text-cyan-400 shadow-sm shrink-0">
            <Sparkles className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className={`text-lg font-bold tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {language === 'zh' ? 'AI 智能中心' : 'AI Intelligence Suite'}
              </h2>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-400/15 text-cyan-500 dark:text-cyan-400 border border-cyan-400/30">
                PRO ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {language === 'zh'
                ? '集成 RFC 标准 DNS/中继健康全景诊断 与 深度协议架构顾问'
                : 'Integrated RFC DNS health diagnostics & protocol architecture advisor'}
            </p>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-2 p-1 rounded-2xl border bg-black/10 dark:bg-black/40 border-white/10 shrink-0">
          <button
            onClick={() => setActiveTab('diagnostic')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'diagnostic'
                ? isLight
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'bg-cyan-400 text-slate-950 shadow-[0_0_12px_rgba(0,242,195,0.3)]'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Stethoscope className="w-4 h-4" />
            <span>{language === 'zh' ? 'AI 智能诊断' : 'AI Diagnostic'}</span>
          </button>

          <button
            onClick={() => setActiveTab('assistant')}
            className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer ${
              activeTab === 'assistant'
                ? isLight
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'bg-cyan-400 text-slate-950 shadow-[0_0_12px_rgba(0,242,195,0.3)]'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Bot className="w-4 h-4" />
            <span>{language === 'zh' ? 'AI 邮件顾问' : 'AI Consultant'}</span>
          </button>
          <button onClick={() => setActiveTab('provider')} className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition-all cursor-pointer ${activeTab === 'provider' ? (isLight ? 'bg-sky-600 text-white' : 'bg-cyan-400 text-slate-950') : 'text-slate-500 dark:text-slate-400'}`}><ShieldCheck className="w-4 h-4"/><span>{language === 'zh' ? 'API 设置' : 'API Settings'}</span></button>
        </div>
      </LiquidGlass>

      {/* Render selected view with seamless transition */}
      <div className="transition-all duration-300">
        {activeTab === 'diagnostic' ? <AiDiagnosticView /> : activeTab === 'assistant' ? <AiAssistantView /> : <AiProviderSettings />}
      </div>
    </div>
  );
};
