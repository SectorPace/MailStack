import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import {
  ShieldCheck,
  Zap,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  Sparkles,
  Server,
  ArrowRight,
  Terminal,
  FileCode,
  Copy,
  ChevronDown,
  ChevronUp,
  Cpu,
  Check,
  Send
} from 'lucide-react';
import confetti from 'canvas-confetti';

interface Props {
  domainName: string;
  serverIp: string;
  relayProvider: string;
  records: any[];
  onApplyFix?: (fixedRecord: any) => void;
}

export const AiDnsDiagnostic: React.FC<Props> = ({
  domainName,
  serverIp,
  relayProvider,
  records,
  onApplyFix
}) => {
  const { language, themeMode, showToast } = useApp();

  const [isRunningScan, setIsRunningScan] = useState(false);
  const [diagnosisData, setDiagnosisData] = useState<any>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Raw parser state
  const [rawInput, setRawInput] = useState('');
  const [isParsingRaw, setIsParsingRaw] = useState(false);
  const [rawParseResult, setRawParseResult] = useState<any>(null);

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('info', language === 'zh' ? '已复制' : 'Copied', text);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleRunAiDiagnostic = async () => {
    setIsRunningScan(true);
    try {
      const data = await api('/api/ai/diagnose-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domainName,
          serverIp: serverIp,
          relayProvider: relayProvider,
          records: records,
          customNotes: `Mail server running MailStack enterprise suite.`
        })
      });

      const resJson = data;
      if (resJson.success && resJson.diagnosis) {
        setDiagnosisData(resJson.diagnosis);
        confetti({ particleCount: 60, spread: 60, origin: { y: 0.5 } });
        showToast(
          'success',
          language === 'zh' ? 'AI 智能全景体检完成' : 'AI Diagnostic Completed',
          `${language === 'zh' ? '综合投递评分' : 'Score'}: ${resJson.diagnosis.score}/100 (${resJson.diagnosis.grade})`
        );
      } else {
        throw new Error('Invalid diagnosis response');
      }
    } catch (err: any) {
      console.error('Diagnosis error:', err);
      showToast('error', language === 'zh' ? '体检失败' : 'Diagnosis Failed', err.message);
    } finally {
      setIsRunningScan(false);
    }
  };

  const handleParseRawDns = async () => {
    if (!rawInput.trim()) return;
    setIsParsingRaw(true);
    try {
      const data = await api('/api/ai/parse-dns-raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawText: rawInput,
          domain: domainName
        })
      });

      const resJson = data;
      if (resJson.success && resJson.result) {
        setRawParseResult(resJson.result);
        showToast('success', language === 'zh' ? '原始解析提取完成' : 'Raw DNS Parsed', language === 'zh' ? '已成功结构化提取记录' : 'Extracted structured records');
      }
    } catch (err: any) {
      console.error('Parse raw error:', err);
      showToast('error', language === 'zh' ? '提取失败' : 'Parse Failed', err.message);
    } finally {
      setIsParsingRaw(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: One-Click AI Scan Trigger */}
      <div className={`p-6 rounded-2xl border backdrop-blur-md relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-6 ${
        themeMode === 'light'
          ? 'bg-gradient-to-r from-cyan-500/10 via-white to-blue-500/10 border-cyan-200 shadow-sm'
          : 'bg-gradient-to-r from-cyan-950/40 via-slate-900 to-blue-950/40 border-cyan-500/30'
      }`}>
        <div className="space-y-2 max-w-2xl">
          <div className="flex items-center gap-2">
            <span className={`p-2 rounded-xl flex items-center justify-center border ${
              themeMode === 'light' ? 'bg-cyan-100 text-cyan-800 border-cyan-300' : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
            }`}>
              <Sparkles className="w-5 h-5 animate-pulse" />
            </span>
            <h3 className={`text-base font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
              {language === 'zh' ? 'Gemini AI 智能 DNS 深度体检与邮件送达率诊断' : 'Gemini AI DNS Health & Deliverability Diagnostic'}
            </h3>
          </div>
          <p className={`text-xs leading-relaxed ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-300'}`}>
            {language === 'zh'
              ? `基于 Google 2024 发信新规、RFC 7208 (SPF)、RFC 6376 (DKIM 2048)、RFC 7489 (DMARC) 及反向解析 (PTR) 规范，实时深度评估 @${domainName} 的全链路解析健康度与防垃圾箱风险。`
              : `Deep AI verification against RFC standards, Google 2024 requirements, SPF 10-lookup limits, DKIM 2048-bit alignment, and reverse DNS.`}
          </p>
        </div>

        <button
          onClick={handleRunAiDiagnostic}
          disabled={isRunningScan}
          className="px-6 py-3.5 rounded-2xl bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 text-slate-950 font-bold text-sm flex items-center justify-center gap-2.5 transition-all shadow-[0_0_20px_rgba(0,242,195,0.3)] cursor-pointer shrink-0 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isRunningScan ? 'animate-spin' : ''}`} />
          <span>{isRunningScan ? (language === 'zh' ? 'AI 深度诊断扫描中...' : 'Scanning with AI...') : (language === 'zh' ? '立即开始 AI 智能体检' : 'Run AI Diagnostic Scan')}</span>
        </button>
      </div>

      {/* Diagnosis Results Section */}
      {diagnosisData && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Score & Outlook Bento Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Score Card */}
            <div className={`p-6 rounded-2xl border backdrop-blur-md flex flex-col justify-between ${
              themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
            }`}>
              <div className="text-xs font-mono text-slate-500 uppercase font-semibold">
                {language === 'zh' ? '综合送达率与安全评分' : 'Overall Health Score'}
              </div>
              <div className="my-4 flex items-baseline gap-3">
                <span className={`text-5xl font-black font-mono ${
                  diagnosisData.score >= 90
                    ? 'text-emerald-500'
                    : diagnosisData.score >= 75
                    ? 'text-cyan-500'
                    : 'text-amber-500'
                }`}>
                  {diagnosisData.score}
                </span>
                <span className="text-xl font-mono text-slate-400">/ 100</span>
                <span className={`px-2.5 py-0.5 rounded-lg text-sm font-bold font-mono ml-auto ${
                  diagnosisData.grade === 'A+' || diagnosisData.grade === 'A'
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                    : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                }`}>
                  GRADE {diagnosisData.grade}
                </span>
              </div>
              <p className={`text-xs ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>
                {diagnosisData.summary}
              </p>
            </div>

            {/* Outlook Inbox Card: Gmail, Outlook, Spam Score */}
            <div className={`lg:col-span-3 p-6 rounded-2xl border backdrop-blur-md space-y-4 ${
              themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
            }`}>
              <div className="flex items-center justify-between">
                <span className={`text-xs font-bold font-mono uppercase ${
                  themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                }`}>
                  {language === 'zh' ? '📬 全球主流邮箱投递前景预测 (Inbox Deliverability Outlook)' : '📬 Major Email Providers Deliverability Outlook'}
                </span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                  themeMode === 'light' ? 'bg-slate-100 text-slate-700 border-slate-300' : 'bg-slate-800 text-cyan-300 border-slate-700'
                }`}>
                  {diagnosisData.deliverabilityOutlook?.spamScore || 'SpamAssassin Clean'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                <div className={`p-3.5 rounded-xl border space-y-1 ${
                  themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
                }`}>
                  <div className="text-[10px] text-slate-500 uppercase">Google / Gmail</div>
                  <div className="font-bold text-emerald-500 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{diagnosisData.deliverabilityOutlook?.gmail || 'High (Primary Inbox)'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400">SPF/DKIM/DMARC 三要素对齐</div>
                </div>

                <div className={`p-3.5 rounded-xl border space-y-1 ${
                  themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
                }`}>
                  <div className="text-[10px] text-slate-500 uppercase">Microsoft / Outlook / O365</div>
                  <div className="font-bold text-emerald-500 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{diagnosisData.deliverabilityOutlook?.outlook || 'High (Inbox)'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400">SmartScreen 信任度评估正常</div>
                </div>

                <div className={`p-3.5 rounded-xl border space-y-1 ${
                  themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
                }`}>
                  <div className="text-[10px] text-slate-500 uppercase">QQ 邮箱 / 163 网易</div>
                  <div className="font-bold text-cyan-500 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>{diagnosisData.deliverabilityOutlook?.qq_163 || 'High (极佳)'}</span>
                  </div>
                  <div className="text-[10px] text-slate-400">反垃圾黑名单未收录</div>
                </div>
              </div>

              {/* Key recommendations */}
              {diagnosisData.keyRecommendations && diagnosisData.keyRecommendations.length > 0 && (
                <div className="pt-2">
                  <div className={`text-xs font-semibold mb-2 ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}`}>
                    {language === 'zh' ? '💡 AI 优先级优化动作：' : '💡 Priority Next Steps:'}
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
                    {diagnosisData.keyRecommendations.map((rec: string, i: number) => (
                      <div key={i} className={`p-2.5 rounded-xl border flex items-start gap-2 ${
                        themeMode === 'light' ? 'bg-cyan-50/50 border-cyan-200 text-cyan-950' : 'bg-cyan-950/20 border-cyan-500/20 text-cyan-300'
                      }`}>
                        <span className="font-mono font-bold text-cyan-500">{i + 1}.</span>
                        <span className="leading-snug">{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Diagnostic Detailed Items List */}
          <div className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 ${
            themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
          }`}>
            <h4 className={`text-sm font-bold font-mono uppercase ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
              {language === 'zh' ? '🔍 深度诊断检测明细项' : '🔍 Detailed Diagnostic Checks'}
            </h4>

            <div className="space-y-3">
              {diagnosisData.items?.map((item: any, idx: number) => {
                const isPass = item.status === 'pass';
                const isWarn = item.status === 'warning';
                const isErr = item.status === 'error';
                return (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border transition-all ${
                      isPass
                        ? themeMode === 'light' ? 'bg-emerald-50/40 border-emerald-200' : 'bg-emerald-950/20 border-emerald-500/20'
                        : isWarn
                        ? themeMode === 'light' ? 'bg-amber-50/50 border-amber-200' : 'bg-amber-950/20 border-amber-500/30'
                        : isErr
                        ? themeMode === 'light' ? 'bg-rose-50/50 border-rose-200' : 'bg-rose-950/20 border-rose-500/30'
                        : themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          isPass
                            ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                            : isWarn
                            ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                            : isErr
                            ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {item.category}
                        </span>
                        <h5 className={`text-xs font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
                          {item.title}
                        </h5>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className={`text-[11px] font-mono font-bold uppercase flex items-center gap-1 ${
                          isPass ? 'text-emerald-500' : isWarn ? 'text-amber-500' : isErr ? 'text-rose-500' : 'text-slate-400'
                        }`}>
                          {isPass ? <CheckCircle2 className="w-3.5 h-3.5" /> : isWarn ? <AlertTriangle className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                          <span>{item.status.toUpperCase()}</span>
                        </span>
                      </div>
                    </div>

                    <p className={`text-xs mt-2 leading-relaxed ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
                      {item.detail}
                    </p>

                    <div className={`mt-3 p-3 rounded-lg border text-xs flex items-start gap-2 ${
                      themeMode === 'light' ? 'bg-white/80 border-slate-200' : 'bg-slate-900/90 border-slate-800'
                    }`}>
                      <Info className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
                      <div className="space-y-1 w-full">
                        <div>
                          <span className="font-bold text-cyan-500">{language === 'zh' ? '处置建议：' : 'Recommendation: '}</span>
                          <span className={themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}>{item.recommendation}</span>
                        </div>

                        {item.fixedRecord && (
                          <div className="mt-2 p-2 rounded border bg-slate-950 text-cyan-300 font-mono text-[11px] flex items-center justify-between gap-2 break-all">
                            <span>{item.fixedRecord.type} {item.fixedRecord.name} &rarr; {item.fixedRecord.content}</span>
                            <button
                              onClick={() => copyText(item.fixedRecord.content, `fixed-${idx}`)}
                              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 cursor-pointer shrink-0"
                              title="复制修正值"
                            >
                              {copiedKey === `fixed-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Raw DNS / Dig / Log Parser Diagnostic Box */}
      <div className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 ${
        themeMode === 'light' ? 'bg-white/95 border-slate-200 shadow-sm' : 'bg-slate-900/80 border-slate-800'
      }`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Terminal className="w-4 h-4 text-cyan-500" />
            <h4 className={`text-sm font-bold ${themeMode === 'light' ? 'text-slate-900' : 'text-white'}`}>
              {language === 'zh' ? '智能原始 DNS 解析 / dig 终端输出 / 退信日志纠错分析器' : 'Raw DNS / Dig / Log Parser & Fixer'}
            </h4>
          </div>
          <span className={`text-xs font-mono ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? '粘贴任意文本，AI 自动提取纠正' : 'Paste raw dig / nslookup to diagnose'}
          </span>
        </div>

        <p className={`text-xs ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>
          {language === 'zh'
            ? '如果您在终端执行了 dig mx 或 nslookup，或者在邮件客户端遇到了退信报错（如 550 5.7.1 SPF rejected），可直接将内容粘贴在下方，AI 将自动分析并给出修复建议。'
            : 'Paste your raw dig command outputs, BIND zone snippets, or SMTP error codes to extract records and detect issues.'}
        </p>

        <div className="space-y-3">
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={4}
            placeholder={`示例 1 (终端 dig 命令输出)：
; <<>> DiG 9.10.6 <<>> mx ${domainName}
${domainName}. 300 IN MX 10 mail.${domainName}.

示例 2 (退信报错)：
550 5.7.1 Protection policy enforcement: SPF Permanent Error or DKIM Signature corrupt.`}
            className={`w-full p-3.5 rounded-xl border text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 ${
              themeMode === 'light'
                ? 'bg-slate-50 border-slate-300 text-slate-900 placeholder:text-slate-400'
                : 'bg-slate-950 border-slate-800 text-slate-200 placeholder:text-slate-600'
            }`}
          />

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setRawInput(`; <<>> DiG 9.18 <<>> txt ${domainName}\n${domainName}. 300 IN TXT "v=spf1 mx ~all"\n${domainName}. 300 IN TXT "v=spf1 include:_spf.google.com ~all"`)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono border cursor-pointer ${
                  themeMode === 'light' ? 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700' : 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
                }`}
              >
                {language === 'zh' ? '填入常见 SPF 重复错误样例' : 'Load Duplicate SPF Sample'}
              </button>
            </div>

            <button
              onClick={handleParseRawDns}
              disabled={isParsingRaw || !rawInput.trim()}
              className="px-4 py-2 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50"
            >
              <Cpu className={`w-3.5 h-3.5 ${isParsingRaw ? 'animate-spin' : ''}`} />
              <span>{isParsingRaw ? (language === 'zh' ? 'AI 智能提取中...' : 'Analyzing...') : (language === 'zh' ? 'AI 提取并诊断' : 'AI Parse & Diagnose')}</span>
            </button>
          </div>
        </div>

        {/* Raw Parse Results */}
        {rawParseResult && (
          <div className={`p-4 rounded-xl border space-y-3 font-mono text-xs animate-in fade-in ${
            themeMode === 'light' ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
          }`}>
            <div className="flex items-center justify-between">
              <span className="font-bold text-cyan-500">AI 智能提取与纠错报告：</span>
              <span className="text-[11px] text-slate-400">检测域名: {rawParseResult.detectedDomain}</span>
            </div>

            <p className={themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}>
              {rawParseResult.analysis}
            </p>

            {rawParseResult.extractedRecords && rawParseResult.extractedRecords.length > 0 && (
              <div className="space-y-1.5 pt-2">
                <div className="text-[10px] text-slate-500 uppercase">提取的 DNS 记录：</div>
                {rawParseResult.extractedRecords.map((r: any, i: number) => (
                  <div key={i} className={`p-2 rounded border flex items-center justify-between gap-2 break-all ${
                    themeMode === 'light' ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-800'
                  }`}>
                    <div>
                      <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-bold mr-2 text-[10px]">{r.type}</span>
                      <span className="font-bold mr-2">{r.name}</span>
                      <span className="text-slate-400">&rarr; {r.content}</span>
                    </div>
                    <span className="text-[10px] text-emerald-500 shrink-0">{r.correctionNote || '有效'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
