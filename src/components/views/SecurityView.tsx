import React, { useState, useEffect } from 'react';
import { useApp } from '../../context/AppContext';
import { api } from '../../api';
import { getErrorMessage } from '../../utils/errors';
import { ShieldAlert, ShieldCheck, Lock, AlertTriangle, RefreshCw, Trash2, CheckCircle2 } from '@/lib/icons';

interface BannedIp {
  ip: string;
  jail: string;
  time: string;
  reason: string;
}

interface SecurityAnomaly {
  id: string;
  timestamp: string;
  type: string;
  message: string;
  severity: 'high' | 'medium' | 'low';
}

export const SecurityView: React.FC = () => {
  const { language, showToast, themeMode } = useApp();
  const [score, setScore] = useState<number>(100);
  const [anomalies, setAnomalies] = useState<SecurityAnomaly[]>([]);
  const [bannedIps, setBannedIps] = useState<BannedIp[]>([]);
  const [loading, setLoading] = useState(false);
  const [newIpToBan, setNewIpToBan] = useState('');
  const [banJail, setBanJail] = useState('postfix-sasl');

  const loadScan = async () => {
    setLoading(true);
    try {
      const res = await api('/api/security/scan', { method: 'POST', body: '{}' });
      setScore(typeof res.score === 'number' ? res.score : 100);
      setAnomalies(Array.isArray(res.events) ? res.events : []);
      setBannedIps(Array.isArray(res.bannedIps) ? res.bannedIps : []);
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '安全扫描失败' : 'Security Scan Failed', getErrorMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScan();
  }, []);

  const handleUnban = async (ip: string, jail: string) => {
    try {
      await api('/api/security/unban', {
        method: 'POST',
        body: JSON.stringify({ ip, jail }),
      });
      showToast(
        'success',
        language === 'zh' ? 'IP 已解封' : 'IP Unbanned',
        `${ip} ${language === 'zh' ? '已从防火墙与 Fail2ban 移除' : 'removed from firewall table'}`
      );
      loadScan();
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '解封操作失败' : 'Unban Failed', getErrorMessage(e));
    }
  };

  const handleManualBan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIpToBan.trim()) return;
    try {
      await api('/api/security/ban', {
        method: 'POST',
        body: JSON.stringify({ ip: newIpToBan.trim(), jail: banJail }),
      });
      showToast(
        'warning',
        language === 'zh' ? 'IP 已加入封禁名单' : 'IP Banned',
        `${newIpToBan} ${language === 'zh' ? '已下发至防火墙规则' : 'blocked in firewall'}`
      );
      setNewIpToBan('');
      loadScan();
    } catch (e: unknown) {
      showToast('error', language === 'zh' ? '封禁操作失败' : 'Ban Failed', getErrorMessage(e));
    }
  };

  const isLight = themeMode === 'light';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top 3 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div
          className={`p-5 rounded-2xl border backdrop-blur-md ${
            isLight ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
          }`}
        >
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? '系统安全得分 (Security Score)' : 'Security Score'}
          </div>
          <div className="flex items-center justify-between">
            <div className={`text-3xl font-black font-mono ${score >= 80 ? 'text-emerald-500' : score >= 60 ? 'text-amber-500' : 'text-rose-500'}`}>
              {score} / 100
            </div>
            <button
              onClick={loadScan}
              disabled={loading}
              title={language === 'zh' ? '重新扫描' : 'Rescan'}
              className="p-2 rounded-xl border border-slate-700/50 hover:bg-slate-800/50 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
            </button>
          </div>
        </div>

        <div
          className={`p-5 rounded-2xl border backdrop-blur-md ${
            isLight ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
          }`}
        >
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? 'Fail2ban 封禁总数' : 'Fail2ban Total Bans'}
          </div>
          <div className="text-3xl font-black text-rose-500 font-mono">{bannedIps.length}</div>
        </div>

        <div
          className={`p-5 rounded-2xl border backdrop-blur-md ${
            isLight ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
          }`}
        >
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? '安全异常侦测 (Anomalies)' : 'Detected Anomalies'}
          </div>
          <div className={`text-3xl font-black font-mono ${anomalies.length === 0 ? 'text-emerald-500' : 'text-amber-500'}`}>
            {anomalies.length}
          </div>
        </div>
      </div>

      {/* Security Anomalies Panel */}
      {anomalies.length > 0 && (
        <div
          className={`p-6 rounded-2xl border backdrop-blur-md space-y-3 ${
            isLight ? 'bg-amber-50/70 border-amber-200/80' : 'bg-amber-950/20 border-amber-900/50'
          }`}
        >
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            <h3 className={`text-sm font-bold ${isLight ? 'text-amber-950' : 'text-amber-200'}`}>
              {language === 'zh' ? '待处置安全建议项' : 'Security Advisory Items'}
            </h3>
          </div>
          <div className="space-y-2">
            {anomalies.map((item) => (
              <div
                key={item.id}
                className={`p-3 rounded-xl border flex items-center justify-between text-xs font-mono ${
                  isLight ? 'bg-white/90 border-amber-200 text-slate-800' : 'bg-slate-950/60 border-slate-800 text-slate-200'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      item.severity === 'high'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {item.severity}
                  </span>
                  <span>{item.message}</span>
                </div>
                <span className="text-[11px] text-slate-400">{item.timestamp?.slice(0, 19)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manual Ban Bar & Table */}
      <div
        className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 ${
          isLight ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className={`text-sm font-bold flex items-center gap-2 ${isLight ? 'text-slate-800' : 'text-white'}`}>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>{language === 'zh' ? 'Fail2ban 封禁 IP 实时列表' : 'Fail2ban Active IP Jail List'}</span>
            </h3>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh' ? '监控暴力破解并自动阻止恶意 SASL 与 IMAP 认证' : 'Automated brute-force prevention and SASL defense'}
            </p>
          </div>

          <form onSubmit={handleManualBan} className="flex items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="192.0.2.1"
              value={newIpToBan}
              onChange={(e) => setNewIpToBan(e.target.value)}
              className={`h-9 px-3 rounded-xl border focus:outline-none focus:border-rose-400 ${
                isLight
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400'
                  : 'bg-slate-950 border-slate-800 text-white placeholder-slate-600'
              }`}
            />
            <select
              value={banJail}
              onChange={(e) => setBanJail(e.target.value)}
              className={`h-9 px-2 rounded-xl border focus:outline-none ${
                isLight
                  ? 'bg-white border-slate-200 text-slate-700'
                  : 'bg-slate-950 border-slate-800 text-slate-300'
              }`}
            >
              <option value="postfix-sasl">postfix-sasl</option>
              <option value="dovecot">dovecot</option>
            </select>
            <button
              type="submit"
              disabled={!newIpToBan.trim()}
              className={`h-9 px-3.5 rounded-xl border font-semibold transition-colors font-sans ${
                isLight
                  ? 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100'
                  : 'bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border-rose-500/40'
              }`}
            >
              {language === 'zh' ? '手动封禁 IP' : 'Ban IP'}
            </button>
          </form>
        </div>

        {/* Banned Table */}
        <div className={`rounded-xl border overflow-hidden font-mono text-xs ${isLight ? 'border-slate-200' : 'border-slate-800'}`}>
          <table className="w-full text-left">
            <thead
              className={`border-b text-[11px] uppercase ${
                isLight
                  ? 'border-slate-200 bg-slate-50 text-slate-600 font-semibold'
                  : 'border-slate-800 bg-slate-950/80 text-slate-400'
              }`}
            >
              <tr>
                <th className="px-4 py-3">{language === 'zh' ? '恶意 IP 地址' : 'IP ADDRESS'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '防护规则 (JAIL)' : 'JAIL'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '封禁原因' : 'REASON'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '状态' : 'STATUS'}</th>
                <th className="px-4 py-3 text-right">{language === 'zh' ? '操作' : 'ACTION'}</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isLight ? 'divide-slate-200 bg-white' : 'divide-slate-800/60'}`}>
              {bannedIps.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500 font-sans">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <CheckCircle2 className="w-6 h-6 text-emerald-500" />
                      <span>{language === 'zh' ? '当前无被封禁的 IP 地址' : 'No active IP bans found'}</span>
                    </div>
                  </td>
                </tr>
              ) : (
                bannedIps.map((item) => (
                  <tr key={item.ip} className={isLight ? 'hover:bg-slate-50' : 'hover:bg-slate-800/40'}>
                    <td className="px-4 py-3 font-bold text-rose-500">{item.ip}</td>
                    <td className={`px-4 py-3 ${isLight ? 'text-slate-700 font-medium' : 'text-slate-300'}`}>{item.jail}</td>
                    <td className={`px-4 py-3 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>{item.reason}</td>
                    <td className={`px-4 py-3 text-[11px] ${isLight ? 'text-slate-400' : 'text-slate-500'}`}>{item.time}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleUnban(item.ip, item.jail)}
                        className={`px-2.5 py-1 rounded-lg text-xs font-sans font-medium transition-colors border ${
                          isLight
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                            : 'bg-slate-800 hover:bg-slate-700 text-emerald-400 border-transparent'
                        }`}
                      >
                        {language === 'zh' ? '解除封禁' : 'Unban'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
