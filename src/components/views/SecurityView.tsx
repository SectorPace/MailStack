import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { ShieldAlert, ShieldCheck, Lock, AlertTriangle, UserX, Globe, Terminal, Trash2 } from 'lucide-react';

export const SecurityView: React.FC = () => {
  const { language, showToast, themeMode } = useApp();
  const [bannedIps, setBannedIps] = useState([
    { ip: '185.220.101.42', jail: 'postfix-sasl', time: '10 分钟前', reason: '5 次密码错误' },
    { ip: '45.154.255.89', jail: 'dovecot-imap', time: '35 分钟前', reason: '暴力破解攻击' },
    { ip: '194.26.29.112', jail: 'postfix-ddos', time: '2 小时前', reason: '异常高频 RCPT 扫描' },
  ]);

  const [newIpToBan, setNewIpToBan] = useState('');

  const handleUnban = (ip: string) => {
    setBannedIps(prev => prev.filter(b => b.ip !== ip));
    showToast('success', language === 'zh' ? 'IP 已解封' : 'IP Unbanned', `${ip} ${language === 'zh' ? '已从 Fail2ban 与 iptables 链移除' : 'removed from firewall table'}`);
  };

  const handleManualBan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIpToBan.trim()) return;
    setBannedIps(prev => [
      { ip: newIpToBan.trim(), jail: 'manual-block', time: '刚刚', reason: '管理员手动封禁' },
      ...prev
    ]);
    setNewIpToBan('');
    showToast('warning', language === 'zh' ? 'IP 已加入封禁名单' : 'IP Banned', `${newIpToBan} ${language === 'zh' ? '已下发至防火墙规则' : 'blocked in firewall'}`);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top 3 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? 'Fail2ban 封禁总数' : 'Fail2ban Total Bans'}
          </div>
          <div className="text-3xl font-black text-rose-500 font-mono">{bannedIps.length}</div>
        </div>

        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? 'Rspamd 垃圾邮件拦截' : 'Spam Filter Rate'}
          </div>
          <div className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-emerald-600' : 'text-emerald-400'}`}>99.4%</div>
        </div>

        <div className={`p-5 rounded-2xl border backdrop-blur-md ${
          themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
        }`}>
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
            {language === 'zh' ? 'GeoIP 地理防护策略' : 'GeoIP Shield'}
          </div>
          <div className={`text-3xl font-black font-mono ${themeMode === 'light' ? 'text-cyan-700' : 'text-cyan-400'}`}>
            {language === 'zh' ? '已启用' : 'Active'}
          </div>
        </div>
      </div>

      {/* Manual Ban Bar & Table */}
      <div className={`p-6 rounded-2xl border backdrop-blur-md space-y-4 ${
        themeMode === 'light' ? 'bg-white/85 border-slate-200/90 shadow-sm' : 'bg-slate-900/70 border-slate-800/90'
      }`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className={`text-sm font-bold flex items-center gap-2 ${themeMode === 'light' ? 'text-slate-800' : 'text-white'}`}>
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>{language === 'zh' ? 'Fail2ban 封禁 IP 实时列表' : 'Fail2ban Active IP Jail List'}</span>
            </h3>
            <p className={`text-xs mt-0.5 ${themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'}`}>
              {language === 'zh' ? '监控暴力破解并自动阻止恶意 SASL 认证请求' : 'Automated brute-force prevention and SASL defense'}
            </p>
          </div>

          <form onSubmit={handleManualBan} className="flex items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="192.0.2.1"
              value={newIpToBan}
              onChange={(e) => setNewIpToBan(e.target.value)}
              className={`h-9 px-3 rounded-xl border focus:outline-none focus:border-rose-400 ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400'
                  : 'bg-slate-950 border-slate-800 text-white placeholder-slate-600'
              }`}
            />
            <button
              type="submit"
              className={`h-9 px-3.5 rounded-xl border font-semibold transition-colors font-sans ${
                themeMode === 'light'
                  ? 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100'
                  : 'bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border-rose-500/40'
              }`}
            >
              {language === 'zh' ? '手动封禁 IP' : 'Ban IP'}
            </button>
          </form>
        </div>

        {/* Banned Table */}
        <div className={`rounded-xl border overflow-hidden font-mono text-xs ${
          themeMode === 'light' ? 'border-slate-200' : 'border-slate-800'
        }`}>
          <table className="w-full text-left">
            <thead className={`border-b text-[11px] uppercase ${
              themeMode === 'light' ? 'border-slate-200 bg-slate-50 text-slate-600 font-semibold' : 'border-slate-800 bg-slate-950/80 text-slate-400'
            }`}>
              <tr>
                <th className="px-4 py-3">{language === 'zh' ? '恶意 IP 地址' : 'IP ADDRESS'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '防护规则 (JAIL)' : 'JAIL'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '封禁原因' : 'REASON'}</th>
                <th className="px-4 py-3">{language === 'zh' ? '拦截时间' : 'TIME'}</th>
                <th className="px-4 py-3 text-right">{language === 'zh' ? '操作' : 'ACTION'}</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${themeMode === 'light' ? 'divide-slate-200 bg-white' : 'divide-slate-800/60'}`}>
              {bannedIps.map((item) => (
                <tr key={item.ip} className={themeMode === 'light' ? 'hover:bg-slate-50' : 'hover:bg-slate-800/40'}>
                  <td className="px-4 py-3 font-bold text-rose-500">{item.ip}</td>
                  <td className={`px-4 py-3 ${themeMode === 'light' ? 'text-slate-700 font-medium' : 'text-slate-300'}`}>{item.jail}</td>
                  <td className={`px-4 py-3 ${themeMode === 'light' ? 'text-slate-600' : 'text-slate-400'}`}>{item.reason}</td>
                  <td className={`px-4 py-3 text-[11px] ${themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'}`}>{item.time}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleUnban(item.ip)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-sans font-medium transition-colors border ${
                        themeMode === 'light'
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                          : 'bg-slate-800 hover:bg-slate-700 text-emerald-400 border-transparent'
                      }`}
                    >
                      {language === 'zh' ? '解除封禁' : 'Unban'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
