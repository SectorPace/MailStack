import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { DomainItem } from '../../types';
import {
  Globe,
  Plus,
  Search,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Eye,
  Trash2,
  ShieldCheck,
  RefreshCw,
  SlidersHorizontal
} from 'lucide-react';
import { AddDomainModal } from '../modals/AddDomainModal';
import { DnsCheckModal } from '../modals/DnsCheckModal';
import { LiquidGlass } from '../common/LiquidGlass';

export const DomainsView: React.FC = () => {
  const { domains, deleteDomain, language, themeMode, showToast } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [inspectDomain, setInspectDomain] = useState<DomainItem | null>(null);

  const filteredDomains = domains.filter((d) =>
    d.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const totalMailboxes = domains.reduce((acc, d) => acc + d.mailboxesCount, 0);

  const handleBatchDnsCheck = () => {
    showToast(
      'info',
      language === 'zh' ? '正在执行全局 DNS 扫描' : 'Batch DNS Check',
      language === 'zh' ? '正在请求权威 DNS 解析服务器...' : 'Querying authoritative nameservers...'
    );
    setTimeout(() => {
      showToast(
        'success',
        language === 'zh' ? 'DNS 批量重测完成' : 'DNS Re-check Completed',
        language === 'zh' ? '除 corp-internal.net 待修复 SPF 外其余域名全绿' : 'All domains verified except corp-internal.net'
      );
    }, 1000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* Top 3 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Card 1: Hosted Domains */}
        <LiquidGlass variant="card" glowColor="cyan" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '已托管域名' : 'Hosted Domains'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              themeMode === 'light' ? 'text-slate-900' : 'text-white'
            }`}>{domains.length}</span>
            <span className={`text-xs ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>{language === 'zh' ? '个独立域' : 'unique domains'}</span>
          </div>
        </LiquidGlass>

        {/* Card 2: Health Score */}
        <LiquidGlass variant="card" glowColor="emerald" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '整体健康度' : 'Health Score'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              themeMode === 'light' ? 'text-emerald-600' : 'text-emerald-400'
            }`}>92%</span>
            <span className={`text-xs font-mono ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>MX / SPF / DKIM</span>
          </div>
        </LiquidGlass>

        {/* Card 3: Total Mailboxes */}
        <LiquidGlass variant="card" glowColor="sky" className="p-5">
          <div className={`text-[11px] font-mono uppercase tracking-wider mb-1 ${
            themeMode === 'light' ? 'text-slate-500 font-semibold' : 'text-slate-400'
          }`}>
            {language === 'zh' ? '总邮箱账户' : 'Total Mailboxes'}
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-black font-mono ${
              themeMode === 'light' ? 'text-slate-900' : 'text-white'
            }`}>{totalMailboxes}</span>
            <span className={`text-xs ${
              themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
            }`}>{language === 'zh' ? '个活跃信箱' : 'active accounts'}</span>
          </div>
        </LiquidGlass>
      </div>

      {/* Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className={`w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 ${
              themeMode === 'light' ? 'text-slate-400' : 'text-slate-500'
            }`} />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={language === 'zh' ? '搜索域名地址...' : 'Search domain...'}
              className={`w-full h-10 pl-10 pr-4 rounded-xl border text-xs font-mono focus:outline-none transition-colors ${
                themeMode === 'light'
                  ? 'bg-white border-slate-200 text-slate-900 placeholder-slate-400 focus:border-cyan-500 shadow-sm'
                  : 'bg-slate-900 border-slate-800 text-white placeholder-slate-500 focus:border-cyan-400'
              }`}
            />
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleBatchDnsCheck}
            className={`h-10 px-3.5 rounded-xl border text-xs font-semibold flex items-center gap-2 transition-colors cursor-pointer ${
              themeMode === 'light'
                ? 'bg-white border-slate-200 hover:bg-slate-50 text-slate-700 shadow-sm'
                : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
            }`}
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-500" />
            <span>{language === 'zh' ? 'DNS 批量重测' : 'Batch DNS Check'}</span>
          </button>

          <button
            onClick={() => setIsAddModalOpen(true)}
            className="h-10 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all hover:scale-[1.02] cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>{language === 'zh' ? '添加新域名' : 'Add Domain'}</span>
          </button>
        </div>
      </div>

      {/* Domains Data Table */}
      <LiquidGlass variant="panel" interactive={false} className="rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className={`border-b text-[11px] font-mono uppercase tracking-wider ${
              themeMode === 'light'
                ? 'border-slate-200 bg-slate-50 text-slate-600 font-semibold'
                : 'border-slate-800 bg-slate-950/80 text-slate-400'
            }`}>
              <tr>
                <th className="px-5 py-3.5">{language === 'zh' ? '域名 (DOMAIN)' : 'DOMAIN'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '创建时间' : 'CREATED'}</th>
                <th className="px-4 py-3.5 text-center">MX</th>
                <th className="px-4 py-3.5 text-center">SPF</th>
                <th className="px-4 py-3.5 text-center">DKIM</th>
                <th className="px-4 py-3.5 text-center">DMARC</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '邮箱配额' : 'MAILBOXES'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '运行状况 (STATUS)' : 'HEALTH STATUS'}</th>
                <th className="px-5 py-3.5 text-right">{language === 'zh' ? '操作' : 'ACTIONS'}</th>
              </tr>
            </thead>
            <tbody className={`divide-y font-mono ${
              themeMode === 'light' ? 'divide-slate-200' : 'divide-slate-800/60'
            }`}>
              {filteredDomains.map((dom) => {
                const getStatusIcon = (st: string) => {
                  if (st === 'ok') {
                    return (
                      <span className={themeMode === 'light' ? 'text-emerald-600 font-bold' : 'text-emerald-400 font-bold'}>
                        ✓
                      </span>
                    );
                  }
                  if (st === 'error') {
                    return (
                      <span className={themeMode === 'light' ? 'text-rose-600 font-bold' : 'text-rose-400 font-bold'}>
                        ✗
                      </span>
                    );
                  }
                  return (
                    <span className={themeMode === 'light' ? 'text-amber-600 font-bold' : 'text-amber-400 font-bold'}>
                      ●
                    </span>
                  );
                };

                // Light and dark mode adaptive health status styles
                const getStatusBadge = () => {
                  if (dom.status === 'active') {
                    return themeMode === 'light'
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-300 font-semibold'
                      : 'text-emerald-400 bg-emerald-950/80 border-emerald-500/40';
                  }
                  if (dom.status === 'spf_failed') {
                    return themeMode === 'light'
                      ? 'bg-amber-50 text-amber-800 border-amber-300 font-semibold'
                      : 'text-amber-400 bg-amber-950/80 border-amber-500/40';
                  }
                  if (dom.status === 'pending') {
                    return themeMode === 'light'
                      ? 'bg-sky-50 text-sky-800 border-sky-300 font-semibold'
                      : 'text-sky-400 bg-sky-950 border-sky-800';
                  }
                  return themeMode === 'light'
                    ? 'bg-slate-100 text-slate-700 border-slate-300 font-semibold'
                    : 'text-slate-400 bg-slate-800 border-slate-700';
                };

                return (
                  <tr key={dom.id} className={`transition-colors group ${
                    themeMode === 'light' ? 'hover:bg-slate-50/80' : 'hover:bg-slate-800/40'
                  }`}>
                    {/* Domain Name */}
                    <td className={`px-5 py-3.5 font-semibold flex items-center gap-2 ${
                      themeMode === 'light' ? 'text-slate-900' : 'text-white'
                    }`}>
                      <Globe className={`w-4 h-4 ${themeMode === 'light' ? 'text-cyan-600' : 'text-cyan-400'}`} />
                      <span>{dom.name}</span>
                    </td>

                    {/* Created Date */}
                    <td className={`px-5 py-3.5 text-[11px] ${
                      themeMode === 'light' ? 'text-slate-500' : 'text-slate-400'
                    }`}>
                      {dom.createdAt}
                    </td>

                    {/* DNS Records Status Badges */}
                    <td className="px-4 py-3.5 text-center">{getStatusIcon(dom.mxStatus)}</td>
                    <td className="px-4 py-3.5 text-center">{getStatusIcon(dom.spfStatus)}</td>
                    <td className="px-4 py-3.5 text-center">{getStatusIcon(dom.dkimStatus)}</td>
                    <td className="px-4 py-3.5 text-center">{getStatusIcon(dom.dmarcStatus)}</td>

                    {/* Mailboxes count */}
                    <td className={`px-5 py-3.5 ${
                      themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'
                    }`}>
                      <span className={`font-semibold ${
                        themeMode === 'light' ? 'text-slate-900' : 'text-white'
                      }`}>{dom.mailboxesCount}</span> / {dom.mailboxesMax}
                    </td>

                    {/* Overall Health Status Badge (Fixed for Light & Dark) */}
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-sans border ${getStatusBadge()}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          dom.status === 'active'
                            ? 'bg-emerald-500'
                            : dom.status === 'spf_failed'
                            ? 'bg-amber-500'
                            : dom.status === 'pending'
                            ? 'bg-sky-500'
                            : 'bg-slate-400'
                        }`} />
                        {language === 'zh' ? dom.statusTextZh : dom.statusTextEn}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="px-5 py-3.5 text-right space-x-1">
                      <button
                        onClick={() => setInspectDomain(dom)}
                        title={language === 'zh' ? '查看并复制 DNS 解析记录' : 'View DNS Records'}
                        className={`px-2.5 py-1 rounded-lg text-xs font-sans font-medium transition-colors cursor-pointer border ${
                          themeMode === 'light'
                            ? 'bg-cyan-50 hover:bg-cyan-100 text-cyan-800 border-cyan-200 shadow-xs'
                            : 'bg-slate-800 hover:bg-slate-700 text-cyan-300 border-transparent'
                        }`}
                      >
                        {language === 'zh' ? 'DNS 配置' : 'DNS Records'}
                      </button>
                      <button
                        onClick={() => deleteDomain(dom.id)}
                        title="Delete domain"
                        className="p-1 rounded text-slate-400 hover:text-rose-500 transition-colors cursor-pointer"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </LiquidGlass>

      {/* Modals */}
      {isAddModalOpen && <AddDomainModal onClose={() => setIsAddModalOpen(false)} />}
      {inspectDomain && (
        <DnsCheckModal domain={inspectDomain} onClose={() => setInspectDomain(null)} />
      )}
    </div>
  );
};
