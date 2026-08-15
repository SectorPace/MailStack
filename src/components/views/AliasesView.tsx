import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { AtSign, Plus, Search, Trash2, ArrowRight, X, Mail } from 'lucide-react';
import { motion } from 'motion/react';

export const AliasesView: React.FC = () => {
  const { aliases, domains, addAlias, deleteAlias, language } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [source, setSource] = useState('');
  const [destinationStr, setDestinationStr] = useState('');
  const [description, setDescription] = useState('');
  const [domain, setDomain] = useState(domains[0]?.name || 'example.com');

  const filteredAliases = aliases.filter((a) =>
    a.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.destinations.some(d => d.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!source.trim()) return;
    const dests = destinationStr.split(/[,;\n]/).map(s => s.trim()).filter(Boolean);
    addAlias({
      source: source.includes('@') ? source.trim() : `${source.trim()}@${domain}`,
      domain,
      destinations: dests.length > 0 ? dests : ['admin@example.com'],
      description: description.trim() || 'Mail forwarding alias',
    });
    setIsModalOpen(false);
    setSource('');
    setDestinationStr('');
    setDescription('');
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            {language === 'zh' ? '总别名路由' : 'Total Aliases'}
          </div>
          <div className="text-3xl font-black text-white font-mono">{aliases.length}</div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            {language === 'zh' ? '通配符捕获 (Catch-all)' : 'Catch-all Rules'}
          </div>
          <div className="text-3xl font-black text-cyan-400 font-mono">
            {aliases.filter(a => a.source.startsWith('*@')).length}
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1">
            {language === 'zh' ? '转发目标地址数' : 'Destinations Linked'}
          </div>
          <div className="text-3xl font-black text-emerald-400 font-mono">
            {aliases.reduce((acc, a) => acc + a.destinations.length, 0)}
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={language === 'zh' ? '搜索别名地址、目标邮箱...' : 'Search alias source or destination...'}
            className="w-full h-10 pl-10 pr-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
        </div>

        <button
          onClick={() => setIsModalOpen(true)}
          className="h-10 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all hover:scale-[1.02] cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>{language === 'zh' ? '添加邮件别名' : 'Create Mail Alias'}</span>
        </button>
      </div>

      {/* Table */}
      <div className="rounded-2xl bg-slate-900/70 border border-slate-800/90 overflow-hidden backdrop-blur-md shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-5 py-3.5">{language === 'zh' ? '别名源地址 (SOURCE ALIAS)' : 'SOURCE ALIAS'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '目标收信邮箱 (DESTINATIONS)' : 'DESTINATIONS'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '规则描述' : 'DESCRIPTION'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '创建时间' : 'CREATED'}</th>
                <th className="px-5 py-3.5 text-right">{language === 'zh' ? '操作' : 'ACTIONS'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredAliases.map((als) => (
                <tr key={als.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-5 py-3.5 font-semibold text-white flex items-center gap-2">
                    <AtSign className="w-4 h-4 text-cyan-400" />
                    <span>{als.source}</span>
                  </td>

                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1.5">
                      {als.destinations.map((dest, i) => (
                        <span key={i} className="px-2 py-0.5 rounded-md bg-slate-800 border border-slate-700 text-cyan-300 text-[11px]">
                          {dest}
                        </span>
                      ))}
                    </div>
                  </td>

                  <td className="px-5 py-3.5 text-slate-300 font-sans">
                    {als.description}
                  </td>

                  <td className="px-5 py-3.5 text-slate-500 text-[11px]">
                    {als.createdAt}
                  </td>

                  <td className="px-5 py-3.5 text-right">
                    <button
                      onClick={() => deleteAlias(als.id)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 transition-colors"
                      title="Delete alias"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="fixed inset-0" onClick={() => setIsModalOpen(false)} />
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="w-full max-w-md bg-slate-900 border border-slate-700/80 rounded-3xl shadow-2xl overflow-hidden relative z-10"
          >
            <div className="px-6 py-4 border-b border-slate-800 bg-slate-950/80 flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <AtSign className="w-5 h-5 text-cyan-400" />
                <span>{language === 'zh' ? '添加邮件别名' : 'Create Mail Alias'}</span>
              </h3>
              <button onClick={() => setIsModalOpen(false)} className="p-1 text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreate} className="p-6 space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1.5">
                  {language === 'zh' ? '别名地址 (如 contact 或 *@domain)' : 'SOURCE ALIAS'}
                </label>
                <input
                  type="text"
                  required
                  placeholder="billing@example.com"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1.5">
                  {language === 'zh' ? '转发目标 (多个请用逗号或换行分隔)' : 'DESTINATIONS'}
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="admin@example.com, finance@example.com"
                  value={destinationStr}
                  onChange={(e) => setDestinationStr(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-300 uppercase tracking-wider mb-1.5">
                  {language === 'zh' ? '规则描述' : 'DESCRIPTION'}
                </label>
                <input
                  type="text"
                  placeholder="General financial invoices"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer font-sans"
                >
                  <Plus className="w-4 h-4" />
                  <span>{language === 'zh' ? '创建并写入 Postfix 别名表' : 'Apply Alias Rule'}</span>
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
};
