import React, { useState } from 'react';
import { useApp } from '../../context/AppContext';
import { Mail, RefreshCw, Trash2, Play, AlertTriangle, Inbox, CheckCircle2, Clock } from 'lucide-react';

export const QueueView: React.FC = () => {
  const { queues, flushQueue, deleteQueueItem, retryQueueItem, language, showToast, themeMode } = useApp();
  const [filterStatus, setFilterStatus] = useState<string>('all');

  const filteredQueues = queues.filter((q) => {
    if (filterStatus === 'all') return true;
    return q.status === filterStatus;
  });

  const getStatusBadge = (status: string) => {
    if (status === 'active') {
      return themeMode === 'light'
        ? 'bg-sky-50 text-sky-700 border border-sky-300 font-semibold'
        : 'bg-sky-950/80 text-sky-300 border border-sky-500/40';
    }
    if (status === 'deferred') {
      return themeMode === 'light'
        ? 'bg-amber-50 text-amber-800 border border-amber-300 font-semibold'
        : 'bg-amber-950/80 text-amber-300 border border-amber-500/40';
    }
    return themeMode === 'light'
      ? 'bg-rose-50 text-rose-700 border border-rose-300 font-semibold'
      : 'bg-rose-950/80 text-rose-300 border border-rose-500/40';
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-5 rounded-2xl bg-slate-900/70 border border-slate-800/90 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Inbox className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">
              {language === 'zh' ? 'Postfix 邮件队列监视器' : 'Postfix Mail Queue Monitor'}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              /var/spool/postfix/ (active, deferred, hold)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={flushQueue}
            className="h-10 px-4 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,242,195,0.25)] transition-all cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
            <span>{language === 'zh' ? '立即刷新并重试所有邮件 (Flush Queue)' : 'Flush & Retry All'}</span>
          </button>
        </div>
      </div>

      {/* Queue Table */}
      <div className="rounded-2xl bg-slate-900/70 border border-slate-800/90 overflow-hidden backdrop-blur-md shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-5 py-3.5">{language === 'zh' ? '队列 ID' : 'QUEUE ID'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '发信人' : 'SENDER'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '收信人' : 'RECIPIENT'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '大小' : 'SIZE'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '队列状态' : 'STATUS'}</th>
                <th className="px-5 py-3.5">{language === 'zh' ? '延迟原因 / 诊断信息' : 'DEFER REASON'}</th>
                <th className="px-5 py-3.5 text-right">{language === 'zh' ? '操作' : 'ACTIONS'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredQueues.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    {language === 'zh' ? '当前没有排队或积压的邮件，队列清空。' : 'Mail queue is clean. No backlog.'}
                  </td>
                </tr>
              ) : (
                filteredQueues.map((q) => (
                  <tr key={q.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-5 py-3.5 font-bold text-cyan-300">
                      {q.queueId}
                    </td>

                    <td className="px-5 py-3.5 text-slate-300">
                      {q.sender}
                    </td>

                    <td className="px-5 py-3.5 text-white">
                      {q.recipient}
                    </td>

                    <td className="px-5 py-3.5 text-slate-400">
                      {(q.sizeBytes / 1024).toFixed(1)} KB
                    </td>

                    <td className="px-5 py-3.5">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-mono ${getStatusBadge(q.status)}`}>
                        {q.status}
                      </span>
                    </td>

                    <td className="px-5 py-3.5 text-slate-400 max-w-xs truncate text-[11px]">
                      {q.errorReason || '正在尝试投递连接...'}
                    </td>

                    <td className="px-5 py-3.5 text-right space-x-1">
                      <button
                        onClick={() => retryQueueItem(q.id)}
                        title="Retry delivery now"
                        className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 transition-colors"
                      >
                        <Play className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => deleteQueueItem(q.id)}
                        title="Drop from queue"
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
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
