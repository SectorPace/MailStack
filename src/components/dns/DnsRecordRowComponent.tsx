import React from 'react';
import { Copy, Edit3, Trash2 } from '@/lib/icons';
import { DnsRecordRow } from './DnsGuideTable';

interface Props {
  record: DnsRecordRow;
  themeMode: string;
  language: string;
  privacyMode: boolean;
  copiedField: string | null;
  verifiedMap: Record<string, boolean>;
  onCopy: (text: string, key: string, label?: string) => void;
  onEdit: (record: DnsRecordRow) => void;
  onDelete: (id: string) => void;
  maskDomain: (val: string) => string;
  maskContent: (val: string) => string;
}

export const DnsRecordRowComponent: React.FC<Props> = ({
  record,
  themeMode,
  language,
  privacyMode,
  copiedField,
  verifiedMap,
  onCopy,
  onEdit,
  onDelete,
  maskDomain,
  maskContent,
}) => {
  const isVerified = verifiedMap[record.id];
  const displayName = privacyMode ? maskDomain(record.name) : record.nameDisplay || record.name;
  const displayContent = privacyMode ? maskContent(record.content) : record.content;

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'MX': return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'TXT': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'CNAME': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'A': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      default: return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
    }
  };

  return (
    <tr className={`border-b transition-colors ${
      themeMode === 'light' ? 'border-slate-200/70 hover:bg-slate-50/80' : 'border-slate-800/60 hover:bg-slate-800/30'
    }`}>
      <td className="p-3.5 font-mono font-bold">
        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] border ${getTypeColor(record.type)}`}>
          {record.type}
        </span>
      </td>

      <td className="p-3.5 font-mono text-xs max-w-[200px]">
        <div className="flex items-center gap-1.5 group">
          <span className={`font-semibold truncate ${themeMode === 'light' ? 'text-slate-800' : 'text-slate-200'}`}>
            {displayName}
          </span>
          <button
            onClick={() => onCopy(record.name, `name-${record.id}`, 'Host/Name')}
            className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-cyan-400 transition-opacity cursor-pointer"
            title="Copy Name"
          >
            <Copy className="w-3 h-3" />
          </button>
        </div>
        {record.comment && (
          <div className="text-[10px] text-slate-400 font-sans mt-0.5 truncate">
            {record.comment}
          </div>
        )}
      </td>

      <td className="p-3.5 font-mono text-xs max-w-[320px]">
        <div className="flex items-start gap-1.5 group">
          <span className={`break-all ${themeMode === 'light' ? 'text-slate-700' : 'text-slate-300'}`}>
            {displayContent}
          </span>
          <button
            onClick={() => onCopy(record.content, `content-${record.id}`, 'Value')}
            className="opacity-0 group-hover:opacity-100 p-1 text-slate-400 hover:text-cyan-400 transition-opacity cursor-pointer shrink-0 mt-0.5"
            title="Copy Value"
          >
            <Copy className="w-3 h-3" />
          </button>
        </div>
      </td>

      <td className="p-3.5 text-center">
        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
          record.proxyStatus === 'dns_only'
            ? 'bg-slate-800 text-amber-300 border-amber-500/30'
            : 'bg-orange-500/10 text-orange-400 border-orange-500/20'
        }`}>
          {record.proxyStatus === 'dns_only' ? '仅 DNS (灰云)' : '已代理 (橙云)'}
        </span>
      </td>

      <td className="p-3.5 text-center font-mono text-[11px] text-slate-400">
        {record.priority !== undefined ? `Pri: ${record.priority}` : record.ttl || 'Auto'}
      </td>

      <td className="p-3.5 text-center">
        {isVerified !== undefined ? (
          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold ${
            isVerified ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
          }`}>
            {isVerified ? '✓ 已生效' : '未检测到'}
          </span>
        ) : (
          <span className="text-[10px] text-slate-500">待检测</span>
        )}
      </td>

      <td className="p-3.5 text-right">
        <div className="flex items-center justify-end gap-1">
          <button
            onClick={() => onCopy(record.content, `btn-${record.id}`, record.type)}
            className="p-1.5 rounded-lg border border-white/10 hover:bg-white/10 text-slate-300 hover:text-cyan-400 text-xs transition-all cursor-pointer"
            title="Copy Content"
          >
            {copiedField === `btn-${record.id}` ? '✓' : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={() => onEdit(record)}
            className="p-1.5 rounded-lg border border-white/10 hover:bg-white/10 text-slate-400 hover:text-amber-400 text-xs transition-all cursor-pointer"
            title="Edit Record"
          >
            <Edit3 className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => onDelete(record.id)}
            className="p-1.5 rounded-lg border border-white/10 hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 text-xs transition-all cursor-pointer"
            title="Delete Record"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </td>
    </tr>
  );
};
