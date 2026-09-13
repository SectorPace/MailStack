import React, { useState } from 'react';
import { api } from '../../api';
import { useApp } from '../../context/AppContext';
import { Lock, X } from '@/lib/icons';
import { getErrorMessage } from '../../utils/errors';

export const IssueCertModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { language, showToast } = useApp();
  const [mailHost, setMailHost] = useState('');
  const [email, setEmail] = useState('');
  const [method, setMethod] = useState('standalone');
  const [webroot, setWebroot] = useState('/var/www/html');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);

  const issue = async () => {
    setBusy(true);
    setResult(null);
    try {
      const r = await api('/api/setup/cert/issue', {
        method: 'POST',
        body: JSON.stringify({ mailHost, email, method, webroot }),
      });
      setResult(r);
      showToast('success', language === 'zh' ? '证书签发并安装完成' : 'Certificate issued and installed', r.domain);
      onClose();
      location.reload();
    } catch (e: unknown) {
      const msg = getErrorMessage(e);
      setResult({ error: msg });
      showToast('error', language === 'zh' ? 'ACME 操作失败' : 'ACME operation failed', msg);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4">
      <div className="w-full max-w-lg rounded-3xl border border-slate-700 bg-slate-900 p-6 text-white">
        <div className="flex justify-between">
          <div>
            <h2 className="flex items-center gap-2 text-xl font-black">
              <Lock className="h-5 w-5 text-cyan-400" />
              {language === 'zh' ? '签发真实 TLS 证书' : 'Issue a real TLS certificate'}
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              {language === 'zh' ? '进度由 ACME 后端操作结果决定，本页面不会模拟验证阶段。' : 'Progress is determined by the ACME backend. This page does not simulate challenge stages.'}
            </p>
          </div>
          <button onClick={onClose}><X className="h-5 w-5" /></button>
        </div>

        <div className="mt-5 space-y-3">
          <input className="input-field" value={mailHost} onChange={e => setMailHost(e.target.value)} placeholder="mail.example.com" />
          <input className="input-field" value={email} onChange={e => setEmail(e.target.value)} placeholder="postmaster@example.com" />
          <select className="input-field" value={method} onChange={e => setMethod(e.target.value)}>
            <option value="standalone">HTTP-01 standalone</option>
            <option value="webroot">HTTP-01 webroot</option>
          </select>
          {method === 'webroot' && (
            <input className="input-field" value={webroot} onChange={e => setWebroot(e.target.value)} />
          )}
        </div>

        {result && (
          <pre className={`mt-4 rounded-xl p-3 text-xs ${result.error ? 'bg-rose-950/50 text-rose-200' : 'bg-emerald-950/40 text-emerald-200'}`}>
            {JSON.stringify(result, null, 2)}
          </pre>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button className="btn-secondary" onClick={onClose}>
            {language === 'zh' ? '取消' : 'Cancel'}
          </button>
          <button className="btn-primary" disabled={busy || !mailHost || !email} onClick={issue}>
            {busy ? (language === 'zh' ? 'ACME 执行中...' : 'Running ACME...') : (language === 'zh' ? '签发并安装' : 'Issue and install')}
          </button>
        </div>
      </div>
    </div>
  );
};
