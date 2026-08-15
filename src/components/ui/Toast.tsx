import React from 'react';
import { useApp } from '../../context/AppContext';
import { CheckCircle2, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast, themeMode } = useApp();

  return (
    <div
      id="liquid-glass-toast-portal"
      className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 pointer-events-none max-w-[340px] w-full"
    >
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => {
          const isLight = themeMode === 'light';

          const iconConfig = {
            success: {
              icon: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" />,
              border: isLight ? 'border-emerald-500/30' : 'border-emerald-500/30',
              badge: isLight ? 'bg-emerald-500/15 text-emerald-700' : 'bg-emerald-500/20 text-emerald-300',
              progressBar: isLight ? 'bg-emerald-500' : 'bg-emerald-400',
              glow: isLight ? 'rgba(16,185,129,0.1)' : 'rgba(16,185,129,0.15)',
            },
            warning: {
              icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 drop-shadow-[0_0_8px_rgba(251,191,36,0.5)]" />,
              border: isLight ? 'border-amber-500/30' : 'border-amber-500/30',
              badge: isLight ? 'bg-amber-500/15 text-amber-700' : 'bg-amber-500/20 text-amber-300',
              progressBar: isLight ? 'bg-amber-500' : 'bg-amber-400',
              glow: isLight ? 'rgba(245,158,11,0.1)' : 'rgba(245,158,11,0.15)',
            },
            error: {
              icon: <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 drop-shadow-[0_0_8px_rgba(244,63,94,0.5)]" />,
              border: isLight ? 'border-rose-500/30' : 'border-rose-500/30',
              badge: isLight ? 'bg-rose-500/15 text-rose-700' : 'bg-rose-500/20 text-rose-300',
              progressBar: isLight ? 'bg-rose-500' : 'bg-rose-400',
              glow: isLight ? 'rgba(244,63,94,0.1)' : 'rgba(244,63,94,0.15)',
            },
            info: {
              icon: <Info className="w-4 h-4 text-cyan-400 shrink-0 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />,
              border: isLight ? 'border-cyan-500/30' : 'border-cyan-500/30',
              badge: isLight ? 'bg-cyan-500/15 text-cyan-700' : 'bg-cyan-500/20 text-cyan-300',
              progressBar: isLight ? 'bg-cyan-500' : 'bg-cyan-400',
              glow: isLight ? 'rgba(6,182,212,0.1)' : 'rgba(0,242,195,0.15)',
            },
          };

          const currentConfig = iconConfig[toast.type] || iconConfig.info;

          return (
            <motion.div
              key={toast.id}
              layout
              initial={{ opacity: 0, y: 16, scale: 0.94, filter: 'blur(4px)' }}
              animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }}
              exit={{ opacity: 0, scale: 0.9, y: -10, filter: 'blur(4px)', transition: { duration: 0.22 } }}
              transition={{ type: 'spring', stiffness: 420, damping: 28 }}
              className={`pointer-events-auto relative overflow-hidden rounded-2xl border p-3 shadow-xl transition-colors backdrop-blur-2xl ${
                isLight
                  ? 'bg-white/88 border-white/95 text-slate-900 shadow-[0_12px_32px_rgba(0,0,0,0.06),inset_0_1.5px_1px_rgba(255,255,255,1)]'
                  : 'bg-slate-950/82 border-white/15 text-white shadow-[0_16px_40px_rgba(0,0,0,0.6),inset_0_1.5px_1px_rgba(255,255,255,0.25)]'
              } ${currentConfig.border}`}
              style={{
                boxShadow: isLight
                  ? `0 10px 25px -3px ${currentConfig.glow}, 0 4px 6px -4px rgba(0,0,0,0.05), inset 0 1.5px 1px #ffffff`
                  : `0 14px 35px -3px ${currentConfig.glow}, 0 4px 12px rgba(0,0,0,0.5), inset 0 1.5px 1px rgba(255,255,255,0.25)`,
              }}
            >
              {/* Dynamic Specular Lens Light */}
              <div
                className="absolute inset-0 pointer-events-none rounded-2xl"
                style={{
                  background: isLight
                    ? 'radial-gradient(ellipse at 30% 0%, rgba(255,255,255,0.8), transparent 70%)'
                    : 'radial-gradient(ellipse at 30% 0%, rgba(255,255,255,0.12), transparent 70%)',
                }}
              />

              <div className="relative flex items-start gap-2.5">
                <div className="mt-0.5 shrink-0">{currentConfig.icon}</div>
                <div className="flex-1 min-w-0 pr-1">
                  <div className="flex items-center gap-1.5">
                    <span className={`text-xs font-bold truncate ${isLight ? 'text-slate-900' : 'text-slate-100'}`}>
                      {toast.title}
                    </span>
                  </div>
                  <div
                    className={`text-[11px] leading-relaxed mt-0.5 break-words line-clamp-2 ${
                      isLight ? 'text-slate-600' : 'text-slate-300'
                    }`}
                  >
                    {toast.message}
                  </div>
                </div>
                <button
                  onClick={() => removeToast(toast.id)}
                  className={`shrink-0 p-1 rounded-lg transition-colors cursor-pointer ${
                    isLight
                      ? 'text-slate-400 hover:text-slate-800 hover:bg-slate-100/80'
                      : 'text-slate-400 hover:text-white hover:bg-white/10'
                  }`}
                  aria-label="Close notification"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Liquid Auto-Dismiss Progress Line */}
              <motion.div
                initial={{ width: '100%' }}
                animate={{ width: '0%' }}
                transition={{ duration: 2.75, ease: 'linear' }}
                className={`absolute bottom-0 left-0 h-[2px] rounded-full ${currentConfig.progressBar}`}
                style={{ opacity: isLight ? 0.8 : 0.9 }}
              />
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
};
