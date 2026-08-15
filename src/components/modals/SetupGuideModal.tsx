import React from 'react';
import { useApp } from '../../context/AppContext';
import { SetupGuideView } from '../views/SetupGuideView';
import { X, Sparkles } from 'lucide-react';
import { LiquidGlass } from '../common/LiquidGlass';

export const SetupGuideModal: React.FC = () => {
  const { isOnboardingModalOpen, setIsOnboardingModalOpen, language } = useApp();

  if (!isOnboardingModalOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-5xl max-h-[90vh] overflow-y-auto rounded-3xl border border-white/20 bg-slate-950/90 shadow-2xl no-scrollbar">
        {/* Floating Close Button */}
        <div className="sticky top-4 right-4 z-20 flex justify-end pr-4 pointer-events-none">
          <button
            onClick={() => setIsOnboardingModalOpen(false)}
            className="w-9 h-9 rounded-full bg-slate-900/90 border border-white/20 text-slate-400 hover:text-white flex items-center justify-center pointer-events-auto transition-all hover:scale-105 cursor-pointer shadow-lg"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="-mt-10">
          <SetupGuideView />
        </div>
      </div>
    </div>
  );
};
