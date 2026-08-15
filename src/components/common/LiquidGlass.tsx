import React, { useRef, useState, useCallback, useEffect } from 'react';
import { useApp } from '../../context/AppContext';

export interface LiquidGlassProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: React.ReactNode;
  variant?: 'card' | 'panel' | 'button' | 'pill' | 'badge' | 'subtle' | 'glow';
  preset?: 'liquid' | 'crystal' | 'frosted' | 'cyber';
  interactive?: boolean; // Enables 3D tilt + dynamic mouse glare
  glowColor?: 'cyan' | 'blue' | 'sky' | 'purple' | 'amber' | 'emerald' | 'none';
  intensity?: 'subtle' | 'medium' | 'deep';
  className?: string;
  id?: string;
  onClick?: (e: React.MouseEvent<HTMLDivElement>) => void;
  role?: string;
  tabIndex?: number;
}

export const LiquidGlass: React.FC<LiquidGlassProps> = ({
  children,
  variant = 'card',
  preset = 'liquid',
  interactive = true,
  glowColor = 'cyan',
  intensity = 'medium',
  className = '',
  id,
  onClick,
  style,
  role,
  tabIndex,
  ...rest
}) => {
  const { themeMode, settings } = useApp();
  const isLight = themeMode === 'light';

  // Variant class mappings
  const getVariantStyles = () => {
    switch (variant) {
      case 'button':
        return isLight
          ? 'liquid-glass-btn text-slate-800 font-semibold px-4 py-2 rounded-xl active:scale-95 cursor-pointer select-none'
          : 'liquid-glass-btn text-white font-semibold px-4 py-2 rounded-xl active:scale-95 cursor-pointer select-none';
      case 'pill':
        return isLight
          ? 'liquid-glass-pill px-3 py-1 rounded-full text-xs font-medium text-slate-800 select-none'
          : 'liquid-glass-pill px-3 py-1 rounded-full text-xs font-medium text-slate-200 select-none';
      case 'badge':
        return isLight
          ? 'liquid-glass-badge px-2.5 py-0.5 rounded-lg text-[11px] font-mono font-bold'
          : 'liquid-glass-badge px-2.5 py-0.5 rounded-lg text-[11px] font-mono font-bold';
      case 'panel':
        return 'liquid-glass-panel rounded-3xl p-6';
      case 'subtle':
        return 'liquid-glass-subtle rounded-2xl p-4';
      case 'glow':
        return 'liquid-glass-glow rounded-2xl p-5';
      case 'card':
      default:
        return 'liquid-glass-card rounded-2xl p-5';
    }
  };

  // Glow color highlights (smooth, stable transition without 3D wobble)
  const getGlowBorder = () => {
    if (glowColor === 'none') return '';
    if (isLight) {
      switch (glowColor) {
        case 'cyan':
        case 'sky':
          return 'hover:border-sky-400/60 hover:shadow-[0_8px_24px_rgba(2,132,199,0.12)]';
        case 'blue':
          return 'hover:border-blue-400/60 hover:shadow-[0_8px_24px_rgba(37,99,235,0.12)]';
        case 'purple':
          return 'hover:border-purple-400/60 hover:shadow-[0_8px_24px_rgba(168,85,247,0.12)]';
        case 'amber':
          return 'hover:border-amber-400/60 hover:shadow-[0_8px_24px_rgba(245,158,11,0.12)]';
        case 'emerald':
          return 'hover:border-emerald-400/60 hover:shadow-[0_8px_24px_rgba(16,185,129,0.12)]';
      }
    } else {
      switch (glowColor) {
        case 'cyan':
          return 'hover:border-cyan-400/60 hover:shadow-[0_0_20px_rgba(0,242,195,0.2)]';
        case 'blue':
        case 'sky':
          return 'hover:border-sky-400/60 hover:shadow-[0_0_20px_rgba(56,189,248,0.2)]';
        case 'purple':
          return 'hover:border-purple-400/60 hover:shadow-[0_0_20px_rgba(192,132,252,0.2)]';
        case 'amber':
          return 'hover:border-amber-400/60 hover:shadow-[0_0_20px_rgba(251,191,36,0.2)]';
        case 'emerald':
          return 'hover:border-emerald-400/60 hover:shadow-[0_0_20px_rgba(52,211,153,0.2)]';
      }
    }
    return '';
  };

  return (
    <div
      id={id}
      onClick={onClick}
      role={role}
      tabIndex={tabIndex}
      className={`relative overflow-hidden transition-all duration-200 ${getVariantStyles()} ${getGlowBorder()} ${className}`}
      style={style}
      {...rest}
    >
      {/* 1. Prismatic Bevel Highlight */}
      <div
        className="absolute inset-0 pointer-events-none rounded-[inherit] border border-white/20 z-0"
        style={{
          maskImage: 'linear-gradient(135deg, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 60%)',
          WebkitMaskImage: 'linear-gradient(135deg, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 60%)',
          borderColor: isLight ? 'rgba(255, 255, 255, 0.95)' : 'rgba(255, 255, 255, 0.25)',
        }}
      />

      {/* 2. Card Content */}
      <div className="relative z-1">{children}</div>
    </div>
  );
};
