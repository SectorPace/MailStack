import React, { useRef, useState, useCallback } from 'react';
import { useApp } from '../../context/AppContext';

interface MailStackLogoProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  theme?: 'light' | 'dark';
  className?: string;
  onClick?: () => void;
  showHoverEffect?: boolean;
}

export const MailStackLogo: React.FC<MailStackLogoProps> = ({
  size = 'md',
  theme,
  className = '',
  onClick,
  showHoverEffect = false,
}) => {
  const { themeMode, customLogo, settings } = useApp();
  const activeTheme = theme || themeMode || 'dark';
  const isReducedMotion = settings.reducedMotion;

  const logoRef = useRef<HTMLDivElement>(null);
  const [tilt, setTilt] = useState({ rotateX: 0, rotateY: 0, scale: 1 });
  const [glare, setGlare] = useState({ x: 50, y: 50, opacity: 0 });

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (!showHoverEffect || isReducedMotion || !logoRef.current) return;
    const rect = logoRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const percentX = (x / rect.width) * 100;
    const percentY = (y / rect.height) * 100;

    const rotateY = ((percentX - 50) / 50) * 8;
    const rotateX = -((percentY - 50) / 50) * 8;

    setTilt({ rotateX, rotateY, scale: 1.06 });
    setGlare({ x: percentX, y: percentY, opacity: 0.85 });
  }, [showHoverEffect, isReducedMotion]);

  const handleMouseLeave = useCallback(() => {
    setTilt({ rotateX: 0, rotateY: 0, scale: 1 });
    setGlare((prev) => ({ ...prev, opacity: 0 }));
  }, []);

  const sizeMap = {
    xs: 'w-6 h-6',
    sm: 'w-8 h-8',
    md: 'w-10 h-10',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16',
    '2xl': 'w-24 h-24',
  };

  const dimensionMap = {
    xs: 24,
    sm: 32,
    md: 40,
    lg: 48,
    xl: 64,
    '2xl': 96,
  };

  const dim = dimensionMap[size];

  const transformStyle = showHoverEffect && !isReducedMotion
    ? {
        transform: `perspective(600px) rotateX(${tilt.rotateX}deg) rotateY(${tilt.rotateY}deg) scale3d(${tilt.scale}, ${tilt.scale}, 1)`,
        transition: 'transform 0.15s cubic-bezier(0.2, 0.8, 0.4, 1)',
      }
    : {};

  // --------------------------------------------------------------------------
  // 1. CUSTOM UPLOADED LOGO
  // --------------------------------------------------------------------------
  if (customLogo && customLogo.length > 0) {
    return (
      <div
        ref={logoRef}
        onClick={onClick}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className={`relative inline-flex items-center justify-center shrink-0 select-none overflow-hidden rounded-2xl ${
          sizeMap[size]
        } ${showHoverEffect ? 'cursor-pointer group' : ''} ${className}`}
        style={{
          filter:
            activeTheme === 'light'
              ? 'drop-shadow(0 4px 14px rgba(2, 132, 199, 0.22))'
              : 'drop-shadow(0 0 16px rgba(0, 242, 195, 0.4))',
          ...transformStyle,
        }}
      >
        <div
          className={`w-full h-full p-1 rounded-2xl border flex items-center justify-center overflow-hidden transition-transform duration-300 ${
            activeTheme === 'light'
              ? 'bg-gradient-to-br from-white via-slate-50 to-sky-50 border-sky-200'
              : 'bg-gradient-to-br from-slate-900 via-slate-950 to-[#030816] border-cyan-500/40 shadow-inner'
          }`}
        >
          <img
            src={customLogo}
            alt="MailStack Custom Logo"
            className="w-full h-full object-contain rounded-xl"
          />
        </div>
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // 2. LIGHT MODE LOGO (7605dbbc-5a91-4f5d-84b3-4ef0ac972760.png)
  // --------------------------------------------------------------------------
  if (activeTheme === 'light') {
    return (
      <div
        ref={logoRef}
        onClick={onClick}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className={`relative inline-flex items-center justify-center shrink-0 select-none overflow-hidden rounded-2xl ${
          sizeMap[size]
        } ${showHoverEffect ? 'cursor-pointer group' : ''} ${className}`}
        style={{
          filter: 'drop-shadow(0 6px 16px rgba(30, 117, 242, 0.22)) drop-shadow(0 2px 4px rgba(0, 0, 0, 0.05))',
          ...transformStyle,
        }}
      >
        <img
          src="/assets/logo-light.png"
          alt="MailStack Light Logo"
          className="w-full h-full object-contain rounded-xl select-none pointer-events-none"
          loading="eager"
        />
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // 3. DARK MODE LOGO (ChatGPT Image 2026年8月14日 23_59_14.png)
  // --------------------------------------------------------------------------
  return (
    <div
      ref={logoRef}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={`relative inline-flex items-center justify-center shrink-0 select-none overflow-hidden rounded-2xl ${
        sizeMap[size]
      } ${showHoverEffect ? 'cursor-pointer group' : ''} ${className}`}
      style={{
        filter: 'drop-shadow(0 0 18px rgba(0, 180, 255, 0.45)) drop-shadow(0 8px 24px rgba(0, 0, 0, 0.8))',
        ...transformStyle,
      }}
    >
      <img
        src="/assets/logo-dark.png"
        alt="MailStack Dark Logo"
        className="w-full h-full object-contain rounded-xl select-none pointer-events-none"
        loading="eager"
      />
    </div>
  );
};
