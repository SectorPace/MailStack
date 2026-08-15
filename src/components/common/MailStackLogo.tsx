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
  // 2. LIGHT MODE LOGO (Exact 1:1 match to ChatGPT Image 2026-08-14 23:59:45)
  // Frosted ice squircle with 3-tier blue mail envelope stack
  // --------------------------------------------------------------------------
  if (activeTheme === 'light') {
    return (
      <div
        ref={logoRef}
        onClick={onClick}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        className={`relative inline-flex items-center justify-center shrink-0 select-none ${
          sizeMap[size]
        } ${showHoverEffect ? 'cursor-pointer group' : ''} ${className}`}
        style={{
          filter: 'drop-shadow(0 6px 16px rgba(30, 117, 242, 0.18)) drop-shadow(0 2px 4px rgba(0, 0, 0, 0.04))',
          ...transformStyle,
        }}
      >
        <svg
          width={dim}
          height={dim}
          viewBox="0 0 128 128"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
        >
          <defs>
            {/* Background Frosted Ice Glass Squircle */}
            <linearGradient id="lightSquircleBg" x1="12" y1="12" x2="116" y2="116" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#ffffff" stopOpacity="0.95" />
              <stop offset="50%" stopColor="#f2f8ff" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#e4efff" stopOpacity="0.85" />
            </linearGradient>

            {/* Squircle Soft Rim Stroke */}
            <linearGradient id="lightSquircleBorder" x1="8" y1="8" x2="120" y2="120" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#ffffff" />
              <stop offset="60%" stopColor="#dbeafe" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#bfdbfe" stopOpacity="0.9" />
            </linearGradient>

            {/* Top Envelope Flap Gradient */}
            <linearGradient id="lTopFlap" x1="64" y1="34" x2="64" y2="66" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="30%" stopColor="#1d8cf8" />
              <stop offset="100%" stopColor="#0d62d9" />
            </linearGradient>

            {/* Top Envelope Body / Lower Half */}
            <linearGradient id="lEnvLowerBody" x1="36" y1="46" x2="92" y2="70" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#7dd3fc" />
              <stop offset="50%" stopColor="#60a5fa" />
              <stop offset="100%" stopColor="#3b82f6" />
            </linearGradient>

            {/* Middle Layer Deck */}
            <linearGradient id="lMiddleDeck" x1="36" y1="69" x2="92" y2="81" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#60a5fa" />
              <stop offset="50%" stopColor="#3b82f6" />
              <stop offset="100%" stopColor="#2563eb" />
            </linearGradient>

            {/* Bottom Layer Deck */}
            <linearGradient id="lBottomDeck" x1="36" y1="77" x2="92" y2="90" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#2563eb" />
              <stop offset="50%" stopColor="#1d4ed8" />
              <stop offset="100%" stopColor="#1e40af" />
            </linearGradient>

            {/* Soft Shadow for Icon Stack */}
            <filter id="lStackDrop" x="-10%" y="-10%" width="120%" height="120%">
              <feDropShadow dx="0" dy="3" stdDeviation="2" floodColor="#0284c7" floodOpacity="0.18" />
            </filter>
          </defs>

          {/* 1. Ice Frosted Glass Squircle Container */}
          <rect
            x="6"
            y="6"
            width="116"
            height="116"
            rx="34"
            fill="url(#lightSquircleBg)"
            stroke="url(#lightSquircleBorder)"
            strokeWidth="2.5"
          />

          {/* 2. Three-Tier Mail Icon Group */}
          <g filter="url(#lStackDrop)">
            {/* TIER 3: Bottom Layer Sheet */}
            <path
              d="M 36 77.5 C 36 77.5 48 83 64 83 C 80 83 92 77.5 92 77.5 L 86.5 87.5 C 85.5 89 83.5 90 81.5 90 L 46.5 90 C 44.5 90 42.5 89 41.5 87.5 Z"
              fill="url(#lBottomDeck)"
            />

            {/* TIER 2: Middle Layer Sheet */}
            <path
              d="M 36 69.5 C 36 69.5 48 75 64 75 C 80 75 92 69.5 92 69.5 L 90.5 76 C 89.8 78 88 79.5 85.8 79.5 L 42.2 79.5 C 40 79.5 38.2 78 37.5 76 Z"
              fill="url(#lMiddleDeck)"
            />

            {/* TIER 1: Top Mail Envelope */}
            {/* Envelope Background Base */}
            <rect
              x="36"
              y="34"
              width="56"
              height="36"
              rx="10"
              fill="url(#lEnvLowerBody)"
            />

            {/* Left & Right Fold Wings */}
            <path
              d="M 36 34 L 54 52 L 36 64 Z"
              fill="#2563eb"
              fillOpacity="0.25"
            />
            <path
              d="M 92 34 L 74 52 L 92 64 Z"
              fill="#2563eb"
              fillOpacity="0.25"
            />

            {/* Bottom Flap Crease */}
            <path
              d="M 36 66 L 64 48 L 92 66 Z"
              fill="#1d4ed8"
              fillOpacity="0.2"
            />

            {/* Top Fold Downward Pointing V-Flap */}
            <path
              d="M 36 34 C 36 34 38 34 42 34 L 86 34 C 90 34 92 34 92 34 L 66.5 56.5 C 65 57.8 63 57.8 61.5 56.5 Z"
              fill="url(#lTopFlap)"
            />

            {/* Crisp White V-Fold Seam Line */}
            <path
              d="M 36.5 35 L 62.5 56.5 C 63.4 57.2 64.6 57.2 65.5 56.5 L 91.5 35"
              stroke="#ffffff"
              strokeWidth="2.4"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeOpacity="0.95"
            />
          </g>
        </svg>
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // 3. DARK MODE LOGO (Exact 1:1 match to ChatGPT Image 2026-08-14 23:59:14)
  // Deep midnight glossy blue squircle with specular highlight arc and glowing cyan rim
  // --------------------------------------------------------------------------
  return (
    <div
      ref={logoRef}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={`relative inline-flex items-center justify-center shrink-0 select-none ${
        sizeMap[size]
      } ${showHoverEffect ? 'cursor-pointer group' : ''} ${className}`}
      style={{
        filter: 'drop-shadow(0 0 20px rgba(0, 180, 255, 0.45)) drop-shadow(0 8px 24px rgba(0, 0, 0, 0.8))',
        ...transformStyle,
      }}
    >
      <svg
        width={dim}
        height={dim}
        viewBox="0 0 128 128"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
      >
        <defs>
          {/* Deep Midnight Blue Squircle Gradient */}
          <linearGradient id="darkSquircleBg" x1="12" y1="12" x2="116" y2="116" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#081c44" />
            <stop offset="45%" stopColor="#040e24" />
            <stop offset="100%" stopColor="#010614" />
          </linearGradient>

          {/* Electric Cyan/Neon Blue Glowing Outer Rim */}
          <linearGradient id="darkNeonRim" x1="6" y1="6" x2="122" y2="122" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#00d4ff" />
            <stop offset="35%" stopColor="#0088ff" />
            <stop offset="70%" stopColor="#0055ff" />
            <stop offset="100%" stopColor="#002288" />
          </linearGradient>

          {/* Top-Left Glossy Specular Light Reflection Arc */}
          <linearGradient id="darkSpecularArc" x1="8" y1="8" x2="64" y2="64" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.75" />
            <stop offset="40%" stopColor="#ffffff" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </linearGradient>

          {/* Dark Mode Envelope Flap */}
          <linearGradient id="dTopFlap" x1="64" y1="34" x2="64" y2="66" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#00b4d8" />
            <stop offset="30%" stopColor="#0084ff" />
            <stop offset="100%" stopColor="#004cd6" />
          </linearGradient>

          {/* Dark Mode Envelope Body */}
          <linearGradient id="dEnvLowerBody" x1="36" y1="46" x2="92" y2="70" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38bdf8" />
            <stop offset="50%" stopColor="#0284c7" />
            <stop offset="100%" stopColor="#0369a1" />
          </linearGradient>

          {/* Dark Mode Middle Deck */}
          <linearGradient id="dMiddleDeck" x1="36" y1="69" x2="92" y2="81" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#00a8ff" />
            <stop offset="50%" stopColor="#0066ff" />
            <stop offset="100%" stopColor="#0044cc" />
          </linearGradient>

          {/* Dark Mode Bottom Deck */}
          <linearGradient id="dBottomDeck" x1="36" y1="77" x2="92" y2="90" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#0055ff" />
            <stop offset="50%" stopColor="#0035cc" />
            <stop offset="100%" stopColor="#002099" />
          </linearGradient>

          {/* Glowing Filter for Icon Stack */}
          <filter id="dStackGlow" x="-15%" y="-15%" width="130%" height="130%">
            <feDropShadow dx="0" dy="2" stdDeviation="3" floodColor="#00a8ff" floodOpacity="0.45" />
          </filter>
        </defs>

        {/* 1. Deep Midnight Blue Squircle Container */}
        <rect
          x="6"
          y="6"
          width="116"
          height="116"
          rx="34"
          fill="url(#darkSquircleBg)"
          stroke="url(#darkNeonRim)"
          strokeWidth="2.5"
        />

        {/* 2. Top-Left Glossy Specular Light Reflection (Arc) */}
        <path
          d="M 8 36 C 8 20.5 20.5 8 36 8 L 76 8 C 46 14 20 32 14 62 L 8 46 Z"
          fill="url(#darkSpecularArc)"
        />

        {/* 3. Three-Tier Glowing Mail Icon Group */}
        <g filter="url(#dStackGlow)">
          {/* TIER 3: Bottom Layer Sheet */}
          <path
            d="M 36 77.5 C 36 77.5 48 83 64 83 C 80 83 92 77.5 92 77.5 L 86.5 87.5 C 85.5 89 83.5 90 81.5 90 L 46.5 90 C 44.5 90 42.5 89 41.5 87.5 Z"
            fill="url(#dBottomDeck)"
          />

          {/* TIER 2: Middle Layer Sheet */}
          <path
            d="M 36 69.5 C 36 69.5 48 75 64 75 C 80 75 92 69.5 92 69.5 L 90.5 76 C 89.8 78 88 79.5 85.8 79.5 L 42.2 79.5 C 40 79.5 38.2 78 37.5 76 Z"
            fill="url(#dMiddleDeck)"
          />

          {/* TIER 1: Top Mail Envelope */}
          {/* Envelope Background Base */}
          <rect
            x="36"
            y="34"
            width="56"
            height="36"
            rx="10"
            fill="url(#dEnvLowerBody)"
          />

          {/* Left & Right Fold Wings */}
          <path
            d="M 36 34 L 54 52 L 36 64 Z"
            fill="#001a44"
            fillOpacity="0.4"
          />
          <path
            d="M 92 34 L 74 52 L 92 64 Z"
            fill="#001a44"
            fillOpacity="0.4"
          />

          {/* Bottom Flap Crease */}
          <path
            d="M 36 66 L 64 48 L 92 66 Z"
            fill="#001133"
            fillOpacity="0.35"
          />

          {/* Top Fold Downward Pointing V-Flap */}
          <path
            d="M 36 34 C 36 34 38 34 42 34 L 86 34 C 90 34 92 34 92 34 L 66.5 56.5 C 65 57.8 63 57.8 61.5 56.5 Z"
            fill="url(#dTopFlap)"
          />

          {/* Crisp White Illuminated V-Fold Seam Line */}
          <path
            d="M 36.5 35 L 62.5 56.5 C 63.4 57.2 64.6 57.2 65.5 56.5 L 91.5 35"
            stroke="#ffffff"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeOpacity="0.98"
          />
        </g>
      </svg>
    </div>
  );
};
