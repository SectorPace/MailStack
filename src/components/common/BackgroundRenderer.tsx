import React from 'react';
import { useApp } from '../../context/AppContext';

export const BackgroundRenderer: React.FC = () => {
  const { backgroundConfig, themeMode } = useApp();
  const isLight = themeMode === 'light';

  const { preset, customImageUrl, overlayOpacity, blur } = backgroundConfig;

  // Preset styles
  const getPresetBackground = () => {
    switch (preset) {
      case 'aurora_cyan':
        return isLight
          ? 'radial-gradient(circle at 20% 20%, rgba(2, 132, 199, 0.18) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(0, 242, 195, 0.15) 0%, transparent 60%), linear-gradient(135deg, #f0fdfa 0%, #e0f2fe 100%)'
          : 'radial-gradient(circle at 20% 20%, rgba(0, 242, 195, 0.15) 0%, transparent 50%), radial-gradient(circle at 80% 80%, rgba(56, 189, 248, 0.18) 0%, transparent 60%), linear-gradient(135deg, #041019 0%, #031e2b 50%, #050b14 100%)';
      case 'purple_velvet':
        return isLight
          ? 'radial-gradient(circle at 30% 20%, rgba(168, 85, 247, 0.15) 0%, transparent 50%), radial-gradient(circle at 75% 75%, rgba(236, 72, 153, 0.12) 0%, transparent 60%), linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%)'
          : 'radial-gradient(circle at 30% 20%, rgba(168, 85, 247, 0.18) 0%, transparent 50%), radial-gradient(circle at 75% 75%, rgba(99, 102, 241, 0.15) 0%, transparent 60%), linear-gradient(135deg, #0b0717 0%, #170b2e 50%, #06050e 100%)';
      case 'matrix_cyber':
        return isLight
          ? 'radial-gradient(circle at 25% 25%, rgba(16, 185, 129, 0.16) 0%, transparent 50%), linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)'
          : 'radial-gradient(circle at 25% 25%, rgba(16, 185, 129, 0.18) 0%, transparent 50%), radial-gradient(circle at 80% 70%, rgba(5, 150, 105, 0.15) 0%, transparent 55%), linear-gradient(135deg, #02120e 0%, #032117 50%, #010a08 100%)';
      case 'minimal_slate':
        return isLight
          ? 'linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%)'
          : 'radial-gradient(circle at 50% 0%, rgba(255, 255, 255, 0.05) 0%, transparent 70%), linear-gradient(180deg, #0b0f19 0%, #080c14 100%)';
      case 'warm_pearl':
        return isLight
          ? 'radial-gradient(circle at 10% 10%, rgba(245, 158, 11, 0.1) 0%, transparent 45%), radial-gradient(circle at 90% 90%, rgba(244, 63, 94, 0.08) 0%, transparent 50%), linear-gradient(135deg, #fffbeb 0%, #fef2f2 100%)'
          : 'radial-gradient(circle at 10% 10%, rgba(245, 158, 11, 0.12) 0%, transparent 45%), radial-gradient(circle at 90% 90%, rgba(244, 63, 94, 0.09) 0%, transparent 50%), linear-gradient(135deg, #18120b 0%, #1a0e12 100%)';
      case 'custom_image':
        return 'none';
      case 'default':
      default:
        return isLight
          ? 'radial-gradient(circle at 50% 0%, rgba(2, 132, 199, 0.08) 0%, transparent 60%), linear-gradient(180deg, #f4f6fb 0%, #eef2f8 100%)'
          : 'radial-gradient(circle at 50% -10%, rgba(0, 242, 195, 0.12) 0%, transparent 65%), radial-gradient(circle at 90% 80%, rgba(56, 189, 248, 0.08) 0%, transparent 50%), linear-gradient(180deg, #050811 0%, #060913 100%)';
    }
  };

  return (
    <div
      id="custom-app-background"
      className="fixed inset-0 pointer-events-none z-[-1] overflow-hidden transition-all duration-700"
      aria-hidden="true"
    >
      {/* 1. Base Gradient Canvas */}
      <div
        className="absolute inset-0 w-full h-full transition-all duration-700"
        style={{
          background: getPresetBackground(),
        }}
      />

      {/* 2. Custom Image Layer (if custom_image preset active & URL provided) */}
      {preset === 'custom_image' && customImageUrl && (
        <div
          className="absolute inset-0 w-full h-full bg-cover bg-center bg-no-repeat transition-all duration-500"
          style={{
            backgroundImage: `url(${customImageUrl})`,
            filter: blur > 0 ? `blur(${blur}px)` : 'none',
            transform: blur > 0 ? 'scale(1.05)' : 'scale(1)', // prevent blur white edges
          }}
        />
      )}

      {/* 3. Dynamic Dark/Light Glass Ambient Mask for contrast & readability */}
      {preset === 'custom_image' && customImageUrl && (
        <div
          className="absolute inset-0 transition-opacity duration-300"
          style={{
            backgroundColor: isLight ? '#ffffff' : '#050811',
            opacity: overlayOpacity / 100,
          }}
        />
      )}

      {/* 4. Subtle Mesh Grid Overlay */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.025] dark:opacity-[0.035]"
        style={{
          backgroundImage: `radial-gradient(${isLight ? '#000' : '#fff'} 1px, transparent 1px)`,
          backgroundSize: '24px 24px',
        }}
      />
    </div>
  );
};
