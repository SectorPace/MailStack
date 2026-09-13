import React, { Suspense, lazy, useCallback } from "react";
import { AppProvider, useApp } from "./context/AppContext";
import { Header } from "./components/layout/Header";
import { Sidebar } from "./components/layout/Sidebar";
import { SearchModal } from "./components/layout/SearchModal";
import { ToastContainer } from "./components/ui/Toast";
import { LoginView } from "./components/views/LoginView";
import { SetupGuideModal } from "./components/modals/SetupGuideModal";
import { BackgroundRenderer } from "./components/common/BackgroundRenderer";
import { ErrorBoundary } from "./components/ErrorBoundary";

const DashboardView = lazy(() =>
  import("./components/views/DashboardView").then((module) => ({
    default: module.DashboardView,
  })),
);
const DomainsView = lazy(() =>
  import("./components/views/DomainsView").then((module) => ({
    default: module.DomainsView,
  })),
);
const UsersView = lazy(() =>
  import("./components/views/UsersView").then((module) => ({
    default: module.UsersView,
  })),
);
const AliasesView = lazy(() =>
  import("./components/views/AliasesView").then((module) => ({
    default: module.AliasesView,
  })),
);
const SmtpRelayView = lazy(() =>
  import("./components/views/SmtpRelayView").then((module) => ({
    default: module.SmtpRelayView,
  })),
);
const DkimDnsView = lazy(() =>
  import("./components/views/DkimDnsView").then((module) => ({
    default: module.DkimDnsView,
  })),
);
const CertificatesView = lazy(() =>
  import("./components/views/CertificatesView").then((module) => ({
    default: module.CertificatesView,
  })),
);
const QueueView = lazy(() =>
  import("./components/views/QueueView").then((module) => ({
    default: module.QueueView,
  })),
);
const LogsView = lazy(() =>
  import("./components/views/LogsView").then((module) => ({
    default: module.LogsView,
  })),
);
const ServicesView = lazy(() =>
  import("./components/views/ServicesView").then((module) => ({
    default: module.ServicesView,
  })),
);
const SecurityView = lazy(() =>
  import("./components/views/SecurityView").then((module) => ({
    default: module.SecurityView,
  })),
);
const SettingsView = lazy(() =>
  import("./components/views/SettingsView").then((module) => ({
    default: module.SettingsView,
  })),
);
const AiSuiteView = lazy(() =>
  import("./components/views/AiSuiteView").then((module) => ({
    default: module.AiSuiteView,
  })),
);
const SetupGuideView = lazy(() =>
  import("./components/views/SetupGuideView").then((module) => ({
    default: module.SetupGuideView,
  })),
);

const LiquidGlassShaderDefs: React.FC = () => (
  <svg className="hidden fixed pointer-events-none w-0 h-0" aria-hidden="true">
    <defs>
      {/* 1. SVG Liquid Refraction Shader (shuding/liquid-glass & archisvaze/liquid-glass) */}
      <filter
        id="liquid-glass-refract"
        x="-20%"
        y="-20%"
        width="140%"
        height="140%"
      >
        <feTurbulence
          type="fractalNoise"
          baseFrequency="0.015 0.015"
          numOctaves="2"
          result="noise"
        />
        <feDisplacementMap
          in="SourceGraphic"
          in2="noise"
          scale="3"
          xChannelSelector="R"
          yChannelSelector="G"
          result="displaced"
        />
        <feGaussianBlur in="displaced" stdDeviation="0.4" result="blurred" />
        <feMerge>
          <feMergeNode in="blurred" />
          <feMergeNode in="SourceGraphic" opacity="0.35" />
        </feMerge>
      </filter>

      {/* 2. Apple Specular Reflection Bevel Light (Mikhail-Bespalov MYwrMNy) */}
      <filter
        id="liquid-specular-light"
        x="-20%"
        y="-20%"
        width="140%"
        height="140%"
      >
        <feGaussianBlur in="SourceAlpha" stdDeviation="2.5" result="blur" />
        <feSpecularLighting
          in="blur"
          surfaceScale="3.5"
          specularConstant="1.4"
          specularExponent="22"
          lightingColor="#ffffff"
          result="specular"
        >
          <fePointLight x="120" y="-60" z="220" />
        </feSpecularLighting>
        <feComposite
          in="specular"
          in2="SourceAlpha"
          operator="in"
          result="specular-light"
        />
        <feComposite
          in="SourceGraphic"
          in2="specular-light"
          operator="arithmetic"
          k1="0"
          k2="1"
          k3="1"
          k4="0"
        />
      </filter>

      {/* 3. Prismatic Chromatic Dispersion Filter (rdev/liquid-glass-react & codesandbox nn5q2y) */}
      <filter
        id="liquid-chromatic-dispersion"
        x="-10%"
        y="-10%"
        width="120%"
        height="120%"
      >
        <feOffset in="SourceGraphic" dx="1.2" dy="0" result="redShift" />
        <feColorMatrix
          in="redShift"
          type="matrix"
          values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0"
          result="red"
        />

        <feOffset in="SourceGraphic" dx="0" dy="0" result="greenShift" />
        <feColorMatrix
          in="greenShift"
          type="matrix"
          values="0 0 0 0 0  0 1 0 0 0  0 0 0 0 0  0 0 0 1 0"
          result="green"
        />

        <feOffset in="SourceGraphic" dx="-1.2" dy="0" result="blueShift" />
        <feColorMatrix
          in="blueShift"
          type="matrix"
          values="0 0 0 0 0  0 0 0 0 0  0 0 1 0 0  0 0 0 1 0"
          result="blue"
        />

        <feBlend in="red" in2="green" mode="screen" result="rg" />
        <feBlend in="rg" in2="blue" mode="screen" result="rgb" />
      </filter>

      {/* 4. Fluid Droplet Surface Tension (wxperia/liquid-glass-vue) */}
      <filter
        id="liquid-droplet-glow"
        x="-25%"
        y="-25%"
        width="150%"
        height="150%"
      >
        <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
        <feColorMatrix
          in="blur"
          type="matrix"
          values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 18 -7"
          result="goo"
        />
        <feBlend in="SourceGraphic" in2="goo" />
      </filter>
    </defs>
  </svg>
);

const MainLayout: React.FC = () => {
  const { currentSection, isLoggedIn, themeMode, settings, hasCompletedOnboarding } = useApp();

  // Interactive mouse tracking for dynamic specular glass sheen
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const { clientX, clientY } = e;
    document.documentElement.style.setProperty("--mouse-x", `${clientX}px`);
    document.documentElement.style.setProperty("--mouse-y", `${clientY}px`);
  }, []);

  if (!isLoggedIn) {
    return (
      <div
        onMouseMove={handleMouseMove}
        className={`relative min-h-screen w-screen overflow-x-hidden flex items-center justify-center transition-colors duration-300 ${
          themeMode === "light" ? "text-slate-900 theme-light bg-[#f4f6fb]" : "text-slate-100 bg-[#060913]"
        }`}
        style={{
          ["--custom-blur" as any]: `${settings.backdropBlur}px`,
        }}
      >
        <BackgroundRenderer />
        <LoginView />
        <ToastContainer />
        <LiquidGlassShaderDefs />
      </div>
    );
  }

  // Fresh install experience: Full-screen setup guide without distractions
  if (!hasCompletedOnboarding) {
    return (
      <div
        onMouseMove={handleMouseMove}
        className={`h-screen w-screen overflow-hidden flex flex-col relative ${
          themeMode === "light" ? "text-slate-900 theme-light" : "text-slate-100"
        }`}
        style={{
          ["--custom-blur" as any]: `${settings.backdropBlur}px`,
        }}
      >
        <BackgroundRenderer />
        <div className="flex-1 overflow-y-auto p-4 sm:p-8 relative z-10">
          <ErrorBoundary>
            <Suspense fallback={<div className="p-8 text-sm text-slate-400">Loading setup guide...</div>}>
              <SetupGuideView />
            </Suspense>
          </ErrorBoundary>
        </div>
        <ToastContainer />
        <LiquidGlassShaderDefs />
      </div>
    );
  }

  const renderCurrentView = () => {
    switch (currentSection) {
      case "dashboard":
        return <DashboardView />;
      case "setup_guide":
        return <SetupGuideView />;
      case "ai_suite":
        return <AiSuiteView />;
      case "ai_diagnostic":
        return <AiSuiteView initialTab="diagnostic" />;
      case "ai_assistant":
        return <AiSuiteView initialTab="assistant" />;
      case "domains":
        return <DomainsView />;
      case "users":
        return <UsersView />;
      case "aliases":
        return <AliasesView />;
      case "smtp_relay":
        return <SmtpRelayView />;
      case "dkim_dns":
        return <DkimDnsView />;
      case "tls_certs":
        return <CertificatesView />;
      case "mail_queue":
        return <QueueView />;
      case "logs":
        return <LogsView />;
      case "services":
        return <ServicesView />;
      case "security":
        return <SecurityView />;
      case "settings":
        return <SettingsView />;
      default:
        return <DashboardView />;
    }
  };

  return (
    <div
      onMouseMove={handleMouseMove}
      className={`h-screen w-screen overflow-hidden flex relative ${
        themeMode === "light" ? "text-slate-900 theme-light" : "text-slate-100"
      }`}
      style={{
        // Dynamic transparency and blur applied from system settings
        ["--custom-blur" as any]: `${settings.backdropBlur}px`,
      }}
    >
      {/* Dynamic Customizable System Background & Wallpaper Layer */}
      <BackgroundRenderer />

      {/* Left Sidebar - Fixed and non-scrolling */}
      <div className="relative z-10">
        <Sidebar />
      </div>

      {/* Main Content Area - Scrollable and responsive */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto overflow-x-hidden relative z-10">
        <Header />
        <main className="flex-1 pb-16">
          <ErrorBoundary>
            <Suspense
              fallback={
                <div className="p-8 text-sm text-slate-400">Loading...</div>
              }
            >
              {renderCurrentView()}
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>

      {/* Global Modals & Notifications */}
      <SearchModal />
      <SetupGuideModal />
      <ToastContainer />
      <LiquidGlassShaderDefs />
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <MainLayout />
    </AppProvider>
  );
}
