// SF Symbols 风格细线描边图标（stroke ≈ 1.5）
import type { ReactNode, SVGProps } from "react";

type P = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 17, children, ...rest }: P & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconDashboard = (p: P) => (
  <Svg {...p}>
    <path d="M12 4a8.5 8.5 0 0 1 8.5 8.5c0 1.8-.56 3.47-1.5 4.85" />
    <path d="M12 4a8.5 8.5 0 0 0-8.5 8.5c0 1.8.56 3.47 1.5 4.85" />
    <path d="M5 17.35h14" />
    <path d="M12 12.5 15.5 8" />
    <circle cx="12" cy="13" r="1.4" fill="currentColor" stroke="none" />
  </Svg>
);

export const IconSparkles = (p: P) => (
  <Svg {...p}>
    <path d="M12 4.5 13.6 9l4.4 1.6L13.6 12 12 16.5 10.4 12 6 10.6 10.4 9 12 4.5Z" />
    <path d="M18.5 15.5 19.2 17.3 21 18l-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7.7-1.8Z" />
    <path d="M5.5 3.5 6 5l1.5.5L6 6l-.5 1.5L5 6l-1.5-.5L5 5l.5-1.5Z" />
  </Svg>
);

export const IconGlobe = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M3.5 12h17" />
    <path d="M12 3.5c2.6 2.3 3.9 5.1 3.9 8.5s-1.3 6.2-3.9 8.5c-2.6-2.3-3.9-5.1-3.9-8.5S9.4 5.8 12 3.5Z" />
  </Svg>
);

export const IconUsers = (p: P) => (
  <Svg {...p}>
    <circle cx="9" cy="8.5" r="3.2" />
    <path d="M3.5 19c.6-3 2.8-4.6 5.5-4.6S13.9 16 14.5 19" />
    <path d="M15.5 5.6a3.2 3.2 0 0 1 0 5.8" />
    <path d="M17.5 14.7c1.7.6 2.7 2 3 4.3" />
  </Svg>
);

export const IconAliases = (p: P) => (
  <Svg {...p}>
    <rect x="3.5" y="5.5" width="17" height="13" rx="2.5" />
    <path d="m4.5 7.5 7.5 5.5 7.5-5.5" />
    <path d="M9 15.5h6" />
    <path d="m13 13.5 2 2-2 2" />
  </Svg>
);

export const IconRelay = (p: P) => (
  <Svg {...p}>
    <path d="M4 17.5V8.8c0-.7.6-1.3 1.3-1.3h13.4c.7 0 1.3.6 1.3 1.3v8.7" />
    <path d="M2.5 19.5c3-.6 5-1 7.5-1s4.5.4 7.5 1" />
    <path d="M12 4.5v6" />
    <path d="m9.5 8 2.5 2.5L14.5 8" />
  </Svg>
);

export const IconKey = (p: P) => (
  <Svg {...p}>
    <circle cx="8.5" cy="12" r="4" />
    <path d="M12.5 12h8" />
    <path d="M17.5 12v3" />
    <path d="M20.5 12v2.2" />
  </Svg>
);

export const IconCert = (p: P) => (
  <Svg {...p}>
    <rect x="4" y="4" width="16" height="16" rx="3" />
    <path d="M8 9h8" />
    <path d="M8 12.5h5" />
    <circle cx="15.5" cy="15.5" r="2.2" />
    <path d="m14.2 17.4-.5 2.4 1.8-1 1.8 1-.5-2.4" />
  </Svg>
);

export const IconQueue = (p: P) => (
  <Svg {...p}>
    <path d="M4 13.5V17c0 1.4 1.1 2.5 2.5 2.5h11c1.4 0 2.5-1.1 2.5-2.5v-3.5" />
    <path d="M4 10.5V7c0-1.4 1.1-2.5 2.5-2.5h11C18.9 4.5 20 5.6 20 7v3.5" />
    <path d="M7 8.5h6" />
    <path d="M7 16h4" />
  </Svg>
);

export const IconLogs = (p: P) => (
  <Svg {...p}>
    <rect x="4.5" y="3.5" width="15" height="17" rx="2.5" />
    <path d="M8 8h8" />
    <path d="M8 11.5h8" />
    <path d="M8 15h4.5" />
  </Svg>
);

export const IconServices = (p: P) => (
  <Svg {...p}>
    <rect x="4" y="4.5" width="16" height="6" rx="2" />
    <rect x="4" y="13.5" width="16" height="6" rx="2" />
    <path d="M7.5 7.5h.01" />
    <path d="M7.5 16.5h.01" />
    <path d="M13 7.5h3.5" />
    <path d="M13 16.5h3.5" />
  </Svg>
);

export const IconShield = (p: P) => (
  <Svg {...p}>
    <path d="M12 3.5 5 6v5.5c0 4.4 3 7.4 7 9 4-1.6 7-4.6 7-9V6l-7-2.5Z" />
    <path d="m9 11.8 2.2 2.2 4-4.2" />
  </Svg>
);

export const IconGear = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="3.2" />
    <path d="M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2 5.5 5.5" />
  </Svg>
);

export const IconSearch = (p: P) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="6.5" />
    <path d="m20 20-4.4-4.4" />
  </Svg>
);

export const IconBell = (p: P) => (
  <Svg {...p}>
    <path d="M12 4a5.5 5.5 0 0 0-5.5 5.5c0 4-1.5 5.4-2 6-.3.4 0 1 .6 1h13.8c.6 0 .9-.6.6-1-.5-.6-2-2-2-6A5.5 5.5 0 0 0 12 4Z" />
    <path d="M10 19.5a2 2 0 0 0 4 0" />
  </Svg>
);

export const IconRefresh = (p: P) => (
  <Svg {...p}>
    <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
    <path d="M19.7 3.8v3.4h-3.4" />
  </Svg>
);

export const IconSun = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v2M12 19.5v2M21.5 12h-2M4.5 12h-2M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4M18.7 18.7l-1.4-1.4M6.7 6.7 5.3 5.3" />
  </Svg>
);

export const IconMoon = (p: P) => (
  <Svg {...p}>
    <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z" />
  </Svg>
);

export const IconLang = (p: P) => (
  <Svg {...p}>
    <path d="M4 5.5h9" />
    <path d="M8.5 3.5v2" />
    <path d="M11 5.5c-.8 3.6-3 6.6-6.5 8.7" />
    <path d="M6 8.8c1.3 2.4 3.2 4.1 5.5 5" />
    <path d="m12.5 20.5 4-9.5 4 9.5" />
    <path d="M13.8 17.5h5.4" />
  </Svg>
);

export const IconChevronDown = (p: P) => (
  <Svg {...p}>
    <path d="m6.5 9.5 5.5 5.5 5.5-5.5" />
  </Svg>
);

export const IconChevronRight = (p: P) => (
  <Svg {...p}>
    <path d="m9.5 6.5 5.5 5.5-5.5 5.5" />
  </Svg>
);

export const IconUser = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="8.5" r="3.8" />
    <path d="M4.5 20c.8-3.6 3.6-5.5 7.5-5.5s6.7 1.9 7.5 5.5" />
  </Svg>
);

export const IconCheck = (p: P) => (
  <Svg {...p}>
    <path d="m5 12.5 4.5 4.5L19 7.5" />
  </Svg>
);

export const IconX = (p: P) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Svg>
);

export const IconWarn = (p: P) => (
  <Svg {...p}>
    <path d="M12 4 3.5 19h17L12 4Z" />
    <path d="M12 10v4" />
    <path d="M12 16.8h.01" />
  </Svg>
);

export const IconInfo = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 11v5" />
    <path d="M12 7.8h.01" />
  </Svg>
);

export const IconPlus = (p: P) => (
  <Svg {...p}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);

export const IconTrash = (p: P) => (
  <Svg {...p}>
    <path d="M4.5 6.5h15" />
    <path d="M9 6V4.8c0-.7.6-1.3 1.3-1.3h3.4c.7 0 1.3.6 1.3 1.3V6" />
    <path d="M6.5 6.5 7.3 19c.1 1 .9 1.5 1.8 1.5h5.8c.9 0 1.7-.5 1.8-1.5l.8-12.5" />
    <path d="M10 10.5v6M14 10.5v6" />
  </Svg>
);

export const IconSend = (p: P) => (
  <Svg {...p}>
    <path d="M20.5 3.5 10 14" />
    <path d="M20.5 3.5 14 20.5l-4-6.5-6.5-4 17-6.5Z" />
  </Svg>
);

export const IconPlay = (p: P) => (
  <Svg {...p}>
    <path d="M7.5 5.5v13l10-6.5-10-6.5Z" />
  </Svg>
);

export const IconStop = (p: P) => (
  <Svg {...p}>
    <rect x="6.5" y="6.5" width="11" height="11" rx="1.5" />
  </Svg>
);

export const IconRestart = (p: P) => (
  <Svg {...p}>
    <path d="M4.5 12a7.5 7.5 0 0 1 12.8-5.3" />
    <path d="M19.5 12a7.5 7.5 0 0 1-12.8 5.3" />
    <path d="M17.5 3.5v3.4h-3.4" />
    <path d="M6.5 20.5v-3.4h3.4" />
  </Svg>
);

export const IconClock = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 7.5V12l3 2.5" />
  </Svg>
);

export const IconCalendar = (p: P) => (
  <Svg {...p}>
    <rect x="4" y="5.5" width="16" height="15" rx="2.5" />
    <path d="M4 10h16" />
    <path d="M8.5 3.5v3M15.5 3.5v3" />
  </Svg>
);

export const IconFilter = (p: P) => (
  <Svg {...p}>
    <path d="M4 6h16" />
    <path d="M7 12h10" />
    <path d="M10 18h4" />
  </Svg>
);

export const IconMail = (p: P) => (
  <Svg {...p}>
    <rect x="3.5" y="5.5" width="17" height="13" rx="2.5" />
    <path d="m4.5 7.5 7.5 5.5 7.5-5.5" />
  </Svg>
);

export const IconEye = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
    <circle cx="12" cy="12" r="2.8" />
  </Svg>
);

export const IconEyeOff = (p: P) => (
  <Svg {...p}>
    <path d="M4 4l16 16" />
    <path d="M9.9 5.9A9.9 9.9 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17.5 17.5 0 0 1-2.4 3.2M6.1 7.6A17 17 0 0 0 2.5 12S6 18.5 12 18.5a9.7 9.7 0 0 0 4.3-1" />
    <path d="M9.5 10.2a3 3 0 0 0 4.2 4.3" />
  </Svg>
);

export const IconMenu = (p: P) => (
  <Svg {...p}>
    <path d="M4 7h16" />
    <path d="M4 12h16" />
    <path d="M4 17h16" />
  </Svg>
);

export const IconLogo = ({ size = 24 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 28 28" fill="none" aria-hidden="true">
    <rect x="1" y="1" width="26" height="26" rx="7.5" fill="url(#mslg)" />
    <rect x="1" y="1" width="26" height="26" rx="7.5" fill="url(#mssh)" fillOpacity="0.35" style={{ mixBlendMode: "overlay" }} />
    <path
      d="M6.5 10.5 14 16l7.5-5.5"
      stroke="#fff"
      strokeWidth="1.9"
      strokeLinecap="round"
      strokeLinejoin="round"
      opacity="0.95"
    />
    <rect x="6.5" y="9" width="15" height="10.5" rx="2.4" stroke="#fff" strokeWidth="1.9" opacity="0.9" />
    <defs>
      <linearGradient id="mslg" x1="1" y1="1" x2="27" y2="27">
        <stop stopColor="#3BA0FF" />
        <stop offset="1" stopColor="#0A6CFF" />
      </linearGradient>
      <linearGradient id="mssh" x1="1" y1="1" x2="1" y2="27">
        <stop stopColor="#fff" />
        <stop offset="1" stopColor="#063" stopOpacity="0" />
      </linearGradient>
    </defs>
  </svg>
);
