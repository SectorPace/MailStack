// Webmail 图标 —— 复用管理台 `src/components/icons.tsx` 的视觉语言（viewBox 24 /
// strokeWidth 1.8 / round 线帽，契约 §5 要求复用该图标集），仅补充邮件客户端特有的
// 符号（星标、回复、转发、归档、文件夹等 SF Symbols 风格细线图标）。

export {
  IconCheck,
  IconChevronDown,
  IconChevronRight,
  IconClock,
  IconEye,
  IconEyeOff,
  IconGear,
  IconGlobe,
  IconInfo,
  IconKey,
  IconMail,
  IconMenu,
  IconMore,
  IconRefresh,
  IconSearch,
  IconSend,
  IconShield,
  IconSun,
  IconMoon,
  IconTrash,
  IconUser,
  IconWarn,
  IconX,
} from "../../components/icons";

import type { ReactNode, SVGProps } from "react";

type P = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 16, children, ...rest }: P & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

/** 星标（filled=true 时实心填充，用于已加星）。 */
export const IconStar = ({ size = 16, filled = false, ...rest }: P & { filled?: boolean }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill={filled ? "currentColor" : "none"}
    stroke="currentColor"
    strokeWidth={1.8}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    {...rest}
  >
    <path d="m12 3.8 2.5 5.1 5.6.8-4 3.9 1 5.6-5.1-2.7-5.1 2.7 1-5.6-4-3.9 5.6-.8L12 3.8Z" />
  </svg>
);

export const IconReply = (p: P) => (
  <Svg {...p}>
    <path d="M9.5 6.5 4 12l5.5 5.5" />
    <path d="M4 12h10.5c3 0 5.5 2.2 5.5 5.2V18" />
  </Svg>
);

export const IconReplyAll = (p: P) => (
  <Svg {...p}>
    <path d="M8 6.5 3 12l5 5.5" />
    <path d="M13 6.5 8 12l5 5.5" />
    <path d="M8 12h7.5c2.8 0 5 2.2 5 5.1V18" />
  </Svg>
);

export const IconForward = (p: P) => (
  <Svg {...p}>
    <path d="M14.5 6.5 20 12l-5.5 5.5" />
    <path d="M20 12H9.5C6.5 12 4 14.2 4 17.2V18" />
  </Svg>
);

export const IconArchive = (p: P) => (
  <Svg {...p}>
    <rect x="3.5" y="5" width="17" height="4" rx="1.2" />
    <path d="M5 9v9.5c0 .8.7 1.5 1.5 1.5h11c.8 0 1.5-.7 1.5-1.5V9" />
    <path d="M10 13h4" />
  </Svg>
);

export const IconInbox = (p: P) => (
  <Svg {...p}>
    <path d="M4 13.5V17c0 1.4 1.1 2.5 2.5 2.5h11c1.4 0 2.5-1.1 2.5-2.5v-3.5" />
    <path d="M4 13.5h4l1.5 2.5h5l1.5-2.5h4L18 6.2c-.4-1-1.3-1.7-2.4-1.7H8.4c-1.1 0-2 .7-2.4 1.7L4 13.5Z" />
  </Svg>
);

export const IconFolder = (p: P) => (
  <Svg {...p}>
    <path d="M3.5 7.5c0-1.1.9-2 2-2h3.4c.6 0 1.1.2 1.5.7l1 1.3h7.1c1.1 0 2 .9 2 2v7.5c0 1.1-.9 2-2 2H5.5c-1.1 0-2-.9-2-2V7.5Z" />
  </Svg>
);

export const IconDraft = (p: P) => (
  <Svg {...p}>
    <path d="M4 20h4l10.5-10.5a2.1 2.1 0 0 0-3-3L5 17v3Z" />
    <path d="m13.5 7.5 3 3" />
  </Svg>
);

export const IconJunk = (p: P) => (
  <Svg {...p}>
    <path d="M12 3.8 21 20H3L12 3.8Z" />
    <path d="M12 9.5v4.5" />
    <path d="M12 17h.01" />
  </Svg>
);

export const IconTrashCan = (p: P) => (
  <Svg {...p}>
    <path d="M4.5 6.5h15" />
    <path d="M9 6V4.8c0-.7.6-1.3 1.3-1.3h3.4c.7 0 1.3.6 1.3 1.3V6" />
    <path d="M6.5 6.5 7.3 19c.1 1 .9 1.5 1.8 1.5h5.8c.9 0 1.7-.5 1.8-1.5l.8-12.5" />
  </Svg>
);

export const IconPaperclip = (p: P) => (
  <Svg {...p}>
    <path d="M20 11.5 12.3 19a4.2 4.2 0 0 1-6-6l8-8a2.8 2.8 0 1 1 4 4l-8 8a1.4 1.4 0 0 1-2-2l7.2-7.2" />
  </Svg>
);

export const IconPrinter = (p: P) => (
  <Svg {...p}>
    <path d="M7 8V4h10v4" />
    <rect x="4" y="8" width="16" height="8" rx="2" />
    <path d="M7 13h10v7H7z" />
  </Svg>
);

export const IconDownload = (p: P) => (
  <Svg {...p}>
    <path d="M12 4v11" />
    <path d="m7.5 10.5 4.5 4.5 4.5-4.5" />
    <path d="M5 20h14" />
  </Svg>
);

export const IconArrowLeft = (p: P) => (
  <Svg {...p}>
    <path d="M19 12H5" />
    <path d="m10.5 6.5-5.5 5.5 5.5 5.5" />
  </Svg>
);

export const IconCompose = (p: P) => (
  <Svg {...p}>
    <path d="M12.5 5H6.8C5.3 5 4 6.3 4 7.8v9.4C4 18.7 5.3 20 6.8 20h9.4c1.5 0 2.8-1.3 2.8-2.8v-5.7" />
    <path d="M18.4 3.6a2.2 2.2 0 0 1 3.1 3.1L13 15.2l-4 1 1-4 8.4-8.6Z" />
  </Svg>
);

export const IconImageOff = (p: P) => (
  <Svg {...p}>
    <rect x="3.5" y="5" width="17" height="14" rx="2.5" />
    <path d="m4.5 18 5-5 3 3 3-2.5 4 4" />
    <path d="M3.5 3.5 20.5 20.5" />
  </Svg>
);

export const IconFolderPlus = (p: P) => (
  <Svg {...p}>
    <path d="M3.5 7.5c0-1.1.9-2 2-2h3.4c.6 0 1.1.2 1.5.7l1 1.3h7.1c1.1 0 2 .9 2 2v2" />
    <path d="M3.5 7.5v9.7c0 1.1.9 2 2 2h6" />
    <path d="M18 14v7M14.5 17.5h7" />
  </Svg>
);

export const IconExpand = (p: P) => (
  <Svg {...p}>
    <path d="M9 4H4v5" />
    <path d="M15 20h5v-5" />
    <path d="M20 9V4h-5" />
    <path d="M4 15v5h5" />
  </Svg>
);

export const IconMinimize = (p: P) => (
  <Svg {...p}>
    <path d="M5 12h14" />
  </Svg>
);

export const IconLink = (p: P) => (
  <Svg {...p}>
    <path d="M10.5 13.5a3.5 3.5 0 0 0 5 0l2.6-2.6a3.5 3.5 0 0 0-5-5l-1.5 1.5" />
    <path d="M13.5 10.5a3.5 3.5 0 0 0-5 0l-2.6 2.6a3.5 3.5 0 0 0 5 5l1.5-1.5" />
  </Svg>
);

export const IconEraser = (p: P) => (
  <Svg {...p}>
    <path d="m7 16.5 6.5-6.5a2.5 2.5 0 0 1 3.5 3.5l-4 4" />
    <path d="M4.5 19.5h15" />
    <path d="m9 14.5 4 4" />
  </Svg>
);

export const IconListOrdered = (p: P) => (
  <Svg {...p}>
    <path d="M9.5 6.5h10M9.5 12h10M9.5 17.5h10" />
    <path d="M4.5 5.5h1v4M4.2 9.5h1.9" />
    <path d="M4.3 13.4c.2-.4.6-.7 1.1-.7.7 0 1.2.5 1.2 1.1 0 .9-1.6 1.3-2.3 2.2h2.4" />
  </Svg>
);

export const IconListBullet = (p: P) => (
  <Svg {...p}>
    <path d="M9.5 6.5h10M9.5 12h10M9.5 17.5h10" />
    <circle cx="5.3" cy="6.5" r="0.9" fill="currentColor" stroke="none" />
    <circle cx="5.3" cy="12" r="0.9" fill="currentColor" stroke="none" />
    <circle cx="5.3" cy="17.5" r="0.9" fill="currentColor" stroke="none" />
  </Svg>
);

export const IconQuoteMark = (p: P) => (
  <Svg {...p}>
    <path d="M9.5 6.5c-2 1-3 2.6-3 4.7v6.3h5V11H8.3" />
    <path d="M18.5 6.5c-2 1-3 2.6-3 4.7v6.3h5V11h-3.2" />
  </Svg>
);

export const IconBold = (p: P) => (
  <Svg {...p} strokeWidth={2.2}>
    <path d="M7.5 5.5h5a3.2 3.2 0 0 1 0 6.5h-5z" />
    <path d="M7.5 12h5.6a3.3 3.3 0 0 1 0 6.5H7.5z" />
  </Svg>
);

export const IconItalic = (p: P) => (
  <Svg {...p}>
    <path d="M10 5.5h7M7 18.5h7M14 5.5 10 18.5" />
  </Svg>
);

export const IconUnderline = (p: P) => (
  <Svg {...p}>
    <path d="M7.5 4.5v6.8a4.5 4.5 0 0 0 9 0V4.5" />
    <path d="M5.5 19.5h13" />
  </Svg>
);

/** 品牌 logo（按主题切换图片；与 BrandLogo.tsx 同源素材）。 */
export function MailBrandLogo({ dark, size = 22 }: { dark: boolean; size?: number }) {
  return (
    <img
      src={dark ? "logo-dark.png" : "logo-light.png"}
      alt="MailStack"
      width={size}
      height={size}
      draggable={false}
      style={{ width: size, height: size, borderRadius: 6, objectFit: "cover", boxShadow: "0 1px 4px rgba(10,22,40,.18)" }}
    />
  );
}
