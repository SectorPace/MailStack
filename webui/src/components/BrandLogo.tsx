import { useSettings } from "../store/settings";
export function BrandLogo({ size = 26, radius = 8 }: {
    size?: number;
    radius?: number;
}) {
    const { resolvedTheme } = useSettings();
    return (<img src={resolvedTheme === "dark" ? "logo-dark.png" : "logo-light.png"} alt="MailStack" width={size} height={size} draggable={false} style={{
            width: size,
            height: size,
            borderRadius: radius,
            objectFit: "cover",
            boxShadow: "0 1px 4px rgba(10, 22, 40, 0.18)",
        }}/>);
}
