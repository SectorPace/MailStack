import { useContext, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { PageHeader, DataPanel, StatusBadge, ConfirmDialog, LoadError, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { IconRefresh, IconShield, IconWarn } from "../components/icons";
type CertRow = {
    domain: string;
    issuer?: string | null;
    subject?: string | null;
    notBefore?: string | null;
    notAfter?: string | null;
    daysUntilExpiry?: number | null;
    daysLeft?: number | null;
    certPresent?: boolean;
    keyPresent?: boolean;
    keyMode?: string | null;
    keyGroupOrWorldReadable?: boolean;
    error?: string | null;
};
function daysOf(r: CertRow): number | null {
    return r.daysUntilExpiry ?? r.daysLeft ?? null;
}
function daysLeftColor(n: number): "ok" | "warn" | "err" {
    return n > 30 ? "ok" : n > 14 ? "warn" : "err";
}
export default function TlsCerts() {
    const { t } = useSettings();
    const refreshN = useContext(RefreshContext);
    const { rows, error, reload } = useApiList<CertRow>("certs.list", [refreshN]);
    const [renew, setRenew] = useState<string | null>(null);
    async function doRenew() {
        if (!renew)
            return;
        const r = await rpc("certs.renew", { domain: renew });
        if (r.ok) {
            toast(`${renew} ✓`);
            reload();
        }
        else
            toast(r.error, "err");
    }
    const cols: Column<CertRow>[] = [
        {
            key: "domain",
            header: t("domain"),
            sortValue: (r) => r.domain,
            render: (r) => (<div className="flex items-center gap-2.5">
          <span className="flex h-8 w-8 items-center justify-center rounded-[10px]" style={{ background: "rgb(var(--accent-rgb) / 0.12)", color: "rgb(var(--accent-rgb))" }}>
            <IconShield size={15}/>
          </span>
          <span className="font-medium">{r.domain}</span>
        </div>),
            width: 220,
        },
        { key: "issuer", header: t("issuer"), sortValue: (r) => r.issuer ?? "", render: (r) => <span className="text-[var(--text-2)]">{r.issuer || "—"}</span>, width: 170 },
        {
            key: "key",
            header: "Key",
            sortValue: (r) => (r.keyPresent ? 1 : 0),
            render: (r) => {
                if (!r.certPresent && !r.keyPresent)
                    return <span className="text-[var(--text-3)]">—</span>;
                if (r.keyGroupOrWorldReadable) {
                    return (<span className="badge badge-warn" style={{ height: 20, fontSize: 11 }}>
              <IconWarn size={11}/> {r.keyMode ?? "open"}
            </span>);
                }
                return <span className="tnum text-[var(--text-2)]">{r.keyMode ?? (r.keyPresent ? "ok" : "—")}</span>;
            },
            width: 100,
        },
        { key: "notAfter", header: t("expires"), sortValue: (r) => daysOf(r) ?? 1e9, render: (r) => <span className="tnum text-[var(--text-2)]">{r.notAfter ? r.notAfter.slice(0, 10) : "—"}</span>, width: 120 },
        {
            key: "daysLeft",
            header: t("status"),
            sortValue: (r) => daysOf(r) ?? 1e9,
            render: (r) => {
                if (r.error)
                    return <StatusBadge kind="err" label={r.error}/>;
                const days = daysOf(r);
                if (days == null)
                    return <StatusBadge kind="neutral" label="—"/>;
                const c = daysLeftColor(days);
                return <StatusBadge kind={c} label={`${days} ${t("expires")}`}/>;
            },
            width: 150,
        },
        {
            key: "act",
            header: "",
            align: "right",
            render: (r) => (<button aria-label={t("renew")} title={t("renew")} className="flex h-7 items-center gap-1 rounded-[8px] px-2 text-[12px]" style={{ color: "rgb(var(--accent-rgb))", background: "rgb(var(--accent-rgb) / 0.10)" }} onClick={() => setRenew(r.domain)}>
          <IconRefresh size={13}/> {t("renew")}
        </button>),
            width: 90,
        },
    ];
    return (<div className="p-4">
      <PageHeader title={t("tls_title")} sub={t("tls_sub")}/>
      {error && <div className="mb-3"><LoadError message={error} onRetry={reload}/></div>}
      <DataPanel>
        <DataTable columns={cols} rows={rows} rowKey={(r) => r.domain} pageSize={10} filterKeys={(r) => `${r.domain} ${r.issuer}`} filterPlaceholder={t("domain")}/>
      </DataPanel>
      <ConfirmDialog open={!!renew} title={t("renew")} body={renew ?? ""} onOpenChange={(o) => !o && setRenew(null)} onConfirm={doRenew}/>
    </div>);
}
