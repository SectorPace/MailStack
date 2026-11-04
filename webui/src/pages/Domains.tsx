import { useContext, useState } from "react";
import * as RDMenu from "@radix-ui/react-dropdown-menu";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { ConfirmDialog, DataPanel, LoadError, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { InputDialog } from "../components/InputDialog";
import { IconMore, IconPlus } from "../components/icons";
type DomainRow = {
    name?: string;
    target?: string;
    domain?: string;
};
const domainName = (r: DomainRow) => r.name ?? r.domain ?? "";
export default function Domains() {
    const { t } = useSettings();
    const refreshN = useContext(RefreshContext);
    const { rows, setRows, error, reload } = useApiList<DomainRow>("domains.list", [refreshN]);
    const [addOpen, setAddOpen] = useState(false);
    const [values, setValues] = useState({ domain: "" });
    const [del, setDel] = useState<string | null>(null);
    const [menuRow, setMenuRow] = useState<string | null>(null);
    const [testingKey, setTestingKey] = useState<string | null>(null);
    async function add() {
        const r = await rpc("domains.add", { domain: values.domain.trim() });
        if (r.ok) {
            toast(`${values.domain.trim()} ✓`);
            setAddOpen(false);
            setValues({ domain: "" });
            reload();
        }
        else
            toast(r.error, "err");
    }
    async function remove() {
        if (!del)
            return;
        const r = await rpc("domains.delete", { domain: del });
        if (r.ok) {
            setRows((x) => x.filter((d) => domainName(d) !== del));
            toast("OK");
        }
        else
            toast(r.error, "err");
    }
    async function testDomain(name: string) {
        setTestingKey(name);
        const r = await rpc<{
            open?: boolean;
            latencyMs?: number;
        }>("network.check_port", {
            host: name,
            port: 25,
        });
        if (r.ok && r.data) {
            const open = r.data.open === true;
            toast(open ? t("domain_test_open", { ms: r.data.latencyMs ?? 0 }) : t("domain_test_closed"), open ? "ok" : "warn");
        }
        else {
            toast(r.ok ? t("domain_test_closed") : r.error, "err");
        }
        setTestingKey(null);
    }
    const cols: Column<DomainRow>[] = [
        { key: "domain", header: t("domain"), sortValue: (r) => domainName(r), render: (r) => <span className="font-medium">{domainName(r)}</span>, width: 260 },
        { key: "target", header: "Target", sortValue: (r) => r.target ?? "", render: (r) => <span className="mono text-[var(--text-2)]">{r.target || "—"}</span>, width: 260 },
        {
            key: "act",
            header: "",
            align: "right",
            width: 56,
            render: (r) => {
                const k = domainName(r);
                return (<RDMenu.Root open={menuRow === k} onOpenChange={(o) => setMenuRow(o ? k : null)}>
            <RDMenu.Trigger className="icon-btn" aria-label={t("actions")} aria-haspopup="menu" onClick={(e) => e.stopPropagation()}>
              <IconMore size={15}/>
            </RDMenu.Trigger>
            <RDMenu.Portal>
              <RDMenu.Content className="glass--clear radix-pop" align="end" sideOffset={4}>
                <RDMenu.Item className="radix-item" disabled={testingKey === k} onSelect={() => void testDomain(k)}>
                  {t("test")}
                </RDMenu.Item>
                <RDMenu.Separator className="radix-sep"/>
                <RDMenu.Item className="radix-item" style={{ color: "rgb(var(--err-rgb))" }} onSelect={() => setDel(k)}>
                  {t("delete")}
                </RDMenu.Item>
              </RDMenu.Content>
            </RDMenu.Portal>
          </RDMenu.Root>);
            },
        },
    ];
    return (<div className="p-4">

      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 items-baseline gap-2.5">
          <h1 className="font-semibold leading-tight tracking-[-0.015em] text-[var(--text-1)]" style={{ fontSize: "var(--font-title)" }}>
            {t("domains_title")}
          </h1>
          <span className="tnum" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            {t("total_items", { n: rows.length })}
          </span>
        </div>
        <button className="btn btn-accent" onClick={() => setAddOpen(true)}>
          <IconPlus size={14}/> {t("add")}
        </button>
      </div>

      {error && (<div className="mb-3">
          <LoadError message={error} onRetry={reload}/>
        </div>)}

      <DataPanel>
        <DataTable columns={cols} rows={rows} rowKey={(r) => domainName(r)} pageSize={10} filterKeys={(r) => domainName(r)} filterPlaceholder={t("domain")} onRowClick={(r) => setMenuRow(domainName(r))}/>
      </DataPanel>

      <InputDialog open={addOpen} title={t("domains_title")} fields={[{ key: "domain", label: t("domain"), placeholder: "mail.example.com" }]} values={values} onChange={(k, v) => setValues((x) => ({ ...x, [k]: v }))} onClose={() => setAddOpen(false)} onSubmit={add}/>

      <ConfirmDialog open={!!del} title={t("delete")} body={del ?? ""} danger onOpenChange={(o) => !o && setDel(null)} onConfirm={remove}/>
    </div>);
}
