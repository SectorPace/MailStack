import { useContext, useState } from "react";
import * as RDropdown from "@radix-ui/react-dropdown-menu";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { PageHeader, DataPanel, StatusBadge, ConfirmDialog, LoadError, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { InputDialog } from "../components/InputDialog";
import { IconPlus, IconGear } from "../components/icons";
type UserRow = {
    address: string;
    name: string;
    active: boolean;
    quotaUsed: number;
    quotaTotal: number;
    createdAt: string;
};
const QUOTA_MIN = 1;
const QUOTA_MAX = 1000000;
export default function Users() {
    const { t, prefs } = useSettings();
    const zh = prefs.lang === "zh";
    const refreshN = useContext(RefreshContext);
    const { rows, setRows, error, reload } = useApiList<UserRow>("users.list", [refreshN]);
    const [addOpen, setAddOpen] = useState(false);
    const [values, setValues] = useState({ address: "", name: "", quota: "10", password: "" });
    const [del, setDel] = useState<string | null>(null);
    const [pwdFor, setPwdFor] = useState<UserRow | null>(null);
    const [pwdValue, setPwdValue] = useState("");
    async function add() {
        const quota = Number(values.quota.trim());
        if (!Number.isInteger(quota) || quota < QUOTA_MIN || quota > QUOTA_MAX) {
            toast(zh ? `配额必须是 ${QUOTA_MIN}–${QUOTA_MAX} 之间的整数（GB）` : `Quota must be an integer between ${QUOTA_MIN} and ${QUOTA_MAX} (GB)`, "err");
            return;
        }
        const r = await rpc("users.add", {
            address: values.address.trim(),
            name: values.name.trim(),
            password: values.password,
            quota,
        });
        if (r.ok) {
            toast(`${values.address.trim()} ✓`);
            setAddOpen(false);
            setValues({ address: "", name: "", quota: "10", password: "" });
            reload();
        }
        else
            toast(r.error, "err");
    }
    async function toggle(u: UserRow) {
        const r = await rpc("users.status", { address: u.address, active: !u.active });
        if (r.ok)
            setRows((x) => x.map((y) => (y.address === u.address ? { ...y, active: !u.active } : y)));
        else
            toast(r.error, "err");
    }
    async function resetPwd() {
        if (!pwdFor)
            return;
        const r = await rpc("users.password", { address: pwdFor.address, password: pwdValue });
        if (r.ok) {
            toast(`${pwdFor.address} · ${t("reset_password")} ✓`);
            setPwdFor(null);
            setPwdValue("");
        }
        else
            toast(r.error, "err");
    }
    async function remove() {
        if (!del)
            return;
        const r = await rpc("users.delete", { address: del });
        if (r.ok) {
            setRows((x) => x.filter((u) => u.address !== del));
            toast("OK");
        }
        else
            toast(r.error, "err");
    }
    const cols: Column<UserRow>[] = [
        {
            key: "address",
            header: t("users_title"),
            sortValue: (r) => r.address,
            render: (r) => (<div className="leading-tight">
          <div className="font-medium">{r.address}</div>
          <div className="text-[11px] text-[var(--text-3)]">{r.name}</div>
        </div>),
            width: 240,
        },
        { key: "active", header: t("status"), sortValue: (r) => (r.active ? 1 : 0), render: (r) => <StatusBadge kind={r.active ? "ok" : "neutral"} label={r.active ? t("enabled") : t("disabled")}/>, width: 110 },
        {
            key: "quota",
            header: t("quota"),
            width: 190,
            render: () => <span className="text-[11.5px] text-[var(--text-3)]">{t("quota_not_impl")}</span>,
        },
        { key: "createdAt", header: t("created_at"), sortValue: (r) => r.createdAt, render: (r) => <span className="tnum text-[var(--text-2)]">{r.createdAt}</span>, width: 158 },
        {
            key: "act",
            header: "",
            align: "right",
            render: (r) => (<UserActions onToggle={() => toggle(r)} onReset={() => setPwdFor(r)} onDelete={() => setDel(r.address)} active={r.active}/>),
            width: 90,
        },
    ];
    return (<div className="p-4">
      <PageHeader title={t("users_title")} sub={t("users_sub")} right={<button className="btn btn-accent" onClick={() => setAddOpen(true)}>
            <IconPlus size={14}/> {t("add")}
          </button>}/>
      <DataPanel>
        {error && <div className="px-3 pt-3"><LoadError message={error} onRetry={reload}/></div>}
        <DataTable columns={cols} rows={rows} rowKey={(r) => r.address} pageSize={10} filterKeys={(r) => `${r.address} ${r.name}`} filterPlaceholder={t("users_title")}/>
      </DataPanel>

      <InputDialog open={addOpen} title={t("users_title")} fields={[
            { key: "address", label: t("users_title"), placeholder: "user@example.com" },
            { key: "name", label: t("field_name"), placeholder: "Name" },
            { key: "password", label: t("field_password"), placeholder: "••••••••", type: "password" },
            { key: "quota", label: `${t("quota")} (GB)`, placeholder: "10", disabled: true, hint: t("quota_not_impl") },
        ]} values={values} onChange={(k, v) => setValues((x) => ({ ...x, [k]: v }))} onClose={() => setAddOpen(false)} onSubmit={add}/>

      <InputDialog open={!!pwdFor} title={t("reset_password")} fields={[{ key: "password", label: "Password", placeholder: "••••••••", type: "password" }]} values={{ password: pwdValue }} onChange={(_, v) => setPwdValue(v)} onClose={() => {
            setPwdFor(null);
            setPwdValue("");
        }} onSubmit={resetPwd}/>

      <ConfirmDialog open={!!del} title={t("delete")} body={del ?? ""} danger onOpenChange={(o) => !o && setDel(null)} onConfirm={remove}/>
    </div>);
}
function UserActions({ onToggle, onReset, onDelete, active }: {
    onToggle: () => void;
    onReset: () => void;
    onDelete: () => void;
    active: boolean;
}) {
    const { t } = useSettings();
    return (<RDropdown.Root>
      <RDropdown.Trigger asChild>
        <button aria-label={t("actions")} className="flex h-7 w-7 items-center justify-center rounded-[8px]" style={{ color: "var(--text-2)", background: "rgb(var(--text-1) / 0.05)" }}>
          <IconGear size={14}/>
        </button>
      </RDropdown.Trigger>
      <RDropdown.Portal>
        <RDropdown.Content align="end" sideOffset={6} className="glass--clear radix-pop edge-lens" style={{ minWidth: 160 }}>
          <RDropdown.Item className="radix-item" onSelect={onToggle}>
            {active ? t("disable") : t("enable")}
          </RDropdown.Item>
          <RDropdown.Item className="radix-item" onSelect={onReset}>
            {t("reset_password")}
          </RDropdown.Item>
          <div className="radix-sep"/>
          <RDropdown.Item className="radix-item" style={{ color: "rgb(var(--err-rgb))" }} onSelect={onDelete}>
            {t("delete")}
          </RDropdown.Item>
        </RDropdown.Content>
      </RDropdown.Portal>
    </RDropdown.Root>);
}
