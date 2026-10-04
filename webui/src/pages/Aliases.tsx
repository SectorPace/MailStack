// 地址与别名 —— 别名映射列表 + 添加/删除（aliases.*）
import { useEffect, useContext, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, DataPanel, StatusBadge, ConfirmDialog, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { InputDialog } from "../components/InputDialog";
import { IconPlus, IconTrash, IconChevronRight } from "../components/icons";

type AliasRow = { source: string; target: string; active: boolean; createdAt: string };

export default function Aliases() {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [rows, setRows] = useState<AliasRow[]>([]);
  const [addOpen, setAddOpen] = useState(false);
  const [values, setValues] = useState({ source: "", target: "" });
  const [del, setDel] = useState<string | null>(null);

  useEffect(() => {
    rpc<AliasRow[]>("aliases.list").then((r) => r.ok && setRows(r.data));
  }, [refreshN]);

  async function add() {
    const r = await rpc("aliases.add", { source: values.source.trim(), target: values.target.trim() });
    if (r.ok) {
      toast("OK");
      setAddOpen(false);
      setValues({ source: "", target: "" });
      const list = await rpc<AliasRow[]>("aliases.list");
      if (list.ok) setRows(list.data);
    } else toast(r.error, "err");
  }

  async function remove() {
    if (!del) return;
    const r = await rpc("aliases.delete", { source: del });
    if (r.ok) {
      setRows((x) => x.filter((a) => a.source !== del));
      toast("OK");
    } else toast(r.error, "err");
  }

  const cols: Column<AliasRow>[] = [
    { key: "source", header: t("from"), sortValue: (r) => r.source, render: (r) => <span className="font-medium">{r.source}</span>, width: 240 },
    {
      key: "arrow",
      header: "",
      width: 40,
      render: () => <IconChevronRight size={14} className="text-[var(--text-3)]" />,
    },
    { key: "target", header: t("to"), sortValue: (r) => r.target, render: (r) => r.target, width: 240 },
    { key: "active", header: t("status"), sortValue: (r) => (r.active ? 1 : 0), render: (r) => <StatusBadge kind={r.active ? "ok" : "neutral"} label={r.active ? t("enabled") : t("disabled")} />, width: 110 },
    { key: "createdAt", header: t("created_at"), sortValue: (r) => r.createdAt, render: (r) => <span className="tnum text-[var(--text-2)]">{r.createdAt}</span>, width: 158 },
    {
      key: "act",
      header: "",
      align: "right",
      render: (r) => (
        <button aria-label={t("delete")} className="flex h-7 w-7 items-center justify-center rounded-[8px]" style={{ color: "rgb(var(--err-rgb))", background: "rgb(var(--err-rgb) / 0.08)" }} onClick={() => setDel(r.source)}>
          <IconTrash size={14} />
        </button>
      ),
      width: 60,
    },
  ];

  return (
    <div className="p-4">
      <PageHeader
        title={t("aliases_title")}
        sub={t("aliases_sub")}
        right={
          <button className="btn btn-accent" onClick={() => setAddOpen(true)}>
            <IconPlus size={14} /> {t("add")}
          </button>
        }
      />
      <DataPanel>
        <DataTable columns={cols} rows={rows} rowKey={(r) => r.source} pageSize={10} filterKeys={(r) => `${r.source} ${r.target}`} filterPlaceholder={t("aliases_title")} />
      </DataPanel>

      <InputDialog
        open={addOpen}
        title={t("aliases_title")}
        fields={[
          { key: "source", label: t("from"), placeholder: "postmaster@example.com" },
          { key: "target", label: t("to"), placeholder: "admin@example.com" },
        ]}
        values={values}
        onChange={(k, v) => setValues((x) => ({ ...x, [k]: v }))}
        onClose={() => setAddOpen(false)}
        onSubmit={add}
      />

      <ConfirmDialog open={!!del} title={t("delete")} body={del ?? ""} danger onOpenChange={(o) => !o && setDel(null)} onConfirm={remove} />
    </div>
  );
}
