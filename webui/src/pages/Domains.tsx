// 邮件域名 —— 域名列表 + 添加/删除（domains.list / domains.add / domains.delete）
import { useEffect, useContext, useState } from "react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, DataPanel, ConfirmDialog, toast } from "../components/ui";
import { DataTable, type Column } from "../components/DataTable";
import { InputDialog } from "../components/InputDialog";
import { IconPlus, IconTrash } from "../components/icons";

// 后端 domains.list 返回 { domains: [{ name, target }] }（表文件的两列），
// 没有 active/mailboxes/delivered/success/createdAt 这些统计字段，故不再展示。
// mock 演示数据用的是 { domain, ... }，保留 domain 作兼容读取。
type DomainRow = { name?: string; target?: string; domain?: string };

const domainName = (r: DomainRow) => r.name ?? r.domain ?? "";

export default function Domains() {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [rows, setRows] = useState<DomainRow[]>([]);
  const [addOpen, setAddOpen] = useState(false);
  const [values, setValues] = useState({ domain: "" });
  const [del, setDel] = useState<string | null>(null);

  useEffect(() => {
    rpc<DomainRow[]>("domains.list").then((r) => r.ok && setRows(r.data));
  }, [refreshN]);

  async function add() {
    const r = await rpc("domains.add", { domain: values.domain.trim() });
    if (r.ok) {
      toast(`${values.domain.trim()} ✓`);
      setAddOpen(false);
      setValues({ domain: "" });
      const list = await rpc<DomainRow[]>("domains.list");
      if (list.ok) setRows(list.data);
    } else toast(r.error, "err");
  }

  async function remove() {
    if (!del) return;
    const r = await rpc("domains.delete", { domain: del });
    if (r.ok) {
      setRows((x) => x.filter((d) => domainName(d) !== del));
      toast("OK");
    } else toast(r.error, "err");
  }

  const cols: Column<DomainRow>[] = [
    { key: "domain", header: t("domain"), sortValue: (r) => domainName(r), render: (r) => <span className="font-medium">{domainName(r)}</span>, width: 260 },
    { key: "target", header: "Target", sortValue: (r) => r.target ?? "", render: (r) => <span className="mono text-[var(--text-2)]">{r.target || "—"}</span>, width: 260 },
    {
      key: "act",
      header: "",
      align: "right",
      render: (r) => (
        <button aria-label={t("delete")} className="flex h-7 w-7 items-center justify-center rounded-[8px]" style={{ color: "rgb(var(--err-rgb))", background: "rgb(var(--err-rgb) / 0.08)" }} onClick={() => setDel(domainName(r))}>
          <IconTrash size={14} />
        </button>
      ),
      width: 60,
    },
  ];

  return (
    <div className="p-4">
      <PageHeader
        title={t("domains_title")}
        sub={t("domains_sub")}
        right={
          <button className="btn btn-accent" onClick={() => setAddOpen(true)}>
            <IconPlus size={14} /> {t("add")}
          </button>
        }
      />
      <DataPanel>
        <DataTable columns={cols} rows={rows} rowKey={(r) => domainName(r)} pageSize={10} filterKeys={(r) => domainName(r)} filterPlaceholder={t("domain")} />
      </DataPanel>

      <InputDialog
        open={addOpen}
        title={t("domains_title")}
        fields={[{ key: "domain", label: t("domain"), placeholder: "mail.example.com" }]}
        values={values}
        onChange={(k, v) => setValues((x) => ({ ...x, [k]: v }))}
        onClose={() => setAddOpen(false)}
        onSubmit={add}
      />

      <ConfirmDialog open={!!del} title={t("delete")} body={del ?? ""} danger onOpenChange={(o) => !o && setDel(null)} onConfirm={remove} />
    </div>
  );
}
