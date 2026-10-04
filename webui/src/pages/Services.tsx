// 服务管理 —— 核心服务状态卡 + 启停/重启（services.list / services.action）
import { useEffect, useState, useContext } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { RefreshContext } from "../App";
import { PageHeader, Card, StatusBadge, ConfirmDialog, toast } from "../components/ui";
import { IconPlay, IconStop, IconRestart, IconGear, IconSparkles } from "../components/icons";

type ServiceRow = { key: string; running: boolean; detail: string };

const SERVICE_META: Record<string, { title: string; sub: string }> = {
  smtp: { title: "SMTP · Postfix", sub: "25 / 465 / 587" },
  imap: { title: "IMAP / POP3 · Dovecot", sub: "143 / 993" },
  lmtp: { title: "LMTP · Dovecot", sub: "local delivery" },
  dkim: { title: "DKIM · Rspamd", sub: "signing & filters" },
  webmail: { title: "Webmail", sub: "roundcube" },
  admin: { title: "Admin Console", sub: "axum · admin-web" },
};

export default function Services() {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  const [rows, setRows] = useState<ServiceRow[]>([]);
  const [confirm, setConfirm] = useState<{ key: string; op: "stop" | "restart" | "start" } | null>(null);

  useEffect(() => {
    rpc<ServiceRow[]>("services.list").then((r) => r.ok && setRows(r.data));
  }, [refreshN]);

  async function act(key: string, op: string) {
    const r = await rpc("services.action", { key, op });
    if (r.ok) {
      toast(`${key} · ${op} ✓`);
      const list = await rpc<ServiceRow[]>("services.list");
      if (list.ok) setRows(list.data);
    } else toast(r.error, "err");
  }

  return (
    <div className="p-4">
      <PageHeader title={t("services_title")} sub={t("services_sub")} />

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {rows.map((s) => {
          const meta = SERVICE_META[s.key] ?? { title: s.key, sub: s.detail };
          return (
            <Card key={s.key}>
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span
                    className="flex h-11 w-11 items-center justify-center rounded-[13px]"
                    style={{
                      background: s.running ? "rgb(var(--ok-rgb) / 0.14)" : "rgb(var(--text-1) / 0.07)",
                      color: s.running ? "rgb(var(--ok-rgb))" : "var(--text-2)",
                      boxShadow: "inset 0 1px 0 var(--edge-spec)",
                    }}
                  >
                    <IconGear size={20} />
                  </span>
                  <div className="leading-tight">
                    <div className="text-[14px] font-semibold text-[var(--text-1)]">{meta.title}</div>
                    <div className="mono mt-0.5 text-[11px] text-[var(--text-3)]">{meta.sub}</div>
                  </div>
                </div>
                <StatusBadge kind={s.running ? "ok" : "err"} label={s.running ? t("running") : t("stopped")} />
              </div>

              <div className="mono mt-3 rounded-[10px] px-3 py-2 text-[11px] text-[var(--text-3)]" style={{ background: "rgb(var(--text-1) / 0.04)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
                {s.detail}
              </div>

              <div className="mt-3 flex gap-2">
                {s.running ? (
                  <>
                    <motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn glass--control flex-1" onClick={() => setConfirm({ key: s.key, op: "restart" })}>
                      <IconRestart size={13} /> {t("restart")}
                    </motion.button>
                    <motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn glass--control" style={{ color: "rgb(var(--err-rgb))" }} onClick={() => setConfirm({ key: s.key, op: "stop" })}>
                      <IconStop size={13} /> {t("stop")}
                    </motion.button>
                  </>
                ) : (
                  <motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn btn-accent flex-1" onClick={() => setConfirm({ key: s.key, op: "start" })}>
                    <IconPlay size={13} /> {t("start")}
                  </motion.button>
                )}
              </div>
            </Card>
          );
        })}
      </div>

      <ConfirmDialog
        open={!!confirm}
        title={`${confirm?.key ?? ""} · ${confirm?.op ?? ""}`}
        body={t("services_sub")}
        danger={confirm?.op === "stop"}
        onOpenChange={(o) => !o && setConfirm(null)}
        onConfirm={() => confirm && act(confirm.key, confirm.op)}
      />
    </div>
  );
}
