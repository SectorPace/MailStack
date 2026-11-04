import { Fragment, useContext, useState } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { PageHeader, StatusBadge, ConfirmDialog, LoadError, toast } from "../components/ui";
import { IconPlay, IconStop, IconRestart } from "../components/icons";
import type { DictKey } from "../i18n";
type ServiceRow = {
    key: string;
    running: boolean;
    detail: string;
};
const SERVICE_META: Record<string, {
    title: string;
    sub: string;
}> = {
    postfix: { title: "SMTP · Postfix", sub: "25 / 465 / 587" },
    dovecot: { title: "IMAP / POP3 · Dovecot", sub: "143 / 993" },
    opendkim: { title: "DKIM · OpenDKIM", sub: "signing & verification" },
    fail2ban: { title: "Fail2ban", sub: "auth brute-force bans" },
    rspamd: { title: "Rspamd", sub: "filtering & dkim signing" },
    smtp: { title: "SMTP · Postfix", sub: "25 / 465 / 587" },
    imap: { title: "IMAP / POP3 · Dovecot", sub: "143 / 993" },
    lmtp: { title: "LMTP · Dovecot", sub: "local delivery" },
    dkim: { title: "DKIM · Rspamd", sub: "signing & filters" },
    webmail: { title: "Webmail", sub: "roundcube" },
    admin: { title: "Admin Console", sub: "axum · admin-web" },
};
const OP_KEY: Record<"stop" | "restart" | "start", DictKey> = { start: "start", stop: "stop", restart: "restart" };
export default function Services() {
    const { t } = useSettings();
    const refreshN = useContext(RefreshContext);
    const { rows, error, reload } = useApiList<ServiceRow>("services.list", [refreshN]);
    const [confirm, setConfirm] = useState<{
        key: string;
        op: "stop" | "restart" | "start";
    } | null>(null);
    async function act(key: string, op: string) {
        const r = await rpc("services.action", { key, op });
        if (r.ok) {
            toast(`${key} · ${op} ✓`);
            reload();
        }
        else
            toast(r.error, "err");
    }
    return (<div className="p-4">
      <PageHeader title={t("services_title")} sub={t("services_sub")}/>
      {error && <div className="mb-3"><LoadError message={error} onRetry={reload}/></div>}

      <section className="overflow-hidden" style={{ background: "var(--surface)", borderRadius: "var(--radius-panel)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
        {rows.map((s, i) => {
            const meta = SERVICE_META[s.key] ?? { title: s.key, sub: s.detail };
            return (<Fragment key={s.key}>

              {i > 0 && <div className="mx-4 h-px" style={{ background: "var(--hairline)" }}/>}
              <div className="flex items-center gap-3 px-4 py-2" style={{ minHeight: "var(--control-h-lg)" }} title={s.detail}>
                <StatusBadge variant="dot" kind={s.running ? "ok" : "err"} label={s.running ? t("running") : t("stopped")}/>
                <div className="min-w-0 flex-1 leading-tight">
                  <div className="truncate font-medium text-[var(--text-1)]" style={{ fontSize: "var(--font-body)" }}>
                    {meta.title}
                  </div>
                  <div className="mono truncate" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
                    {s.key} · {meta.sub}
                  </div>
                </div>
                <div className="flex shrink-0 gap-2">
                  {s.running ? (<>
                      <motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn glass--control" onClick={() => setConfirm({ key: s.key, op: "restart" })}>
                        <IconRestart size={13}/> {t("restart")}
                      </motion.button>
                      <motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn glass--control" style={{ color: "rgb(var(--err-rgb))" }} onClick={() => setConfirm({ key: s.key, op: "stop" })}>
                        <IconStop size={13}/> {t("stop")}
                      </motion.button>
                    </>) : (<motion.button whileTap={{ scale: 0.94 }} transition={{ type: "spring", stiffness: 600, damping: 26 }} className="btn btn-accent" onClick={() => setConfirm({ key: s.key, op: "start" })}>
                      <IconPlay size={13}/> {t("start")}
                    </motion.button>)}
                </div>
              </div>
            </Fragment>);
        })}
        {rows.length === 0 && !error && (<div className="px-4 py-6 text-center" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            {t("no_data")}
          </div>)}
      </section>

      <ConfirmDialog open={!!confirm} title={t("confirm")} body={confirm
            ? t("service_confirm", { name: SERVICE_META[confirm.key]?.title ?? confirm.key, op: t(OP_KEY[confirm.op]) })
            : ""} danger={confirm?.op === "stop"} onOpenChange={(o) => !o && setConfirm(null)} onConfirm={() => confirm && act(confirm.key, confirm.op)}/>
    </div>);
}
