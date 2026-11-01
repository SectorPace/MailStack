// 服务管理 —— 核心服务源列表（macOS source-list 行：状态点 + 显示名 + 单元 id 脚注
// + 行尾操作）；services.list / services.action，启停/重启仍走 ConfirmDialog。
// 原 3 列状态卡片阵改为 System Settings 式分组列表：一眼扫状态，操作贴行尾。
import { Fragment, useContext, useState } from "react";
import { motion } from "motion/react";
import { useSettings } from "../store/settings";
import { rpc } from "../api/client";
import { useApiList } from "../hooks/useApiList";
import { RefreshContext } from "../App";
import { PageHeader, StatusBadge, ConfirmDialog, LoadError, toast } from "../components/ui";
import { IconPlay, IconStop, IconRestart } from "../components/icons";
import type { DictKey } from "../i18n";

type ServiceRow = { key: string; running: boolean; detail: string };

/**
 * 后端 services.list 的真实 id 是 postfix / dovecot / opendkim / fail2ban 一类
 * 守护进程名（Security.tsx 实查 fail2ban、Dashboard snapshot services[].id 可证），
 * 原先按 mock 的 smtp/imap/lmtp/dkim 建表 —— 真后端下全部对不上号，只能走兜底。
 * 两套键都给文案（旧键仅 mock 演示数据仍在用），未登记的 id 继续走兜底分支。
 */
const SERVICE_META: Record<string, { title: string; sub: string }> = {
  // 真后端 id
  postfix: { title: "SMTP · Postfix", sub: "25 / 465 / 587" },
  dovecot: { title: "IMAP / POP3 · Dovecot", sub: "143 / 993" },
  opendkim: { title: "DKIM · OpenDKIM", sub: "signing & verification" },
  fail2ban: { title: "Fail2ban", sub: "auth brute-force bans" },
  rspamd: { title: "Rspamd", sub: "filtering & dkim signing" },
  // mock 演示键（仅开发构建）
  smtp: { title: "SMTP · Postfix", sub: "25 / 465 / 587" },
  imap: { title: "IMAP / POP3 · Dovecot", sub: "143 / 993" },
  lmtp: { title: "LMTP · Dovecot", sub: "local delivery" },
  dkim: { title: "DKIM · Rspamd", sub: "signing & filters" },
  webmail: { title: "Webmail", sub: "roundcube" },
  admin: { title: "Admin Console", sub: "axum · admin-web" },
};

/** 确认弹窗里的操作动词走词典（原先 title 直接拼裸 key/op，没过 i18n）。 */
const OP_KEY: Record<"stop" | "restart" | "start", DictKey> = { start: "start", stop: "stop", restart: "restart" };

export default function Services() {
  const { t } = useSettings();
  const refreshN = useContext(RefreshContext);
  // useApiList：undefined 载荷兜底 []、失败显示重试横幅、seq 守卫防旧响应覆写。
  const { rows, error, reload } = useApiList<ServiceRow>("services.list", [refreshN]);
  const [confirm, setConfirm] = useState<{ key: string; op: "stop" | "restart" | "start" } | null>(null);

  async function act(key: string, op: string) {
    const r = await rpc("services.action", { key, op });
    if (r.ok) {
      toast(`${key} · ${op} ✓`);
      reload();
    } else toast(r.error, "err");
  }

  return (
    <div className="p-4">
      <PageHeader title={t("services_title")} sub={t("services_sub")} />
      {error && <div className="mb-3"><LoadError message={error} onRetry={reload} /></div>}

      {/* 源列表容器：--surface 近实心面 + --radius-panel + 发丝描边（不用玻璃） */}
      <section
        className="overflow-hidden"
        style={{ background: "var(--surface)", borderRadius: "var(--radius-panel)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}
      >
        {rows.map((s, i) => {
          const meta = SERVICE_META[s.key] ?? { title: s.key, sub: s.detail };
          return (
            <Fragment key={s.key}>
              {/* 发丝分隔：左右从文本内缩（mx-4 对齐 px-4），不顶到容器边 */}
              {i > 0 && <div className="mx-4 h-px" style={{ background: "var(--hairline)" }} />}
              <div
                className="flex items-center gap-3 px-4 py-2"
                style={{ minHeight: "var(--control-h-lg)" }}
                title={s.detail}
              >
                <StatusBadge variant="dot" kind={s.running ? "ok" : "err"} label={s.running ? t("running") : t("stopped")} />
                <div className="min-w-0 flex-1 leading-tight">
                  <div className="truncate font-medium text-[var(--text-1)]" style={{ fontSize: "var(--font-body)" }}>
                    {meta.title}
                  </div>
                  <div className="mono truncate" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
                    {s.key} · {meta.sub}
                  </div>
                </div>
                <div className="flex shrink-0 gap-2">
                  {s.running ? (
                    <>
                      <motion.button
                        whileTap={{ scale: 0.94 }}
                        transition={{ type: "spring", stiffness: 600, damping: 26 }}
                        className="btn glass--control"
                        onClick={() => setConfirm({ key: s.key, op: "restart" })}
                      >
                        <IconRestart size={13} /> {t("restart")}
                      </motion.button>
                      <motion.button
                        whileTap={{ scale: 0.94 }}
                        transition={{ type: "spring", stiffness: 600, damping: 26 }}
                        className="btn glass--control"
                        style={{ color: "rgb(var(--err-rgb))" }}
                        onClick={() => setConfirm({ key: s.key, op: "stop" })}
                      >
                        <IconStop size={13} /> {t("stop")}
                      </motion.button>
                    </>
                  ) : (
                    <motion.button
                      whileTap={{ scale: 0.94 }}
                      transition={{ type: "spring", stiffness: 600, damping: 26 }}
                      className="btn btn-accent"
                      onClick={() => setConfirm({ key: s.key, op: "start" })}
                    >
                      <IconPlay size={13} /> {t("start")}
                    </motion.button>
                  )}
                </div>
              </div>
            </Fragment>
          );
        })}
        {rows.length === 0 && !error && (
          <div className="px-4 py-6 text-center" style={{ fontSize: "var(--font-caption)", color: "var(--text-3)" }}>
            {t("no_data")}
          </div>
        )}
      </section>

      <ConfirmDialog
        open={!!confirm}
        // 原先 title 拼裸 key/op（未过 i18n）、body 直接复用页面副标题 —— 既不像
        // 确认语也解释不了会发生什么。改为词典确认语，name 用服务的展示名。
        title={t("confirm")}
        body={
          confirm
            ? t("service_confirm", { name: SERVICE_META[confirm.key]?.title ?? confirm.key, op: t(OP_KEY[confirm.op]) })
            : ""
        }
        danger={confirm?.op === "stop"}
        onOpenChange={(o) => !o && setConfirm(null)}
        onConfirm={() => confirm && act(confirm.key, confirm.op)}
      />
    </div>
  );
}
