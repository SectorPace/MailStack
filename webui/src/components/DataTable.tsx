// 高密度运营表格：排序 / 过滤 / 分页（行为对齐 TanStack Table 参考实现）
// 数据面保持中性、可读：表体在内容表面（main .glass 降级规则 / thead 近实心由
// index.css 提供），行高与发丝分隔走 macOS 列表密度。
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSettings } from "../store/settings";
import { GlassSelect } from "./ui";
import { IconChevronDown, IconSearch } from "./icons";

export type Column<T> = {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number;
  width?: number | string;
  align?: "left" | "right" | "center";
};

/**
 * 分页窗口：`« ‹ 1 2 3 … 6 7 8 … 125 › »`，首尾恒显、当前页 ±1。
 * 原先 `current>3` 才插头部分隔符：current=3 时窗口 [2,4] 与首页 [0] 之间
 * **跳过了第 2 页（索引 1）却不显示省略号** —— 页码凭空消失。现在：
 * 头部固定窗 0..2 与当前窗相接时不插 gap，出现缺页必插 gap（两处都不静默丢页）。
 */
function pageWindow(current: number, total: number): (number | "gap")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i);
  const out: (number | "gap")[] = [];
  const add = (n: number) => {
    if (!out.includes(n)) out.push(n);
  };
  const addRange = (a: number, b: number) => {
    for (let i = a; i <= b; i++) add(i);
  };
  add(0);
  addRange(1, Math.min(2, total - 2)); // 头部固定窗 0..2
  const lo = Math.max(1, current - 1);
  const hi = Math.min(total - 2, current + 1);
  if (lo > 3) out.push("gap"); // 与头部窗之间缺页才插 gap（lo=3 时 2→3 连续）
  addRange(lo, hi);
  if (hi < total - 2) out.push("gap"); // 与尾页之间缺页
  add(total - 1);
  return out;
}

export function DataTable<T extends object>({
  columns,
  rows,
  pageSize = 10,
  filterKeys,
  filterPlaceholder,
  toolbar,
  rowKey,
  footerRight,
  onRowClick,
  activeRowKey,
}: {
  columns: Column<T>[];
  rows: T[];
  pageSize?: number;
  /** 参与搜索过滤的字段 getter */
  filterKeys?: (row: T) => string;
  filterPlaceholder?: string;
  toolbar?: ReactNode;
  rowKey: (row: T) => string;
  footerRight?: ReactNode;
  onRowClick?: (row: T) => void;
  activeRowKey?: string;
}) {
  const { t } = useSettings();
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(pageSize);

  // `columns` / `filterKeys` 在各页面每次 render 都是**新建的数组/闭包**，直接放进
  // useMemo 依赖等于让缓存永久失效。用 ref 保存最新值，依赖改为数据本身 + 列签名。
  const latest = useRef({ columns, filterKeys });
  useEffect(() => {
    latest.current = { columns, filterKeys };
  });
  const columnsSig = columns.map((c) => c.key).join("|");

  const filtered = useMemo(() => {
    const { columns: cols, filterKeys: filterFn } = latest.current;
    let out = rows;
    if (query.trim() && filterFn) {
      const q = query.trim().toLowerCase();
      out = out.filter((r) => filterFn(r).toLowerCase().includes(q));
    }
    if (sort) {
      const col = cols.find((c) => c.key === sort.key);
      if (col?.sortValue) {
        out = [...out].sort((a, b) => {
          const va = col.sortValue!(a);
          const vb = col.sortValue!(b);
          if (va < vb) return -1 * sort.dir;
          if (va > vb) return 1 * sort.dir;
          return 0;
        });
      }
    }
    return out;
  }, [rows, query, sort, columnsSig]);

  const pages = Math.max(1, Math.ceil(filtered.length / size));

  // 行数据变少（删除末页最后一条）时显式收敛页码，而不是只靠 safePage 兜底。
  useEffect(() => {
    setPage((p) => Math.min(p, pages - 1));
  }, [pages]);

  const safePage = Math.min(page, pages - 1);
  const pageRows = filtered.slice(safePage * size, safePage * size + size);
  const pageItems = pageWindow(safePage, pages);

  function toggleSort(col: Column<T>) {
    if (!col.sortValue) return;
    setSort((s) => (s?.key === col.key ? { key: col.key, dir: s.dir === 1 ? -1 : 1 } : { key: col.key, dir: 1 }));
  }

  return (
    <div className="flex min-h-0 flex-col">
      {(filterKeys || toolbar) && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-3 pb-2.5 pt-3">
          <div className="flex flex-wrap items-center gap-2">{toolbar}</div>
          {filterKeys && (
            <div className="relative w-56">
              <IconSearch size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-3)]" />
              <input
                className="input pl-8"
                style={{ height: 30 }}
                value={query}
                placeholder={filterPlaceholder}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(0);
                }}
              />
            </div>
          )}
        </div>
      )}

      <div
        className="min-h-0 flex-1 overflow-auto"
        style={{ borderRadius: "var(--radius-panel)", boxShadow: "inset 0 0 0 1px var(--hairline)" }}
      >
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={c.sortValue ? "sortable" : ""}
                  // 行高密度走 --control-h（桌面 28 / iOS 44）；index.css 的 9px 纵向
                  // 内边距是旧密度，这里内联收紧到 macOS 列表档（不改动 index.css）。
                  style={{ width: c.width, textAlign: c.align, padding: "6px 12px" }}
                  aria-sort={sort?.key === c.key ? (sort.dir === 1 ? "ascending" : "descending") : undefined}
                >
                  {c.sortValue ? (
                    // 排序入口必须可聚焦 + 可键盘触发；直接绑在 <th> 上只有鼠标可达。
                    <button
                      type="button"
                      onClick={() => toggleSort(c)}
                      className="inline-flex items-center gap-1"
                      style={{
                        background: "none",
                        border: 0,
                        padding: 0,
                        color: "inherit",
                        font: "inherit",
                        cursor: "pointer",
                        width: "100%",
                        justifyContent: c.align === "right" ? "flex-end" : c.align === "center" ? "center" : "flex-start",
                      }}
                    >
                      {c.header}
                      {sort?.key === c.key && (
                        <IconChevronDown size={12} style={{ transform: sort.dir === -1 ? "rotate(180deg)" : undefined }} />
                      )}
                    </button>
                  ) : (
                    <span className="inline-flex items-center gap-1">{c.header}</span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageRows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="py-10 text-center text-[var(--text-3)]">
                  {t("no_data")}
                </td>
              </tr>
            )}
            {pageRows.map((row) => {
              const k = rowKey(row);
              const active = activeRowKey === k;
              return (
                <tr
                  key={k}
                  onClick={() => onRowClick?.(row)}
                  onKeyDown={
                    onRowClick
                      ? (e) => {
                          // 行聚焦后 Enter / Space 触发主操作（onRowClick）——
                          // 没有主操作的表格不抢占 Tab 焦点序。
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            onRowClick(row);
                          }
                        }
                      : undefined
                  }
                  tabIndex={onRowClick ? 0 : undefined}
                  style={{
                    cursor: onRowClick ? "pointer" : undefined,
                    // 选中态：accent 低透明度着色（悬停着色由 .data-table CSS 提供）
                    background: active ? "rgb(var(--accent-rgb) / 0.10)" : undefined,
                  }}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      style={{ textAlign: c.align, padding: "5px 12px", height: "var(--control-h)" }}
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-3 px-3 py-2.5 text-[12px] text-[var(--text-2)]">
        <span>{t("total_items", { n: filtered.length })}</span>
        <div className="flex items-center gap-2">
          {footerRight}
          <div className="flex items-center gap-1">
            <PageBtn
              label={t("prev_page")}
              disabled={safePage === 0}
              onClick={() => setPage(Math.max(0, safePage - 1))}
            >
              ‹
            </PageBtn>
            {pageItems.map((item, idx) =>
              item === "gap" ? (
                <span key={`gap-${idx}`} className="px-1 text-[var(--text-3)]" aria-hidden>
                  …
                </span>
              ) : (
                <button
                  key={item}
                  onClick={() => setPage(item)}
                  aria-label={t("page_number", { n: item + 1 })}
                  aria-current={safePage === item ? "page" : undefined}
                  className="flex h-7 min-w-7 items-center justify-center rounded-full px-2 text-[12px] transition-colors"
                  style={
                    safePage === item
                      ? { background: "rgb(var(--accent-rgb))", color: "#fff" }
                      : { color: "var(--text-2)", background: "rgb(var(--text-1) / 0.05)" }
                  }
                >
                  {item + 1}
                </button>
              ),
            )}
            <PageBtn
              label={t("next_page")}
              disabled={safePage >= pages - 1}
              onClick={() => setPage(Math.min(pages - 1, safePage + 1))}
            >
              ›
            </PageBtn>
          </div>
          <GlassSelect
            value={String(size)}
            onChange={(v) => {
              setSize(Number(v));
              setPage(0);
            }}
            options={[
              { value: "10", label: `10 ${t("per_page")}` },
              { value: "20", label: `20 ${t("per_page")}` },
              { value: "50", label: `50 ${t("per_page")}` },
            ]}
            ariaLabel={t("per_page")}
            width={104}
          />
        </div>
      </div>
    </div>
  );
}

function PageBtn({
  label,
  disabled,
  onClick,
  children,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      className="flex h-7 w-7 items-center justify-center rounded-full text-[12px] transition-colors disabled:opacity-40"
      style={{ color: "var(--text-2)", background: "rgb(var(--text-1) / 0.05)" }}
    >
      {children}
    </button>
  );
}
