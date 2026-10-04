// 高密度运营表格：排序 / 过滤 / 分页（行为对齐 TanStack Table 参考实现）
// 数据面保持中性、可读；玻璃只出现在表头磨砂与工具区。
import { useMemo, useState, type ReactNode } from "react";
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

  const filtered = useMemo(() => {
    let out = rows;
    if (query.trim() && filterKeys) {
      const q = query.trim().toLowerCase();
      out = out.filter((r) => filterKeys(r).toLowerCase().includes(q));
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
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
  }, [rows, query, sort, columns, filterKeys]);

  const pages = Math.max(1, Math.ceil(filtered.length / size));
  const safePage = Math.min(page, pages - 1);
  const pageRows = filtered.slice(safePage * size, safePage * size + size);

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

      <div className="min-h-0 flex-1 overflow-auto rounded-[12px]" style={{ boxShadow: "inset 0 0 0 1px var(--hairline)" }}>
        <table className="data-table">
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={c.sortValue ? "sortable" : ""}
                  style={{ width: c.width, textAlign: c.align }}
                  onClick={() => toggleSort(c)}
                  aria-sort={sort?.key === c.key ? (sort.dir === 1 ? "ascending" : "descending") : undefined}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {c.sortValue && sort?.key === c.key && (
                      <IconChevronDown size={12} style={{ transform: sort.dir === -1 ? "rotate(180deg)" : undefined }} />
                    )}
                  </span>
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
                  style={{
                    cursor: onRowClick ? "pointer" : undefined,
                    background: active ? "rgb(var(--accent-rgb) / 0.10)" : undefined,
                  }}
                >
                  {columns.map((c) => (
                    <td key={c.key} style={{ textAlign: c.align }}>
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
            {Array.from({ length: pages }, (_, i) => i).map((i) => (
              <button
                key={i}
                onClick={() => setPage(i)}
                aria-label={`page ${i + 1}`}
                aria-current={safePage === i ? "page" : undefined}
                className="flex h-7 min-w-7 items-center justify-center rounded-full px-2 text-[12px] transition-colors"
                style={
                  safePage === i
                    ? { background: "rgb(var(--accent-rgb))", color: "#fff" }
                    : { color: "var(--text-2)", background: "rgb(var(--text-1) / 0.05)" }
                }
              >
                {i + 1}
              </button>
            ))}
          </div>
          <GlassSelect
            value={String(size)}
            onChange={(v) => {
              setSize(Number(v));
              setPage(0);
            }}
            options={[
              { value: "10", label: "10 / page" },
              { value: "20", label: "20 / page" },
              { value: "50", label: "50 / page" },
            ]}
            ariaLabel="page size"
            width={104}
          />
        </div>
      </div>
    </div>
  );
}
