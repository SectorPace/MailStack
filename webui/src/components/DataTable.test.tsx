// src/components/DataTable.test.tsx —— 分页窗口契约（通过组件渲染测试；
// pageWindow 是模块内部函数，不导出）。核心回归点：current=3 / total=8 时
// 第 2 页（索引 1）必须出现 —— 旧实现的窗口 [2,4] 与首页 [0] 之间静默丢页。
// 渲染经由真实 SettingsProvider（DataTable 依赖 useSettings 的 t()，jsdom 的
// matchMedia 由 vitest.setup.ts 兜底 mock）。
import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { DataTable } from "./DataTable";
import type { Column } from "./DataTable";
import { SettingsProvider } from "../store/settings";

type Row = { id: string; name: string };

const columns: Column<Row>[] = [{ key: "name", header: "Name", render: (r) => r.name }];
const rowKey = (r: Row) => r.id;

function makeRows(n: number): Row[] {
  return Array.from({ length: n }, (_, i) => ({ id: `r${i}`, name: `row ${i}` }));
}

function renderTable(rows: Row[]) {
  // pageSize 默认 10：行数决定总页数（80 行 → 8 页，50 行 → 5 页）。
  return render(
    <SettingsProvider>
      <DataTable columns={columns} rows={rows} rowKey={rowKey} />
    </SettingsProvider>,
  );
}

const pageBtn = (n: number) => screen.getByRole("button", { name: `第 ${n} 页` });

describe("DataTable pagination window", () => {
  it("with current=3 of 8 pages, page 2 is present and the tail gap is the only one", async () => {
    const user = userEvent.setup();
    renderTable(makeRows(80)); // 8 pages

    await user.click(pageBtn(3)); // → safePage = 2（索引）

    // 审计回归点：current=3 时第 2 页不得凭空消失
    expect(pageBtn(2)).toBeInTheDocument();
    expect(pageBtn(3)).toHaveAttribute("aria-current", "page");
    // 窗口 [1..4] + 尾部 gap + 末页 8：第 5 页隐藏，第 8 页恒显，省略号恰好一个
    expect(pageBtn(1)).toBeInTheDocument();
    expect(pageBtn(4)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "第 5 页" })).not.toBeInTheDocument();
    expect(pageBtn(8)).toBeInTheDocument();
    expect(screen.getAllByText("…")).toHaveLength(1);
  });

  it("with total pages ≤ 7 every page renders and no gap appears", () => {
    renderTable(makeRows(50)); // 5 pages
    for (let n = 1; n <= 5; n++) {
      expect(pageBtn(n)).toBeInTheDocument();
    }
    expect(screen.queryByText("…")).not.toBeInTheDocument();
  });

  it("clicking a page button navigates and moves aria-current", async () => {
    const user = userEvent.setup();
    renderTable(makeRows(80));

    await user.click(pageBtn(2));
    expect(pageBtn(2)).toHaveAttribute("aria-current", "page");
    expect(pageBtn(3)).not.toHaveAttribute("aria-current");
  });

  it("prev/next buttons respect the page bounds", async () => {
    const user = userEvent.setup();
    renderTable(makeRows(80));

    // 首页时 prev 禁用
    expect(screen.getByRole("button", { name: "上一页" })).toBeDisabled();
    await user.click(pageBtn(8));
    expect(pageBtn(8)).toHaveAttribute("aria-current", "page");
    // 末页时 next 禁用
    expect(screen.getByRole("button", { name: "下一页" })).toBeDisabled();
  });

  it("shows the localized empty state when there are no rows", () => {
    renderTable([]);
    expect(screen.getByText("暂无数据")).toBeInTheDocument();
    // 页数收敛为 1，仍渲染第 1 页按钮
    expect(pageBtn(1)).toBeInTheDocument();
  });
});
