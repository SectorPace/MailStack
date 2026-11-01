// 列表页统一加载器 —— 修三个系统性问题（WEBUI_AUDIT）：
//   1. `r.ok && setRows(r.data)`：后端 {ok:true} 无载荷时 bridge() 产出 data===undefined，
//      state 变 undefined → 渲染崩溃（白屏）。这里统一兜底成 []。
//   2. 加载失败静默：没有 else 分支时失败页长得跟「暂无数据」一模一样。error 暴露给
//      页面渲染 <LoadError/> 重试横幅。
//   3. 竞态：并发刷新/操作后补拉时，旧响应可能后到并覆写新数据。seq 守卫只让
//      **最新**一次请求落地。
import { useCallback, useEffect, useRef, useState } from "react";
import { rpc } from "../api/client";

export function useApiList<T>(action: string, deps: readonly unknown[] = []) {
  const [rows, setRows] = useState<T[]>([]);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);

  const load = useCallback(() => {
    const id = ++seq.current;
    void rpc<T[]>(action).then((r) => {
      if (id !== seq.current) return; // 只让最新一次响应落地
      if (r.ok) {
        setRows(Array.isArray(r.data) ? r.data : []);
        setError(null);
      } else {
        setError(r.error);
      }
    });
  }, [action]);

  useEffect(() => {
    load();
  }, [load, ...deps]);

  return { rows, setRows, error, reload: load };
}
