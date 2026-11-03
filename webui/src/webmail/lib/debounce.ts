// 300ms 防抖（顶栏搜索）—— 纯 hook，无第三方依赖。
import { useEffect, useRef, useState } from "react";

/** 返回随输入变化、滞后 `delayMs` 才更新的值；组件卸载/值变化时清定时器。 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), Math.max(0, delayMs));
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

/** 稳定回调版防抖：连续调用只执行最后一次（用于「输入停止后触发搜索」）。 */
export function useDebouncedCallback<A extends unknown[]>(
  fn: (...args: A) => void,
  delayMs = 300,
): (...args: A) => void {
  const fnRef = useRef(fn);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    fnRef.current = fn;
  }, [fn]);
  useEffect(
    () => () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    },
    [],
  );
  return (...args: A) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => fnRef.current(...args), Math.max(0, delayMs));
  };
}
