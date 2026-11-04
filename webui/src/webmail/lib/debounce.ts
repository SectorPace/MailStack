import { useEffect, useRef, useState } from "react";
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
    const [debounced, setDebounced] = useState(value);
    useEffect(() => {
        const timer = setTimeout(() => setDebounced(value), Math.max(0, delayMs));
        return () => clearTimeout(timer);
    }, [value, delayMs]);
    return debounced;
}
export function useDebouncedCallback<A extends unknown[]>(fn: (...args: A) => void, delayMs = 300): (...args: A) => void {
    const fnRef = useRef(fn);
    const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    useEffect(() => {
        fnRef.current = fn;
    }, [fn]);
    useEffect(() => () => {
        if (timerRef.current)
            clearTimeout(timerRef.current);
    }, []);
    return (...args: A) => {
        if (timerRef.current)
            clearTimeout(timerRef.current);
        timerRef.current = setTimeout(() => fnRef.current(...args), Math.max(0, delayMs));
    };
}
