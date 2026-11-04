import { useCallback, useEffect, useRef, useState } from "react";
import { rpc } from "../api/client";
export function useApiList<T>(action: string, deps: readonly unknown[] = []) {
    const [rows, setRows] = useState<T[]>([]);
    const [error, setError] = useState<string | null>(null);
    const seq = useRef(0);
    const load = useCallback(() => {
        const id = ++seq.current;
        void rpc<T[]>(action).then((r) => {
            if (id !== seq.current)
                return;
            if (r.ok) {
                setRows(Array.isArray(r.data) ? r.data : []);
                setError(null);
            }
            else {
                setError(r.error);
            }
        });
    }, [action]);
    useEffect(() => {
        load();
    }, [load, ...deps]);
    return { rows, setRows, error, reload: load };
}
