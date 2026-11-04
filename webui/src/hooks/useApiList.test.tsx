import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { rpc } from "../api/client";
import type { RpcResult } from "../api/client";
import { useApiList } from "./useApiList";
vi.mock("../api/client", () => ({ rpc: vi.fn() }));
const rpcMock = vi.mocked(rpc);
beforeEach(() => {
    rpcMock.mockReset();
});
describe("useApiList", () => {
    it("returns rows on success and exposes no error", async () => {
        rpcMock.mockResolvedValue({ ok: true, data: [1, 2, 3] });
        const { result } = renderHook(() => useApiList<number[]>("queue.list"));
        await waitFor(() => expect(result.current.rows).toEqual([1, 2, 3]));
        expect(result.current.error).toBeNull();
        expect(rpcMock).toHaveBeenCalledWith("queue.list");
    });
    it("falls back to [] when the payload is undefined ({ok:true} without data)", async () => {
        rpcMock.mockResolvedValue({ ok: true, data: undefined });
        const { result } = renderHook(() => useApiList<number[]>("x"));
        await waitFor(() => expect(result.current.rows).toEqual([]));
        expect(result.current.error).toBeNull();
    });
    it("falls back to [] when the payload is not an array", async () => {
        rpcMock.mockResolvedValue({ ok: true, data: { nope: true } as unknown as number[] });
        const { result } = renderHook(() => useApiList<number[]>("x"));
        await waitFor(() => expect(result.current.rows).toEqual([]));
        expect(result.current.error).toBeNull();
    });
    it("exposes the error string on failure and keeps rows empty", async () => {
        rpcMock.mockResolvedValue({ ok: false, error: "boom" });
        const { result } = renderHook(() => useApiList<number[]>("x"));
        await waitFor(() => expect(result.current.error).toBe("boom"));
        expect(result.current.rows).toEqual([]);
    });
    it("reload refetches and replaces rows", async () => {
        rpcMock
            .mockResolvedValueOnce({ ok: true, data: [1] })
            .mockResolvedValueOnce({ ok: true, data: [2] });
        const { result } = renderHook(() => useApiList<number[]>("x"));
        await waitFor(() => expect(result.current.rows).toEqual([1]));
        act(() => {
            result.current.reload();
        });
        await waitFor(() => expect(result.current.rows).toEqual([2]));
        expect(rpcMock).toHaveBeenCalledTimes(2);
    });
    it("drops a stale response that lands after a newer reload (seq guard)", async () => {
        let resolveFirst!: (r: RpcResult<number[]>) => void;
        const first = new Promise<RpcResult<number[]>>((resolve) => {
            resolveFirst = resolve;
        });
        rpcMock
            .mockImplementationOnce(() => first)
            .mockResolvedValueOnce({ ok: true, data: [2] });
        const { result } = renderHook(() => useApiList<number[]>("x"));
        act(() => {
            result.current.reload();
        });
        await waitFor(() => expect(result.current.rows).toEqual([2]));
        resolveFirst({ ok: true, data: [1] });
        await act(async () => {
            await new Promise((r) => setTimeout(r, 0));
        });
        expect(result.current.rows).toEqual([2]);
    });
    it("refetches when deps change", async () => {
        rpcMock.mockResolvedValue({ ok: true, data: [] });
        const { result, rerender } = renderHook(({ dep }) => useApiList("x", [dep]), {
            initialProps: { dep: 1 },
        });
        await waitFor(() => expect(rpcMock).toHaveBeenCalledTimes(1));
        rerender({ dep: 2 });
        await waitFor(() => expect(rpcMock).toHaveBeenCalledTimes(2));
        expect(result.current.rows).toEqual([]);
    });
});
