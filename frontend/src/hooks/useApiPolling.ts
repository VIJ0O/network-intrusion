"use client";

/**
 * Performance-optimized API polling hook.
 * - Smart deduplication: skips update if new JSON equals cached JSON.
 * - Avoids re-render storms when backend returns unchanged data.
 * - Uses setTimeout instead of setInterval to avoid drift/accumulation.
 */

import { useState, useEffect, useCallback, useRef } from "react";

export function useApiPolling<T>(
  fetcher: () => Promise<T>,
  intervalMs: number = 5000
) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const lastJsonRef = useRef<string>("");
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const fetchData = useCallback(async () => {
    try {
      const result = await fetcher();
      if (!mountedRef.current) return;

      // Skip re-render if data hasn't changed
      const json = JSON.stringify(result);
      if (json !== lastJsonRef.current) {
        lastJsonRef.current = json;
        setData(result);
        setError(null);
      }
    } catch (err: unknown) {
      if (!mountedRef.current) return;
      setError(err instanceof Error ? err.message : "Failed to fetch");
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    mountedRef.current = true;
    lastJsonRef.current = "";

    // Fetch immediately on mount
    fetchData();

    // Chain with setTimeout so intervals don't stack when fetch is slow
    const schedule = () => {
      timerRef.current = setTimeout(async () => {
        await fetchData();
        if (mountedRef.current) schedule();
      }, intervalMs);
    };
    schedule();

    return () => {
      mountedRef.current = false;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [fetchData, intervalMs]);

  return { data, error, loading, refetch: fetchData };
}
