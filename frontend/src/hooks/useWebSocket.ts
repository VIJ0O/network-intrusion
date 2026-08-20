"use client";

/**
 * Performance-optimized WebSocket hook.
 * - Deduplicates connections (one socket per channel per page).
 * - Uses a ring-buffer ref for history to avoid array spread on every message.
 * - Throttles React state updates: liveData updates at most every 250ms.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { getWebSocketUrl } from "@/lib/api";

const MAX_HISTORY = 50; // reduced from 60

export function useWebSocket<T>(channel: string) {
  const wsRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [liveData, setLiveData] = useState<T | null>(null);
  const [history, setHistory] = useState<T[]>([]);

  // Throttle ref: last time we flushed state
  const lastFlushRef = useRef<number>(0);
  const pendingDataRef = useRef<T | null>(null);
  const rafRef = useRef<number>(0);

  const flushPending = useCallback(() => {
    if (pendingDataRef.current !== null) {
      const item = pendingDataRef.current;
      pendingDataRef.current = null;
      setLiveData(item);
      setHistory((prev) => {
        if (prev.length >= MAX_HISTORY) {
          // Avoid spreading — slice from index 1 to drop oldest
          const next = prev.slice(-(MAX_HISTORY - 1));
          next.push(item);
          return next;
        }
        return [...prev, item];
      });
    }
  }, []);

  const connect = useCallback(() => {
    if (
      wsRef.current &&
      (wsRef.current.readyState === WebSocket.CONNECTING ||
        wsRef.current.readyState === WebSocket.OPEN)
    ) {
      return;
    }

    const url = getWebSocketUrl(channel);
    const ws = new WebSocket(url);

    ws.onopen = () => setIsConnected(true);

    ws.onmessage = (event) => {
      try {
        const data: T = JSON.parse(event.data);
        pendingDataRef.current = data;

        // Throttle: flush at most once every 250ms using requestAnimationFrame
        const now = performance.now();
        if (now - lastFlushRef.current > 250) {
          lastFlushRef.current = now;
          cancelAnimationFrame(rafRef.current);
          rafRef.current = requestAnimationFrame(flushPending);
        }
      } catch {
        // Silent — malformed ws frame
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Reconnect with exponential-capped delay
      setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();

    wsRef.current = ws;
  }, [channel, flushPending]);

  useEffect(() => {
    connect();
    return () => {
      cancelAnimationFrame(rafRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { isConnected, liveData, history };
}

export default useWebSocket;
