"use client";

/**
 * Custom hook for WebSocket connections to specific backend channels.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { getWebSocketUrl } from "@/lib/api";

const MAX_HISTORY = 60;

export function useWebSocket<T>(channel: string) {
  const wsRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [liveData, setLiveData] = useState<T | null>(null);
  const [history, setHistory] = useState<T[]>([]);

  const connect = useCallback(() => {
    // Avoid double connections
    if (wsRef.current && (wsRef.current.readyState === WebSocket.CONNECTING || wsRef.current.readyState === WebSocket.OPEN)) {
      return;
    }

    const url = getWebSocketUrl(channel);
    const ws = new WebSocket(url);

    ws.onopen = () => {
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data: T = JSON.parse(event.data);
        setLiveData(data);
        setHistory((prev) => {
          const next = [...prev, data];
          return next.length > MAX_HISTORY ? next.slice(-MAX_HISTORY) : next;
        });
      } catch (err) {
        console.error(`WebSocket [${channel}] parse error:`, err);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Reconnect after 3 seconds
      setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  }, [channel]);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { isConnected, liveData, history };
}
export default useWebSocket;
