"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { Terminal, Shield, RefreshCw, Trash2, Pause, Play } from "lucide-react";
import type { LogEntry, DashboardStats } from "@/types";

export default function LogsPage() {
  const { isConnected, liveData } = useWebSocket<LogEntry>("logs");
  const [logList, setLogList] = useState<LogEntry[]>([]);
  const [sourceFilter, setSourceFilter] = useState("All");
  const [levelFilter, setLevelFilter] = useState("All");
  const [isPaused, setIsPaused] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);

  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  // Poll historical logs on first mount
  useEffect(() => {
    async function loadLogs() {
      try {
        const hist = await api.getLogs(100);
        setLogList(hist.reverse()); // Show oldest first in stream layout
      } catch (err) {
        console.error("Failed to load historical logs:", err);
      }
    }
    loadLogs();
  }, []);

  // Listen to new live WebSocket logs
  useEffect(() => {
    if (liveData && !isPaused) {
      setLogList(prev => {
        const next = [...prev, liveData];
        return next.length > 500 ? next.slice(-500) : next;
      });
    }
  }, [liveData, isPaused]);

  // Autoscroll to bottom
  useEffect(() => {
    if (logContainerRef.current && !isPaused) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logList, isPaused]);

  const filteredLogs = logList.filter(log => {
    const matchSrc = sourceFilter === "All" || log.source === sourceFilter;
    const matchLvl = levelFilter === "All" || log.level === levelFilter;
    return matchSrc && matchLvl;
  });

  const getLevelColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "#EF4444";
      case "ERROR": return "#EF6C00";
      case "WARNING": return "#F59E0B";
      case "INFO": return "#3B82F6";
      default: return "#8BA3C4";
    }
  };

  const clearLogs = () => {
    setLogList([]);
  };

  return (
    <div className="app-layout">
      <Sidebar isConnected={isConnected} />
      <Header title="Live System Logs" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content" style={{ display: "flex", flexDirection: "column", height: "calc(100vh - var(--header-height) - 48px)", gap: 20 }}>
        
        {/* Logs Control Panel */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h2 style={{ fontSize: 22, fontWeight: 700 }}>Intrusion Log Console</h2>
            <p style={{ color: "var(--text-muted)", fontSize: 13 }}>Streams debugging logs and detection logs from all NDR engine modules</p>
          </div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            
            {/* Filters */}
            <select 
              className="settings-value" 
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              style={{ background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 6, padding: "6px 12px", outline: "none", cursor: "pointer" }}
            >
              <option value="All">All Sources</option>
              <option value="System">System Controller</option>
              <option value="PacketCapture">Packet Capture</option>
              <option value="DeviceDiscovery">Device Discovery</option>
              <option value="AIEngine">AI Predictor</option>
              <option value="AlertEngine">Alert Correlator</option>
            </select>

            <select 
              className="settings-value" 
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              style={{ background: "var(--bg-secondary)", color: "var(--text-primary)", border: "1px solid var(--border)", borderRadius: 6, padding: "6px 12px", outline: "none", cursor: "pointer" }}
            >
              <option value="All">All Levels</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>

            {/* Actions */}
            <button className="btn btn-sm" onClick={() => setIsPaused(!isPaused)}>
              {isPaused ? <Play size={14} /> : <Pause size={14} />} {isPaused ? "Resume" : "Pause"}
            </button>
            <button className="btn btn-sm btn-danger" onClick={clearLogs}>
              <Trash2 size={14} /> Clear Console
            </button>
          </div>
        </div>

        {/* Console Box */}
        <div 
          ref={logContainerRef}
          style={{ 
            flex: 1, 
            background: "rgba(6, 11, 24, 0.95)", 
            border: "1px solid var(--border)", 
            borderRadius: 12, 
            padding: 20, 
            overflowY: "auto", 
            fontFamily: "var(--font-mono)", 
            fontSize: 13, 
            lineHeight: "1.7",
            boxShadow: "inset 0 4px 16px rgba(0,0,0,0.6)"
          }}
        >
          {filteredLogs.length === 0 ? (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)" }}>
              <Terminal size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
              Console empty — listening for engine logs
            </div>
          ) : (
            filteredLogs.map((log, idx) => (
              <div 
                key={log.id || idx} 
                style={{ 
                  display: "flex", 
                  gap: 12, 
                  borderBottom: "1px solid rgba(30, 47, 80, 0.15)",
                  padding: "4px 0",
                  alignItems: "flex-start"
                }}
              >
                {/* Timestamp */}
                <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>
                  [{new Date(log.timestamp).toLocaleTimeString()}]
                </span>

                {/* Subsystem Name Tag */}
                <span style={{ color: "var(--accent-cyan)", fontWeight: 600, minWidth: 120, flexShrink: 0 }}>
                  {log.source.padEnd(15)}
                </span>

                {/* Level Badge */}
                <span style={{ color: getLevelColor(log.level), fontWeight: 700, minWidth: 80, flexShrink: 0 }}>
                  {log.level.padEnd(8)}
                </span>

                {/* Log Line Text */}
                <span style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>
                  {log.message}
                </span>
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
}
