"use client";

import React, { useState, useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { Search, AlertTriangle, Shield } from "lucide-react";
import type { Alert, DashboardStats } from "@/types";

export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [searchText, setSearchText] = useState("");

  const alertsFetcher = useCallback(() => api.getAlerts(100), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: alerts, refetch: refetchAlerts } = useApiPolling<Alert[]>(alertsFetcher, 4000);
  const { data: stats, refetch: refetchStats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  const filtered = (alerts || []).filter((a) => {
    const matchSev = severityFilter === "All" || a.severity === severityFilter;
    const matchSearch =
      a.title.toLowerCase().includes(searchText.toLowerCase()) ||
      (a.attacker_ip || "").includes(searchText) ||
      (a.victim_ip || "").includes(searchText) ||
      (a.message || "").toLowerCase().includes(searchText.toLowerCase());
    return matchSev && matchSearch;
  });

  const sevClass = (s: string) =>
    s === "Critical" ? "critical" : s === "High" ? "high" : s === "Warning" ? "warning" : "info";

  const sevBadgeClass = (s: string) =>
    s === "Critical" ? "critical" : s === "High" ? "danger" : s === "Warning" ? "warning" : "info";

  const handleClearAll = async () => {
    try {
      await api.clearAllAlerts();
      refetchAlerts();
      refetchStats();
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  return (
    <div className="app-layout">
      <Sidebar alertCount={stats?.active_alerts} isConnected />
      <Header title="Security Alerts" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2>Security Incident Alerts</h2>
            <p>Real-time rule matches and autoencoder warnings — {filtered.length} alerts logged</p>
          </div>
          {filtered.length > 0 && (
            <button
              className="btn btn-secondary"
              onClick={handleClearAll}
              style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 16px" }}
            >
              <Shield size={16} /> Clear & Resolve All Alerts
            </button>
          )}
        </div>

        <div className="filter-bar">
          <div className="search-input" style={{ flex: 1, maxWidth: 400 }}>
            <Search size={16} className="search-icon" />
            <input
              placeholder="Search alerts by IP, title, message..."
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
          </div>
          {["All", "Critical", "High", "Warning", "Info"].map((s) => (
            <button
              key={s}
              className={`filter-btn ${severityFilter === s ? "active" : ""}`}
              onClick={() => setSeverityFilter(s)}
            >
              {s}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon"><Shield size={48} /></div>
            <h3>No security alerts logged</h3>
            <p>Offending signatures will automatically generate alerts here</p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {filtered.map((alert) => (
              <div key={alert.id} className={`alert-card ${sevClass(alert.severity)}`}>
                <div className="alert-card-header">
                  <span className="alert-card-title">
                    {alert.severity === "Critical" ? "🚨 " : alert.severity === "High" ? "⚠️ " : "ℹ️ "}
                    {alert.title}
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className={`badge ${sevBadgeClass(alert.severity)}`}>{alert.severity}</span>
                    <span className="alert-card-time">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
                <div className="alert-card-body">
                  <div>
                    <span className="alert-field-label">Attacker: </span>
                    <span className="ip-address">{alert.attacker_ip || "External / Unknown"}</span>
                  </div>
                  <div>
                    <span className="alert-field-label">Victim: </span>
                    <span className="ip-address">{alert.victim_ip || "Internal Node"}</span>
                  </div>
                  <div style={{ gridColumn: "1 / -1" }}>
                    <span className="alert-field-label">Description: </span>
                    <span className="alert-field-value" style={{ fontWeight: 400, color: "var(--text-secondary)" }}>
                      {alert.message}
                    </span>
                  </div>
                  <div>
                    <span className="alert-field-label">Threat Confidence: </span>
                    <span className="alert-field-value">{alert.confidence}%</span>
                  </div>
                </div>
                <div className="alert-action">
                  <AlertTriangle size={12} />
                  Recommended Action: {alert.recommended_action}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
