"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { useWebSocket } from "@/hooks/useWebSocket";
import { api } from "@/lib/api";
import { Settings, Server, Globe, Bell, Palette, Shield, Cpu, Info } from "lucide-react";
import type { DashboardStats, SystemMetrics } from "@/types";

export default function SettingsPage() {
  const { isConnected: isMetricsConnected } = useWebSocket<SystemMetrics>("metrics");
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const metricsFetcher = useCallback(() => api.getSystemMetrics(), []);
  
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 10000);
  const { data: metrics } = useApiPolling<SystemMetrics>(metricsFetcher, 2000);

  return (
    <div className="app-layout">
      <Sidebar isConnected />
      <Header title="System Settings" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header">
          <h2>Platform Settings</h2>
          <p>Local NDR engine settings, capture parameters, and system metrics</p>
        </div>

        {/* Real-time System Metrics */}
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header">
            <span className="card-title"><Cpu size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Active OS Hardware Monitor</span>
            <span className={`badge ${isMetricsConnected ? "safe" : "warning"}`}>{isMetricsConnected ? "Live Connection" : "Polled Data"}</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20, marginTop: 10 }}>
            <div>
              <span className="settings-label">CPU Usage</span>
              <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: "var(--accent-cyan)" }}>
                {metrics?.cpu_percent ? `${metrics.cpu_percent.toFixed(1)}%` : "0.0%"}
              </div>
              <div className="progress-bar" style={{ marginTop: 8 }}>
                <div className="progress-fill accent" style={{ width: `${metrics?.cpu_percent || 0}%` }} />
              </div>
            </div>
            
            <div>
              <span className="settings-label">RAM Usage</span>
              <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: "var(--accent-cyan)" }}>
                {metrics?.ram_percent ? `${metrics.ram_percent.toFixed(1)}%` : "0.0%"}
              </div>
              <div className="progress-bar" style={{ marginTop: 8 }}>
                <div className="progress-fill accent" style={{ width: `${metrics?.ram_percent || 0}%` }} />
              </div>
            </div>

            <div>
              <span className="settings-label">Disk Storage</span>
              <div style={{ fontSize: 24, fontWeight: 700, marginTop: 4, color: "var(--accent-cyan)" }}>
                {metrics?.disk_percent ? `${metrics.disk_percent.toFixed(1)}%` : "0.0%"}
              </div>
              <div className="progress-bar" style={{ marginTop: 8 }}>
                <div className="progress-fill accent" style={{ width: `${metrics?.disk_percent || 0}%` }} />
              </div>
            </div>
          </div>
        </div>

        <div className="content-grid">
          {/* API Configuration */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Server size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> API Connections</span>
            </div>
            <div className="settings-group">
              <div className="settings-row">
                <span className="settings-label">Backend REST Endpoint</span>
                <span className="settings-value">http://localhost:8000</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">NDR WebSocket Streams</span>
                <span className="settings-value">ws://localhost:8000/ws</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Database Store Connection</span>
                <span className="settings-value">SQLite (nids.db)</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">API Version</span>
                <span className="settings-value">v2.0.0 (Real Data)</span>
              </div>
            </div>
          </div>

          {/* Notification Thresholds */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Bell size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Anomaly Detection Limits</span>
            </div>
            <div className="settings-group">
              <div className="settings-row">
                <span className="settings-label">AI Baseline Collection Period</span>
                <span className="settings-value">120 seconds</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Intrusion Alert Threshold</span>
                <span className="settings-value">Threat Prob ≥ 50%</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">LSTM forecasting interval</span>
                <span className="settings-value">5 seconds</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Auto-log Anomalous Packets</span>
                <span className="settings-value">Enabled</span>
              </div>
            </div>
          </div>

          {/* Network Config */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Globe size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Sniffer Configuration</span>
            </div>
            <div className="settings-group">
              <div className="settings-row">
                <span className="settings-label">Capture Engine</span>
                <span className="settings-value">Scapy + Npcap (Windows)</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Interface Selection</span>
                <span className="settings-value">Auto-detect Primary NIC</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Active Scans</span>
                <span className="settings-value">ARP sweeps + Ping sweeps</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Scan Frequency</span>
                <span className="settings-value">30 seconds</span>
              </div>
            </div>
          </div>

          {/* Platform Information */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Shield size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Engine Profile</span>
            </div>
            <div className="settings-group">
              <div className="settings-row">
                <span className="settings-label">Device Discovery sweeps</span>
                <span className="settings-value">Online</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">PyTorch Autoencoder</span>
                <span className="settings-value">Online (Adam optimizer)</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Uptime</span>
                <span className="settings-value">
                  {metrics?.backend_uptime_seconds ? `${(metrics.backend_uptime_seconds / 3600).toFixed(2)} hours` : "—"}
                </span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Database Logs Size</span>
                <span className="settings-value">Auto-managed</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
