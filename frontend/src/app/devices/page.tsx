"use client";

import React, { useState, useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { Search, X, MonitorSmartphone, Server, Wifi, Smartphone, Router, Cpu, AlertTriangle } from "lucide-react";
import type { Device, DashboardStats } from "@/types";

const deviceTypeIcons: Record<string, React.ReactNode> = {
  "Workstation": <MonitorSmartphone size={16} />,
  "Server": <Server size={16} />,
  "Router": <Router size={16} />,
  "Switch": <Cpu size={16} />,
  "IoT Device": <Wifi size={16} />,
  "Mobile": <Smartphone size={16} />,
  "Unknown": <MonitorSmartphone size={16} />,
};

export default function DevicesPage() {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("All");
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  const devicesFetcher = useCallback(() => api.getDevices(), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: devices } = useApiPolling<Device[]>(devicesFetcher, 5000);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  const filtered = (devices || []).filter((d) => {
    const matchesSearch =
      (d.hostname || "").toLowerCase().includes(search.toLowerCase()) ||
      d.ip_address.includes(search) ||
      (d.mac_address || "").toLowerCase().includes(search.toLowerCase());
    const matchesRisk = riskFilter === "All" || d.risk_level === riskFilter;
    return matchesSearch && matchesRisk;
  });

  const riskBadge = (level: string) => {
    const cls = level === "Critical" ? "critical" : level === "High" ? "danger" : level === "Medium" ? "warning" : "safe";
    return <span className={`badge ${cls}`}>{level}</span>;
  };

  const statusBadge = (status: string) => {
    const cls = status === "Online" ? "safe" : status === "Offline" ? "warning" : "critical";
    return <span className={`badge ${cls}`}>{status}</span>;
  };

  return (
    <div className="app-layout">
      <Sidebar isConnected />
      <Header title="Scanned Subnet Assets" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header">
          <h2>Network Host Devices</h2>
          <p>Dynamically discovered assets from ARP and ICMP scans — {filtered.length} showing</p>
        </div>

        {/* Search + Filters */}
        <div className="filter-bar">
          <div className="search-input" style={{ flex: 1, maxWidth: 400 }}>
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search by IP, Hostname, MAC..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          {["All", "Low", "Medium", "High", "Critical"].map((level) => (
            <button
              key={level}
              className={`filter-btn ${riskFilter === level ? "active" : ""}`}
              onClick={() => setRiskFilter(level)}
            >
              {level}
            </button>
          ))}
        </div>

        {/* Device Table */}
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>Category</th>
                <th>Status</th>
                <th>Risk Level</th>
                <th>Link Latency</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: "center", color: "var(--text-muted)", padding: 40 }}>
                    <MonitorSmartphone size={32} style={{ opacity: 0.3, marginBottom: 8 }} /><br />
                    No network devices scanned yet
                  </td>
                </tr>
              ) : (
                filtered.map((device) => (
                  <tr key={device.id} onClick={() => setSelectedDevice(device)}>
                    <td style={{ fontWeight: 600, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 8 }}>
                      {deviceTypeIcons[device.device_type] || <MonitorSmartphone size={16} />}
                      {device.hostname || "Unknown Host"}
                    </td>
                    <td className="ip-address">{device.ip_address}</td>
                    <td className="mac-address">{device.mac_address || "—"}</td>
                    <td>{device.vendor || "—"}</td>
                    <td>{device.device_type}</td>
                    <td>{statusBadge(device.status)}</td>
                    <td>{riskBadge(device.risk_level)}</td>
                    <td style={{ fontFamily: "var(--font-mono)", fontWeight: 500 }}>
                      {device.ping_latency_ms ? `${device.ping_latency_ms.toFixed(1)} ms` : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Device Detail Modal */}
        {selectedDevice && (
          <div className="modal-overlay" onClick={() => setSelectedDevice(null)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <span className="modal-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {deviceTypeIcons[selectedDevice.device_type] || <MonitorSmartphone size={16} />}
                  {selectedDevice.hostname || "Device Detail"}
                </span>
                <button className="modal-close" onClick={() => setSelectedDevice(null)}>
                  <X size={16} />
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px 24px" }}>
                <div className="attack-field">
                  <span className="attack-field-label">IP Address</span>
                  <span className="ip-address" style={{ fontSize: 15 }}>{selectedDevice.ip_address}</span>
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">MAC Address</span>
                  <span className="mac-address" style={{ fontSize: 13 }}>{selectedDevice.mac_address || "—"}</span>
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">Hardware Vendor</span>
                  <span className="attack-field-value">{selectedDevice.vendor || "Unknown OEM"}</span>
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">OS Guess (TTL)</span>
                  <span className="attack-field-value">{selectedDevice.os_guess || "Unknown OS"}</span>
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">Risk Level</span>
                  {riskBadge(selectedDevice.risk_level)}
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">Status</span>
                  {statusBadge(selectedDevice.status)}
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">Ping Latency</span>
                  <span className="attack-field-value" style={{ fontFamily: "var(--font-mono)" }}>
                    {selectedDevice.ping_latency_ms ? `${selectedDevice.ping_latency_ms.toFixed(1)} ms` : "Offline / Unresponsive"}
                  </span>
                </div>
                <div className="attack-field">
                  <span className="attack-field-label">Last Discovered</span>
                  <span className="attack-field-value" style={{ fontSize: 12, fontFamily: "var(--font-mono)" }}>
                    {selectedDevice.last_seen ? new Date(selectedDevice.last_seen).toLocaleString() : "—"}
                  </span>
                </div>
                {selectedDevice.risk_level !== "Low" && (
                  <div style={{ gridColumn: "1 / -1", background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: 8, padding: 12, display: "flex", gap: 10 }}>
                    <AlertTriangle size={18} color="var(--color-critical)" style={{ flexShrink: 0 }} />
                    <div style={{ fontSize: 12 }}>
                      <strong style={{ color: "var(--color-critical)", display: "block" }}>Risk warning triggered</strong>
                      Host matches anomalous payload signature from local packet captures. Monitor closely or drop connection.
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
