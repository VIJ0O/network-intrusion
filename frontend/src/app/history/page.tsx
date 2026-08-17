"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import type { Attack, DashboardStats } from "@/types";

export default function HistoryPage() {
  const attacksFetcher = useCallback(() => api.getAttacks(100), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: attacks } = useApiPolling<Attack[]>(attacksFetcher, 5000);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  // Aggregate attack types for chart
  const typeCount: Record<string, number> = {};
  (attacks || []).forEach((a) => {
    typeCount[a.attack_type] = (typeCount[a.attack_type] || 0) + 1;
  });
  const chartData = Object.entries(typeCount).map(([type, count]) => ({ type, count }));

  const sevBadge = (s: string) => {
    const cls = s === "Critical" ? "critical" : s === "High" ? "danger" : s === "Medium" ? "warning" : "safe";
    return <span className={`badge ${cls}`}>{s}</span>;
  };

  const statusBadge = (s: string) => {
    const cls = s === "Active" ? "critical" : s === "Mitigated" ? "warning" : "safe";
    return <span className={`badge ${cls}`}>{s}</span>;
  };

  return (
    <div className="app-layout">
      <Sidebar isConnected />
      <Header title="Attack History" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header">
          <h2>Attack Incident History</h2>
          <p>Chronological records of all correlated alerts and system mitigations — {(attacks || []).length} incidents logged</p>
        </div>

        {/* Attack Type Distribution Chart */}
        <div className="chart-container" style={{ marginBottom: 24 }}>
          <div className="chart-header">
            <span className="chart-title">Attack Type Distribution</span>
          </div>
          {chartData.length === 0 ? (
            <div style={{ height: 250, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
              No incidents logged yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" tick={{ fontSize: 11, fill: "#5A7294" }} angle={-20} textAnchor="end" height={60} />
                <YAxis tick={{ fontSize: 10, fill: "#5A7294" }} />
                <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                <Bar dataKey="count" fill="#5B6EE8" radius={[4, 4, 0, 0]} name="Incident Count" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Attack Table */}
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Attack Type</th>
                <th>Source Address</th>
                <th>Destination Target</th>
                <th>Triggered Time</th>
                <th>End Time</th>
                <th>Status</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {attacks && attacks.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: 40 }}>
                    No attack history logged
                  </td>
                </tr>
              ) : (
                (attacks || []).map((atk) => (
                  <tr key={atk.id}>
                    <td style={{ fontWeight: 600, color: "var(--text-primary)" }}>{atk.attack_type}</td>
                    <td>
                      <span className="ip-address" style={{ fontSize: 13 }}>{atk.attacker_ip || "External IP"}</span>
                    </td>
                    <td>
                      <span className="ip-address" style={{ fontSize: 13 }}>{atk.victim_ip || "Internal Target"}</span>
                    </td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>
                      {new Date(atk.start_time).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-muted)" }}>
                      {atk.end_time ? new Date(atk.end_time).toLocaleString() : "—"}
                    </td>
                    <td>{statusBadge(atk.status)}</td>
                    <td>{sevBadge(atk.severity)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
