"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { Download, Shield, AlertTriangle, CheckCircle, Bell, Activity } from "lucide-react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import type { ReportSummary, DashboardStats } from "@/types";

const COLORS = ["#00D4FF", "#5B6EE8", "#F59E0B", "#EF4444", "#10B981", "#EF6C00", "#3B82F6"];

export default function ReportsPage() {
  const reportFetcher = useCallback(() => api.getReportSummary(), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: report } = useApiPolling<ReportSummary>(reportFetcher, 5000);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  const pieData = report
    ? Object.entries(report.attack_type_distribution).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="app-layout">
      <Sidebar isConnected />
      <Header title="Reports" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <h2>Analysis Reports</h2>
            <p>Database statistics, protocol volumes, and attack log exports</p>
          </div>
          <a href={api.exportCSV()} download className="btn btn-primary">
            <Download size={16} /> Export Incidents CSV
          </a>
        </div>

        {/* Summary Stats */}
        <div className="report-stats-grid">
          <div className="stat-card info">
            <div className="stat-card-label"><Shield size={14} /> Total Attacks</div>
            <div className="stat-card-value">{report?.total_attacks ?? 0}</div>
          </div>
          <div className="stat-card critical">
            <div className="stat-card-label"><AlertTriangle size={14} /> Active Attacks</div>
            <div className="stat-card-value">{report?.active_attacks ?? 0}</div>
          </div>
          <div className="stat-card safe">
            <div className="stat-card-label"><CheckCircle size={14} /> Mitigated</div>
            <div className="stat-card-value">{report?.resolved_attacks ?? 0}</div>
          </div>
          <div className="stat-card warning">
            <div className="stat-card-label"><Bell size={14} /> Critical Alerts</div>
            <div className="stat-card-value">{report?.critical_alerts ?? 0}</div>
          </div>
        </div>

        {/* Attack Type Pie */}
        <div className="content-grid">
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">Attack Type Breakdown</span>
            </div>
            {pieData.length === 0 ? (
              <div style={{ height: 350, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                No incident statistics logged in database
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={350}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={80}
                    outerRadius={130}
                    paddingAngle={3}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <span className="card-title">Intrusion Database Metrics</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div className="settings-row">
                <span className="settings-label">Total Packets Evaluated</span>
                <span className="settings-value">{report?.total_packets?.toLocaleString() ?? 0}</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Total Correlated Alerts</span>
                <span className="settings-value">{report?.total_alerts ?? 0}</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Critical Threat Alerts</span>
                <span className="settings-value">{report?.critical_alerts ?? 0}</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Incident Mitigations Logged</span>
                <span className="settings-value">{report?.resolved_attacks ?? 0}</span>
              </div>
              <div className="settings-row">
                <span className="settings-label">Threat Remediation Rate</span>
                <span className="settings-value">
                  {report && report.total_attacks > 0
                    ? `${((report.resolved_attacks / report.total_attacks) * 100).toFixed(1)}%`
                    : "100.0%"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
