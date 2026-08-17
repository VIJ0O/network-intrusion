"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import { Activity, Zap, Globe, BarChart3 } from "lucide-react";
import {
  AreaChart, Area, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import type { DashboardStats, TrafficStats } from "@/types";

const PROTOCOL_COLORS = ["#00D4FF", "#5B6EE8", "#F59E0B", "#10B981", "#EF6C00"];

export default function MonitoringPage() {
  const { isConnected: isTrafficConnected, liveData: liveTraffic, history: trafficHistory } = useWebSocket<TrafficStats>("traffic");
  
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 3000);

  const ppsData = trafficHistory.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false, second: "2-digit" }),
    pps: d.packets_per_second,
  }));

  const bwData = trafficHistory.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false, second: "2-digit" }),
    bandwidth: parseFloat(((d.bytes_per_second * 8) / (1024 ** 2)).toFixed(2)),
  }));

  const protocolData = liveTraffic
    ? Object.entries(liveTraffic.protocol_distribution).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="app-layout">
      <Sidebar isConnected={isTrafficConnected} />
      <Header title="Live Monitoring" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header">
          <h2>Live Monitoring</h2>
          <p>Real-time packet captures and protocol distributions</p>
        </div>

        {/* Live stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className="stat-card accent">
            <div className="stat-card-label"><Activity size={14} /> Packets/s</div>
            <div className="stat-card-value">{liveTraffic?.packets_per_second?.toLocaleString() ?? 0}</div>
          </div>
          <div className="stat-card info">
            <div className="stat-card-label"><Zap size={14} /> Bandwidth</div>
            <div className="stat-card-value">
              {liveTraffic ? ((liveTraffic.bytes_per_second * 8) / (1024 ** 2)).toFixed(2) : "0.00"} <span style={{fontSize:14}}>Mbps</span>
            </div>
          </div>
          <div className="stat-card info">
            <div className="stat-card-label"><Globe size={14} /> Connection Rate</div>
            <div className="stat-card-value">{liveTraffic?.active_connections ?? 0}</div>
          </div>
          <div className="stat-card info">
            <div className="stat-card-label"><BarChart3 size={14} /> Captured Packets</div>
            <div className="stat-card-value">{liveTraffic?.total_packets_captured?.toLocaleString() ?? 0}</div>
          </div>
        </div>

        {/* Charts */}
        <div className="content-grid">
          {/* Packet Rate */}
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">Real-Time Packet Rate</span>
              <span className="badge accent"><Zap size={12} /> Live</span>
            </div>
            {ppsData.length === 0 ? (
              <div style={{ height: 280, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                Waiting for Network Traffic...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={ppsData}>
                  <defs>
                    <linearGradient id="gPps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00D4FF" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#00D4FF" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Area type="monotone" dataKey="pps" stroke="#00D4FF" strokeWidth={2} fill="url(#gPps)" name="Packets/s" dot={false} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Bandwidth */}
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">Bandwidth Usage (Mbps)</span>
              <span className="badge info">Mbps</span>
            </div>
            {bwData.length === 0 ? (
              <div style={{ height: 280, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                Waiting for Network Traffic...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <LineChart data={bwData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Line type="monotone" dataKey="bandwidth" stroke="#5B6EE8" strokeWidth={2} dot={false} isAnimationActive={false} name="Mbps" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="content-grid">
          {/* Protocol Distribution */}
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">Protocol Distribution</span>
            </div>
            {protocolData.length === 0 ? (
              <div style={{ height: 280, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                No active traffic protocol metadata
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={protocolData}
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={110}
                    paddingAngle={3}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {protocolData.map((_, index) => (
                      <Cell key={index} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Heavy Talkers */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Heavy Traffic Sources</span>
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr><th>Host Address</th><th>Transferred Volume</th></tr>
                </thead>
                <tbody>
                  {liveTraffic?.top_talkers.length === 0 ? (
                    <tr>
                      <td colSpan={2} style={{ textAlign: "center", color: "var(--text-muted)" }}>
                        No heavy talkers captured
                      </td>
                    </tr>
                  ) : (
                    liveTraffic?.top_talkers.map((t, i) => (
                      <tr key={i}>
                        <td className="ip-address">{t.ip}</td>
                        <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>{(t.bytes / 1024).toFixed(1)} KB</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
