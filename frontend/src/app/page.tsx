"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import {
  Shield,
  Crosshair,
  Brain,
  MonitorSmartphone,
  Bell,
  Wifi,
  AlertTriangle,
  Activity,
  Zap,
  TrendingUp,
  TrendingDown,
  Minus,
  Sparkles,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { DashboardStats, PredictionResult, Attack, TrafficStats, Alert, RLStatus, RLDecision } from "@/types";
import Link from "next/link";

export default function DashboardPage() {
  // Subscribe to WebSocket live channels
  const { isConnected: isTrafficConnected, liveData: liveTraffic, history: trafficHistory } = useWebSocket<TrafficStats>("traffic");
  const { isConnected: isPredConnected, liveData: livePred } = useWebSocket<PredictionResult>("predictions");
  const { isConnected: isAlertConnected, liveData: liveAlert } = useWebSocket<Alert | { type: string, data: any }>("alerts");
  const { liveData: liveRLDecision } = useWebSocket<RLDecision>("rl");

  // REST polling for statistics and lists
  const dashboardFetcher = useCallback(() => api.getDashboard(), []);
  const predictionsFetcher = useCallback(() => api.getPredictions(), []);
  const attackFetcher = useCallback(() => api.getCurrentAttack(), []);
  const alertsFetcher = useCallback(() => api.getAlerts(5), []);
  const rlStatusFetcher = useCallback(() => api.getRLStatus(), []);

  const { data: stats, refetch: refetchStats } = useApiPolling<DashboardStats>(dashboardFetcher, 5000);
  const { data: predictions } = useApiPolling<PredictionResult>(predictionsFetcher, 5000);
  const { data: currentAttack } = useApiPolling<Attack | { active: false }>(attackFetcher, 5000);
  const { data: alerts } = useApiPolling<Alert[]>(alertsFetcher, 8000);
  const { data: rlStatus } = useApiPolling<RLStatus>(rlStatusFetcher, 8000);

  const systemStatus = stats?.system_status || "Offline";
  const alertCount = stats?.active_alerts || 0;
  const isCaptureOnline = stats?.capture_online || false;
  const isModelOnline = stats?.prediction_online || false;

  const hasActiveAttack = currentAttack && "attack_type" in currentAttack;

  // Chart data from WebSocket traffic stream history
  const chartData = trafficHistory.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false, second: "2-digit" }),
    pps: d.packets_per_second,
    bandwidth: parseFloat(((d.bytes_per_second * 8) / (1024 ** 2)).toFixed(2)),
  }));

  const getProgressColor = (value: number) => {
    if (value >= 75) return "critical";
    if (value >= 50) return "danger";
    if (value >= 25) return "warning";
    return "safe";
  };

  const trendIcon = predictions?.trend === "rising" ? (
    <TrendingUp size={14} />
  ) : predictions?.trend === "falling" ? (
    <TrendingDown size={14} />
  ) : (
    <Minus size={14} />
  );

  return (
    <div className="app-layout">
      <Sidebar alertCount={alertCount} isConnected={isTrafficConnected} />
      <Header
        title="NDR Dashboard"
        systemStatus={(systemStatus as any)}
        onRefresh={refetchStats}
      />

      <main className="main-content">
        
        {/* Offline warnings if packet capture fails */}
        {!isCaptureOnline && (
          <div style={{ background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: 12, padding: "16px 20px", display: "flex", gap: 12, alignItems: "center", marginBottom: 24 }}>
            <AlertTriangle size={24} color="var(--color-critical)" />
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 700, color: "var(--color-critical)" }}>Packet Capture Offline</h3>
              <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>
                The backend service cannot open the network interface. Please ensure the Python script is running with <strong>Administrator/root privileges</strong>.
              </p>
            </div>
          </div>
        )}

        {/* Status Cards */}
        <div className="stats-grid">
          <div className={`stat-card ${systemStatus === "Critical" ? "critical" : systemStatus === "Warning" ? "warning" : systemStatus === "Safe" ? "safe" : "info"}`}>
            <div className="stat-card-label">
              <Shield size={14} /> System Health
            </div>
            <div className="stat-card-value">{systemStatus}</div>
            <div className="stat-card-sub">NDR analyzer state</div>
          </div>

          <div className={`stat-card ${(stats?.threat_score || 0) >= 75 ? "critical" : (stats?.threat_score || 0) >= 50 ? "warning" : "safe"}`}>
            <div className="stat-card-label">
              <Crosshair size={14} /> Threat Probability
            </div>
            <div className="stat-card-value">{stats?.threat_score ?? 0}%</div>
            <div className="stat-card-sub">{stats?.packets_per_second?.toLocaleString() ?? 0} pkt/s</div>
          </div>

          <div className="stat-card accent">
            <div className="stat-card-label">
              <Brain size={14} /> AI Model Status
            </div>
            <div className="stat-card-value" style={{ fontSize: 20 }}>{stats?.ai_status || "Offline"}</div>
            <div className="stat-card-sub">{stats?.ai_confidence ?? 0}% confidence</div>
          </div>

          <div className="stat-card info">
            <div className="stat-card-label">
              <MonitorSmartphone size={14} /> Discovered Assets
            </div>
            <div className="stat-card-value">{stats?.connected_devices ?? 0}</div>
            <div className="stat-card-sub">Active hosts on subnet</div>
          </div>

          <div className={`stat-card ${alertCount > 0 ? "critical" : "safe"}`}>
            <div className="stat-card-label">
              <Bell size={14} /> Open Alerts
            </div>
            <div className="stat-card-value">{alertCount}</div>
            <div className="stat-card-sub">Unresolved alarms</div>
          </div>

          <div className={`stat-card ${stats?.network_status === "Under Attack" ? "critical" : "safe"}`}>
            <div className="stat-card-label">
              <Wifi size={14} /> Link Bandwidth
            </div>
            <div className="stat-card-value">{stats?.bandwidth_mbps?.toFixed(2) ?? 0.0} <span style={{ fontSize: 14, fontWeight: 500 }}>Mbps</span></div>
            <div className="stat-card-sub">{stats?.network_status || "Offline"}</div>
          </div>
        </div>

        {/* Live Charts + AI Prediction */}
        <div className="content-grid-3">
          
          {/* Live Network Traffic Chart */}
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">
                <Activity size={16} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} />
                Real-Time Packet Flow
              </span>
              <span className="badge accent">
                <Zap size={12} /> Live Capture
              </span>
            </div>
            {chartData.length === 0 ? (
              <div style={{ height: 260, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                Waiting for Network Traffic...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="gradientPps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00D4FF" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#00D4FF" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <YAxis tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Area
                    type="monotone"
                    dataKey="pps"
                    stroke="#00D4FF"
                    strokeWidth={2}
                    fill="url(#gradientPps)"
                    name="Packets/s"
                    dot={false}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* AI Prediction Panel */}
          <div className="prediction-panel">
            <div className="card-header">
              <span className="card-title">
                <Brain size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} />
                Autoencoder Inference
              </span>
              <span className="badge accent">{trendIcon} {predictions?.trend || "Stable"}</span>
            </div>

            {!isModelOnline ? (
              <div style={{ height: 180, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: 10 }}>
                <Brain size={24} className="loading-shimmer" style={{ marginBottom: 12 }} />
                Prediction Engine Offline / Gathering Baseline...
                <span style={{ fontSize: 10, marginTop: 4, opacity: 0.7 }}>AIEngine requires ~120s baseline normal traffic flow</span>
              </div>
            ) : (
              <>
                <div className="progress-container">
                  <div className="progress-label">
                    <span className="progress-label-text">Anomaly Threat Prob</span>
                    <span className="progress-label-value">{predictions?.threat_probability?.toFixed(0) ?? 0}%</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className={`progress-fill ${getProgressColor(predictions?.threat_probability || 0)}`}
                      style={{ width: `${predictions?.threat_probability || 0}%` }}
                    />
                  </div>
                </div>

                <div className="progress-container">
                  <div className="progress-label">
                    <span className="progress-label-text">Next 10s Forecast</span>
                    <span className="progress-label-value">{predictions?.forecast_10s?.toFixed(0) ?? 0}%</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className={`progress-fill ${getProgressColor(predictions?.forecast_10s || 0)}`}
                      style={{ width: `${predictions?.forecast_10s || 0}%` }}
                    />
                  </div>
                </div>

                <div className="progress-container">
                  <div className="progress-label">
                    <span className="progress-label-text">Next 30s Forecast</span>
                    <span className="progress-label-value">{predictions?.forecast_30s?.toFixed(0) ?? 0}%</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className={`progress-fill ${getProgressColor(predictions?.forecast_30s || 0)}`}
                      style={{ width: `${predictions?.forecast_30s || 0}%` }}
                    />
                  </div>
                </div>

                <div className="progress-container">
                  <div className="progress-label">
                    <span className="progress-label-text">Reconstruction Confidence</span>
                    <span className="progress-label-value">{predictions?.confidence?.toFixed(1) ?? 0}%</span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-fill accent"
                      style={{ width: `${predictions?.confidence || 0}%` }}
                    />
                  </div>
                </div>

                <div className={`prediction-action ${hasActiveAttack ? "critical" : "safe"}`}>
                  <AlertTriangle size={14} />
                  {predictions?.reason || "System monitoring online."}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Active Attack + Recent Alerts */}
        <div className="content-grid">
          
          {/* Active Attack Panel */}
          <div className={`attack-panel ${hasActiveAttack ? "active" : ""}`}>
            <div className={`attack-panel-header ${hasActiveAttack ? "active" : ""}`}>
              <AlertTriangle size={18} color={hasActiveAttack ? "#EF4444" : "#5A7294"} />
              <span style={{ fontWeight: 600, fontSize: 15 }}>
                {hasActiveAttack ? "⚠️ Active Attack Detected" : "No Active Attack Incident"}
              </span>
              {hasActiveAttack && <span className="badge critical">LIVE</span>}
            </div>
            <div className="attack-panel-body">
              {hasActiveAttack && "attacker_ip" in currentAttack ? (
                <>
                  <div className="attack-field">
                    <span className="attack-field-label">Attacker Host</span>
                    <span className="attack-field-value">{currentAttack.attacker_device || "External / Unknown"}</span>
                  </div>
                  <div className="attack-field">
                    <span className="attack-field-label">Victim Host</span>
                    <span className="attack-field-value">{currentAttack.victim_device || "Internal Host"}</span>
                  </div>
                  <div className="attack-field">
                    <span className="attack-field-label">Attacker IP</span>
                    <span className="attack-field-value ip-address">{currentAttack.attacker_ip}</span>
                  </div>
                  <div className="attack-field">
                    <span className="attack-field-label">Victim IP</span>
                    <span className="attack-field-value ip-address">{currentAttack.victim_ip}</span>
                  </div>
                  <div className="attack-field">
                    <span className="attack-field-label">Classification</span>
                    <span className="attack-field-value">{currentAttack.attack_type}</span>
                  </div>
                  <div className="attack-field">
                    <span className="attack-field-label">Severity</span>
                    <span className="badge critical">{currentAttack.severity}</span>
                  </div>
                  <div className="attack-field" style={{ gridColumn: "1 / -1" }}>
                    <span className="attack-field-label">Correlated Reason</span>
                    <span className="attack-field-value" style={{ fontSize: 13, fontWeight: 400, color: "var(--text-secondary)" }}>
                      {currentAttack.description}
                    </span>
                  </div>
                </>
              ) : (
                <div style={{ gridColumn: "1 / -1", textAlign: "center", padding: "30px 0", color: "var(--text-muted)" }}>
                  <Shield size={32} style={{ opacity: 0.3, marginBottom: 8 }} /><br />
                  All network hosts verified safe — no threat vectors detected
                </div>
              )}
            </div>
          </div>

          {/* Recent Alerts */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Bell size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} />
                Correlated Alerts
              </span>
              <span className="badge info">{(alerts || []).length}</span>
            </div>
            {alerts && alerts.length === 0 ? (
              <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)", fontSize: 12 }}>
                No active threat alerts logged
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {alerts?.slice(0, 3).map((alert) => {
                  const s = alert.severity;
                  const sevClass = s === "Critical" ? "critical" : s === "High" ? "high" : s === "Warning" ? "warning" : "info";
                  const sevBadgeClass = s === "Critical" ? "critical" : s === "High" ? "danger" : s === "Warning" ? "warning" : "info";
                  return (
                    <div key={alert.id} className={`alert-card ${sevClass}`}>
                      <div className="alert-card-header">
                        <span className="alert-card-title">
                          {alert.severity === "Critical" ? "🚨" : alert.severity === "High" ? "⚠️" : "ℹ️"}
                          {alert.title}
                        </span>
                        <span className={`badge ${sevBadgeClass}`}>{alert.severity}</span>
                      </div>
                      <div className="alert-card-body">
                        <div>
                          <span className="alert-field-label">Source: </span>
                          <span className="ip-address">{alert.attacker_ip || "—"}</span>
                        </div>
                        <div>
                          <span className="alert-field-label">Target: </span>
                          <span className="ip-address">{alert.victim_ip || "—"}</span>
                        </div>
                        <div>
                          <span className="alert-field-label">Reason: </span>
                          <span className="alert-field-value">{alert.message || "—"}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* RL Adaptive Defense Live Overview Card */}
        <div className="card" style={{ marginTop: 24, border: "1px solid rgba(91, 110, 232, 0.3)", background: "linear-gradient(135deg, rgba(13, 21, 39, 0.9), rgba(17, 29, 53, 0.95))" }}>
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Sparkles size={16} color="var(--accent-cyan)" />
              <span className="card-title" style={{ color: "var(--accent-cyan)" }}>RL Adaptive Response Engine</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{
                fontSize: 11,
                fontWeight: 600,
                padding: "2px 8px",
                borderRadius: 4,
                background: rlStatus?.dry_run ? "rgba(16, 185, 129, 0.15)" : "rgba(0, 212, 255, 0.15)",
                color: rlStatus?.dry_run ? "#10B981" : "var(--accent-cyan)",
                border: "1px solid rgba(0, 212, 255, 0.2)"
              }}>
                {rlStatus?.dry_run ? "DRY-RUN (Safe)" : "CONTROLLED ACTIVE"}
              </span>
              <Link href="/rl" style={{ fontSize: 12, color: "var(--accent-cyan)", textDecoration: "none", fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
                Open RL Console →
              </Link>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr", gap: 16, marginTop: 12 }}>
            <div style={{ background: "var(--bg-secondary)", padding: "12px 16px", borderRadius: 8, border: "1px solid var(--border)" }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>Recommended Defense Action</span>
              <p style={{ fontSize: 16, fontWeight: 700, color: "var(--accent-cyan)", marginTop: 2 }}>
                {liveRLDecision?.action_name || rlStatus?.latest_decision?.action_name || "CONTINUE_MONITORING"}
              </p>
              <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                {liveRLDecision?.action_description || rlStatus?.latest_decision?.action_description || "Safe passive monitoring baseline active."}
              </span>
            </div>

            <div style={{ background: "var(--bg-secondary)", padding: "12px 16px", borderRadius: 8, border: "1px solid var(--border)" }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>Target Host & Context</span>
              <p style={{ fontSize: 14, fontWeight: 600, fontFamily: "var(--font-mono)", marginTop: 2 }}>
                {liveRLDecision?.target_ip || rlStatus?.latest_decision?.target_ip || "127.0.0.1"}
              </p>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Confidence: {liveRLDecision?.confidence || rlStatus?.latest_decision?.confidence || 100}% • V(s): {liveRLDecision?.expected_reward ?? rlStatus?.latest_decision?.expected_reward ?? 0.0}
              </span>
            </div>

            <div style={{ background: "var(--bg-secondary)", padding: "12px 16px", borderRadius: 8, border: "1px solid var(--border)" }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>Policy Status</span>
              <p style={{ fontSize: 14, fontWeight: 600, color: rlStatus?.policy_trained ? "#10B981" : "#F59E0B", marginTop: 2 }}>
                {rlStatus?.policy_trained ? "Trained PPO Policy Online" : "Untrained / Baseline"}
              </p>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Version: v{rlStatus?.policy_version || "1.0.0"} • Sub-millisecond inference
              </span>
            </div>
          </div>
        </div>

        {/* Top talkers */}
        {liveTraffic && liveTraffic.top_talkers.length > 0 && (
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-header">
              <span className="card-title">
                <Activity size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} />
                Bandwidth Heavy Talkers
              </span>
            </div>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Host IP</th>
                    <th>Volume Transferred</th>
                  </tr>
                </thead>
                <tbody>
                  {liveTraffic.top_talkers.map((t, i) => (
                    <tr key={i}>
                      <td className="ip-address">{t.ip}</td>
                      <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>{(t.bytes / 1024).toFixed(1)} KB</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
