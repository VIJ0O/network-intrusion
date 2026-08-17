"use client";

import React, { useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useApiPolling } from "@/hooks/useApiPolling";
import { useWebSocket } from "@/hooks/useWebSocket";
import { api } from "@/lib/api";
import { Brain, TrendingUp, TrendingDown, Minus, AlertTriangle, Target, BarChart3 } from "lucide-react";
import {
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import type { PredictionResult, DashboardStats } from "@/types";

export default function PredictionsPage() {
  const { isConnected: isPredConnected, liveData: livePred, history: predHistory } = useWebSocket<PredictionResult>("predictions");
  
  const predFetcher = useCallback(() => api.getPredictions(), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);
  const { data: predictions } = useApiPolling<PredictionResult>(predFetcher, 2000);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  const modelStatus = predictions?.model_status || "Offline";
  const isModelOnline = modelStatus === "Active";

  const threatHistory = predHistory.map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString("en-US", { hour12: false, second: "2-digit" }),
    threat: d.threat_probability,
    anomaly: d.anomaly_score * 1000, // scale to visualize micro values
  }));

  const getColor = (v: number) => v >= 75 ? "critical" : v >= 50 ? "danger" : v >= 25 ? "warning" : "safe";
  
  const trendIcon = predictions?.trend === "rising" ? (
    <TrendingUp size={16} />
  ) : predictions?.trend === "falling" ? (
    <TrendingDown size={16} />
  ) : (
    <Minus size={16} />
  );

  return (
    <div className="app-layout">
      <Sidebar isConnected={isPredConnected} />
      <Header title="AI Predictions" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header">
          <h2>AI Anomaly Prediction Engine</h2>
          <p>Online PyTorch Autoencoder + sequence-based LSTM forecast metrics</p>
        </div>

        {/* Stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className={`stat-card ${getColor(predictions?.threat_probability || 0)}`}>
            <div className="stat-card-label"><Target size={14} /> Threat Probability</div>
            <div className="stat-card-value">{predictions?.threat_probability?.toFixed(0) ?? 0}%</div>
            <div className="stat-card-sub">Reconstruction offset ratio</div>
          </div>
          <div className="stat-card accent">
            <div className="stat-card-label"><Brain size={14} /> AI Confidence</div>
            <div className="stat-card-value">{predictions?.confidence?.toFixed(1) ?? 0}%</div>
            <div className="stat-card-sub">Model certainty score</div>
          </div>
          <div className="stat-card info">
            <div className="stat-card-label"><BarChart3 size={14} /> Anomaly Loss</div>
            <div className="stat-card-value" style={{ fontSize: 20, fontFamily: "var(--font-mono)" }}>
              {predictions?.anomaly_score ? predictions.anomaly_score.toFixed(5) : "0.00000"}
            </div>
            <div className="stat-card-sub">MSE reconstruction error</div>
          </div>
          <div className="stat-card info">
            <div className="stat-card-label">{trendIcon} Forecast Trend</div>
            <div className="stat-card-value" style={{ textTransform: "capitalize" }}>{predictions?.trend || "Stable"}</div>
            <div className="stat-card-sub">LSTM projected curve</div>
          </div>
        </div>

        <div className="content-grid">
          {/* Threat Trend Chart */}
          <div className="chart-container">
            <div className="chart-header">
              <span className="chart-title">Threat Score & Anomaly Trend</span>
            </div>
            {threatHistory.length === 0 ? (
              <div style={{ height: 300, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 13 }}>
                Waiting for AI model pipeline...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={threatHistory}>
                  <defs>
                    <linearGradient id="gThreat" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#5A7294" }} />
                  <Tooltip contentStyle={{ background: "#111D35", border: "1px solid #1E2F50", borderRadius: 8 }} />
                  <Area type="monotone" dataKey="threat" stroke="#EF4444" strokeWidth={2} fill="url(#gThreat)" name="Threat Score" dot={false} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Forecast Panel */}
          <div className="prediction-panel">
            <div className="card-header">
              <span className="card-title">
                <Brain size={14} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> 
                Prediction Pipeline Status: {modelStatus}
              </span>
            </div>

            {!isModelOnline ? (
              <div style={{ height: 260, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-muted)", fontSize: 12, textAlign: "center", padding: 20 }}>
                <Brain size={36} className="loading-shimmer" style={{ marginBottom: 16 }} />
                AI Model Gathering Subnet Traffic Baseline...
                <p style={{ fontSize: 10, marginTop: 6, opacity: 0.7 }}>Analyzing packet patterns, sequence length, and port distinctness</p>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {[
                  { label: "Current Anomaly Probability", value: predictions?.threat_probability },
                  { label: "Projected Threat in 10s (LSTM)", value: predictions?.forecast_10s },
                  { label: "Projected Threat in 30s (LSTM)", value: predictions?.forecast_30s },
                  { label: "Projected Threat in 60s (LSTM)", value: predictions?.forecast_60s },
                  { label: "Model Reconstruction Confidence", value: predictions?.confidence, isAccent: true },
                ].map((item, i) => (
                  <div key={i} className="progress-container">
                    <div className="progress-label">
                      <span className="progress-label-text">{item.label}</span>
                      <span className="progress-label-value">{item.value?.toFixed(1) ?? 0}%</span>
                    </div>
                    <div className="progress-bar">
                      <div
                        className={`progress-fill ${item.isAccent ? "accent" : getColor(item.value || 0)}`}
                        style={{ width: `${item.value || 0}%` }}
                      />
                    </div>
                  </div>
                ))}

                <div className={`prediction-action ${(predictions?.threat_probability || 0) >= 50 ? "critical" : "safe"}`}>
                  <AlertTriangle size={14} />
                  {predictions?.reason || "Monitoring..."}
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
