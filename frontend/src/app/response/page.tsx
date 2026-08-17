"use client";

import React, { useState, useCallback } from "react";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import { useWebSocket } from "@/hooks/useWebSocket";
import { useApiPolling } from "@/hooks/useApiPolling";
import { api } from "@/lib/api";
import {
  ShieldAlert,
  Shield,
  ShieldCheck,
  AlertTriangle,
  Plus,
  Trash2,
  Lock,
  Unlock,
  Radio,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  Filter
} from "lucide-react";
import type {
  ResponseConfig,
  ResponseRule,
  MitigationAction,
  DashboardStats
} from "@/types";

export default function ResponsePage() {
  const { isConnected, history: liveMitigationHistory } = useWebSocket<MitigationAction>("response");

  const configFetcher = useCallback(() => api.getResponseConfig(), []);
  const rulesFetcher = useCallback(() => api.getResponseRules(), []);
  const actionsFetcher = useCallback(() => api.getMitigationActions(50), []);
  const dashFetcher = useCallback(() => api.getDashboard(), []);

  const { data: config, refetch: refetchConfig } = useApiPolling<ResponseConfig>(configFetcher, 3000);
  const { data: rules, refetch: refetchRules } = useApiPolling<ResponseRule[]>(rulesFetcher, 3000);
  const { data: actions, refetch: refetchActions } = useApiPolling<MitigationAction[]>(actionsFetcher, 3000);
  const { data: stats } = useApiPolling<DashboardStats>(dashFetcher, 5000);

  // Manual block form state
  const [manualIp, setManualIp] = useState("");
  const [manualAction, setManualAction] = useState("block_ip");
  const [executing, setExecuting] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");

  // New rule form state
  const [showAddModal, setShowAddModal] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [triggerType, setTriggerType] = useState("severity");
  const [triggerValue, setTriggerValue] = useState("Critical");
  const [actionType, setActionType] = useState("block_ip");

  const handleModeChange = async (mode: "auto" | "semi_auto" | "dry_run") => {
    try {
      await api.updateResponseConfig(mode);
      refetchConfig();
    } catch {
      setStatusMsg("Failed to update defense mode.");
    }
  };

  const handleManualExecute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIp) return;
    setExecuting(true);
    setStatusMsg("");
    try {
      await api.executeDefenseAction(manualAction, manualIp);
      setManualIp("");
      setStatusMsg(`Action '${manualAction}' executed successfully on ${manualIp}`);
      refetchActions();
      refetchConfig();
    } catch (err: any) {
      setStatusMsg(`Execution failed: ${err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  const handleToggleRule = async (ruleId: number, currentEnabled: boolean) => {
    try {
      await api.toggleResponseRule(ruleId, !currentEnabled);
      refetchRules();
    } catch {
      setStatusMsg("Failed to toggle response rule.");
    }
  };

  const handleDeleteRule = async (ruleId: number) => {
    try {
      await api.deleteResponseRule(ruleId);
      refetchRules();
    } catch {
      setStatusMsg("Failed to delete response rule.");
    }
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleName || !triggerValue) return;
    try {
      await api.createResponseRule({
        name: ruleName,
        trigger_type: triggerType,
        trigger_value: triggerValue,
        action_type: actionType,
        enabled: true
      });
      setShowAddModal(false);
      setRuleName("");
      refetchRules();
    } catch {
      setStatusMsg("Failed to create response rule.");
    }
  };

  const combinedActions = [...liveMitigationHistory, ...(actions || [])].filter(
    (action, idx, self) => self.findIndex(a => a.id === action.id) === idx
  );

  return (
    <div className="app-layout">
      <Sidebar isConnected={isConnected} />
      <Header title="Configurable Response Engine" systemStatus={(stats?.system_status as any) || "Safe"} />

      <main className="main-content">
        <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <h2>Active Defense & Countermeasures</h2>
            <p>Automated OS firewall mitigations, active threat isolation, and customizable security policies</p>
          </div>
          <div className="badge" style={{ background: config?.is_admin ? "rgba(16, 185, 129, 0.15)" : "rgba(245, 158, 11, 0.15)", color: config?.is_admin ? "var(--color-safe)" : "var(--color-warning)", padding: "8px 14px", fontSize: 13, border: "1px solid rgba(255,255,255,0.1)" }}>
            {config?.is_admin ? "🛡️ OS Admin Elevation Active (Real Netsh Firewall)" : "⚠️ User Mode (OS Firewall Simulation)"}
          </div>
        </div>

        {statusMsg && (
          <div style={{ background: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)", color: "var(--accent-cyan)", padding: "12px 16px", borderRadius: 10, marginBottom: 20, fontSize: 13 }}>
            {statusMsg}
          </div>
        )}

        {/* Defense Mode Cards */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20, marginBottom: 24 }}>
          <div
            className={`card-glass ${config?.defense_mode === "dry_run" ? "active" : ""}`}
            style={{ cursor: "pointer", border: config?.defense_mode === "dry_run" ? "2px solid var(--accent-cyan)" : "1px solid var(--border)", position: "relative" }}
            onClick={() => handleModeChange("dry_run")}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: "var(--accent-cyan)" }}><Shield size={18} style={{ display: "inline", verticalAlign: "middle", marginRight: 8 }} /> Dry-Run (Simulation)</span>
              {config?.defense_mode === "dry_run" && <CheckCircle size={18} color="var(--accent-cyan)" />}
            </div>
            <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Evaluates incoming threat events against rules and logs proposed mitigations into audit history without modifying system firewall rules. Safe for baseline tuning.
            </p>
          </div>

          <div
            className={`card-glass ${config?.defense_mode === "semi_auto" ? "active" : ""}`}
            style={{ cursor: "pointer", border: config?.defense_mode === "semi_auto" ? "2px solid var(--color-warning)" : "1px solid var(--border)", position: "relative" }}
            onClick={() => handleModeChange("semi_auto")}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: "var(--color-warning)" }}><Clock size={18} style={{ display: "inline", verticalAlign: "middle", marginRight: 8 }} /> Semi-Automatic</span>
              {config?.defense_mode === "semi_auto" && <CheckCircle size={18} color="var(--color-warning)" />}
            </div>
            <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Generates pending block tickets when threat thresholds trigger. Requires explicit Security Analyst confirmation before applying OS firewall blocks.
            </p>
          </div>

          <div
            className={`card-glass ${config?.defense_mode === "auto" ? "active" : ""}`}
            style={{ cursor: "pointer", border: config?.defense_mode === "auto" ? "2px solid var(--color-critical)" : "1px solid var(--border)", position: "relative" }}
            onClick={() => handleModeChange("auto")}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: "var(--color-critical)" }}><Zap size={18} style={{ display: "inline", verticalAlign: "middle", marginRight: 8 }} /> Fully Autonomous</span>
              {config?.defense_mode === "auto" && <CheckCircle size={18} color="var(--color-critical)" />}
            </div>
            <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.5 }}>
              Instantly executes active OS firewall rules (`netsh` / `iptables`) and quarantines host devices whenever high-confidence intrusions are detected.
            </p>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: 24, marginBottom: 24 }}>
          {/* Quick Manual Defense Control */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><ShieldAlert size={16} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Quick Manual Execution</span>
            </div>
            <form onSubmit={handleManualExecute} style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 10 }}>
              <div>
                <label className="settings-label">Target IP Address</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.105"
                  value={manualIp}
                  onChange={(e) => setManualIp(e.target.value)}
                  style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border)", color: "white", fontSize: 13, marginTop: 6 }}
                  required
                />
              </div>

              <div>
                <label className="settings-label">Action Type</label>
                <select
                  value={manualAction}
                  onChange={(e) => setManualAction(e.target.value)}
                  style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border)", color: "white", fontSize: 13, marginTop: 6 }}
                >
                  <option value="block_ip">🔒 Block IP (Firewall Rule)</option>
                  <option value="unblock_ip">🔓 Unblock IP (Remove Rule)</option>
                  <option value="isolate_device">☣️ Isolate Host Device</option>
                  <option value="log_only">📝 Record Security Log Only</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={executing}
                style={{
                  background: manualAction === "unblock_ip" ? "var(--color-safe)" : "var(--color-critical)",
                  color: "white",
                  padding: "12px",
                  borderRadius: 8,
                  fontWeight: 600,
                  fontSize: 14,
                  cursor: "pointer",
                  border: "none",
                  marginTop: 6
                }}
              >
                {executing ? "Executing Action..." : `Execute ${manualAction.replace("_", " ").toUpperCase()}`}
              </button>
            </form>

            <div style={{ marginTop: 24, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <span className="settings-label">Currently Blocked IPs ({config?.blocked_ips.length || 0})</span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
                {config?.blocked_ips && config.blocked_ips.length > 0 ? (
                  config.blocked_ips.map(ip => (
                    <span key={ip} className="badge critical" style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px" }}>
                      <Lock size={12} /> {ip}
                      <button
                        onClick={() => api.executeDefenseAction("unblock_ip", ip).then(() => { refetchConfig(); refetchActions(); })}
                        style={{ background: "none", border: "none", color: "white", cursor: "pointer", padding: 0 }}
                        title="Unblock IP"
                      >
                        <Unlock size={12} />
                      </button>
                    </span>
                  ))
                ) : (
                  <span style={{ fontSize: 12, color: "var(--text-muted)" }}>No active IP firewall blocks present.</span>
                )}
              </div>
            </div>
          </div>

          {/* Configurable Response Rules Table */}
          <div className="card">
            <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="card-title"><Filter size={16} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Active Response Rules ({rules?.length || 0})</span>
              <button
                onClick={() => setShowAddModal(true)}
                style={{ background: "var(--accent-cyan)", color: "#000", border: "none", borderRadius: 6, padding: "6px 14px", fontWeight: 700, fontSize: 12, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}
              >
                <Plus size={14} /> Add New Rule
              </button>
            </div>

            <table className="data-table" style={{ marginTop: 14 }}>
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Trigger Condition</th>
                  <th>Trigger Value</th>
                  <th>Defensive Action</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules && rules.length > 0 ? (
                  rules.map(rule => (
                    <tr key={rule.id}>
                      <td style={{ fontWeight: 600 }}>{rule.name}</td>
                      <td><span className="badge info">{rule.trigger_type}</span></td>
                      <td><span className="badge warning">{rule.trigger_value}</span></td>
                      <td>
                        <span className={`badge ${rule.action_type === "block_ip" ? "critical" : rule.action_type === "isolate_device" ? "danger" : "safe"}`}>
                          {rule.action_type}
                        </span>
                      </td>
                      <td>
                        <button
                          onClick={() => handleToggleRule(rule.id, rule.enabled)}
                          style={{
                            background: rule.enabled ? "rgba(16, 185, 129, 0.2)" : "rgba(148, 163, 184, 0.2)",
                            color: rule.enabled ? "var(--color-safe)" : "var(--text-muted)",
                            border: "none",
                            borderRadius: 12,
                            padding: "4px 12px",
                            fontSize: 12,
                            fontWeight: 600,
                            cursor: "pointer"
                          }}
                        >
                          {rule.enabled ? "Enabled" : "Disabled"}
                        </button>
                      </td>
                      <td>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          style={{ background: "none", border: "none", color: "var(--color-danger)", cursor: "pointer" }}
                          title="Delete Rule"
                        >
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: 20 }}>No response rules configured.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Mitigation Execution Audit Log */}
        <div className="card">
          <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span className="card-title"><Radio size={16} style={{ display: "inline", verticalAlign: "middle", marginRight: 6 }} /> Live Mitigation Execution Audit Log</span>
            <span className="badge info">{combinedActions.length} recorded actions</span>
          </div>

          <table className="data-table" style={{ marginTop: 14 }}>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Target Host IP</th>
                <th>Triggered Rule</th>
                <th>Action Type</th>
                <th>Executed By</th>
                <th>Status</th>
                <th>Action Details</th>
              </tr>
            </thead>
            <tbody>
              {combinedActions.length > 0 ? (
                combinedActions.map((act) => (
                  <tr key={act.id}>
                    <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                      {new Date(act.timestamp).toLocaleTimeString()}
                    </td>
                    <td style={{ fontWeight: 600, fontFamily: "monospace", color: "var(--accent-cyan)" }}>
                      {act.target_ip || "—"}
                    </td>
                    <td style={{ fontSize: 13 }}>{act.rule_name || "Manual Action"}</td>
                    <td>
                      <span className={`badge ${act.action_type === "block_ip" ? "critical" : act.action_type === "unblock_ip" ? "safe" : "warning"}`}>
                        {act.action_type}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>{act.executed_by}</td>
                    <td>
                      <span className={`badge ${act.status.includes("Enforced") || act.status === "Success" || act.status === "Isolated" ? "critical" : act.status.includes("Simulated") ? "info" : "safe"}`}>
                        {act.status}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {act.details}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>
                    No defense actions have been executed yet. Real actions will stream live here.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Modal for creating a new Response Rule */}
        {showAddModal && (
          <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100 }}>
            <div className="card-glass" style={{ width: 440, padding: 24 }}>
              <h3 style={{ fontSize: 18, fontWeight: 700, marginBottom: 16 }}>Add Response Rule</h3>
              <form onSubmit={handleCreateRule} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                <div>
                  <label className="settings-label">Rule Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Quarantine Ransomware Host"
                    value={ruleName}
                    onChange={e => setRuleName(e.target.value)}
                    style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.8)", border: "1px solid var(--border)", color: "white", marginTop: 6 }}
                    required
                  />
                </div>

                <div>
                  <label className="settings-label">Trigger Condition</label>
                  <select
                    value={triggerType}
                    onChange={e => setTriggerType(e.target.value)}
                    style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.8)", border: "1px solid var(--border)", color: "white", marginTop: 6 }}
                  >
                    <option value="severity">Alert Severity</option>
                    <option value="attack_type">Attack Type</option>
                    <option value="threat_score">Threat Probability (%)</option>
                  </select>
                </div>

                <div>
                  <label className="settings-label">Trigger Value</label>
                  <input
                    type="text"
                    placeholder="e.g. Critical, DDoS Attack, or 75"
                    value={triggerValue}
                    onChange={e => setTriggerValue(e.target.value)}
                    style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.8)", border: "1px solid var(--border)", color: "white", marginTop: 6 }}
                    required
                  />
                </div>

                <div>
                  <label className="settings-label">Defensive Action to Take</label>
                  <select
                    value={actionType}
                    onChange={e => setActionType(e.target.value)}
                    style={{ width: "100%", padding: "10px 14px", borderRadius: 8, background: "rgba(15, 23, 42, 0.8)", border: "1px solid var(--border)", color: "white", marginTop: 6 }}
                  >
                    <option value="block_ip">🔒 Block IP Address (OS Firewall Rule)</option>
                    <option value="isolate_device">☣️ Isolate Host Device</option>
                    <option value="log_only">📝 Record Audit Log Only</option>
                  </select>
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: 12, marginTop: 12 }}>
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    style={{ background: "transparent", border: "1px solid var(--border)", color: "white", padding: "8px 16px", borderRadius: 8, cursor: "pointer" }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    style={{ background: "var(--accent-cyan)", color: "#000", fontWeight: 700, border: "none", padding: "8px 20px", borderRadius: 8, cursor: "pointer" }}
                  >
                    Save Rule
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
