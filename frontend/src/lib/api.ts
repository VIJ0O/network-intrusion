/**
 * API client utility for the real-data NIDS backend.
 * Dynamically resolves backend host & Next.js proxy rewrite for seamless mobile device access.
 */

import type {
  DashboardStats,
  Device,
  Alert,
  PredictionResult,
  Attack,
  ReportSummary,
  TopologyData,
  SystemMetrics,
  LogEntry,
  ResponseConfig,
  ResponseRule,
  MitigationAction,
  RLStatus,
  RLDecision,
  RLEvaluation
} from "@/types";

export function getApiBase(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  if (typeof window !== "undefined") {
    return "";
  }
  return "http://127.0.0.1:8000";
}

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const apiBase = getApiBase();
  const res = await fetch(`${apiBase}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }

  return res.json();
}

export const api = {
  getDashboard: () => fetchApi<DashboardStats>("/api/dashboard"),
  getDevices: () => fetchApi<Device[]>("/api/devices"),
  getDevice: (id: string) => fetchApi<Device>(`/api/devices/${id}`),
  getAlerts: (limit = 20, severity?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (severity) params.set("severity", severity);
    return fetchApi<Alert[]>(`/api/alerts?${params}`);
  },
  getPredictions: () => fetchApi<PredictionResult>("/api/predictions"),
  getAttacks: (limit = 20) => fetchApi<Attack[]>(`/api/attacks?limit=${limit}`),
  getCurrentAttack: () => fetchApi<Attack | { active: false }>("/api/attacks/current"),
  getReportSummary: () => fetchApi<ReportSummary>("/api/reports/summary"),
  getTopology: () => fetchApi<TopologyData>("/api/topology"),
  getSystemMetrics: () => fetchApi<SystemMetrics>("/api/metrics"),
  getLogs: (limit = 50, source?: string, level?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (source) params.set("source", source);
    if (level) params.set("level", level);
    return fetchApi<LogEntry[]>(`/api/logs?${params}`);
  },
  exportCSV: () => `${getApiBase()}/api/reports/export`,

  // Alerts Management
  clearAllAlerts: () => fetchApi<{ status: string }>("/api/alerts/clear-all", { method: "POST" }),
  resolveAlert: (alertId: number) => fetchApi<{ status: string }>(`/api/alerts/${alertId}/resolve`, { method: "POST" }),
  simulateAttack: (attackType = "SYN Flood") => fetchApi<{ status: string; alert_id: number; attack_type: string }>(`/api/alerts/simulate-attack?attack_type=${encodeURIComponent(attackType)}`, { method: "POST" }),

  // Response & Active Defense Engine
  getResponseConfig: () => fetchApi<ResponseConfig>("/api/response/config"),
  updateResponseConfig: (mode: "auto" | "semi_auto" | "dry_run", firewall_enabled = true) => 
    fetchApi<{ status: string; config: ResponseConfig }>(`/api/response/config?mode=${mode}&firewall_enabled=${firewall_enabled}`, { method: "POST" }),
  getResponseRules: () => fetchApi<ResponseRule[]>("/api/response/rules"),
  createResponseRule: (rule: { name: string; trigger_type: string; trigger_value: string; action_type: string; enabled?: boolean }) =>
    fetchApi<{ status: string; rule_id: number }>("/api/response/rules", { method: "POST", body: JSON.stringify(rule) }),
  toggleResponseRule: (ruleId: number, enabled: boolean) =>
    fetchApi<{ status: string }>(`/api/response/rules/${ruleId}/toggle?enabled=${enabled}`, { method: "POST" }),
  deleteResponseRule: (ruleId: number) =>
    fetchApi<{ status: string }>(`/api/response/rules/${ruleId}`, { method: "DELETE" }),
  getMitigationActions: (limit = 50) => fetchApi<MitigationAction[]>(`/api/response/actions?limit=${limit}`),
  executeDefenseAction: (action_type: string, target_ip: string, reason = "Manual Analyst Action") =>
    fetchApi<MitigationAction>("/api/response/execute", { method: "POST", body: JSON.stringify({ action_type, target_ip, reason }) }),

  // Reinforcement Learning Adaptive Defense Subsystem
  getRLStatus: () => fetchApi<RLStatus>("/api/rl/status"),
  getRLDecisions: (limit = 50) => fetchApi<RLDecision[]>(`/api/rl/decisions?limit=${limit}`),
  getRLEvaluation: () => fetchApi<RLEvaluation>("/api/rl/evaluation"),
  triggerRLTrain: (timesteps = 25000) => fetchApi<{ status: string; metadata?: any }>("/api/rl/train", { method: "POST", body: JSON.stringify({ timesteps }) }),
  triggerRLEvaluate: (episodes = 15) => fetchApi<{ status: string; evaluation?: RLEvaluation }>(`/api/rl/evaluate?episodes=${episodes}`, { method: "POST" }),
  updateRLConfig: (config: { dry_run?: boolean; auto_response_enabled?: boolean; allowed_actions?: number[] }) =>
    fetchApi<{ status: string; config: RLStatus }>("/api/rl/config", { method: "POST", body: JSON.stringify(config) }),
  triggerRLInferNow: () => fetchApi<RLDecision>("/api/rl/infer-now", { method: "POST" }),
};

export function getWebSocketUrl(channel: string): string {
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const hostname = window.location.hostname;
    const host = hostname === "localhost" ? "127.0.0.1" : hostname;
    return `${protocol}//${host}:8000/ws/${channel}`;
  }
  return `ws://127.0.0.1:8000/ws/${channel}`;
}
