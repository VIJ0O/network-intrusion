/**
 * TypeScript interfaces for the NIDS v2 Real Data NDR platform.
 */

export type SystemStatus = "Safe" | "Warning" | "Critical" | "Offline";
export type RiskLevel = "Low" | "Medium" | "High" | "Critical";
export type AlertSeverity = "Info" | "Warning" | "High" | "Critical";

export interface PacketSummary {
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  src_port: number;
  dst_port: number;
  size: number;
  tcp_flags: string;
  info: string;
}

export interface TrafficStats {
  timestamp: string;
  packets_per_second: number;
  bytes_per_second: number;
  active_connections: number;
  total_packets_captured: number;
  protocol_distribution: Record<string, number>;
  top_talkers: { ip: string; bytes: number }[];
  capture_online: boolean;
}

export interface Device {
  id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  device_type: string;
  status: string;
  risk_level: string;
  last_seen: string | null;
  first_seen: string | null;
  ping_latency_ms: number | null;
  os_guess: string | null;
  interface: string | null;
}

export interface SystemMetrics {
  timestamp: string;
  cpu_percent: number;
  cpu_per_core: number[];
  ram_total_gb: number;
  ram_used_gb: number;
  ram_percent: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  net_bytes_sent: number;
  net_bytes_recv: number;
  net_packets_sent: number;
  net_packets_recv: number;
  process_count: number;
  backend_uptime_seconds: number;
}

export interface TopologyNode {
  id: string;
  ip: string;
  label: string;
  friendly_name?: string | null;
  mac: string | null;
  vendor?: string | null;
  device_type: string;
  classification_confidence?: number;
  verification_score?: number;
  evidence_list?: string[];
  is_virtual_adapter?: boolean;
  connection_type?: "WiFi" | "Ethernet";
  signal_strength_dbm?: number | null;
  os_guess?: string | null;
  status: "Online" | "Idle" | "Active" | "High Traffic" | "Under Investigation" | "Disconnected" | "Monitoring Server" | "Under Attack" | "Offline" | string;
  risk_level: string;
  threat_score?: number;
  ping_latency_ms?: number | null;
  is_router?: boolean;
  is_monitoring_server?: boolean;
  is_attacker?: boolean;
  is_victim?: boolean;
  cpu_usage?: number | null;
  memory_usage?: number | null;
  packets_per_second?: number;
  bandwidth_mbps?: number;
  download_mbps?: number;
  upload_mbps?: number;
  active_connections?: number;
  recent_alerts_count?: number;
  last_seen?: string | null;
  disconnected_for_seconds?: number | null;
}

export interface TopologyEdge {
  source: string;
  target: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  packet_count: number;
  bytes_total: number;
  packets_per_second?: number;
  bytes_per_second?: number;
  bandwidth_mbps?: number;
  duration_seconds?: number;
  rtt_latency_ms?: number;
  tcp_flags?: string;
  classification?: "Normal" | "Suspicious" | "Malicious" | "Blocked" | "Unknown";
  protocols: string[];
  is_attack: boolean;
  is_blocked?: boolean;
  attack_type?: string | null;
  threat_score?: number | null;
  prediction_confidence?: number | null;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  timestamp: string;
}

export interface PredictionResult {
  timestamp: string;
  threat_probability: number;
  confidence: number;
  predicted_attack_type: string;
  expected_severity: string;
  reason: string;
  model_status: string;
  anomaly_score: number;
  forecast_10s?: number;
  forecast_30s?: number;
  forecast_60s?: number;
  trend?: string;
}

export interface Alert {
  id: number;
  timestamp: string;
  severity: string;
  title: string;
  message: string;
  attacker_ip: string | null;
  victim_ip: string | null;
  attack_type: string | null;
  threat_score: number;
  confidence: number;
  recommended_action: string;
  action_taken: string;
  status: string;
  is_read: boolean;
}

export interface Attack {
  id: number;
  start_time: string;
  end_time: string | null;
  attack_type: string;
  attacker_ip: string | null;
  attacker_device: string;
  victim_ip: string | null;
  victim_device: string;
  severity: string;
  status: string;
  packets_involved: number;
  description: string;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  source: string;
  level: string;
  message: string;
}

export interface DashboardStats {
  system_status: string;
  threat_score: number;
  ai_confidence: number;
  ai_status: string;
  connected_devices: number;
  active_alerts: number;
  network_status: string;
  packets_per_second: number;
  bandwidth_mbps: number;
  uptime_seconds: number;
  capture_online: boolean;
  prediction_online: boolean;
}

export interface ReportSummary {
  total_attacks: number;
  active_attacks: number;
  resolved_attacks: number;
  critical_alerts: number;
  total_alerts: number;
  total_packets: number;
  attack_type_distribution: Record<string, number>;
}

export interface ResponseRule {
  id: number;
  name: string;
  trigger_type: string;
  trigger_value: string;
  action_type: string;
  enabled: boolean;
  created_at: string;
}

export interface MitigationAction {
  id: number;
  timestamp: string;
  rule_id: number | null;
  rule_name: string | null;
  action_type: string;
  target_ip: string | null;
  target_device: string | null;
  status: string;
  details: string;
  executed_by: string;
}

export interface ResponseConfig {
  defense_mode: "auto" | "semi_auto" | "dry_run";
  firewall_enabled: boolean;
  is_admin: boolean;
  blocked_ips: string[];
}

