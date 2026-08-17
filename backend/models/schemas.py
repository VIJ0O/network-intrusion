"""
Pydantic models for the NIDS API — Real Data Edition.
Every model represents actual captured/computed data, never mock values.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime
from enum import Enum


# ────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────

class SystemStatus(str, Enum):
    SAFE = "Safe"
    WARNING = "Warning"
    CRITICAL = "Critical"
    OFFLINE = "Offline"


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AlertSeverity(str, Enum):
    INFO = "Info"
    WARNING = "Warning"
    HIGH = "High"
    CRITICAL = "Critical"


class ServiceHealth(str, Enum):
    ONLINE = "Online"
    OFFLINE = "Offline"
    STARTING = "Starting"
    ERROR = "Error"


# ────────────────────────────────────────────
# Packet Capture
# ────────────────────────────────────────────

class PacketSummary(BaseModel):
    """A single captured packet summary."""
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    size: int = 0
    tcp_flags: str = ""
    info: str = ""


class TrafficStats(BaseModel):
    """Aggregated traffic statistics from live capture."""
    timestamp: str
    packets_per_second: int = 0
    bytes_per_second: int = 0
    active_connections: int = 0
    total_packets_captured: int = 0
    protocol_distribution: Dict[str, int] = {}
    top_talkers: List[Dict] = []
    capture_online: bool = False


# ────────────────────────────────────────────
# Device Discovery
# ────────────────────────────────────────────

class Device(BaseModel):
    """A discovered network device."""
    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "Unknown"
    status: str = "Online"
    risk_level: str = "Low"
    last_seen: Optional[str] = None
    first_seen: Optional[str] = None
    ping_latency_ms: Optional[float] = None
    os_guess: Optional[str] = None
    interface: Optional[str] = None


# ────────────────────────────────────────────
# System Metrics
# ────────────────────────────────────────────

class SystemMetrics(BaseModel):
    """Real operating system metrics from psutil."""
    timestamp: str
    cpu_percent: float = 0.0
    cpu_per_core: List[float] = []
    ram_total_gb: float = 0.0
    ram_used_gb: float = 0.0
    ram_percent: float = 0.0
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_percent: float = 0.0
    net_bytes_sent: int = 0
    net_bytes_recv: int = 0
    net_packets_sent: int = 0
    net_packets_recv: int = 0
    process_count: int = 0
    backend_uptime_seconds: float = 0.0


# ────────────────────────────────────────────
# Network Topology
# ────────────────────────────────────────────

class TopologyNode(BaseModel):
    """A node in the network topology graph."""
    id: str
    ip: str
    label: str  # hostname or Unknown
    friendly_name: Optional[str] = None
    mac: Optional[str] = "Unknown"
    vendor: Optional[str] = "Unknown"
    device_type: str = "Unknown Device"
    classification_confidence: float = 95.0
    verification_score: float = 100.0  # Verification score % based on evidence methods
    evidence_list: List[str] = []  # Evidence items supporting classification & verification
    is_virtual_adapter: bool = False  # Hyper-V, VMware, VirtualBox, WSL, Docker
    connection_type: str = "Ethernet"  # WiFi or Ethernet
    signal_strength_dbm: Optional[int] = None
    os_guess: Optional[str] = "Unknown"
    status: str = "Online"  # Online, Idle, Active, High Traffic, Under Investigation, Disconnected, Monitoring Server
    risk_level: str = "Low"
    threat_score: float = 0.0
    ping_latency_ms: Optional[float] = None
    is_router: bool = False
    is_monitoring_server: bool = False
    is_attacker: bool = False
    is_victim: bool = False
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    packets_per_second: float = 0.0
    bandwidth_mbps: float = 0.0
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    active_connections: int = 0
    recent_alerts_count: int = 0
    last_seen: Optional[str] = None
    disconnected_for_seconds: Optional[float] = None


class TopologyEdge(BaseModel):
    """An edge (active communication session flow) in the topology graph."""
    source: str  # src IP
    target: str  # dst IP
    src_port: int = 49152
    dst_port: int = 443
    protocol: str = "TCP"
    packet_count: int = 0
    bytes_total: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    bandwidth_mbps: float = 0.0
    duration_seconds: float = 0.0
    rtt_latency_ms: float = 0.0
    tcp_flags: str = "SYN, ACK"
    classification: str = "Normal"  # Normal, Suspicious, Malicious, Blocked, Unknown
    protocols: List[str] = []
    is_attack: bool = False
    is_blocked: bool = False
    attack_type: Optional[str] = None
    threat_score: Optional[float] = None
    prediction_confidence: Optional[float] = None


class TopologyData(BaseModel):
    """Full topology graph data."""
    nodes: List[TopologyNode] = []
    edges: List[TopologyEdge] = []
    timestamp: str = ""


# ────────────────────────────────────────────
# AI Predictions
# ────────────────────────────────────────────

class PredictionResult(BaseModel):
    """AI prediction from the Autoencoder + LSTM pipeline."""
    timestamp: str
    threat_probability: float = 0.0
    confidence: float = 0.0
    predicted_attack_type: str = ""
    expected_severity: str = ""
    reason: str = ""
    model_status: str = "Offline"  # "Collecting Baseline", "Active", "Offline"
    anomaly_score: float = 0.0


# ────────────────────────────────────────────
# Alerts
# ────────────────────────────────────────────

class Alert(BaseModel):
    """A security alert generated from real detection."""
    id: int = 0
    timestamp: str
    severity: str
    title: str
    message: str = ""
    attacker_ip: Optional[str] = None
    victim_ip: Optional[str] = None
    attack_type: Optional[str] = None
    threat_score: float = 0.0
    confidence: float = 0.0
    recommended_action: str = ""
    action_taken: str = ""
    status: str = "Open"
    is_read: bool = False


# ────────────────────────────────────────────
# Attacks
# ────────────────────────────────────────────

class Attack(BaseModel):
    """A detected attack record from the database."""
    id: int = 0
    start_time: str
    end_time: Optional[str] = None
    attack_type: str
    attacker_ip: Optional[str] = None
    attacker_device: str = ""
    victim_ip: Optional[str] = None
    victim_device: str = ""
    severity: str = "Medium"
    status: str = "Active"
    packets_involved: int = 0
    description: str = ""


# ────────────────────────────────────────────
# Logs
# ────────────────────────────────────────────

class LogEntry(BaseModel):
    """A log entry from any backend subsystem."""
    id: int = 0
    timestamp: str
    source: str  # "PacketCapture", "DeviceDiscovery", "AIEngine", "AlertEngine", "System"
    level: str   # "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
    message: str


# ────────────────────────────────────────────
# Dashboard
# ────────────────────────────────────────────

class DashboardStats(BaseModel):
    """Aggregated dashboard overview — all from real sources."""
    system_status: str = "Offline"
    threat_score: float = 0.0
    ai_confidence: float = 0.0
    ai_status: str = "Offline"
    connected_devices: int = 0
    active_alerts: int = 0
    network_status: str = "Offline"
    packets_per_second: int = 0
    bandwidth_mbps: float = 0.0
    uptime_seconds: float = 0.0
    capture_online: bool = False
    prediction_online: bool = False


# ────────────────────────────────────────────
# Service Status
# ────────────────────────────────────────────

class ServiceStatusReport(BaseModel):
    """Health status of each backend subsystem."""
    packet_capture: str = "Offline"
    device_discovery: str = "Offline"
    ai_engine: str = "Offline"
    alert_engine: str = "Offline"
    system_metrics: str = "Offline"
    database: str = "Offline"
    websocket: str = "Offline"


# ────────────────────────────────────────────
# Report
# ────────────────────────────────────────────

class ReportSummary(BaseModel):
    """Report summary from database aggregation."""
    total_attacks: int = 0
    active_attacks: int = 0
    resolved_attacks: int = 0
    critical_alerts: int = 0
    total_alerts: int = 0
    total_packets: int = 0
    attack_type_distribution: Dict[str, int] = {}


# ────────────────────────────────────────────
# Response & Active Defense Engine Schemas
# ────────────────────────────────────────────

class ResponseRule(BaseModel):
    id: int
    name: str
    trigger_type: str  # "severity", "attack_type", "threat_score"
    trigger_value: str
    action_type: str   # "block_ip", "isolate_device", "log_only"
    enabled: bool
    created_at: str


class ResponseRuleCreate(BaseModel):
    name: str
    trigger_type: str
    trigger_value: str
    action_type: str
    enabled: bool = True


class MitigationAction(BaseModel):
    id: int
    timestamp: str
    rule_id: Optional[int] = None
    rule_name: Optional[str] = None
    action_type: str
    target_ip: Optional[str] = None
    target_device: Optional[str] = None
    status: str
    details: str
    executed_by: str = "System Auto-Mitigate"


class ResponseConfig(BaseModel):
    defense_mode: str  # "auto", "semi_auto", "dry_run"
    firewall_enabled: bool
    is_admin: bool
    blocked_ips: List[str] = []


class ExecuteActionRequest(BaseModel):
    action_type: str  # "block_ip", "unblock_ip", "isolate_device"
    target_ip: str
    reason: Optional[str] = "Manual Analyst Action"

