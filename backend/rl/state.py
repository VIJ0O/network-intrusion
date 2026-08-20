"""
RL State Representation and Live Feature Normalization.
Converts real-time telemetry, AI predictions, and device states into normalized observation vectors.
"""

import numpy as np
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any

STATE_DIM = 18

FEATURE_LABELS = [
    "anomaly_score",
    "threat_probability",
    "pps",
    "bps",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "distinct_ports",
    "unique_ips",
    "attack_confidence",
    "attack_severity_num",
    "attack_duration",
    "num_attackers",
    "num_victims",
    "victim_risk_score",
    "current_defense_status",
    "forecast_trend"
]

# Normalization upper bounds for raw values
MAX_PPS = 5000.0
MAX_BPS = 20_000_000.0  # 20 MB/s
MAX_PORTS = 200.0
MAX_IPS = 50.0
MAX_DURATION_SEC = 300.0
MAX_ATTACKERS = 10.0
MAX_VICTIMS = 10.0


@dataclass
class SecurityState:
    """Structured security state holding both raw metrics and normalized vector."""
    anomaly_score: float = 0.0          # 0.0 - 1.0
    threat_probability: float = 0.0     # 0.0 - 1.0
    pps: float = 0.0                    # raw packets/sec
    bps: float = 0.0                    # raw bytes/sec
    tcp_ratio: float = 0.0              # 0.0 - 1.0
    udp_ratio: float = 0.0              # 0.0 - 1.0
    icmp_ratio: float = 0.0             # 0.0 - 1.0
    syn_ratio: float = 0.0              # 0.0 - 1.0
    distinct_ports: float = 0.0         # raw count
    unique_ips: float = 0.0             # raw count
    attack_confidence: float = 0.0      # 0.0 - 1.0
    attack_severity_num: float = 0.0    # 0.0=None, 0.25=Low, 0.5=Med, 0.75=High, 1.0=Crit
    attack_duration: float = 0.0        # seconds
    num_attackers: float = 0.0          # count
    num_victims: float = 0.0            # count
    victim_risk_score: float = 0.0      # 0.0 - 1.0
    current_defense_status: float = 0.0 # 0.0=None, 0.25=Monitored, 0.5=RateLimited, 0.75=Blocked, 1.0=Isolated
    forecast_trend: float = 0.5         # 0.0=falling, 0.5=stable, 1.0=rising

    # Metadata for contextual reasoning / explainability (not fed directly to vector)
    target_ip: Optional[str] = None
    attacker_ip: Optional[str] = None
    victim_ip: Optional[str] = None
    attack_type: str = "None"
    severity_label: str = "Low"

    def to_vector(self) -> np.ndarray:
        """Returns normalized float32 numpy array of length STATE_DIM."""
        vec = np.array([
            np.clip(self.anomaly_score, 0.0, 1.0),
            np.clip(self.threat_probability, 0.0, 1.0),
            np.clip(self.pps / MAX_PPS, 0.0, 1.0),
            np.clip(self.bps / MAX_BPS, 0.0, 1.0),
            np.clip(self.tcp_ratio, 0.0, 1.0),
            np.clip(self.udp_ratio, 0.0, 1.0),
            np.clip(self.icmp_ratio, 0.0, 1.0),
            np.clip(self.syn_ratio, 0.0, 1.0),
            np.clip(self.distinct_ports / MAX_PORTS, 0.0, 1.0),
            np.clip(self.unique_ips / MAX_IPS, 0.0, 1.0),
            np.clip(self.attack_confidence, 0.0, 1.0),
            np.clip(self.attack_severity_num, 0.0, 1.0),
            np.clip(self.attack_duration / MAX_DURATION_SEC, 0.0, 1.0),
            np.clip(self.num_attackers / MAX_ATTACKERS, 0.0, 1.0),
            np.clip(self.num_victims / MAX_VICTIMS, 0.0, 1.0),
            np.clip(self.victim_risk_score, 0.0, 1.0),
            np.clip(self.current_defense_status, 0.0, 1.0),
            np.clip(self.forecast_trend, 0.0, 1.0)
        ], dtype=np.float32)
        return vec

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation."""
        d = asdict(self)
        d["vector"] = self.to_vector().tolist()
        return d


def severity_to_num(severity: str) -> float:
    mapping = {
        "none": 0.0,
        "low": 0.25,
        "medium": 0.50,
        "high": 0.75,
        "critical": 1.00
    }
    return mapping.get(str(severity).lower(), 0.25)


def trend_to_num(trend: str) -> float:
    mapping = {
        "falling": 0.0,
        "stable": 0.5,
        "rising": 1.0
    }
    return mapping.get(str(trend).lower(), 0.5)


def defense_status_to_num(status: str) -> float:
    mapping = {
        "none": 0.0,
        "normal": 0.0,
        "monitored": 0.25,
        "rate_limited": 0.5,
        "blocked": 0.75,
        "isolated": 1.0,
        "quarantined": 1.0
    }
    return mapping.get(str(status).lower(), 0.0)


def extract_rl_state(
    ai_prediction: Optional[Dict] = None,
    traffic_stats: Optional[Dict] = None,
    active_attack: Optional[Dict] = None,
    alerts: Optional[List[Dict]] = None,
    devices: Optional[List[Dict]] = None,
    defense_state: Optional[Dict] = None
) -> SecurityState:
    """
    Constructs a real SecurityState from live system components.
    Uses real Autoencoder anomaly scores, LSTM predictions, Scapy traffic counters, and discovery data.
    """
    ai_pred = ai_prediction or {}
    t_stats = traffic_stats or {}
    atk = active_attack or {}
    alerts_list = alerts or []
    devs_list = devices or []
    def_state = defense_state or {}

    # 1. Anomaly & AI Prediction features
    threat_prob_raw = float(ai_pred.get("threat_probability", 0.0))
    threat_prob = threat_prob_raw / 100.0 if threat_prob_raw > 1.0 else threat_prob_raw
    anomaly_score = float(ai_pred.get("anomaly_score", 0.0))
    confidence_raw = float(ai_pred.get("confidence", 95.0))
    confidence = confidence_raw / 100.0 if confidence_raw > 1.0 else confidence_raw
    trend_str = ai_pred.get("trend", "stable")
    forecast_trend = trend_to_num(trend_str)

    # 2. Traffic Flow metrics
    pps = float(t_stats.get("packets_per_second", 0.0))
    bps = float(t_stats.get("bytes_per_second", 0.0))
    
    proto_dist = t_stats.get("protocol_distribution", {})
    if isinstance(proto_dist, dict) and sum(proto_dist.values()) > 0:
        total_proto = sum(proto_dist.values())
        tcp_ratio = proto_dist.get("TCP", 0) / total_proto
        udp_ratio = proto_dist.get("UDP", 0) / total_proto
        icmp_ratio = proto_dist.get("ICMP", 0) / total_proto
    else:
        tcp_ratio = 0.5
        udp_ratio = 0.3
        icmp_ratio = 0.0

    syn_ratio = float(t_stats.get("syn_ratio", 0.0))
    distinct_ports = float(t_stats.get("distinct_ports", 0.0))
    unique_ips = float(t_stats.get("unique_ips", 0.0))

    # 3. Threat and Incident context
    severity_str = atk.get("severity") or ai_pred.get("expected_severity", "Low")
    severity_num = severity_to_num(severity_str)
    attack_type = atk.get("attack_type") or ai_pred.get("predicted_attack_type", "None")

    attacker_ip = atk.get("attacker_ip")
    victim_ip = atk.get("victim_ip")
    target_ip = attacker_ip or victim_ip

    num_attackers = 1.0 if attacker_ip else 0.0
    num_victims = 1.0 if victim_ip else 0.0

    # Calculate duration
    attack_duration = 0.0
    start_time_str = atk.get("start_time")
    if start_time_str:
        try:
            from datetime import datetime
            start_dt = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            attack_duration = max(0.0, (datetime.now().astimezone(start_dt.tzinfo) - start_dt).total_seconds())
        except Exception:
            attack_duration = 10.0

    # 4. Device and Asset risk assessment
    victim_risk = 0.2
    if victim_ip and devs_list:
        for d in devs_list:
            if d.get("ip_address") == victim_ip:
                risk_lvl = d.get("risk_level", "Low").lower()
                victim_risk = severity_to_num(risk_lvl)
                break

    # 5. Active Defense State
    current_defense = 0.0
    if target_ip and def_state:
        blocked = def_state.get("blocked_ips", [])
        if target_ip in blocked:
            current_defense = 0.75
        elif def_state.get("defense_mode") == "active":
            current_defense = 0.25

    return SecurityState(
        anomaly_score=anomaly_score,
        threat_probability=threat_prob,
        pps=pps,
        bps=bps,
        tcp_ratio=tcp_ratio,
        udp_ratio=udp_ratio,
        icmp_ratio=icmp_ratio,
        syn_ratio=syn_ratio,
        distinct_ports=distinct_ports,
        unique_ips=unique_ips,
        attack_confidence=confidence,
        attack_severity_num=severity_num,
        attack_duration=attack_duration,
        num_attackers=num_attackers,
        num_victims=num_victims,
        victim_risk_score=victim_risk,
        current_defense_status=current_defense,
        forecast_trend=forecast_trend,
        target_ip=target_ip,
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        attack_type=attack_type,
        severity_label=severity_str
    )
