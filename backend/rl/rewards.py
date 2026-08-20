"""
Configurable Reward Function for Network Security RL Agent.
Balances threat mitigation efficacy against false positives and service disruption penalties.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any
from rl.actions import RLAction

@dataclass
class RewardConfig:
    """Configurable reward coefficients."""
    mitigated_attack_reward: float = 10.0
    normal_traffic_monitored_reward: float = 5.0
    attack_continues_penalty: float = -10.0
    false_positive_penalty: float = -8.0
    unnecessary_blocking_penalty: float = -15.0
    unnecessary_quarantine_penalty: float = -20.0
    service_disruption_penalty: float = -15.0
    successful_recovery_reward: float = 8.0
    rate_limit_mitigated_reward: float = 7.0
    increase_monitoring_reward: float = 2.0

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


DEFAULT_REWARD_CONFIG = RewardConfig()


def calculate_reward(
    action: int,
    is_attack: bool,
    attack_type: str,
    threat_severity: float,  # 0.0 to 1.0
    is_heavy_legitimate_traffic: bool = False,
    attack_mitigated: bool = False,
    recovered: bool = False,
    config: RewardConfig = DEFAULT_REWARD_CONFIG
) -> float:
    """
    Computes situational reward based on action taken and network context.
    Strictly penalizes misclassifying heavy legitimate traffic as attacks (unnecessary blocking/quarantine).
    """
    act = RLAction(action) if action in RLAction._value2member_map_ else RLAction.CONTINUE_MONITORING

    # ────────────────────────────────────────────
    # Scenario A: Benign / Normal or Heavy Traffic
    # ────────────────────────────────────────────
    if not is_attack:
        if is_heavy_legitimate_traffic:
            # Crucial test: heavy benign bandwidth (e.g. database backup or video stream)
            if act == RLAction.CONTINUE_MONITORING:
                return config.normal_traffic_monitored_reward + 2.0  # Extra reward for not interfering
            elif act == RLAction.INCREASE_MONITORING:
                return 1.0  # Acceptable cautious observation
            elif act == RLAction.GENERATE_ALERT:
                return config.false_positive_penalty * 0.5  # Minor FP penalty
            elif act == RLAction.RATE_LIMIT:
                return config.service_disruption_penalty * 0.7  # Throttled legitimate user
            elif act == RLAction.BLOCK_SOURCE:
                return config.unnecessary_blocking_penalty + config.service_disruption_penalty
            elif act == RLAction.QUARANTINE_DEVICE:
                return config.unnecessary_quarantine_penalty + config.service_disruption_penalty
        else:
            # Standard baseline traffic
            if act == RLAction.CONTINUE_MONITORING:
                return config.normal_traffic_monitored_reward
            elif act in [RLAction.GENERATE_ALERT, RLAction.INCREASE_MONITORING]:
                return config.false_positive_penalty
            elif act == RLAction.RATE_LIMIT:
                return config.service_disruption_penalty
            elif act == RLAction.BLOCK_SOURCE:
                return config.unnecessary_blocking_penalty
            elif act == RLAction.QUARANTINE_DEVICE:
                return config.unnecessary_quarantine_penalty

    # ────────────────────────────────────────────
    # Scenario B: True Cyber Attack in Progress
    # ────────────────────────────────────────────
    if is_attack:
        # High-severity threats: DoS, SYN Flood, Malware C2, Exploit
        if threat_severity >= 0.7:
            if act == RLAction.BLOCK_SOURCE:
                return config.mitigated_attack_reward + (config.successful_recovery_reward if recovered else 0.0)
            elif act == RLAction.QUARANTINE_DEVICE:
                return config.mitigated_attack_reward + 2.0 if attack_type in ["Malware C2", "Lateral Movement"] else config.mitigated_attack_reward - 3.0
            elif act == RLAction.RATE_LIMIT:
                # Partially helpful for DoS/SYN floods, but insufficient for malware
                if "Flood" in attack_type or "DoS" in attack_type:
                    return config.rate_limit_mitigated_reward
                return config.attack_continues_penalty * 0.5
            elif act in [RLAction.GENERATE_ALERT, RLAction.INCREASE_MONITORING]:
                return config.attack_continues_penalty * 0.5  # Under-reaction to critical threat
            elif act == RLAction.CONTINUE_MONITORING:
                return config.attack_continues_penalty  # Severe failure to act

        # Medium-severity threats: Port Scan, Brute Force, Suspicious Anomaly
        elif threat_severity >= 0.4:
            if act == RLAction.RATE_LIMIT:
                return config.mitigated_attack_reward
            elif act == RLAction.INCREASE_MONITORING:
                return config.increase_monitoring_reward + 3.0
            elif act == RLAction.GENERATE_ALERT:
                return config.increase_monitoring_reward + 2.0
            elif act == RLAction.BLOCK_SOURCE:
                # Might be slightly aggressive for a gentle scan, but still mitigates
                return config.mitigated_attack_reward * 0.7
            elif act == RLAction.QUARANTINE_DEVICE:
                return config.unnecessary_quarantine_penalty * 0.5  # Overkill for simple probe
            elif act == RLAction.CONTINUE_MONITORING:
                return config.attack_continues_penalty * 0.6

        # Low-severity threats: Background probe / early anomaly
        else:
            if act in [RLAction.INCREASE_MONITORING, RLAction.GENERATE_ALERT]:
                return config.increase_monitoring_reward
            elif act == RLAction.CONTINUE_MONITORING:
                return 1.0
            elif act in [RLAction.BLOCK_SOURCE, RLAction.QUARANTINE_DEVICE]:
                return config.unnecessary_blocking_penalty * 0.5

    return 0.0
