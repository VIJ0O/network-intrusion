"""
Action Space Definition and Response Engine Mapping.
Defines discrete defensive actions, disruption profiles, and execution safety allowlists.
"""

from enum import IntEnum
from typing import Dict, Any, Optional

class RLAction(IntEnum):
    CONTINUE_MONITORING = 0
    GENERATE_ALERT = 1
    INCREASE_MONITORING = 2
    RATE_LIMIT = 3
    BLOCK_SOURCE = 4
    QUARANTINE_DEVICE = 5


ACTION_COUNT = 6

ACTION_NAMES: Dict[int, str] = {
    RLAction.CONTINUE_MONITORING: "CONTINUE_MONITORING",
    RLAction.GENERATE_ALERT: "GENERATE_ALERT",
    RLAction.INCREASE_MONITORING: "INCREASE_MONITORING",
    RLAction.RATE_LIMIT: "RATE_LIMIT",
    RLAction.BLOCK_SOURCE: "BLOCK_SOURCE",
    RLAction.QUARANTINE_DEVICE: "QUARANTINE_DEVICE",
}

ACTION_DESCRIPTIONS: Dict[int, str] = {
    RLAction.CONTINUE_MONITORING: "Continue passive monitoring without intervening. Zero operational disruption.",
    RLAction.GENERATE_ALERT: "Dispatch prioritized SOC security alert notification for analyst review.",
    RLAction.INCREASE_MONITORING: "Elevate inspection frequency and packet capture sampling on suspect host.",
    RLAction.RATE_LIMIT: "Apply dynamic traffic/bandwidth throttling to prevent resource exhaustion.",
    RLAction.BLOCK_SOURCE: "Inject OS firewall rule dropping all ingress/egress packets from adversary IP.",
    RLAction.QUARANTINE_DEVICE: "Isolate compromised host from network segment to prevent lateral movement.",
}

# Mapping from RL action integer to Response Engine action_type strings
ACTION_TO_RESPONSE_MAP: Dict[int, Optional[str]] = {
    RLAction.CONTINUE_MONITORING: "log_only",
    RLAction.GENERATE_ALERT: "log_only",
    RLAction.INCREASE_MONITORING: "log_only",
    RLAction.RATE_LIMIT: "rate_limit",
    RLAction.BLOCK_SOURCE: "block_ip",
    RLAction.QUARANTINE_DEVICE: "isolate_device",
}

# Operational impact severity (0: None, 1: Low, 2: Moderate, 3: High, 4: Critical)
ACTION_DISRUPTION_LEVEL: Dict[int, int] = {
    RLAction.CONTINUE_MONITORING: 0,
    RLAction.GENERATE_ALERT: 0,
    RLAction.INCREASE_MONITORING: 1,
    RLAction.RATE_LIMIT: 2,
    RLAction.BLOCK_SOURCE: 3,
    RLAction.QUARANTINE_DEVICE: 4,
}

# Default safety allowlist (safe actions permitted for auto execution when enabled)
DEFAULT_ALLOWED_ACTIONS = {
    RLAction.CONTINUE_MONITORING,
    RLAction.GENERATE_ALERT,
    RLAction.INCREASE_MONITORING,
    RLAction.RATE_LIMIT,
    RLAction.BLOCK_SOURCE
}


def get_action_details(action: int) -> Dict[str, Any]:
    """Returns human-readable metadata for an action."""
    act_enum = RLAction(action) if action in RLAction._value2member_map_ else RLAction.CONTINUE_MONITORING
    return {
        "action_id": int(act_enum),
        "name": ACTION_NAMES.get(act_enum, "UNKNOWN"),
        "description": ACTION_DESCRIPTIONS.get(act_enum, ""),
        "response_engine_action": ACTION_TO_RESPONSE_MAP.get(act_enum),
        "disruption_level": ACTION_DISRUPTION_LEVEL.get(act_enum, 0)
    }
