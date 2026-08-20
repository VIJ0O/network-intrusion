"""
Gymnasium-compatible Network Security Simulation Environment.
Simulates realistic cybersecurity scenarios including high legitimate traffic vs severe attacks.
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces
from typing import Dict, Tuple, Optional, Any
from rl.state import SecurityState, STATE_DIM
from rl.actions import RLAction, ACTION_COUNT
from rl.rewards import RewardConfig, calculate_reward, DEFAULT_REWARD_CONFIG

# Simulation Scenarios
SCENARIOS = [
    "normal_baseline",
    "heavy_legitimate_traffic",
    "port_scan",
    "syn_flood",
    "ddos_attack",
    "brute_force",
    "unknown_anomaly",
    "attack_escalation",
    "attack_recovery"
]


class NetworkSecurityEnv(gym.Env):
    """
    Gymnasium environment simulating realistic network telemetry, AI anomaly detection signals,
    and defensive response interactions.
    """
    metadata = {"render_modes": ["human"]}

    def __init__(self, reward_config: Optional[RewardConfig] = None, max_steps: int = 30):
        super(NetworkSecurityEnv, self).__init__()
        self.reward_config = reward_config or DEFAULT_REWARD_CONFIG
        self.max_steps = max_steps

        # Observation space: 18 normalized security state features [0.0, 1.0]
        self.observation_space = spaces.Box(
            low=0.0,
            high=1.0,
            shape=(STATE_DIM,),
            dtype=np.float32
        )

        # Action space: 6 discrete defensive decisions
        self.action_space = spaces.Discrete(ACTION_COUNT)

        # Internal state tracking
        self.current_step = 0
        self.current_scenario = "normal_baseline"
        self.current_state: Optional[SecurityState] = None
        self.is_attack = False
        self.is_heavy_legitimate = False
        self.attack_type = "None"
        self.attack_severity = 0.0
        self.attack_mitigated = False
        self.consecutive_correct_actions = 0
        self.cumulative_disruption = 0.0

    def reset(self, seed: Optional[int] = None, options: Optional[Dict] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        super().reset(seed=seed)
        self.current_step = 0
        self.attack_mitigated = False
        self.consecutive_correct_actions = 0
        self.cumulative_disruption = 0.0

        # Select scenario from options or random choice with weighted distribution
        if options and "scenario" in options:
            self.current_scenario = options["scenario"]
        else:
            # 30% normal/heavy benign, 70% various threat scenarios
            scenario_weights = [
                0.20,  # normal_baseline
                0.15,  # heavy_legitimate_traffic
                0.15,  # port_scan
                0.15,  # syn_flood
                0.10,  # ddos_attack
                0.08,  # brute_force
                0.07,  # unknown_anomaly
                0.05,  # attack_escalation
                0.05   # attack_recovery
            ]
            self.current_scenario = self.np_random.choice(SCENARIOS, p=scenario_weights)

        self._init_scenario_state(self.current_scenario)
        obs = self.current_state.to_vector()
        
        info = {
            "scenario": self.current_scenario,
            "is_attack": self.is_attack,
            "is_heavy_legitimate": self.is_heavy_legitimate,
            "attack_type": self.attack_type,
            "severity": self.attack_severity
        }
        return obs, info

    def _init_scenario_state(self, scenario: str):
        """Generates realistic initial state features for each scenario."""
        if scenario == "normal_baseline":
            self.is_attack = False
            self.is_heavy_legitimate = False
            self.attack_type = "None"
            self.attack_severity = 0.0
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.001, 0.02)),
                threat_probability=float(self.np_random.uniform(0.01, 0.15)),
                pps=float(self.np_random.uniform(20.0, 150.0)),
                bps=float(self.np_random.uniform(50_000.0, 500_000.0)),
                tcp_ratio=float(self.np_random.uniform(0.4, 0.6)),
                udp_ratio=float(self.np_random.uniform(0.3, 0.5)),
                icmp_ratio=float(self.np_random.uniform(0.0, 0.05)),
                syn_ratio=float(self.np_random.uniform(0.01, 0.08)),
                distinct_ports=float(self.np_random.uniform(2.0, 15.0)),
                unique_ips=float(self.np_random.uniform(2.0, 10.0)),
                attack_confidence=0.98,
                attack_severity_num=0.0,
                attack_duration=0.0,
                num_attackers=0.0,
                num_victims=0.0,
                victim_risk_score=0.1,
                current_defense_status=0.0,
                forecast_trend=0.5,
                attack_type="None",
                severity_label="Low"
            )

        elif scenario == "heavy_legitimate_traffic":
            # CRITICAL: High PPS/BPS, but LOW anomaly score, LOW syn_ratio, normal TCP/UDP
            self.is_attack = False
            self.is_heavy_legitimate = True
            self.attack_type = "None"
            self.attack_severity = 0.05
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.01, 0.035)),  # within normal baseline threshold
                threat_probability=float(self.np_random.uniform(0.05, 0.20)),
                pps=float(self.np_random.uniform(2500.0, 4500.0)),  # High bandwidth transfer / backup
                bps=float(self.np_random.uniform(8_000_000.0, 18_000_000.0)),
                tcp_ratio=float(self.np_random.uniform(0.7, 0.9)),
                udp_ratio=float(self.np_random.uniform(0.1, 0.2)),
                icmp_ratio=0.0,
                syn_ratio=float(self.np_random.uniform(0.01, 0.05)),  # Normal connection establishment
                distinct_ports=float(self.np_random.uniform(5.0, 20.0)),
                unique_ips=float(self.np_random.uniform(2.0, 8.0)),
                attack_confidence=0.92,
                attack_severity_num=0.0,
                attack_duration=0.0,
                num_attackers=0.0,
                num_victims=0.0,
                victim_risk_score=0.2,
                current_defense_status=0.0,
                forecast_trend=0.5,
                attack_type="None",
                severity_label="Low"
            )

        elif scenario == "port_scan":
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "Port Scan"
            self.attack_severity = 0.45
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.15, 0.45)),
                threat_probability=float(self.np_random.uniform(0.45, 0.70)),
                pps=float(self.np_random.uniform(80.0, 400.0)),
                bps=float(self.np_random.uniform(80_000.0, 400_000.0)),
                tcp_ratio=float(self.np_random.uniform(0.8, 0.95)),
                udp_ratio=float(self.np_random.uniform(0.05, 0.15)),
                icmp_ratio=0.0,
                syn_ratio=float(self.np_random.uniform(0.5, 0.85)),  # High SYN scan probes
                distinct_ports=float(self.np_random.uniform(80.0, 180.0)),  # Scanning many ports
                unique_ips=2.0,
                attack_confidence=0.88,
                attack_severity_num=0.5,
                attack_duration=float(self.np_random.uniform(5.0, 40.0)),
                num_attackers=1.0,
                num_victims=1.0,
                victim_risk_score=0.5,
                current_defense_status=0.0,
                forecast_trend=0.8,
                target_ip="192.168.1.105",
                attacker_ip="192.168.1.105",
                victim_ip="192.168.1.1",
                attack_type="Port Scan",
                severity_label="Medium"
            )

        elif scenario == "syn_flood":
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "SYN Flood"
            self.attack_severity = 0.85
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.55, 0.95)),
                threat_probability=float(self.np_random.uniform(0.80, 0.99)),
                pps=float(self.np_random.uniform(2500.0, 4800.0)),
                bps=float(self.np_random.uniform(2_000_000.0, 10_000_000.0)),
                tcp_ratio=0.98,
                udp_ratio=0.01,
                icmp_ratio=0.0,
                syn_ratio=float(self.np_random.uniform(0.85, 0.99)),  # Overwhelming SYNs
                distinct_ports=float(self.np_random.uniform(5.0, 25.0)),
                unique_ips=float(self.np_random.uniform(5.0, 25.0)),
                attack_confidence=0.96,
                attack_severity_num=0.85,
                attack_duration=float(self.np_random.uniform(10.0, 60.0)),
                num_attackers=1.0,
                num_victims=1.0,
                victim_risk_score=0.8,
                current_defense_status=0.0,
                forecast_trend=1.0,  # Rising rapidly
                target_ip="192.168.1.200",
                attacker_ip="192.168.1.200",
                victim_ip="192.168.1.50",
                attack_type="SYN Flood",
                severity_label="Critical"
            )

        elif scenario == "ddos_attack":
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "DDoS"
            self.attack_severity = 0.95
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.70, 0.99)),
                threat_probability=float(self.np_random.uniform(0.90, 1.0)),
                pps=float(self.np_random.uniform(3500.0, 4950.0)),
                bps=float(self.np_random.uniform(12_000_000.0, 19_500_000.0)),
                tcp_ratio=float(self.np_random.uniform(0.4, 0.8)),
                udp_ratio=float(self.np_random.uniform(0.2, 0.6)),
                icmp_ratio=float(self.np_random.uniform(0.0, 0.3)),
                syn_ratio=float(self.np_random.uniform(0.6, 0.95)),
                distinct_ports=float(self.np_random.uniform(10.0, 50.0)),
                unique_ips=float(self.np_random.uniform(20.0, 48.0)),  # Distributed sources
                attack_confidence=0.98,
                attack_severity_num=1.0,
                attack_duration=float(self.np_random.uniform(15.0, 90.0)),
                num_attackers=float(self.np_random.uniform(5.0, 9.0)),
                num_victims=1.0,
                victim_risk_score=0.95,
                current_defense_status=0.0,
                forecast_trend=1.0,
                target_ip="192.168.1.250",
                attacker_ip="192.168.1.250",
                victim_ip="192.168.1.1",
                attack_type="DDoS",
                severity_label="Critical"
            )

        elif scenario == "brute_force":
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "Brute Force"
            self.attack_severity = 0.60
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.25, 0.55)),
                threat_probability=float(self.np_random.uniform(0.60, 0.80)),
                pps=float(self.np_random.uniform(100.0, 600.0)),
                bps=float(self.np_random.uniform(150_000.0, 800_000.0)),
                tcp_ratio=0.95,
                udp_ratio=0.05,
                icmp_ratio=0.0,
                syn_ratio=float(self.np_random.uniform(0.2, 0.4)),
                distinct_ports=2.0,  # Targeting SSH/RDP/HTTP auth port
                unique_ips=2.0,
                attack_confidence=0.91,
                attack_severity_num=0.6,
                attack_duration=float(self.np_random.uniform(20.0, 120.0)),
                num_attackers=1.0,
                num_victims=1.0,
                victim_risk_score=0.7,
                current_defense_status=0.0,
                forecast_trend=0.7,
                target_ip="192.168.1.140",
                attacker_ip="192.168.1.140",
                victim_ip="192.168.1.20",
                attack_type="Brute Force",
                severity_label="High"
            )

        elif scenario == "unknown_anomaly":
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "Zero-Day Anomaly"
            self.attack_severity = 0.70
            self.current_state = SecurityState(
                anomaly_score=float(self.np_random.uniform(0.60, 0.90)),  # High reconstruction error
                threat_probability=float(self.np_random.uniform(0.70, 0.88)),
                pps=float(self.np_random.uniform(400.0, 1500.0)),
                bps=float(self.np_random.uniform(600_000.0, 3_000_000.0)),
                tcp_ratio=float(self.np_random.uniform(0.3, 0.7)),
                udp_ratio=float(self.np_random.uniform(0.3, 0.7)),
                icmp_ratio=float(self.np_random.uniform(0.0, 0.2)),
                syn_ratio=float(self.np_random.uniform(0.3, 0.6)),
                distinct_ports=float(self.np_random.uniform(15.0, 60.0)),
                unique_ips=4.0,
                attack_confidence=0.82,
                attack_severity_num=0.75,
                attack_duration=float(self.np_random.uniform(10.0, 50.0)),
                num_attackers=1.0,
                num_victims=1.0,
                victim_risk_score=0.75,
                current_defense_status=0.0,
                forecast_trend=0.9,
                target_ip="192.168.1.188",
                attacker_ip="192.168.1.188",
                victim_ip="192.168.1.35",
                attack_type="Zero-Day Anomaly",
                severity_label="High"
            )

        elif scenario == "attack_escalation":
            # Starts as port scan, will escalate if unhandled
            self.is_attack = True
            self.is_heavy_legitimate = False
            self.attack_type = "Port Scan -> Escalating"
            self.attack_severity = 0.40
            self.current_state = SecurityState(
                anomaly_score=0.30,
                threat_probability=0.45,
                pps=150.0,
                bps=150_000.0,
                tcp_ratio=0.9,
                udp_ratio=0.1,
                icmp_ratio=0.0,
                syn_ratio=0.6,
                distinct_ports=60.0,
                unique_ips=2.0,
                attack_confidence=0.85,
                attack_severity_num=0.4,
                attack_duration=10.0,
                num_attackers=1.0,
                num_victims=1.0,
                victim_risk_score=0.6,
                current_defense_status=0.0,
                forecast_trend=1.0,  # Escalating forecast
                target_ip="192.168.1.199",
                attacker_ip="192.168.1.199",
                victim_ip="192.168.1.10",
                attack_type="Port Scan",
                severity_label="Medium"
            )

        elif scenario == "attack_recovery":
            # Attack has stopped or been blocked, returning to normal
            self.is_attack = False
            self.is_heavy_legitimate = False
            self.attack_type = "Recovering"
            self.attack_severity = 0.15
            self.current_state = SecurityState(
                anomaly_score=0.08,
                threat_probability=0.25,
                pps=90.0,
                bps=100_000.0,
                tcp_ratio=0.6,
                udp_ratio=0.4,
                icmp_ratio=0.0,
                syn_ratio=0.05,
                distinct_ports=10.0,
                unique_ips=3.0,
                attack_confidence=0.90,
                attack_severity_num=0.2,
                attack_duration=60.0,
                num_attackers=0.0,
                num_victims=0.0,
                victim_risk_score=0.3,
                current_defense_status=0.75,
                forecast_trend=0.0,  # Falling rapidly
                attack_type="None",
                severity_label="Low"
            )

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        self.current_step += 1
        act = RLAction(action) if action in RLAction._value2member_map_ else RLAction.CONTINUE_MONITORING

        # Evaluate mitigation outcome
        mitigated = False
        recovered = False
        disruption = 0.0

        if self.is_attack:
            if self.attack_severity >= 0.7:
                if act in [RLAction.BLOCK_SOURCE, RLAction.QUARANTINE_DEVICE]:
                    mitigated = True
                    self.attack_mitigated = True
                elif act == RLAction.RATE_LIMIT and "Flood" in self.attack_type:
                    mitigated = True
                    self.attack_mitigated = True
            elif self.attack_severity >= 0.4:
                if act in [RLAction.RATE_LIMIT, RLAction.BLOCK_SOURCE, RLAction.INCREASE_MONITORING]:
                    mitigated = True
                    self.attack_mitigated = True
            else:
                if act in [RLAction.GENERATE_ALERT, RLAction.INCREASE_MONITORING, RLAction.CONTINUE_MONITORING]:
                    mitigated = True
                    self.attack_mitigated = True
        else:
            if act in [RLAction.BLOCK_SOURCE, RLAction.QUARANTINE_DEVICE]:
                disruption = 1.0
            elif act == RLAction.RATE_LIMIT and self.is_heavy_legitimate:
                disruption = 0.5

        # Compute reward
        reward = calculate_reward(
            action=action,
            is_attack=self.is_attack,
            attack_type=self.attack_type,
            threat_severity=self.attack_severity,
            is_heavy_legitimate_traffic=self.is_heavy_legitimate,
            attack_mitigated=mitigated,
            recovered=recovered,
            config=self.reward_config
        )

        # Transition dynamics to next step
        self._evolve_state(act, mitigated)

        terminated = False
        truncated = self.current_step >= self.max_steps

        # If attack successfully mitigated and recovered, terminate episode early
        if self.is_attack and self.attack_mitigated and self.current_step >= 3:
            terminated = True

        obs = self.current_state.to_vector()
        info = {
            "scenario": self.current_scenario,
            "is_attack": self.is_attack,
            "is_heavy_legitimate": self.is_heavy_legitimate,
            "mitigated": mitigated,
            "disruption": disruption,
            "step": self.current_step,
            "action_taken": act.name
        }

        return obs, reward, terminated, truncated, info

    def _evolve_state(self, action: RLAction, mitigated: bool):
        """Simulates how the environment reacts to defensive action."""
        if mitigated:
            # Threat metrics reduce towards baseline
            self.current_state.anomaly_score = max(0.01, self.current_state.anomaly_score * 0.4)
            self.current_state.threat_probability = max(0.05, self.current_state.threat_probability * 0.4)
            self.current_state.pps = max(50.0, self.current_state.pps * 0.3)
            self.current_state.forecast_trend = 0.0
            self.attack_severity = max(0.0, self.attack_severity * 0.3)
            if action == RLAction.BLOCK_SOURCE:
                self.current_state.current_defense_status = 0.75
            elif action == RLAction.QUARANTINE_DEVICE:
                self.current_state.current_defense_status = 1.0
            elif action == RLAction.RATE_LIMIT:
                self.current_state.current_defense_status = 0.5
        else:
            if self.is_attack:
                # Unmitigated attack escalates
                self.current_state.anomaly_score = min(1.0, self.current_state.anomaly_score * 1.15)
                self.current_state.threat_probability = min(1.0, self.current_state.threat_probability * 1.1)
                self.current_state.attack_duration += 5.0
                self.current_state.forecast_trend = 1.0
