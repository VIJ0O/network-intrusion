"""
Safe Live RL Inference Engine with Explainability Attribution and Dry-Run Safety Gates.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
import numpy as np

from rl.state import SecurityState, extract_rl_state, FEATURE_LABELS
from rl.actions import (
    RLAction,
    ACTION_NAMES,
    ACTION_DESCRIPTIONS,
    ACTION_TO_RESPONSE_MAP,
    get_action_details
)
from rl.policy import ActorCriticPolicy


class RLInferenceEngine:
    """Performs real-time defensive decision inference on live telemetry."""

    def __init__(self):
        self.policy = ActorCriticPolicy()
        self.dry_run = True  # Default safety requirement: Dry-Run enabled
        self.auto_response_enabled = False  # Default safety requirement: Auto-response disabled
        self.last_decision: Optional[Dict[str, Any]] = None

    def reload_policy(self) -> bool:
        """Reloads trained model from disk."""
        return self.policy.load()

    def set_config(self, dry_run: Optional[bool] = None, auto_response_enabled: Optional[bool] = None):
        if dry_run is not None:
            self.dry_run = dry_run
        if auto_response_enabled is not None:
            self.auto_response_enabled = auto_response_enabled

    def generate_explainability(self, state: SecurityState, action: int, confidence: float) -> List[Dict[str, Any]]:
        """
        Extracts prominent telemetry factors explaining why the RL agent chose this action.
        """
        factors = []
        
        # 1. Anomaly factor
        if state.anomaly_score > 0.05:
            factors.append({
                "factor": "Autoencoder Anomaly Score",
                "value": f"{state.anomaly_score:.4f}",
                "impact": "High" if state.anomaly_score > 0.2 else "Moderate",
                "detail": "Reconstruction loss exceeds normal baseline threshold"
            })

        # 2. Threat probability & LSTM forecast
        if state.threat_probability > 0.3:
            factors.append({
                "factor": "AI Threat Probability",
                "value": f"{state.threat_probability * 100:.1f}%",
                "impact": "High" if state.threat_probability > 0.7 else "Moderate",
                "detail": f"LSTM threat trend is {state.severity_label.lower()}"
            })

        # 3. Protocol & Packet signatures
        if state.syn_ratio > 0.3:
            factors.append({
                "factor": "SYN Packet Ratio",
                "value": f"{state.syn_ratio * 100:.1f}%",
                "impact": "High",
                "detail": "Elevated half-open connection attempts indicative of SYN flood"
            })

        if state.distinct_ports > 30:
            factors.append({
                "factor": "Distinct Port Probes",
                "value": f"{int(state.distinct_ports)} ports",
                "impact": "Moderate",
                "detail": "Wide port enumeration pattern characteristic of reconnaissance"
            })

        if state.pps > 1000:
            is_benign = state.anomaly_score < 0.05 and state.syn_ratio < 0.1
            factors.append({
                "factor": "Packet Flow Rate",
                "value": f"{int(state.pps)} pps ({int(state.bps / 1024)} KB/s)",
                "impact": "High" if not is_benign else "Low (Benign Stream)",
                "detail": "High-bandwidth transfer identified" if is_benign else "Volumetric burst detected"
            })

        # 4. Target Asset Criticality
        if state.victim_risk_score >= 0.5:
            factors.append({
                "factor": "Target Asset Risk",
                "value": f"Risk Score {state.victim_risk_score:.2f}",
                "impact": "High",
                "detail": "Critical host asset involved in network event"
            })

        if not factors:
            factors.append({
                "factor": "Baseline Telemetry",
                "value": "Nominal",
                "impact": "Normal",
                "detail": "All telemetry features conform to verified normal network profiles"
            })

        return factors

    def infer(self, state: SecurityState) -> Dict[str, Any]:
        """
        Executes safe inference on current security state.
        Failsafe: Returns fallback monitoring decision if model is not trained.
        """
        timestamp = datetime.now().isoformat()
        target_ip = state.target_ip or state.attacker_ip or "127.0.0.1"

        if not self.policy.is_trained:
            # Failsafe fallback
            decision = {
                "timestamp": timestamp,
                "status": "RL model not trained",
                "action_id": int(RLAction.CONTINUE_MONITORING),
                "action_name": "CONTINUE_MONITORING",
                "action_description": "RL policy not trained yet. Operating in safe monitoring mode.",
                "confidence": 100.0,
                "expected_reward": 0.0,
                "action_probabilities": [1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
                "target_ip": target_ip,
                "attacker_ip": state.attacker_ip,
                "victim_ip": state.victim_ip,
                "attack_type": state.attack_type,
                "threat_score": state.threat_probability * 100.0,
                "anomaly_score": state.anomaly_score,
                "explainability": [{
                    "factor": "Failsafe Safety Active",
                    "value": "Model Untrained",
                    "impact": "Info",
                    "detail": "Passive monitoring active until RL training is completed."
                }],
                "dry_run": self.dry_run,
                "auto_response_enabled": self.auto_response_enabled,
                "mode": "DRY RUN" if self.dry_run else ("AUTO RESPONSE" if self.auto_response_enabled else "STANDBY"),
                "policy_version": self.policy.version,
                "executed": False
            }
            self.last_decision = decision
            return decision

        # Normalized feature vector
        vec = state.to_vector()
        action_idx, log_prob, expected_val, probs = self.policy.predict(vec, deterministic=True)
        act_enum = RLAction(action_idx)
        act_details = get_action_details(action_idx)

        confidence = round(float(probs[action_idx] * 100.0), 1)
        explainability = self.generate_explainability(state, action_idx, confidence)

        decision = {
            "timestamp": timestamp,
            "status": "Ready",
            "action_id": int(act_enum),
            "action_name": act_details["name"],
            "action_description": act_details["description"],
            "response_engine_action": act_details["response_engine_action"],
            "disruption_level": act_details["disruption_level"],
            "confidence": confidence,
            "expected_reward": round(float(expected_val), 2),
            "action_probabilities": [round(float(p), 4) for p in probs],
            "target_ip": target_ip,
            "attacker_ip": state.attacker_ip,
            "victim_ip": state.victim_ip,
            "attack_type": state.attack_type,
            "threat_score": round(state.threat_probability * 100.0, 1),
            "anomaly_score": round(state.anomaly_score, 5),
            "explainability": explainability,
            "dry_run": self.dry_run,
            "auto_response_enabled": self.auto_response_enabled,
            "mode": "DRY RUN" if self.dry_run else ("AUTO RESPONSE" if self.auto_response_enabled else "MANUAL CONFIRM"),
            "policy_version": self.policy.version,
            "executed": False
        }
        self.last_decision = decision
        return decision


rl_inference_engine = RLInferenceEngine()
