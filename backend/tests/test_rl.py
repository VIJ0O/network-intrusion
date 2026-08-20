"""
Automated Test Suite for Reinforcement Learning Adaptive Defense Subsystem.
Tests state representations, action spaces, reward calculations, environment transitions,
model inference, failsafe behavior, and benchmark evaluations.
"""

import os
import sys
import unittest
import numpy as np

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl.state import SecurityState, extract_rl_state, STATE_DIM, FEATURE_LABELS
from rl.actions import (
    RLAction,
    ACTION_NAMES,
    ACTION_TO_RESPONSE_MAP,
    ACTION_COUNT,
    get_action_details,
    DEFAULT_ALLOWED_ACTIONS
)
from rl.rewards import RewardConfig, calculate_reward, DEFAULT_REWARD_CONFIG
from rl.environment import NetworkSecurityEnv, SCENARIOS
from rl.policy import ActorCriticNetwork, ActorCriticPolicy, PPOTrainer
from rl.inference import RLInferenceEngine
from rl.evaluate import evaluate_agent, RuleBasedBaseline


class TestRLSubsystem(unittest.TestCase):

    def test_state_vector_shape_and_normalization(self):
        """Test that state vector has exact length STATE_DIM and all elements are bounded in [0.0, 1.0]."""
        state = SecurityState(
            anomaly_score=0.15,
            threat_probability=0.85,
            pps=3000.0,
            bps=15_000_000.0,
            tcp_ratio=0.9,
            udp_ratio=0.1,
            icmp_ratio=0.0,
            syn_ratio=0.8,
            distinct_ports=120.0,
            unique_ips=15.0,
            attack_confidence=0.95,
            attack_severity_num=0.75,
            attack_duration=45.0,
            num_attackers=1.0,
            num_victims=1.0,
            victim_risk_score=0.8,
            current_defense_status=0.0,
            forecast_trend=1.0
        )
        vec = state.to_vector()
        self.assertEqual(len(vec), STATE_DIM)
        self.assertTrue(np.all(vec >= 0.0))
        self.assertTrue(np.all(vec <= 1.0))
        self.assertEqual(len(FEATURE_LABELS), STATE_DIM)

    def test_extract_rl_state_live(self):
        """Test state extraction from simulated live telemetry feeds."""
        dummy_pred = {
            "threat_probability": 72.0,
            "anomaly_score": 0.08,
            "confidence": 94.0,
            "trend": "rising",
            "predicted_attack_type": "SYN Flood",
            "expected_severity": "High"
        }
        dummy_stats = {
            "packets_per_second": 1200,
            "bytes_per_second": 450000,
            "protocol_distribution": {"TCP": 900, "UDP": 300},
            "syn_ratio": 0.7,
            "distinct_ports": 25,
            "unique_ips": 6
        }
        sec_state = extract_rl_state(ai_prediction=dummy_pred, traffic_stats=dummy_stats)
        self.assertAlmostEqual(sec_state.threat_probability, 0.72)
        self.assertAlmostEqual(sec_state.anomaly_score, 0.08)
        self.assertEqual(sec_state.pps, 1200.0)
        vec = sec_state.to_vector()
        self.assertEqual(len(vec), 18)

    def test_action_space_and_mapping(self):
        """Verify that all 6 discrete actions map to defined response engine actions."""
        self.assertEqual(ACTION_COUNT, 6)
        for act in RLAction:
            details = get_action_details(int(act))
            self.assertIn(details["name"], ACTION_NAMES.values())
            self.assertIn("response_engine_action", details)

    def test_reward_heavy_traffic_vs_attack(self):
        """
        Verify that the reward function strictly distinguishes heavy legitimate traffic
        from true attacks and heavily penalizes unnecessary blocking.
        """
        cfg = DEFAULT_REWARD_CONFIG

        # 1. Normal traffic correctly monitored
        r_benign_monitored = calculate_reward(
            action=int(RLAction.CONTINUE_MONITORING),
            is_attack=False,
            attack_type="None",
            threat_severity=0.0,
            is_heavy_legitimate_traffic=False
        )
        self.assertEqual(r_benign_monitored, cfg.normal_traffic_monitored_reward)

        # 2. Heavy legitimate traffic blocked (unnecessary blocking + service disruption)
        r_heavy_blocked = calculate_reward(
            action=int(RLAction.BLOCK_SOURCE),
            is_attack=False,
            attack_type="None",
            threat_severity=0.05,
            is_heavy_legitimate_traffic=True
        )
        self.assertLess(r_heavy_blocked, -20.0)

        # 3. Severe attack mitigated with block
        r_attack_mitigated = calculate_reward(
            action=int(RLAction.BLOCK_SOURCE),
            is_attack=True,
            attack_type="SYN Flood",
            threat_severity=0.9,
            attack_mitigated=True
        )
        self.assertGreaterEqual(r_attack_mitigated, cfg.mitigated_attack_reward)

        # 4. Severe attack ignored with continue monitoring
        r_attack_ignored = calculate_reward(
            action=int(RLAction.CONTINUE_MONITORING),
            is_attack=True,
            attack_type="SYN Flood",
            threat_severity=0.9,
            attack_mitigated=False
        )
        self.assertEqual(r_attack_ignored, cfg.attack_continues_penalty)

    def test_gymnasium_environment_transitions(self):
        """Verify Gymnasium environment reset, step, termination, and observation spaces."""
        env = NetworkSecurityEnv(max_steps=10)
        obs, info = env.reset()
        self.assertEqual(obs.shape, (18,))
        self.assertIn(info["scenario"], SCENARIOS)

        total_reward = 0.0
        for step in range(5):
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            total_reward += reward
            self.assertEqual(obs.shape, (18,))
            if terminated or truncated:
                break

    def test_actor_critic_network_forward(self):
        """Verify Actor-Critic network produces valid action probabilities and value estimates."""
        net = ActorCriticNetwork()
        dummy_state = np.random.uniform(0.0, 1.0, size=(18,)).astype(np.float32)
        policy = ActorCriticPolicy()
        policy.network = net
        action, log_prob, value, probs = policy.predict(dummy_state)

        self.assertIn(action, list(range(6)))
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=4)
        self.assertIsInstance(value, float)

    def test_failsafe_untrained_model(self):
        """Verify that an untrained engine safely falls back to monitoring mode."""
        engine = RLInferenceEngine()
        engine.policy.is_trained = False
        state = SecurityState(anomaly_score=0.8, threat_probability=0.9)
        decision = engine.infer(state)
        self.assertEqual(decision["status"], "RL model not trained")
        self.assertEqual(decision["action_name"], "CONTINUE_MONITORING")
        self.assertFalse(decision["executed"])

    def test_evaluation_baseline_comparison(self):
        """Verify that evaluate_agent runs and compares RL vs Rule-Based baseline across scenarios."""
        policy = ActorCriticPolicy()
        results = evaluate_agent(policy, episodes_per_scenario=2)
        self.assertIn("rl_performance", results)
        self.assertIn("baseline_performance", results)
        self.assertIn("reward_improvement", results)
        self.assertIn("disruption_reduction", results)


if __name__ == "__main__":
    unittest.main()
