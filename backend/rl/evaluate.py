"""
Evaluation Harness for RL Defense Policy vs Rule-Based Baseline.
Benchmarks performance across diverse cyber threat & heavy traffic scenarios.
"""

import time
import numpy as np
from typing import Dict, Any, List
from rl.state import STATE_DIM, SecurityState
from rl.actions import RLAction, ACTION_COUNT, ACTION_NAMES
from rl.environment import NetworkSecurityEnv, SCENARIOS
from rl.policy import ActorCriticPolicy


class RuleBasedBaseline:
    """Standard rule-based response baseline for comparison."""

    def select_action(self, obs: np.ndarray) -> int:
        anomaly_score = obs[0]
        threat_prob = obs[1]
        pps = obs[2]
        syn_ratio = obs[7]

        # Standard static thresholds
        if threat_prob >= 0.75 or (pps > 0.6 and syn_ratio > 0.5):
            return int(RLAction.BLOCK_SOURCE)
        elif threat_prob >= 0.50 or pps > 0.5:
            return int(RLAction.RATE_LIMIT)
        elif threat_prob >= 0.30 or anomaly_score > 0.2:
            return int(RLAction.GENERATE_ALERT)
        elif anomaly_score > 0.1:
            return int(RLAction.INCREASE_MONITORING)
        else:
            return int(RLAction.CONTINUE_MONITORING)


def evaluate_agent(
    policy: ActorCriticPolicy,
    episodes_per_scenario: int = 15
) -> Dict[str, Any]:
    """
    Evaluates RL Policy vs Rule-Based Baseline across all scenarios.
    Measures mitigation rate, false positives, disruption, and average rewards.
    """
    env = NetworkSecurityEnv()
    baseline = RuleBasedBaseline()

    # Track metrics for both agents
    def create_tracker():
        return {
            "rewards": [],
            "mitigated_count": 0,
            "attack_count": 0,
            "false_positives": 0,
            "benign_count": 0,
            "unnecessary_blocks": 0,
            "service_disruptions": 0,
            "latencies_ms": [],
            "action_counts": {name: 0 for name in ACTION_NAMES.values()}
        }

    rl_tracker = create_tracker()
    rule_tracker = create_tracker()

    for scenario in SCENARIOS:
        for _ in range(episodes_per_scenario):
            # 1. Test RL Policy
            obs, info = env.reset(options={"scenario": scenario})
            is_attack = info["is_attack"]
            is_heavy = info["is_heavy_legitimate"]

            if is_attack:
                rl_tracker["attack_count"] += 1
            else:
                rl_tracker["benign_count"] += 1

            t0 = time.perf_counter()
            action_rl, _, _, _ = policy.predict(obs, deterministic=True)
            t1 = time.perf_counter()
            rl_tracker["latencies_ms"].append((t1 - t0) * 1000.0)

            act_rl_name = ACTION_NAMES.get(RLAction(action_rl), "UNKNOWN")
            rl_tracker["action_counts"][act_rl_name] += 1

            _, reward_rl, _, _, info_rl = env.step(action_rl)
            rl_tracker["rewards"].append(reward_rl)

            if is_attack:
                if info_rl.get("mitigated"):
                    rl_tracker["mitigated_count"] += 1
            else:
                if action_rl in [RLAction.GENERATE_ALERT, RLAction.INCREASE_MONITORING]:
                    rl_tracker["false_positives"] += 1
                elif action_rl in [RLAction.BLOCK_SOURCE, RLAction.QUARANTINE_DEVICE]:
                    rl_tracker["unnecessary_blocks"] += 1
                    rl_tracker["service_disruptions"] += 1
                elif action_rl == RLAction.RATE_LIMIT and is_heavy:
                    rl_tracker["service_disruptions"] += 1

            # 2. Test Rule-Based Baseline on identical scenario
            obs_b, info_b = env.reset(options={"scenario": scenario})
            if is_attack:
                rule_tracker["attack_count"] += 1
            else:
                rule_tracker["benign_count"] += 1

            t0 = time.perf_counter()
            action_rule = baseline.select_action(obs_b)
            t1 = time.perf_counter()
            rule_tracker["latencies_ms"].append((t1 - t0) * 1000.0)

            act_rule_name = ACTION_NAMES.get(RLAction(action_rule), "UNKNOWN")
            rule_tracker["action_counts"][act_rule_name] += 1

            _, reward_rule, _, _, info_rule = env.step(action_rule)
            rule_tracker["rewards"].append(reward_rule)

            if is_attack:
                if info_rule.get("mitigated"):
                    rule_tracker["mitigated_count"] += 1
            else:
                if action_rule in [RLAction.GENERATE_ALERT, RLAction.INCREASE_MONITORING]:
                    rule_tracker["false_positives"] += 1
                elif action_rule in [RLAction.BLOCK_SOURCE, RLAction.QUARANTINE_DEVICE]:
                    rule_tracker["unnecessary_blocks"] += 1
                    rule_tracker["service_disruptions"] += 1
                elif action_rule == RLAction.RATE_LIMIT and is_heavy:
                    rule_tracker["service_disruptions"] += 1

    def summarize(tracker):
        total_episodes = len(tracker["rewards"])
        atk_cnt = max(1, tracker["attack_count"])
        bng_cnt = max(1, tracker["benign_count"])
        return {
            "total_episodes": total_episodes,
            "average_reward": round(float(np.mean(tracker["rewards"])), 2),
            "attack_mitigation_rate": round(float(tracker["mitigated_count"] / atk_cnt * 100.0), 1),
            "false_positive_rate": round(float(tracker["false_positives"] / bng_cnt * 100.0), 1),
            "unnecessary_blocking_rate": round(float(tracker["unnecessary_blocks"] / bng_cnt * 100.0), 1),
            "service_disruption_rate": round(float(tracker["service_disruptions"] / bng_cnt * 100.0), 1),
            "avg_latency_ms": round(float(np.mean(tracker["latencies_ms"])), 3),
            "action_distribution": tracker["action_counts"]
        }

    summary_rl = summarize(rl_tracker)
    summary_rule = summarize(rule_tracker)

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy_version": policy.version,
        "scenarios_evaluated": len(SCENARIOS),
        "total_test_episodes": len(rl_tracker["rewards"]),
        "rl_performance": summary_rl,
        "baseline_performance": summary_rule,
        "reward_improvement": round(summary_rl["average_reward"] - summary_rule["average_reward"], 2),
        "disruption_reduction": round(summary_rule["service_disruption_rate"] - summary_rl["service_disruption_rate"], 1)
    }
