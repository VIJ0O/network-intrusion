"""
Training Script for PPO Network Defense Agent.
Executes training against the NetworkSecurityEnv simulation and benchmarks policy.
"""

import sys
import argparse
from rl.environment import NetworkSecurityEnv
from rl.policy import PPOTrainer
from rl.evaluate import evaluate_agent


def run_training(timesteps: int = 25000, evaluate: bool = True):
    print(f"[*] Initializing PPO Training on NetworkSecurityEnv (timesteps={timesteps})...")
    trainer = PPOTrainer()
    meta = trainer.train(total_timesteps=timesteps)
    print(f"[+] Training completed in {meta['training_duration_seconds']}s.")
    print(f"    Final Policy Loss: {meta['final_policy_loss']}")
    print(f"    Final Value Loss:  {meta['final_value_loss']}")
    print(f"    Final Entropy:     {meta['final_entropy']}")

    if evaluate:
        print("\n[*] Evaluating Trained Policy vs Rule-Based Baseline...")
        results = evaluate_agent(trainer.policy, episodes_per_scenario=20)
        rl_p = results["rl_performance"]
        base_p = results["baseline_performance"]
        print(f"\n================ BENCHMARK RESULTS ================")
        print(f"Metric                    RL Agent      Rule-Based")
        print(f"---------------------------------------------------")
        print(f"Average Reward:          {rl_p['average_reward']:>8.2f}      {base_p['average_reward']:>8.2f}")
        print(f"Mitigation Rate (%):     {rl_p['attack_mitigation_rate']:>8.1f}%     {base_p['attack_mitigation_rate']:>8.1f}%")
        print(f"False Positive Rate (%): {rl_p['false_positive_rate']:>8.1f}%     {base_p['false_positive_rate']:>8.1f}%")
        print(f"Service Disruption (%):  {rl_p['service_disruption_rate']:>8.1f}%     {base_p['service_disruption_rate']:>8.1f}%")
        print(f"Avg Latency (ms):        {rl_p['avg_latency_ms']:>8.3f}ms    {base_p['avg_latency_ms']:>8.3f}ms")
        print(f"===================================================")
        print(f"Reward Improvement: +{results['reward_improvement']:.2f}")
        print(f"Disruption Reduction: {results['disruption_reduction']:.1f}%")
        return meta, results

    return meta, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PPO Network Defense Agent")
    parser.add_argument("--timesteps", type=int, default=25000, help="Total training timesteps")
    parser.add_argument("--no-eval", action="store_true", help="Skip evaluation after training")
    args = parser.parse_args()

    run_training(timesteps=args.timesteps, evaluate=not args.no_eval)
