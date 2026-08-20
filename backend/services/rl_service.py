"""
RL Adaptive Defense Service.
Integrates PPO reinforcement learning engine with live network telemetry, AI pipeline,
and active defense execution gates.
"""

import asyncio
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

from rl.state import extract_rl_state, SecurityState
from rl.actions import RLAction, ACTION_NAMES, ACTION_TO_RESPONSE_MAP, DEFAULT_ALLOWED_ACTIONS
from rl.inference import rl_inference_engine
from rl.policy import PPOTrainer, ActorCriticPolicy
from rl.evaluate import evaluate_agent
from database import (
    insert_rl_decision,
    get_rl_decisions,
    insert_rl_evaluation,
    get_latest_rl_evaluation,
    get_all_devices,
    get_active_attack
)
from services.log_manager import log_manager
from services.ai_engine import ai_engine
from services.alert_engine import alert_engine
from services.packet_capture import packet_capture


class RLService:
    """Manages continuous RL decision inference, training/eval orchestrations, and response gates."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: List[Callable] = []

        # Safety flags
        self.dry_run: bool = os.getenv("RL_DRY_RUN", "true").lower() == "true"
        self.auto_response_enabled: bool = os.getenv("RL_AUTO_RESPONSE_ENABLED", "false").lower() == "true"
        self.allowed_actions = set(DEFAULT_ALLOWED_ACTIONS)

        # Sync inference engine safety settings
        rl_inference_engine.set_config(
            dry_run=self.dry_run,
            auto_response_enabled=self.auto_response_enabled
        )

        self.latest_decision: Optional[Dict[str, Any]] = None
        self.is_training: bool = False
        self.is_evaluating: bool = False

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True

        # Subscribe to AI engine updates for real-time reactive decision inference
        ai_engine.subscribe(self._on_ai_prediction)
        alert_engine.subscribe(self._on_alert_event)

        status_str = "Trained Policy Online" if rl_inference_engine.policy.is_trained else "Untrained (Monitoring Mode)"
        mode_str = "DRY RUN (Safe)" if self.dry_run else ("AUTO DEFENSE" if self.auto_response_enabled else "MANUAL CONFIRM")
        await log_manager.log("RLService", "INFO", f"RL Adaptive Response Service started — [{status_str}] Mode: [{mode_str}]")

    async def stop(self):
        self.is_running = False
        ai_engine.unsubscribe(self._on_ai_prediction)
        alert_engine.unsubscribe(self._on_alert_event)
        await log_manager.log("RLService", "INFO", "RL Adaptive Response Service stopped")

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status of the RL engine."""
        policy_trained = rl_inference_engine.policy.is_trained
        return {
            "is_running": self.is_running,
            "policy_trained": policy_trained,
            "policy_version": rl_inference_engine.policy.version,
            "dry_run": self.dry_run,
            "auto_response_enabled": self.auto_response_enabled,
            "allowed_actions": [ACTION_NAMES.get(a, str(a)) for a in self.allowed_actions],
            "is_training": self.is_training,
            "is_evaluating": self.is_evaluating,
            "training_metadata": rl_inference_engine.policy.training_metadata,
            "latest_decision": self.latest_decision
        }

    def set_config(
        self,
        dry_run: Optional[bool] = None,
        auto_response_enabled: Optional[bool] = None,
        allowed_actions: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """Updates configuration and safety gates."""
        if dry_run is not None:
            self.dry_run = dry_run
        if auto_response_enabled is not None:
            self.auto_response_enabled = auto_response_enabled
        if allowed_actions is not None:
            self.allowed_actions = set(allowed_actions)

        rl_inference_engine.set_config(
            dry_run=self.dry_run,
            auto_response_enabled=self.auto_response_enabled
        )
        return self.get_status()

    async def _on_ai_prediction(self, pred: Dict):
        """Asynchronously reacts to new AI anomaly prediction."""
        if not self.is_running:
            return
        # Fire inference as detached async task so it never slows down packet analysis
        asyncio.create_task(self.evaluate_live_state(ai_prediction=pred))

    async def _on_alert_event(self, event_type: str, data: Dict):
        """Asynchronously reacts to new Alert Engine event."""
        if not self.is_running or event_type != "alert":
            return
        asyncio.create_task(self.evaluate_live_state(alert_event=data))

    async def evaluate_live_state(
        self,
        ai_prediction: Optional[Dict] = None,
        alert_event: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Extracts real security state from live subsystem telemetry and computes RL decision.
        """
        try:
            # 1. Gather live telemetry without blocking
            t_stats = packet_capture.get_latest_stats()
            ai_pred = ai_prediction or ai_engine.latest_result
            active_atk = await get_active_attack()
            devs = await get_all_devices()

            from services.response_engine import response_engine
            def_state = response_engine.get_config()

            # 2. Extract normalized real security state
            sec_state = extract_rl_state(
                ai_prediction=ai_pred,
                traffic_stats=t_stats,
                active_attack=active_atk,
                devices=devs,
                defense_state=def_state
            )

            # 3. Perform safe RL inference
            decision = rl_inference_engine.infer(sec_state)

            # 4. Action Execution Gate
            action_idx = decision["action_id"]
            target_ip = decision["target_ip"]
            response_action = decision["response_engine_action"]
            executed = False
            response_result = "Simulated (Dry-Run)"

            if self.dry_run:
                response_result = "Recommended Only (Dry-Run Mode Active)"
            elif not self.auto_response_enabled:
                response_result = "Standby (Auto-Response Disabled)"
            elif action_idx not in self.allowed_actions:
                response_result = f"Blocked by Allowlist Safety Gate (Action {decision['action_name']} not in allowlist)"
            elif response_action and response_action != "log_only" and target_ip:
                # Real Execution through validated Response Engine
                res = await response_engine.execute_action(
                    action_type=response_action,
                    target_ip=target_ip,
                    rule_name=f"RL Adaptive Response ({decision['action_name']})",
                    executed_by=f"RL Policy v{decision['policy_version']}"
                )
                executed = True
                response_result = res.get("status", "Executed")

            decision["executed"] = executed
            decision["response_result"] = response_result
            self.latest_decision = decision

            # 5. Persist decision to DB
            try:
                await insert_rl_decision(
                    timestamp=decision["timestamp"],
                    state_json=json.dumps(sec_state.to_dict()),
                    action_id=decision["action_id"],
                    action_name=decision["action_name"],
                    action_confidence=decision["confidence"],
                    expected_reward=decision["expected_reward"],
                    target_ip=decision["target_ip"],
                    attacker_ip=decision["attacker_ip"],
                    victim_ip=decision["victim_ip"],
                    attack_type=decision["attack_type"],
                    threat_score=decision["threat_score"],
                    anomaly_score=decision["anomaly_score"],
                    response_result=response_result,
                    explainability_json=json.dumps(decision["explainability"]),
                    policy_version=decision["policy_version"],
                    mode=decision["mode"]
                )
            except Exception as e:
                pass

            # 6. Broadcast to WebSocket subscribers
            for callback in self._subscribers:
                try:
                    await callback(decision)
                except Exception:
                    pass

            return decision

        except Exception as e:
            await log_manager.log("RLService", "ERROR", f"RL evaluation failed safely: {str(e)}")
            return {"status": "error", "message": str(e)}

    async def trigger_training(self, timesteps: int = 25000) -> Dict[str, Any]:
        """Triggers asynchronous PPO training task."""
        if self.is_training:
            return {"status": "busy", "message": "Training already in progress"}

        self.is_training = True
        await log_manager.log("RLService", "INFO", f"Starting PPO Adaptive Defense Training ({timesteps} timesteps)...")

        def _train():
            trainer = PPOTrainer()
            meta = trainer.train(total_timesteps=timesteps)
            return meta

        loop = asyncio.get_running_loop()
        try:
            meta = await loop.run_in_executor(None, _train)
            rl_inference_engine.reload_policy()
            self.is_training = False
            await log_manager.log("RLService", "INFO", f"RL Model Training Complete. Policy v{rl_inference_engine.policy.version} loaded.")

            # Trigger automated evaluation
            asyncio.create_task(self.trigger_evaluation())
            return {"status": "success", "metadata": meta}
        except Exception as e:
            self.is_training = False
            await log_manager.log("RLService", "ERROR", f"RL Training failed: {str(e)}")
            return {"status": "error", "message": str(e)}

    async def trigger_evaluation(self, episodes_per_scenario: int = 15) -> Dict[str, Any]:
        """Benchmarks trained RL policy against rule-based baseline."""
        if self.is_evaluating:
            return {"status": "busy", "message": "Evaluation already in progress"}

        self.is_evaluating = True
        await log_manager.log("RLService", "INFO", "Evaluating RL Defense Policy vs Rule-Based Baseline...")

        def _eval():
            return evaluate_agent(rl_inference_engine.policy, episodes_per_scenario=episodes_per_scenario)

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, _eval)
            self.is_evaluating = False

            rl_p = results["rl_performance"]
            base_p = results["baseline_performance"]

            # Store in DB
            await insert_rl_evaluation(
                timestamp=results["timestamp"],
                policy_version=results["policy_version"],
                episodes=results["total_test_episodes"],
                rl_avg_reward=rl_p["average_reward"],
                rule_avg_reward=base_p["average_reward"],
                rl_mitigation_rate=rl_p["attack_mitigation_rate"],
                rule_mitigation_rate=base_p["attack_mitigation_rate"],
                rl_fp_rate=rl_p["false_positive_rate"],
                rule_fp_rate=base_p["false_positive_rate"],
                reward_improvement=results["reward_improvement"],
                disruption_reduction=results["disruption_reduction"],
                metrics_json=json.dumps(results)
            )

            await log_manager.log(
                "RLService", "INFO",
                f"RL Benchmark Complete: Avg Reward RL={rl_p['average_reward']} vs Rule={base_p['average_reward']} (Disruption Reduction: {results['disruption_reduction']}%)"
            )
            return {"status": "success", "evaluation": results}
        except Exception as e:
            self.is_evaluating = False
            await log_manager.log("RLService", "ERROR", f"RL Evaluation failed: {str(e)}")
            return {"status": "error", "message": str(e)}


# Global singleton
rl_service = RLService()
