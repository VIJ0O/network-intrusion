"""
Reinforcement Learning Package for Adaptive Network Intrusion Response.
Provides state representations, action mappings, configurable rewards, Gymnasium simulation environment,
PPO training pipeline, evaluation baseline comparison, and safe live inference.
"""

from rl.state import SecurityState, extract_rl_state, STATE_DIM, FEATURE_LABELS
from rl.actions import (
    RLAction,
    ACTION_NAMES,
    ACTION_DESCRIPTIONS,
    ACTION_TO_RESPONSE_MAP,
    ACTION_COUNT
)
from rl.rewards import RewardConfig, calculate_reward
from rl.environment import NetworkSecurityEnv
from rl.policy import ActorCriticPolicy, PPOTrainer
from rl.inference import RLInferenceEngine, rl_inference_engine

__all__ = [
    "SecurityState",
    "extract_rl_state",
    "STATE_DIM",
    "FEATURE_LABELS",
    "RLAction",
    "ACTION_NAMES",
    "ACTION_DESCRIPTIONS",
    "ACTION_TO_RESPONSE_MAP",
    "ACTION_COUNT",
    "RewardConfig",
    "calculate_reward",
    "NetworkSecurityEnv",
    "ActorCriticPolicy",
    "PPOTrainer",
    "RLInferenceEngine",
    "rl_inference_engine"
]
