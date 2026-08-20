"""
PyTorch Actor-Critic PPO Implementation for Network Intrusion Response.
Implements Proximal Policy Optimization with GAE, entropy regularization, and value clipping.
"""

import os
import json
import time
import torch
import torch.nn as nn
import torch.optim as optim
from torch.distributions import Categorical
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

from rl.state import STATE_DIM
from rl.actions import ACTION_COUNT, ACTION_NAMES
from rl.environment import NetworkSecurityEnv
from rl.rewards import RewardConfig

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "rl_policy.pt")
META_PATH = os.path.join(MODEL_DIR, "rl_meta.json")


class ActorCriticNetwork(nn.Module):
    """Deep Actor-Critic architecture with shared representation layer and orthogonal initialization."""

    def __init__(self, state_dim: int = STATE_DIM, action_dim: int = ACTION_COUNT, hidden_dim: int = 64):
        super(ActorCriticNetwork, self).__init__()

        # Shared feature extractor
        self.shared = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.Tanh()
        )

        # Actor head: output action logits
        self.actor = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, action_dim)
        )

        # Critic head: output scalar state-value estimate V(s)
        self.critic = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1)
        )

        # Apply orthogonal initialization (PPO best practice)
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=np.sqrt(2))
                nn.init.constant_(m.bias, 0.0)
        # Actor head gets small gain to encourage initial exploration
        for m in self.actor.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=0.01)
        # Critic head
        for m in self.critic.modules():
            if isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=1.0)

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        features = self.shared(state)
        logits = self.actor(features)
        value = self.critic(features)
        return logits, value

    def get_action(self, state: torch.Tensor, deterministic: bool = False) -> Tuple[int, float, float, np.ndarray]:
        """Samples or selects best action from state tensor."""
        features = self.shared(state)
        logits = self.actor(features)
        value = self.critic(features).item()
        
        probs = torch.softmax(logits, dim=-1)
        dist = Categorical(probs)

        if deterministic:
            action_idx = torch.argmax(probs, dim=-1).item()
        else:
            action_idx = dist.sample().item()

        log_prob = dist.log_prob(torch.tensor(action_idx)).item()
        probs_np = probs.detach().cpu().numpy().flatten()
        return action_idx, log_prob, value, probs_np

    def evaluate_actions(self, states: torch.Tensor, actions: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Evaluates batch of states and actions for PPO gradient step."""
        features = self.shared(states)
        logits = self.actor(features)
        values = self.critic(features).squeeze(-1)

        dist = Categorical(logits=logits)
        log_probs = dist.log_prob(actions)
        entropy = dist.entropy()
        return values, log_probs, entropy


class ActorCriticPolicy:
    """Wrapper managing policy lifecycle, inference, and serialization."""

    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.meta_path = META_PATH
        self.network = ActorCriticNetwork()
        self.is_trained = False
        self.version = "1.0.0"
        self.training_metadata: Dict[str, Any] = {}
        self.load()

    def save(self, metadata: Optional[Dict] = None):
        """Persists weights and metadata to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        torch.save(self.network.state_dict(), self.model_path)
        self.is_trained = True

        meta = {
            "version": self.version,
            "saved_at": datetime.now().isoformat(),
            "state_dim": STATE_DIM,
            "action_count": ACTION_COUNT,
            **(metadata or {})
        }
        self.training_metadata = meta
        with open(self.meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    def load(self) -> bool:
        """Loads trained weights if available."""
        if os.path.exists(self.model_path):
            try:
                self.network.load_state_dict(torch.load(self.model_path, map_location=torch.device('cpu'), weights_only=True))
                self.network.eval()
                self.is_trained = True

                if os.path.exists(self.meta_path):
                    with open(self.meta_path, "r") as f:
                        self.training_metadata = json.load(f)
                        self.version = self.training_metadata.get("version", "1.0.0")
                return True
            except Exception as e:
                self.is_trained = False
                return False
        self.is_trained = False
        return False

    def predict(self, state_vector: np.ndarray, deterministic: bool = True) -> Tuple[int, float, float, np.ndarray]:
        """Performs forward pass inference on a normalized state vector."""
        state_t = torch.FloatTensor(state_vector).unsqueeze(0)
        self.network.eval()
        with torch.no_grad():
            action, log_prob, value, probs = self.network.get_action(state_t, deterministic=deterministic)
        return action, log_prob, value, probs


class PPOTrainer:
    """Trainer implementing Proximal Policy Optimization for NetworkSecurityEnv."""

    def __init__(
        self,
        env: Optional[NetworkSecurityEnv] = None,
        lr: float = 3e-4,
        gamma: float = 0.99,
        gae_lambda: float = 0.95,
        clip_eps: float = 0.2,
        entropy_coef: float = 0.01,
        value_loss_coef: float = 0.5,
        max_grad_norm: float = 0.5
    ):
        self.env = env or NetworkSecurityEnv()
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.clip_eps = clip_eps
        self.entropy_coef = entropy_coef
        self.value_loss_coef = value_loss_coef
        self.max_grad_norm = max_grad_norm

        self.policy = ActorCriticPolicy()
        self.optimizer = optim.Adam(self.policy.network.parameters(), lr=lr)

    def collect_rollout(self, steps_per_rollout: int = 1024) -> Dict[str, torch.Tensor]:
        """Runs policy in environment to collect a trajectory buffer."""
        states, actions, log_probs, rewards, values, dones = [], [], [], [], [], []

        obs, _ = self.env.reset()
        for _ in range(steps_per_rollout):
            obs_t = torch.FloatTensor(obs).unsqueeze(0)
            with torch.no_grad():
                action, log_prob, value, _ = self.policy.network.get_action(obs_t, deterministic=False)

            next_obs, reward, terminated, truncated, _ = self.env.step(action)
            done = terminated or truncated

            states.append(obs)
            actions.append(action)
            log_probs.append(log_prob)
            rewards.append(reward)
            values.append(value)
            dones.append(done)

            obs = next_obs
            if done:
                obs, _ = self.env.reset()

        # Compute GAE Advantages and discounted Returns
        with torch.no_grad():
            last_val = self.policy.network.critic(self.policy.network.shared(torch.FloatTensor(obs).unsqueeze(0))).item()

        scaled_rewards = [r * 0.1 for r in rewards]
        advantages = np.zeros(len(scaled_rewards), dtype=np.float32)
        last_gae_lam = 0.0
        for t in reversed(range(len(scaled_rewards))):
            next_non_terminal = 1.0 - float(dones[t])
            next_value = last_val if t == len(scaled_rewards) - 1 else values[t + 1]
            delta = scaled_rewards[t] + self.gamma * next_value * next_non_terminal - values[t]
            advantages[t] = last_gae_lam = delta + self.gamma * self.gae_lambda * next_non_terminal * last_gae_lam

        returns = advantages + np.array(values, dtype=np.float32)

        return {
            "states": torch.FloatTensor(np.array(states)),
            "actions": torch.LongTensor(actions),
            "log_probs": torch.FloatTensor(log_probs),
            "returns": torch.FloatTensor(returns),
            "advantages": torch.FloatTensor(advantages)
        }

    def train(
        self,
        total_timesteps: int = 15000,
        rollout_steps: int = 512,
        ppo_epochs: int = 4,
        batch_size: int = 64
    ) -> Dict[str, Any]:
        """Executes complete PPO training loop on simulation environment."""
        start_time = time.time()
        num_updates = max(1, total_timesteps // rollout_steps)
        training_history = []

        total_steps = 0
        for update in range(1, num_updates + 1):
            rollout = self.collect_rollout(steps_per_rollout=rollout_steps)
            total_steps += rollout_steps

            states = rollout["states"]
            actions = rollout["actions"]
            old_log_probs = rollout["log_probs"]
            returns = rollout["returns"]
            advantages = rollout["advantages"]

            # Normalize advantages
            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

            dataset_size = states.size(0)
            indices = np.arange(dataset_size)

            policy_losses, value_losses, entropies = [], [], []

            for _ in range(ppo_epochs):
                np.random.shuffle(indices)
                for start_idx in range(0, dataset_size, batch_size):
                    batch_idx = indices[start_idx:start_idx + batch_size]

                    b_states = states[batch_idx]
                    b_actions = actions[batch_idx]
                    b_old_log_probs = old_log_probs[batch_idx]
                    b_returns = returns[batch_idx]
                    b_advantages = advantages[batch_idx]

                    values, new_log_probs, entropy = self.policy.network.evaluate_actions(b_states, b_actions)

                    # Ratio for PPO surrogate
                    ratios = torch.exp(new_log_probs - b_old_log_probs)

                    # Clipped surrogate objective
                    surr1 = ratios * b_advantages
                    surr2 = torch.clamp(ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * b_advantages
                    policy_loss = -torch.min(surr1, surr2).mean()

                    # Value function MSE loss
                    value_loss = nn.MSELoss()(values, b_returns)

                    # Total loss
                    loss = policy_loss + self.value_loss_coef * value_loss - self.entropy_coef * entropy.mean()

                    self.optimizer.zero_grad()
                    loss.backward()
                    nn.utils.clip_grad_norm_(self.policy.network.parameters(), self.max_grad_norm)
                    self.optimizer.step()

                    policy_losses.append(policy_loss.item())
                    value_losses.append(value_loss.item())
                    entropies.append(entropy.mean().item())

            avg_p_loss = float(np.mean(policy_losses))
            avg_v_loss = float(np.mean(value_losses))
            avg_entropy = float(np.mean(entropies))

            training_history.append({
                "update": update,
                "timesteps": total_steps,
                "policy_loss": round(avg_p_loss, 4),
                "value_loss": round(avg_v_loss, 4),
                "entropy": round(avg_entropy, 4)
            })

        duration = time.time() - start_time
        meta = {
            "total_timesteps": total_steps,
            "training_duration_seconds": round(duration, 2),
            "final_policy_loss": round(avg_p_loss, 4),
            "final_value_loss": round(avg_v_loss, 4),
            "final_entropy": round(avg_entropy, 4),
            "history": training_history[-10:]
        }
        self.policy.save(meta)
        return meta
