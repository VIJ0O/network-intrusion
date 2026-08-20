"""
FastAPI Router for Reinforcement Learning Adaptive Defense System.
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from services.rl_service import rl_service
from database import get_rl_decisions, get_latest_rl_evaluation

router = APIRouter(prefix="/api/rl", tags=["Reinforcement Learning"])


class RLConfigUpdate(BaseModel):
    dry_run: Optional[bool] = None
    auto_response_enabled: Optional[bool] = None
    allowed_actions: Optional[List[int]] = None


class RLTrainRequest(BaseModel):
    timesteps: int = 25000


@router.get("/status")
async def get_rl_status():
    """Returns RL policy status, latest decision, and safety configuration."""
    return rl_service.get_status()


@router.get("/decisions")
async def get_decisions(limit: int = Query(50, ge=1, le=200)):
    """Fetches recent RL decision history with explainability context."""
    return await get_rl_decisions(limit=limit)


@router.get("/evaluation")
async def get_evaluation():
    """Retrieves the latest benchmark evaluation comparing RL vs Rule-Based baseline."""
    eval_record = await get_latest_rl_evaluation()
    if not eval_record:
        # If no DB record yet, run a fast evaluation
        res = await rl_service.trigger_evaluation(episodes_per_scenario=10)
        return res.get("evaluation", {})
    return eval_record


@router.post("/train")
async def trigger_training(req: RLTrainRequest = Body(default=RLTrainRequest())):
    """Triggers background PPO training on simulation environment."""
    return await rl_service.trigger_training(timesteps=req.timesteps)


@router.post("/evaluate")
async def trigger_evaluation(episodes: int = Query(15, ge=5, le=50)):
    """Triggers comparative benchmark evaluation."""
    return await rl_service.trigger_evaluation(episodes_per_scenario=episodes)


@router.post("/config")
async def update_rl_config(cfg: RLConfigUpdate):
    """Updates safety gates: Dry-Run mode, Controlled Auto-Response, and Allowed Actions."""
    updated = rl_service.set_config(
        dry_run=cfg.dry_run,
        auto_response_enabled=cfg.auto_response_enabled,
        allowed_actions=cfg.allowed_actions
    )
    return {"status": "success", "config": updated}


@router.post("/infer-now")
async def trigger_immediate_inference():
    """Forces an immediate evaluation of the current live network state."""
    decision = await rl_service.evaluate_live_state()
    return decision
