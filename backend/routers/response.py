"""
Response Router — Configurable Active Defense, Rules, and Firewall Execution API.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict
from models.schemas import (
    ResponseRule,
    ResponseRuleCreate,
    MitigationAction,
    ResponseConfig,
    ExecuteActionRequest
)
from database import (
    get_response_rules,
    insert_response_rule,
    toggle_response_rule,
    delete_response_rule,
    get_mitigation_actions
)
from services.response_engine import response_engine

router = APIRouter(prefix="/api/response", tags=["Response Engine"])


@router.get("/config", response_model=ResponseConfig)
async def get_config():
    """Get active defense mode and firewall status."""
    return ResponseConfig(**response_engine.get_config())


@router.post("/config")
async def update_config(mode: str = Query(..., description="defense mode: auto, semi_auto, dry_run"), firewall_enabled: bool = True):
    """Update active defense configuration mode."""
    if mode not in ["auto", "semi_auto", "dry_run"]:
        raise HTTPException(status_code=400, detail="Invalid defense mode. Must be auto, semi_auto, or dry_run.")
    response_engine.set_config(mode=mode, firewall_enabled=firewall_enabled)
    return {"status": "updated", "config": response_engine.get_config()}


@router.get("/rules", response_model=List[ResponseRule])
async def list_rules():
    """Get all configured active response rules."""
    rules = await get_response_rules()
    return [ResponseRule(**r) for r in rules]


@router.post("/rules", response_model=Dict)
async def create_rule(rule: ResponseRuleCreate):
    """Create a new automated response rule."""
    rule_id = await insert_response_rule(
        name=rule.name,
        trigger_type=rule.trigger_type,
        trigger_value=rule.trigger_value,
        action_type=rule.action_type,
        enabled=rule.enabled
    )
    return {"status": "created", "rule_id": rule_id}


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: int, enabled: bool):
    """Enable or disable a specific response rule."""
    await toggle_response_rule(rule_id, enabled)
    return {"status": "updated", "rule_id": rule_id, "enabled": enabled}


@router.delete("/rules/{rule_id}")
async def remove_rule(rule_id: int):
    """Delete a response rule."""
    await delete_response_rule(rule_id)
    return {"status": "deleted", "rule_id": rule_id}


@router.get("/actions", response_model=List[MitigationAction])
async def list_actions(limit: int = Query(50, ge=1, le=200)):
    """Get audit log history of executed mitigation actions."""
    actions = await get_mitigation_actions(limit=limit)
    return [MitigationAction(**a) for a in actions]


@router.post("/execute", response_model=MitigationAction)
async def execute_manual_action(req: ExecuteActionRequest):
    """Manually trigger a defensive action (block_ip, unblock_ip, isolate_device)."""
    res = await response_engine.execute_action(
        action_type=req.action_type,
        target_ip=req.target_ip,
        rule_name="Manual Analyst Action",
        executed_by="Security Analyst"
    )
    return MitigationAction(**res)
