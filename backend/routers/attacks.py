"""
Attacks router — Returns active or resolved attack incident summaries.
"""

from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Union
from models.schemas import Attack
from database import get_attacks
from services.alert_engine import alert_engine

router = APIRouter(prefix="/api/attacks", tags=["Attacks"])


@router.get("", response_model=List[Attack])
async def attack_history(limit: int = Query(20, ge=1, le=100)):
    """Get recent attack incident logs."""
    history = await get_attacks(limit=limit)
    return [Attack(**a) for a in history]


@router.get("/current")
async def current_attack() -> Union[Attack, Dict]:
    """Get details of the currently active attack, if one is running."""
    atk = alert_engine.get_current_attack()
    if atk:
        return Attack(**atk)
    return {"active": False, "message": "No active attack detected"}
