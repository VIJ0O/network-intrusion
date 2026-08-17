"""
Logs router — Returns recent log entries from the database.
"""

from fastapi import APIRouter, Query
from typing import Optional, List
from models.schemas import LogEntry
from database import get_logs

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.get("", response_model=List[LogEntry])
async def get_system_logs(
    limit: int = Query(50, ge=1, le=500),
    source: Optional[str] = Query(None, description="Filter logs by source"),
    level: Optional[str] = Query(None, description="Filter logs by level")
):
    """Query recent logs from database."""
    logs = await get_logs(limit=limit, source=source, level=level)
    return [LogEntry(**l) for l in logs]
