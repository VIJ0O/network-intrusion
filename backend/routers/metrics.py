"""
Metrics router — Returns current OS metrics.
"""

from fastapi import APIRouter
from models.schemas import SystemMetrics
from services.system_metrics import system_metrics

router = APIRouter(prefix="/api/metrics", tags=["Metrics"])


@router.get("", response_model=SystemMetrics)
async def get_system_metrics():
    """Retrieve actual host resources usage from psutil."""
    return SystemMetrics(**system_metrics.current_metrics)
