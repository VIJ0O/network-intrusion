"""
Dashboard router — Aggregated status metrics from real services.
"""

from fastapi import APIRouter
from models.schemas import DashboardStats
from services.packet_capture import packet_capture
from services.ai_engine import ai_engine
from services.system_metrics import system_metrics
from database import get_online_device_count, get_unread_alert_count

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("", response_model=DashboardStats)
async def dashboard_overview():
    """Get active metrics collected directly from Scapy, PyTorch, and psutil."""
    stats = packet_capture.current_stats
    ai_res = ai_engine.latest_result
    
    online_devices = await get_online_device_count()
    unread_alerts = await get_unread_alert_count()
    
    threat_score = ai_res.get("threat_probability", 0.0)
    ai_conf = ai_res.get("confidence", 95.0)
    ai_status = ai_res.get("model_status", "Offline")
    
    # Calculate status label
    if not packet_capture.is_online:
        sys_status = "Offline"
        net_status = "Offline"
    elif threat_score >= 75.0:
        sys_status = "Critical"
        net_status = "Under Attack"
    elif threat_score >= 50.0:
        sys_status = "Warning"
        net_status = "Anomalous Traffic"
    else:
        sys_status = "Safe"
        net_status = "Operational"

    # Bandwidth calculation: bytes/s to Mbps
    bps = stats.get("bytes_per_second", 0)
    bandwidth_mbps = round((bps * 8) / (1024 ** 2), 2)

    return DashboardStats(
        system_status=sys_status,
        threat_score=threat_score,
        ai_confidence=ai_conf,
        ai_status=ai_status,
        connected_devices=online_devices,
        active_alerts=unread_alerts,
        network_status=net_status,
        packets_per_second=stats.get("packets_per_second", 0),
        bandwidth_mbps=bandwidth_mbps,
        uptime_seconds=system_metrics.current_metrics.get("backend_uptime_seconds", 0.0),
        capture_online=packet_capture.is_online,
        prediction_online=ai_engine.is_trained
    )
