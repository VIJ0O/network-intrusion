"""
Alerts router — Retrieves security alerts from the SQLite database.
"""

from fastapi import APIRouter, Query
from typing import Optional, List
from models.schemas import Alert
from database import get_alerts, clear_all_alerts, resolve_alert

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("", response_model=List[Alert])
async def list_alerts(
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, description="Filter by severity: Info, Warning, High, Critical")
):
    """List generated security events and warnings."""
    alerts = await get_alerts(limit=limit, severity=severity)
    return [Alert(**a) for a in alerts]


@router.post("/clear-all")
async def clear_alerts():
    """Clear all unread alerts and resolve active attacks."""
    from services.alert_engine import alert_engine
    if alert_engine.active_attack_db_id:
        alert_engine.active_attack_db_id = None
        alert_engine.active_attack_info = None
    await clear_all_alerts()
    return {"status": "cleared", "message": "All alerts marked as resolved."}


@router.post("/{alert_id}/resolve")
async def resolve_single_alert(alert_id: int):
    """Mark a specific alert as resolved."""
    await resolve_alert(alert_id)
    return {"status": "resolved", "alert_id": alert_id}


@router.post("/simulate-attack")
async def simulate_attack(attack_type: str = Query("SYN Flood")):
    """Triggers a real attack situation across AI engine, database, and 3D topology map."""
    from services.alert_engine import alert_engine
    from services.ai_engine import ai_engine
    from database import insert_alert, insert_attack, get_all_devices
    from datetime import datetime

    devices = await get_all_devices()
    ips = [d["ip_address"] for d in devices if d["ip_address"] not in ["0.0.0.0", "127.0.0.1"]]

    attacker_ip = ips[-1] if len(ips) > 1 else "192.168.0.220"
    victim_ip = ips[0] if len(ips) > 0 else "192.168.0.114"

    # 1. Update AI engine state
    ai_engine.latest_result = {
        "timestamp": datetime.now().isoformat(),
        "threat_probability": 100.0,
        "confidence": 98.5,
        "predicted_attack_type": attack_type,
        "expected_severity": "Critical",
        "reason": f"CRITICAL: High-volume anomalous packet burst ({attack_type}) detected from {attacker_ip} targeting {victim_ip}.",
        "model_status": "Active",
        "anomaly_score": 0.85,
        "forecast_10s": 100.0,
        "forecast_30s": 100.0,
        "forecast_60s": 95.0,
        "trend": "rising"
    }

    # 2. Insert Alert into SQLite
    alert_id = await insert_alert(
        severity="Critical",
        title=f"CRITICAL INTRUSION: {attack_type}",
        message=f"Real-time AI engine flagged malicious traffic vector from {attacker_ip} ➔ {victim_ip}.",
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        attack_type=attack_type,
        threat_score=100.0,
        confidence=98.5,
        recommended_action="Active Defense Triggered: Auto-block offending IP and isolate socket path.",
        action_taken="IP Block Rule Dispatched"
    )

    # 3. Create active attack record
    atk_id = await insert_attack(
        attack_type=attack_type,
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        attacker_device="Adversary Host",
        victim_device="Target Workstation",
        severity="Critical",
        description=f"Active {attack_type} vector in progress"
    )

    alert_engine.active_attack_db_id = atk_id
    alert_engine.active_attack_info = {
        "id": atk_id,
        "start_time": datetime.now().isoformat(),
        "attack_type": attack_type,
        "attacker_ip": attacker_ip,
        "victim_ip": victim_ip,
        "severity": "Critical",
        "status": "Active",
        "packets_involved": 14500,
        "description": f"Active {attack_type} in progress"
    }

    return {
        "status": "triggered",
        "alert_id": alert_id,
        "attack_id": atk_id,
        "attack_type": attack_type,
        "attacker_ip": attacker_ip,
        "victim_ip": victim_ip
    }

