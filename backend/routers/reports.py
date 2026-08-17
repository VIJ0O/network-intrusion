"""
Reports router — Aggregates network statistics and generates CSV exports.
"""

import csv
import io
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from models.schemas import ReportSummary
from database import get_report_summary, get_attacks

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/summary", response_model=ReportSummary)
async def report_summary():
    """Get system-wide metrics and attack distributions from the DB."""
    summary = await get_report_summary()
    return ReportSummary(**summary)


@router.get("/export")
async def export_csv():
    """Export attack logs as a downloadable CSV file."""
    attacks = await get_attacks(limit=200)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Attack Type", "Attacker IP", "Attacker Device",
        "Victim IP", "Victim Device", "Start Time", "End Time",
        "Status", "Severity", "Packets Involved"
    ])

    for atk in attacks:
        writer.writerow([
            atk.get("id"),
            atk.get("attack_type"),
            atk.get("attacker_ip"),
            atk.get("attacker_device"),
            atk.get("victim_ip"),
            atk.get("victim_device"),
            atk.get("start_time"),
            atk.get("end_time") or "",
            atk.get("status"),
            atk.get("severity"),
            atk.get("packets_involved")
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=nids_attack_history.csv"}
    )
