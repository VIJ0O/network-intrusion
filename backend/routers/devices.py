"""
Devices router — Returns real-time discovered subnet hosts.
"""

from fastapi import APIRouter, HTTPException
from models.schemas import Device
from database import get_all_devices, get_device_by_id
from typing import List

router = APIRouter(prefix="/api/devices", tags=["Devices"])


@router.get("", response_model=List[Device])
async def list_devices():
    """List all dynamically scanned network hosts."""
    devices = await get_all_devices()
    # map row dicts to Pydantic models
    return [Device(**d) for d in devices]


@router.get("/{device_id}", response_model=Device)
async def device_detail(device_id: str):
    """Get single device details by database ID."""
    device = await get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return Device(**device)
