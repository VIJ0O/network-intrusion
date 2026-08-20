"""
WebSocket stream controller.
Broadcasts real-time events on multiple channels to connected frontends.
"""

import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from services.packet_capture import packet_capture
from services.system_metrics import system_metrics
from services.ai_engine import ai_engine
from services.alert_engine import alert_engine
from services.log_manager import log_manager
from typing import List, Set, Dict

router = APIRouter()


class WebSocketManager:
    """Manages active socket clients for broadcasting updates."""

    def __init__(self):
        # channel_name -> set of sockets
        self.channels: Dict[str, Set[WebSocket]] = {
            "traffic": set(),
            "metrics": set(),
            "topology": set(),
            "alerts": set(),
            "logs": set(),
            "predictions": set(),
            "response": set(),
            "rl": set()
        }

    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel in self.channels:
            self.channels[channel].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.channels and websocket in self.channels[channel]:
            self.channels[channel].remove(websocket)

    async def broadcast(self, channel: str, data: dict):
        """Broadcasts data to all subscribers of a specific channel."""
        if channel not in self.channels or not self.channels[channel]:
            return

        # Prepare JSON string once
        payload = json.dumps(data)
        
        # Gather sends to run in parallel
        await asyncio.gather(*(
            self._send_payload(ws, payload, channel)
            for ws in list(self.channels[channel])
        ), return_exceptions=True)

    async def _send_payload(self, ws: WebSocket, payload: str, channel: str):
        try:
            await ws.send_text(payload)
        except Exception:
            # Client disconnected/failed, remove it
            self.disconnect(ws, channel)


# Global singleton
ws_manager = WebSocketManager()


# ────────────────────────────────────────────
# Event Listeners to Broadcast
# ────────────────────────────────────────────

async def on_traffic_stats(stats: dict):
    await ws_manager.broadcast("traffic", stats)


async def on_system_metrics(metrics: dict):
    await ws_manager.broadcast("metrics", metrics)


async def on_ai_prediction(pred: dict):
    await ws_manager.broadcast("predictions", pred)


async def on_alert_or_attack(event_type: str, data: dict):
    """Correlator listener to push security events."""
    if event_type == "alert":
        await ws_manager.broadcast("alerts", data)
    elif event_type == "attack":
        # Attack status updates also trigger topology updates
        await ws_manager.broadcast("alerts", {"type": "attack_update", "data": data})


async def on_log_message(log_entry: dict):
    await ws_manager.broadcast("logs", log_entry)


async def on_device_discovery_update(devices: list):
    try:
        from routers.topology import get_network_topology
        topo_data = await get_network_topology()
        await ws_manager.broadcast("topology", topo_data.model_dump())
    except Exception:
        pass


# Initialize event callbacks linking services to WebSocket hub
def link_services_to_websocket():
    from services.response_engine import response_engine
    from services.device_discovery import device_discovery
    from services.rl_service import rl_service
    packet_capture.subscribe(lambda stats: asyncio.create_task(on_traffic_stats(stats)))
    system_metrics.subscribe(lambda metrics: asyncio.create_task(on_system_metrics(metrics)))
    ai_engine.subscribe(lambda pred: asyncio.create_task(on_ai_prediction(pred)))
    alert_engine.subscribe(lambda ev_type, data: asyncio.create_task(on_alert_or_attack(ev_type, data)))
    log_manager.subscribe(lambda entry: asyncio.create_task(on_log_message(entry)))
    response_engine.subscribe(lambda action: asyncio.create_task(ws_manager.broadcast("response", action)))
    device_discovery.subscribe(lambda devs: asyncio.create_task(on_device_discovery_update(devs)))
    rl_service.subscribe(lambda decision: asyncio.create_task(ws_manager.broadcast("rl", decision)))


# ────────────────────────────────────────────
# WebSocket Endpoint Routers
# ────────────────────────────────────────────

@router.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    """Streams live packet counters, bandwidth rate, and top talkers."""
    await ws_manager.connect(websocket, "traffic")
    try:
        while True:
            # Keep connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "traffic")


@router.websocket("/ws/metrics")
async def websocket_metrics(websocket: WebSocket):
    """Streams live operating system resource logs."""
    await ws_manager.connect(websocket, "metrics")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "metrics")


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Streams live security alarms and mitigation notifications."""
    await ws_manager.connect(websocket, "alerts")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "alerts")


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """Streams live developer debug and processing output."""
    await ws_manager.connect(websocket, "logs")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "logs")


@router.websocket("/ws/predictions")
async def websocket_predictions(websocket: WebSocket):
    """Streams live machine learning threat score computations."""
    await ws_manager.connect(websocket, "predictions")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "predictions")


@router.websocket("/ws/topology")
async def websocket_topology(websocket: WebSocket):
    """Streams live network topology map updates."""
    await ws_manager.connect(websocket, "topology")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "topology")


@router.websocket("/ws/response")
async def websocket_response(websocket: WebSocket):
    """Streams live active defense mitigation executions."""
    await ws_manager.connect(websocket, "response")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "response")


@router.websocket("/ws/rl")
async def websocket_rl(websocket: WebSocket):
    """Streams live reinforcement learning adaptive defense decisions and explainability."""
    await ws_manager.connect(websocket, "rl")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "rl")


