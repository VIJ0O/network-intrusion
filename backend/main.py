"""
Network Intrusion Detection System — Backend Main.
Handles server lifecycle, database initialization, background services, and API routing.
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Database and Logging
from database import init_database
from services.log_manager import log_manager

# Core Subsystem Services
from services.packet_capture import packet_capture
from services.device_discovery import device_discovery
from services.system_metrics import system_metrics
from services.ai_engine import ai_engine
from services.alert_engine import alert_engine
from services.response_engine import response_engine

# API Routers
from routers import (
    dashboard, devices, alerts, predictions, 
    attacks, reports, topology, metrics, logs, response
)
from websocket.stream import router as ws_router, link_services_to_websocket


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle controller: starts all real background monitors at startup."""
    # 1. Initialize SQLite Database
    init_database()
    log_manager.log_sync("System", "INFO", "SQLite database initialized successfully")
    
    # 2. Get running event loop
    loop = asyncio.get_running_loop()
    
    # 3. Link services to push WebSocket streams
    link_services_to_websocket()
    
    # 4. Start background service threads & tasks
    await log_manager.log("System", "INFO", "Launching background NDR capture and analyzer threads...")
    
    # Start packet capture (auto-detect interface)
    await packet_capture.start(loop)
    
    # Start system resources monitor
    await system_metrics.start(loop)
    
    # Start device active/passive discovery sweeps
    await device_discovery.start(loop)
    
    # Start AI prediction engine (online training on baseline)
    await ai_engine.start(loop)
    
    # Start Alert engine
    await alert_engine.start(loop)

    # Start Active Defense Response Engine
    await response_engine.start(loop)

    yield

    # Shutdown lifecycles
    await log_manager.log("System", "INFO", "Shutting down background NDR services...")
    await packet_capture.stop()
    await system_metrics.stop()
    await device_discovery.stop()
    await ai_engine.stop()
    await alert_engine.stop()
    await response_engine.stop()


app = FastAPI(
    title="NIDS Real Data NDR API",
    description="Network Detection and Response (NDR) platform API with Scapy packet captures and PyTorch anomaly classification.",
    version="2.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(dashboard.router)
app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(predictions.router)
app.include_router(attacks.router)
app.include_router(reports.router)
app.include_router(topology.router)
app.include_router(metrics.router)
app.include_router(logs.router)
app.include_router(response.router)
app.include_router(ws_router)


@app.get("/")
async def root():
    return {
        "name": "NIDS NDR API",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
        "capture_status": "online" if packet_capture.is_online else "offline / pending permissions"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "services": {
            "packet_capture": "online" if packet_capture.is_online else "offline",
            "device_discovery": "online" if device_discovery.is_running else "offline",
            "ai_engine": ai_engine.model_status,
            "system_metrics": "online" if system_metrics.is_running else "offline"
        }
    }
