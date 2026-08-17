"""
Real system metrics service using psutil.
Monitors CPU, RAM, Disk, Network interfaces, and active processes.
"""

import asyncio
import time
from datetime import datetime
from typing import List, Dict, Callable, Optional
import psutil
from services.log_manager import log_manager


class SystemMetricsService:
    """Monitors real operating system resource utilization and statistics."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._interval = 2  # Monitor every 2 seconds
        self._subscribers: List[Callable] = []
        self._start_time = time.time()
        
        self.current_metrics = {
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": 0.0,
            "cpu_per_core": [],
            "ram_total_gb": 0.0,
            "ram_used_gb": 0.0,
            "ram_percent": 0.0,
            "disk_total_gb": 0.0,
            "disk_used_gb": 0.0,
            "disk_percent": 0.0,
            "net_bytes_sent": 0,
            "net_bytes_recv": 0,
            "net_packets_sent": 0,
            "net_packets_recv": 0,
            "process_count": 0,
            "backend_uptime_seconds": 0.0
        }

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True
        asyncio.ensure_future(self._monitor_loop())
        await log_manager.log("SystemMetrics", "INFO", "System metrics monitoring service started")

    async def stop(self):
        self.is_running = False
        await log_manager.log("SystemMetrics", "INFO", "System metrics monitoring service stopped")

    async def _monitor_loop(self):
        # Initial network counters to calculate rates if needed
        last_net = psutil.net_io_counters()
        
        while self.is_running:
            try:
                # CPU
                cpu = psutil.cpu_percent(interval=None)
                cpu_cores = psutil.cpu_percent(interval=None, percpu=True)
                
                # RAM
                ram = psutil.virtual_memory()
                ram_total = ram.total / (1024 ** 3)
                ram_used = ram.used / (1024 ** 3)
                ram_pct = ram.percent
                
                # Disk
                disk = psutil.disk_usage('/')
                disk_total = disk.total / (1024 ** 3)
                disk_used = disk.used / (1024 ** 3)
                disk_pct = disk.percent
                
                # Network I/O
                net = psutil.net_io_counters()
                
                # Process count
                process_count = len(psutil.pids())
                
                # Uptime
                uptime = time.time() - self._start_time

                self.current_metrics = {
                    "timestamp": datetime.now().isoformat(),
                    "cpu_percent": cpu,
                    "cpu_per_core": cpu_cores,
                    "ram_total_gb": round(ram_total, 2),
                    "ram_used_gb": round(ram_used, 2),
                    "ram_percent": ram_pct,
                    "disk_total_gb": round(disk_total, 2),
                    "disk_used_gb": round(disk_used, 2),
                    "disk_percent": disk_pct,
                    "net_bytes_sent": net.bytes_sent,
                    "net_bytes_recv": net.bytes_recv,
                    "net_packets_sent": net.packets_sent,
                    "net_packets_recv": net.packets_recv,
                    "process_count": process_count,
                    "backend_uptime_seconds": round(uptime, 1)
                }

                # Broadcast metrics
                for callback in self._subscribers:
                    try:
                        await callback(self.current_metrics)
                    except Exception:
                        pass

            except Exception as e:
                await log_manager.log("SystemMetrics", "ERROR", f"Error getting metrics: {e}")
                
            await asyncio.sleep(self._interval)


# Global singleton
system_metrics = SystemMetricsService()
