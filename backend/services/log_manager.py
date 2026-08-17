"""
Centralized log manager for the NIDS Dashboard.
Collects logs from all subsystems, stores in DB, and broadcasts via WebSocket.
"""

import asyncio
from datetime import datetime
from typing import List, Dict, Callable, Optional
from database import insert_log, insert_log_sync, get_logs


class LogManager:
    """Singleton log manager that stores and broadcasts log entries."""

    def __init__(self):
        self._subscribers: List[Callable] = []
        self._recent_logs: List[Dict] = []
        self._max_recent = 200

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def log(self, source: str, level: str, message: str):
        """Async log entry — stores in DB and notifies subscribers."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "level": level,
            "message": message
        }

        # Store in DB
        try:
            await insert_log(source, level, message)
        except Exception:
            pass  # Don't crash if DB write fails

        # Keep in memory for fast access
        self._recent_logs.append(entry)
        if len(self._recent_logs) > self._max_recent:
            self._recent_logs = self._recent_logs[-self._max_recent:]

        # Broadcast to WebSocket subscribers
        for callback in self._subscribers:
            try:
                await callback(entry)
            except Exception:
                pass

    def log_sync(self, source: str, level: str, message: str):
        """Synchronous log for use in non-async code (threads)."""
        try:
            insert_log_sync(source, level, message)
        except Exception:
            pass

    async def get_recent(self, limit: int = 100, source: str = None, level: str = None) -> List[Dict]:
        """Get recent logs from database."""
        return await get_logs(limit=limit, source=source, level=level)

    @property
    def recent_in_memory(self) -> List[Dict]:
        return list(self._recent_logs)


# Global singleton
log_manager = LogManager()
