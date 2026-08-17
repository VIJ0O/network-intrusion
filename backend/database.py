"""
SQLite database manager for the NIDS Dashboard.
Handles all persistent storage: packets, devices, alerts, attacks, predictions, logs, metrics.
"""

import sqlite3
import aiosqlite
import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nids.db")


def get_db_path() -> str:
    return DB_PATH


def init_database():
    """Create all tables if they don't exist. Called once at startup."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            tcp_flags TEXT,
            info TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            ip_address TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            device_type TEXT DEFAULT 'Unknown',
            status TEXT DEFAULT 'Online',
            risk_level TEXT DEFAULT 'Low',
            last_seen TEXT,
            ping_latency_ms REAL,
            os_guess TEXT,
            interface TEXT,
            first_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            attacker_ip TEXT,
            victim_ip TEXT,
            attack_type TEXT,
            threat_score REAL,
            confidence REAL,
            recommended_action TEXT,
            action_taken TEXT,
            status TEXT DEFAULT 'Open',
            is_read INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            attack_type TEXT NOT NULL,
            attacker_ip TEXT,
            attacker_device TEXT,
            victim_ip TEXT,
            victim_device TEXT,
            severity TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'Active',
            packets_involved INTEGER DEFAULT 0,
            description TEXT,
            prediction_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_probability REAL,
            confidence REAL,
            predicted_attack_type TEXT,
            expected_severity TEXT,
            reason TEXT,
            model_status TEXT,
            features_json TEXT
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            packets_per_second INTEGER,
            bytes_per_second INTEGER,
            active_connections INTEGER,
            protocol_distribution TEXT,
            top_talkers TEXT
        );

        CREATE TABLE IF NOT EXISTS response_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            trigger_type TEXT NOT NULL,
            trigger_value TEXT NOT NULL,
            action_type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mitigation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_id INTEGER,
            rule_name TEXT,
            action_type TEXT NOT NULL,
            target_ip TEXT,
            target_device TEXT,
            status TEXT NOT NULL,
            details TEXT,
            executed_by TEXT DEFAULT 'System Auto-Mitigate'
        );

        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_attacks_start ON attacks(start_time);
        CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON predictions(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);
        CREATE INDEX IF NOT EXISTS idx_response_rules_enabled ON response_rules(enabled);
        CREATE INDEX IF NOT EXISTS idx_mitigation_actions_timestamp ON mitigation_actions(timestamp);
    """)

    cursor.execute("SELECT COUNT(*) FROM response_rules")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        cursor.executemany("""
            INSERT INTO response_rules (name, trigger_type, trigger_value, action_type, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            ("Block Critical Intrusion IP", "severity", "Critical", "block_ip", 1, now),
            ("Isolate High-Risk DDoS Adversary", "attack_type", "DDoS Attack", "isolate_device", 1, now),
            ("Log & Alert Port Scanning Host", "attack_type", "Port Scan", "log_only", 1, now),
            ("Quarantine Malware Activity", "attack_type", "Malware C2", "block_ip", 1, now),
        ])

    conn.commit()
    conn.close()


async def get_async_db() -> aiosqlite.Connection:
    """Get an async database connection."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


# ────────────────────────────────────────────
# Packet operations
# ────────────────────────────────────────────

async def insert_packet(timestamp: str, src_ip: str, dst_ip: str,
                        protocol: str, src_port: int, dst_port: int,
                        size: int, tcp_flags: str = "", info: str = ""):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, tcp_flags, info) VALUES (?,?,?,?,?,?,?,?,?)",
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, tcp_flags, info)
        )
        await db.commit()


async def insert_packets_batch(packets: List[tuple]):
    """Insert many packets at once for performance."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, tcp_flags, info) VALUES (?,?,?,?,?,?,?,?,?)",
            packets
        )
        await db.commit()


async def get_recent_packets(limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_packet_count_since(since: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM packets WHERE timestamp >= ?", (since,)
        )
        row = await cursor.fetchone()
        return row[0] if row else 0


# ────────────────────────────────────────────
# Device operations
# ────────────────────────────────────────────

async def upsert_device(ip_address: str, mac_address: str = None,
                        hostname: str = None, vendor: str = None,
                        device_type: str = "Unknown", status: str = "Online",
                        risk_level: str = None, ping_latency_ms: float = None,
                        os_guess: str = None, interface: str = None):
    now = datetime.now().isoformat()
    dev_id = f"dev-{ip_address.replace('.', '-')}"
    r_level = risk_level or "Low"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO devices (id, ip_address, mac_address, hostname, vendor, device_type, status, risk_level, last_seen, ping_latency_ms, os_guess, interface, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address = COALESCE(excluded.mac_address, devices.mac_address),
                hostname = COALESCE(excluded.hostname, devices.hostname),
                vendor = COALESCE(excluded.vendor, devices.vendor),
                device_type = COALESCE(excluded.device_type, devices.device_type),
                status = excluded.status,
                risk_level = COALESCE(excluded.risk_level, devices.risk_level),
                last_seen = excluded.last_seen,
                ping_latency_ms = COALESCE(excluded.ping_latency_ms, devices.ping_latency_ms),
                os_guess = COALESCE(excluded.os_guess, devices.os_guess),
                interface = COALESCE(excluded.interface, devices.interface)
        """, (dev_id, ip_address, mac_address, hostname, vendor, device_type, status, r_level, now, ping_latency_ms, os_guess, interface, now))
        await db.commit()


async def get_all_devices() -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_device_by_id(device_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def mark_device_offline(ip_address: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE devices SET status = 'Offline' WHERE ip_address = ?", (ip_address,))
        await db.commit()


async def get_online_device_count() -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM devices WHERE status = 'Online'")
        row = await cursor.fetchone()
        return row[0] if row else 0


async def get_current_devices(timeout_seconds: int = 120) -> List[Dict]:
    """Return only devices that are currently active (Online) or were last seen within
    the timeout window. This separates LIVE topology from historical records."""
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """SELECT * FROM devices
               WHERE status = 'Online'
                  OR (last_seen IS NOT NULL
                      AND julianday(?) - julianday(last_seen) < ? / 86400.0)
               ORDER BY last_seen DESC""",
            (now, timeout_seconds)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_device_counts() -> Dict[str, int]:
    """Return counts of devices by status for topology counters."""
    async with aiosqlite.connect(DB_PATH) as db:
        total = (await (await db.execute("SELECT COUNT(*) FROM devices WHERE status = 'Online'")).fetchone())[0]
        online = (await (await db.execute("SELECT COUNT(*) FROM devices WHERE status = 'Online'")).fetchone())[0]
        offline = (await (await db.execute("SELECT COUNT(*) FROM devices WHERE status = 'Offline'")).fetchone())[0]
        return {
            "total": online,  # total current = online devices only
            "online": online,
            "offline": offline,
            "unknown": 0
        }


# ────────────────────────────────────────────
# Alert operations
# ────────────────────────────────────────────

async def insert_alert(severity: str, title: str, message: str,
                       attacker_ip: str = None, victim_ip: str = None,
                       attack_type: str = None, threat_score: float = 0,
                       confidence: float = 0, recommended_action: str = "",
                       action_taken: str = "") -> int:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO alerts (timestamp, severity, title, message, attacker_ip, victim_ip,
               attack_type, threat_score, confidence, recommended_action, action_taken)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (now, severity, title, message, attacker_ip, victim_ip,
             attack_type, threat_score, confidence, recommended_action, action_taken)
        )
        await db.commit()
        return cursor.lastrowid


async def get_alerts(limit: int = 50, severity: str = None) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if severity:
            cursor = await db.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_unread_alert_count() -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM alerts WHERE is_read = 0")
        row = await cursor.fetchone()
        return row[0] if row else 0


async def clear_all_alerts():
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE alerts SET is_read = 1, action_taken = 'Resolved'")
        await db.execute("UPDATE attacks SET end_time = ? WHERE end_time IS NULL", (now,))
        await db.commit()


async def resolve_alert(alert_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE alerts SET is_read = 1, action_taken = 'Resolved' WHERE id = ?", (alert_id,))
        await db.commit()


# ────────────────────────────────────────────
# Attack operations
# ────────────────────────────────────────────

async def insert_attack(attack_type: str, attacker_ip: str, victim_ip: str,
                        attacker_device: str = "", victim_device: str = "",
                        severity: str = "Medium", description: str = "") -> int:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO attacks (start_time, attack_type, attacker_ip, attacker_device,
               victim_ip, victim_device, severity, description)
               VALUES (?,?,?,?,?,?,?,?)""",
            (now, attack_type, attacker_ip, attacker_device, victim_ip, victim_device, severity, description)
        )
        await db.commit()
        return cursor.lastrowid


async def resolve_attack(attack_id: int, packets: int = 0):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE attacks SET status = 'Resolved', end_time = ?, packets_involved = ? WHERE id = ?",
            (now, packets, attack_id)
        )
        await db.commit()


async def get_active_attack() -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM attacks WHERE status = 'Active' ORDER BY start_time DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_attacks(limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM attacks ORDER BY start_time DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ────────────────────────────────────────────
# Prediction operations
# ────────────────────────────────────────────

async def insert_prediction(threat_probability: float, confidence: float,
                            predicted_attack_type: str = "", expected_severity: str = "",
                            reason: str = "", model_status: str = "", features_json: str = "") -> int:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO predictions (timestamp, threat_probability, confidence,
               predicted_attack_type, expected_severity, reason, model_status, features_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (now, threat_probability, confidence, predicted_attack_type,
             expected_severity, reason, model_status, features_json)
        )
        await db.commit()
        return cursor.lastrowid


async def get_latest_prediction() -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM predictions ORDER BY timestamp DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_predictions(limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM predictions ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ────────────────────────────────────────────
# Log operations
# ────────────────────────────────────────────

async def insert_log(source: str, level: str, message: str):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO logs (timestamp, source, level, message) VALUES (?,?,?,?)",
            (now, source, level, message)
        )
        await db.commit()


def insert_log_sync(source: str, level: str, message: str):
    """Synchronous log insert for use in non-async contexts."""
    now = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO logs (timestamp, source, level, message) VALUES (?,?,?,?)",
        (now, source, level, message)
    )
    conn.commit()
    conn.close()


async def get_logs(limit: int = 100, source: str = None, level: str = None) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        conditions = []
        params = []
        if source:
            conditions.append("source = ?")
            params.append(source)
        if level:
            conditions.append("level = ?")
            params.append(level)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        cursor = await db.execute(
            f"SELECT * FROM logs {where} ORDER BY id DESC LIMIT ?",
            (*params, limit)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ────────────────────────────────────────────
# Traffic stats operations
# ────────────────────────────────────────────

async def insert_traffic_stats(pps: int, bps: int, connections: int,
                                protocol_dist: dict, top_talkers: list):
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO traffic_stats (timestamp, packets_per_second, bytes_per_second, active_connections, protocol_distribution, top_talkers) VALUES (?,?,?,?,?,?)",
            (now, pps, bps, connections, json.dumps(protocol_dist), json.dumps(top_talkers))
        )
        await db.commit()


# ────────────────────────────────────────────
# Report aggregations
# ────────────────────────────────────────────

async def get_report_summary() -> Dict:
    async with aiosqlite.connect(DB_PATH) as db:
        total_attacks = (await (await db.execute("SELECT COUNT(*) FROM attacks")).fetchone())[0]
        active_attacks = (await (await db.execute("SELECT COUNT(*) FROM attacks WHERE status='Active'")).fetchone())[0]
        resolved_attacks = (await (await db.execute("SELECT COUNT(*) FROM attacks WHERE status='Resolved'")).fetchone())[0]
        total_alerts = (await (await db.execute("SELECT COUNT(*) FROM alerts")).fetchone())[0]
        critical_alerts = (await (await db.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'")).fetchone())[0]
        total_packets = (await (await db.execute("SELECT COUNT(*) FROM packets")).fetchone())[0]

        # Attack type distribution
        cursor = await db.execute("SELECT attack_type, COUNT(*) as cnt FROM attacks GROUP BY attack_type")
        rows = await cursor.fetchall()
        attack_dist = {row[0]: row[1] for row in rows}

        return {
            "total_attacks": total_attacks,
            "active_attacks": active_attacks,
            "resolved_attacks": resolved_attacks,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "total_packets": total_packets,
            "attack_type_distribution": attack_dist
        }


# ────────────────────────────────────────────
# Response rules & Mitigation actions
# ────────────────────────────────────────────

async def get_response_rules() -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM response_rules ORDER BY id ASC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def insert_response_rule(name: str, trigger_type: str, trigger_value: str, action_type: str, enabled: bool = True) -> int:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO response_rules (name, trigger_type, trigger_value, action_type, enabled, created_at) VALUES (?,?,?,?,?,?)",
            (name, trigger_type, trigger_value, action_type, 1 if enabled else 0, now)
        )
        await db.commit()
        return cursor.lastrowid


async def toggle_response_rule(rule_id: int, enabled: bool):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE response_rules SET enabled = ? WHERE id = ?", (1 if enabled else 0, rule_id))
        await db.commit()


async def delete_response_rule(rule_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM response_rules WHERE id = ?", (rule_id,))
        await db.commit()


async def get_mitigation_actions(limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM mitigation_actions ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def insert_mitigation_action(rule_id: Optional[int], rule_name: str, action_type: str, target_ip: str, target_device: str, status: str, details: str, executed_by: str = "System Auto-Mitigate") -> int:
    now = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """INSERT INTO mitigation_actions 
               (timestamp, rule_id, rule_name, action_type, target_ip, target_device, status, details, executed_by) 
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (now, rule_id, rule_name, action_type, target_ip, target_device, status, details, executed_by)
        )
        await db.commit()
        return cursor.lastrowid

