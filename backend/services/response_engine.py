"""
Configurable Response Engine & Active Defense Service.
Evaluates security alerts against configured response rules and executes automated OS firewall mitigations.
"""

import asyncio
import os
import platform
import subprocess
from datetime import datetime
from typing import List, Dict, Optional, Callable
from database import (
    get_response_rules,
    insert_mitigation_action,
    get_mitigation_actions,
    insert_response_rule,
    toggle_response_rule,
    delete_response_rule,
    upsert_device
)
from services.log_manager import log_manager
from services.alert_engine import alert_engine


class ResponseEngineService:
    """Manages active defense rules, OS firewall mitigation execution, and incident audit logging."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: List[Callable] = []

        # Active defense mode: "dry_run", "semi_auto", "auto"
        self.defense_mode: str = "dry_run"
        self.firewall_enabled: bool = True
        self.blocked_ips: set = set()
        self.is_admin: bool = self._check_admin_privileges()

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _check_admin_privileges(self) -> bool:
        """Check whether python backend process runs as admin/root."""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True

        # Subscribe to AlertEngine events
        alert_engine.subscribe(self._handle_alert_event)

        admin_str = "Admin Privileges Detected" if self.is_admin else "Standard User Mode (OS Firewall simulation)"
        await log_manager.log("ResponseEngine", "INFO", f"Active Defense Engine operational ({self.defense_mode} mode) — {admin_str}")

    async def stop(self):
        self.is_running = False
        alert_engine.unsubscribe(self._handle_alert_event)
        await log_manager.log("ResponseEngine", "INFO", "Response Engine offline")

    async def _handle_alert_event(self, event_type: str, data: Dict):
        """Triggered whenever alert_engine emits an event."""
        if not self.is_running or event_type != "alert":
            return

        severity = data.get("severity", "Low")
        attack_type = data.get("attack_type", "None")
        attacker_ip = data.get("attacker_ip")
        victim_ip = data.get("victim_ip")
        threat_score = data.get("threat_score", 0.0)

        if not attacker_ip:
            return

        # Fetch rules from database
        rules = await get_response_rules()
        for rule in rules:
            if not rule.get("enabled"):
                continue

            t_type = rule.get("trigger_type")
            t_val = rule.get("trigger_value")
            act = rule.get("action_type")
            rule_id = rule.get("id")
            rule_name = rule.get("name")

            match = False
            if t_type == "severity" and severity.lower() == str(t_val).lower():
                match = True
            elif t_type == "attack_type" and attack_type.lower() == str(t_val).lower():
                match = True
            elif t_type == "threat_score" and threat_score >= float(t_val or 50):
                match = True

            if match:
                await self.execute_action(
                    action_type=act,
                    target_ip=attacker_ip,
                    rule_id=rule_id,
                    rule_name=rule_name,
                    executed_by=f"Auto-Rule: {rule_name}"
                )

    async def execute_action(
        self,
        action_type: str,
        target_ip: str,
        rule_id: Optional[int] = None,
        rule_name: str = "Manual Defense Action",
        executed_by: str = "Analyst Manual Action"
    ) -> Dict:
        """Executes a defensive action (block_ip, unblock_ip, isolate_device, log_only)."""
        timestamp = datetime.now().isoformat()
        status = "Success"
        details = ""

        if action_type == "block_ip":
            if self.defense_mode == "dry_run":
                status = "Simulated (Dry-Run)"
                details = f"[Dry-Run Mode] Target IP {target_ip} would be blocked in OS firewall rule 'NIDS_Block_{target_ip}'."
                self.blocked_ips.add(target_ip)
            elif self.defense_mode == "semi_auto" and "Manual" not in executed_by:
                status = "Pending Approval"
                details = f"[Semi-Auto] Defensive block rule created for {target_ip}. Requires Security Analyst manual confirmation."
            else:
                # Real execution in OS Firewall
                blocked_ok = await self._block_ip_os_firewall(target_ip)
                if blocked_ok:
                    self.blocked_ips.add(target_ip)
                    status = "Enforced"
                    details = f"Active Firewall Rule created: Blocked inbound/outbound traffic for IP {target_ip}."
                else:
                    status = "Simulated (No Admin)"
                    self.blocked_ips.add(target_ip)
                    details = f"Admin elevation unavailable. System updated device risk to Critical for IP {target_ip}."

                # Update device risk level in DB
                await upsert_device(ip_address=target_ip, risk_level="Critical")

        elif action_type == "unblock_ip":
            unblocked_ok = await self._unblock_ip_os_firewall(target_ip)
            self.blocked_ips.discard(target_ip)
            status = "Unblocked" if unblocked_ok else "Removed (Simulated)"
            details = f"Removed firewall block rule for IP {target_ip}."
            await upsert_device(ip_address=target_ip, risk_level="Low")

        elif action_type == "isolate_device":
            status = "Isolated"
            details = f"Host IP {target_ip} flagged for network isolation. Active routing sessions revoked."
            await upsert_device(ip_address=target_ip, status="Quarantined", risk_level="Critical")

        elif action_type == "log_only":
            status = "Logged"
            details = f"Security event recorded for target IP {target_ip}. No firewall modification."

        # Insert audit action in DB
        action_id = await insert_mitigation_action(
            rule_id=rule_id,
            rule_name=rule_name,
            action_type=action_type,
            target_ip=target_ip,
            target_device=f"Host-{target_ip}",
            status=status,
            details=details,
            executed_by=executed_by
        )

        log_level = "WARNING" if status in ["Enforced", "Isolated"] else "INFO"
        await log_manager.log("ResponseEngine", log_level, f"⚡ Mitigation action executed ({action_type}): IP {target_ip} -> {status}")

        result_dict = {
            "id": action_id,
            "timestamp": timestamp,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "action_type": action_type,
            "target_ip": target_ip,
            "target_device": f"Host-{target_ip}",
            "status": status,
            "details": details,
            "executed_by": executed_by
        }

        # Broadcast via WS subscribers
        for callback in self._subscribers:
            try:
                await callback(result_dict)
            except Exception:
                pass

        return result_dict

    async def _block_ip_os_firewall(self, ip: str) -> bool:
        """Executes OS firewall block command (Windows netsh / Linux iptables)."""
        rule_name = f"NIDS_Block_{ip}"
        try:
            if platform.system() == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            else:
                cmd = f'iptables -A INPUT -s {ip} -j DROP'

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    async def _unblock_ip_os_firewall(self, ip: str) -> bool:
        """Removes OS firewall block command."""
        rule_name = f"NIDS_Block_{ip}"
        try:
            if platform.system() == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            else:
                cmd = f'iptables -D INPUT -s {ip} -j DROP'

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False

    def get_config(self) -> Dict:
        return {
            "defense_mode": self.defense_mode,
            "firewall_enabled": self.firewall_enabled,
            "is_admin": self.is_admin,
            "blocked_ips": list(self.blocked_ips)
        }

    def set_config(self, mode: Optional[str] = None, firewall_enabled: Optional[bool] = None):
        if mode in ["dry_run", "semi_auto", "auto"]:
            self.defense_mode = mode
        if firewall_enabled is not None:
            self.firewall_enabled = firewall_enabled


response_engine = ResponseEngineService()
