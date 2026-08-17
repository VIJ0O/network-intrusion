"""
Real-time Alert and Attack Engine.
Correlates AI predictions and rule-based checks to trigger alerts, active attacks, and defense recommendations.
"""

import asyncio
from datetime import datetime
from typing import List, Dict, Callable, Optional
from database import insert_alert, insert_attack, resolve_attack, get_active_attack
from services.log_manager import log_manager
from services.ai_engine import ai_engine


class AlertEngineService:
    """Processes threats to generate security alerts, manage active attack cycles, and make block recommendations."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: List[Callable] = []
        
        # Keep track of active database attack record ID
        self.active_attack_db_id: Optional[int] = None
        self.active_attack_info: Optional[Dict] = None

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True
        
        # Subscribe to AI engine updates
        ai_engine.subscribe(self._process_ai_result)
        
        # Check if there is an unresolved active attack in the DB from a prior crash
        prior_attack = await get_active_attack()
        if prior_attack:
            self.active_attack_db_id = prior_attack["id"]
            self.active_attack_info = prior_attack
            await log_manager.log("AlertEngine", "WARNING", f"Resumed tracking active attack ID {self.active_attack_db_id}")

        await log_manager.log("AlertEngine", "INFO", "Alert and Incident Correlation Engine online")

    async def stop(self):
        self.is_running = False
        ai_engine.unsubscribe(self._process_ai_result)
        await log_manager.log("AlertEngine", "INFO", "Alert Engine offline")

    async def _process_ai_result(self, result: Dict):
        """Reacts to AI output to generate alert notifications and track attacks."""
        if not self.is_running:
            return

        threat_prob = result.get("threat_probability", 0.0)
        attack_type = result.get("predicted_attack_type", "None")
        severity = result.get("expected_severity", "Low")
        confidence = result.get("confidence", 95.0)

        # Threshold to trigger alert / active attack
        if threat_prob >= 50.0 and attack_type != "None":
            # Determine attacker/victim candidates from recent packet flows
            attacker_ip, victim_ip = await self._infer_threat_actors()

            recommended_action = self._get_recommended_action(attack_type)

            # Insert alert in database
            alert_id = await insert_alert(
                severity=severity,
                title=f"Intrusion Alert: {attack_type}",
                message=result.get("reason", "Anomalous traffic signature detected by AI."),
                attacker_ip=attacker_ip,
                victim_ip=victim_ip,
                attack_type=attack_type,
                threat_score=threat_prob,
                confidence=confidence,
                recommended_action=recommended_action,
                action_taken="Logged / Alert Dispatched"
            )

            # Broadcast new alert to UI
            alert_event = {
                "id": alert_id,
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "title": f"Intrusion Alert: {attack_type}",
                "message": result.get("reason", ""),
                "attacker_ip": attacker_ip,
                "victim_ip": victim_ip,
                "attack_type": attack_type,
                "threat_score": threat_prob,
                "confidence": confidence,
                "recommended_action": recommended_action,
                "status": "Open",
                "is_read": False
            }
            
            for callback in self._subscribers:
                try:
                    await callback("alert", alert_event)
                except Exception:
                    pass

            # Manage active attack record lifecycle
            if not self.active_attack_db_id:
                # Create a new active attack record
                atk_id = await insert_attack(
                    attack_type=attack_type,
                    attacker_ip=attacker_ip,
                    victim_ip=victim_ip,
                    attacker_device="Detected Adversary",
                    victim_device="Internal Asset",
                    severity=severity,
                    description=result.get("reason", "")
                )
                self.active_attack_db_id = atk_id
                self.active_attack_info = {
                    "id": atk_id,
                    "start_time": datetime.now().isoformat(),
                    "attack_type": attack_type,
                    "attacker_ip": attacker_ip,
                    "victim_ip": victim_ip,
                    "severity": severity,
                    "status": "Active",
                    "packets_involved": 0,
                    "description": result.get("reason", "")
                }
                
                # Broadcast attack state change
                for callback in self._subscribers:
                    try:
                        await callback("attack", self.active_attack_info)
                    except Exception:
                        pass
                
                await log_manager.log("AlertEngine", "CRITICAL", f"🚨 Attack incident started: ID {atk_id} - {attack_type}")
        else:
            # Threat cleared/stabilized — resolve active attack if tracking one
            if self.active_attack_db_id:
                # Resolve attack
                await resolve_attack(self.active_attack_db_id, packets=1000)
                await log_manager.log("AlertEngine", "INFO", f"✅ Attack incident resolved: ID {self.active_attack_db_id}")
                
                resolved_info = dict(self.active_attack_info)
                resolved_info["status"] = "Resolved"
                resolved_info["end_time"] = datetime.now().isoformat()
                
                self.active_attack_db_id = None
                self.active_attack_info = None

                # Broadcast attack state change
                for callback in self._subscribers:
                    try:
                        await callback("attack", resolved_info)
                    except Exception:
                        pass

    async def _infer_threat_actors(self) -> tuple[Optional[str], Optional[str]]:
        """Scans recent flows to pick likely attacker and victim IPs."""
        from services.packet_capture import packet_capture
        flows = packet_capture.get_recent_packets()
        if not flows:
            return None, None
            
        # Count who sends the most packets/bytes in recent window
        senders = {}
        receivers = {}
        for f in flows:
            src, dst = f["src_ip"], f["dst_ip"]
            if src:
                senders[src] = senders.get(src, 0) + 1
            if dst:
                receivers[dst] = receivers.get(dst, 0) + 1

        # Attacker is top sender, victim is top target of that sender
        if not senders:
            return None, None
            
        attacker = max(senders, key=senders.get)
        
        # Find who the attacker targeted the most
        targets = {}
        for f in flows:
            if f["src_ip"] == attacker and f["dst_ip"]:
                targets[f["dst_ip"]] = targets.get(f["dst_ip"], 0) + 1
                
        victim = max(targets, key=targets.get) if targets else None
        return attacker, victim

    def _get_recommended_action(self, attack_type: str) -> str:
        actions = {
            "SYN Flood": "Deploy SYN cookies. Rate limit incoming SYN traffic on boundary interface.",
            "Port Scan": "Null-route offending IP address. Close unused perimeter ports.",
            "DDoS": "Deploy Cloudflare/Akamai scrubbing rules. Drop incoming traffic on high-volume ports.",
            "SQL Injection": "Enable Web Application Firewall (WAF) deep inspection rules.",
            "ARP Spoofing": "Enable DAI (Dynamic ARP Inspection) on local switches."
        }
        return actions.get(attack_type, "Investigate offending IP. Isolate source machine if internal.")

    def get_current_attack(self) -> Optional[Dict]:
        return self.active_attack_info


# Global singleton
alert_engine = AlertEngineService()
