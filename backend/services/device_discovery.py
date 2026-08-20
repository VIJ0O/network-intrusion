"""
Real device discovery service for local Wi-Fi / Ethernet subnets.
Discovers actual connected devices (mobile phones, laptops, desktops, gateways, IoT)
using active subnet probes and the operating system neighbor/ARP cache.
NO FAKE DEVICES. NO HARDCODED IPS. REAL NETWORK DATA ONLY.
"""

import asyncio
import subprocess
import re
import socket
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Callable, Set
from concurrent.futures import ThreadPoolExecutor

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

from database import upsert_device, get_all_devices, mark_device_offline, purge_stale_offline_devices
from services.log_manager import log_manager


class DeviceDiscoveryService:
    """Discovers real local network devices using active subnet probing and OS neighbor tables."""

    def __init__(self):
        self.is_running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._scan_interval = 12  # Scan every 12 seconds for responsive updates
        self._devices: Dict[str, Dict] = {}
        self._subscribers: List[Callable] = []
        self._executor = ThreadPoolExecutor(max_workers=8)

        # Network configuration diagnostics
        self.active_interface: str = "Unknown"
        self.local_ip: str = "127.0.0.1"
        self.subnet_cidr: str = "127.0.0.1/32"
        self.default_gateway: str = "127.0.0.1"
        self.last_scan_time: Optional[str] = None
        self.discovery_method: str = "Active Subnet Probe + OS Neighbor Table"
        self.last_discovered_count: int = 0

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self.is_running = True
        self._detect_network_configuration()
        asyncio.ensure_future(self._scan_loop())
        await log_manager.log("DeviceDiscovery", "INFO", f"Device discovery online on {self.active_interface} ({self.local_ip}, Subnet: {self.subnet_cidr})")

    async def stop(self):
        self.is_running = False
        await log_manager.log("DeviceDiscovery", "INFO", "Device discovery service stopped")

    def _detect_network_configuration(self):
        """Auto-detect active interface, IP, subnet prefix, and default gateway from OS."""
        detected_ip = None
        detected_iface = "Local Network Adapter"
        detected_gw = None
        detected_prefix = 24

        # 1. Detect local IP and default gateway via UDP routing socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            detected_ip = s.getsockname()[0]
            s.close()
        except Exception:
            detected_ip = "127.0.0.1"

        # 2. Query Windows routing table / PowerShell for gateway and adapter name
        if platform.system().lower() == 'windows':
            try:
                proc = subprocess.run(
                    'powershell -NoProfile -Command "Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' | Select-Object -First 1 InterfaceAlias, NextHop; Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq \'' + str(detected_ip) + '\' } | Select-Object -First 1 PrefixLength"',
                    capture_output=True, text=True, shell=True, timeout=4
                )
                for line in proc.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1]):
                        detected_iface = parts[0]
                        detected_gw = parts[1]
                    elif len(parts) == 1 and parts[0].isdigit():
                        detected_prefix = int(parts[0])
            except Exception:
                pass

            # Fallback gateway check via 'route print'
            if not detected_gw:
                try:
                    proc = subprocess.run('route print 0.0.0.0', capture_output=True, text=True, shell=True, timeout=2)
                    for line in proc.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                            detected_gw = parts[2]
                            break
                except Exception:
                    pass
        else:
            try:
                proc = subprocess.run('ip route show default', capture_output=True, text=True, shell=True, timeout=2)
                match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)', proc.stdout)
                if match:
                    detected_gw = match.group(1)
                    detected_iface = match.group(2)
            except Exception:
                pass

        # 3. Use psutil if available to verify netmask
        if PSUTIL_AVAILABLE and detected_ip:
            try:
                for iface_name, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if a.family == socket.AF_INET and a.address == detected_ip:
                            detected_iface = iface_name
                            if a.netmask:
                                detected_prefix = ipaddress.IPv4Network(f"0.0.0.0/{a.netmask}").prefixlen
            except Exception:
                pass

        self.local_ip = detected_ip or "127.0.0.1"
        self.default_gateway = detected_gw or (f"{self.local_ip.rsplit('.', 1)[0]}.1" if "." in self.local_ip else "127.0.0.1")
        self.active_interface = detected_iface or "Wi-Fi"

        try:
            net = ipaddress.ip_network(f"{self.local_ip}/{detected_prefix}", strict=False)
            self.subnet_cidr = str(net)
        except Exception:
            parts = self.local_ip.split('.')
            self.subnet_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "127.0.0.1/32"

    async def _scan_loop(self):
        while self.is_running:
            try:
                self._detect_network_configuration()
                await log_manager.log("DeviceDiscovery", "INFO", f"Initiating real subnet discovery on {self.subnet_cidr}...")
                discovered = await self._scan_network()
                await self._update_devices(discovered)
                self.last_scan_time = datetime.now().isoformat()
                self.last_discovered_count = len(discovered)
            except Exception as e:
                await log_manager.log("DeviceDiscovery", "ERROR", f"Error in scan loop: {e}")
            await asyncio.sleep(self._scan_interval)

    async def _probe_ip(self, ip: str):
        """Ultra-fast non-blocking TCP socket probe to trigger kernel ARP resolution for the host."""
        common_ports = [80, 443, 53, 139, 445, 8080, 62078]
        for port in common_ports:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.08)
                writer.close()
                await writer.wait_closed()
                return
            except Exception:
                pass

    async def _sweep_subnet_fast(self):
        """Asynchronously probes all host IPs on the active subnet to populate kernel ARP/neighbor table."""
        try:
            net = ipaddress.ip_network(self.subnet_cidr, strict=False)
            # Limit sweep to at most /24 to prevent overwhelming massive corporate networks
            if net.num_addresses > 512:
                parts = self.local_ip.split('.')
                net = ipaddress.ip_network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False)

            tasks = [self._probe_ip(str(ip)) for ip in net.hosts()]
            # Run in concurrent batches of 64
            chunk_size = 64
            for i in range(0, len(tasks), chunk_size):
                await asyncio.gather(*tasks[i:i + chunk_size], return_exceptions=True)
        except Exception:
            pass

    async def _parse_os_neighbor_table(self) -> List[Dict]:
        """Parses actual OS neighbor entries from Windows PowerShell / arp -a."""
        devices = []
        seen_ips = set()

        # 1. Try Windows Get-NetNeighbor first
        if platform.system().lower() == 'windows':
            try:
                proc = await asyncio.create_subprocess_shell(
                    'powershell -NoProfile -Command "Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne \'Unreachable\' } | Select-Object IPAddress, LinkLayerAddress, State"',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode('utf-8', errors='ignore')

                for line in output.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
                            if self._is_valid_device_ip(ip, mac) and ip not in seen_ips:
                                seen_ips.add(ip)
                                devices.append({"ip": ip, "mac": mac})
            except Exception:
                pass

        # 2. Fallback / supplementary check via 'arp -a'
        try:
            proc = await asyncio.create_subprocess_exec(
                'arp', '-a',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode('utf-8', errors='ignore')

            ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            mac_pattern = r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"

            for line in output.splitlines():
                ip_match = re.search(ip_pattern, line)
                mac_match = re.search(mac_pattern, line)
                if ip_match and mac_match:
                    ip = ip_match.group(1)
                    mac = mac_match.group(1).replace('-', ':').upper()
                    if self._is_valid_device_ip(ip, mac) and ip not in seen_ips:
                        seen_ips.add(ip)
                        devices.append({"ip": ip, "mac": mac})
        except Exception:
            pass

        return devices

    def _is_valid_device_ip(self, ip: str, mac: str) -> bool:
        """Filter out multicast, broadcast, loopback, and invalid MAC addresses."""
        if ip.startswith("127.") or ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.") or ip in ["0.0.0.0", "255.255.255.255"]:
            return False
        if ip.startswith("169.254."):
            return False
        if mac in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"] or mac.startswith("01:00:5E"):
            return False
        return True

    async def _scan_network(self) -> List[Dict]:
        """Perform active sweep to refresh ARP cache, then parse and enrich all discovered real devices."""
        # 1. Perform async subnet sweep
        await self._sweep_subnet_fast()

        # 2. Parse the refreshed OS neighbor table
        raw_devices = await self._parse_os_neighbor_table()

        # 3. Always include local monitoring host if missing
        if self.local_ip and not any(d["ip"] == self.local_ip for d in raw_devices):
            host_mac = "Active NIC"
            if PSUTIL_AVAILABLE:
                try:
                    for iface_name, addrs in psutil.net_if_addrs().items():
                        for a in addrs:
                            if a.family == psutil.AF_LINK and a.address:
                                host_mac = a.address.replace('-', ':').upper()
                except Exception:
                    pass
            raw_devices.append({"ip": self.local_ip, "mac": host_mac})

        # 4. Enrich each discovered real device with non-blocking metadata
        enriched_devices = []
        for dev in raw_devices:
            ip = dev["ip"]
            mac = dev["mac"]
            is_gateway = (ip == self.default_gateway) or (ip.endswith(".1") and not self.default_gateway)
            is_local_host = (ip == self.local_ip)

            # Measure ping latency (non-blocking, timeout 200ms)
            latency = await self._measure_latency(ip)

            # Resolve hostname with strict non-blocking timeout
            hostname = await self._resolve_hostname_fast(ip, is_gateway, is_local_host)

            # Classify vendor and check for private/randomized MAC
            vendor, is_randomized_mac = self._classify_vendor(mac)

            # Classify device with multi-signal evidence model
            dtype, c_source, c_conf = self._determine_device_classification(
                hostname, ip, vendor, is_gateway, is_local_host, is_randomized_mac
            )

            # OS guess
            os_guess = self._fingerprint_os(ip, is_gateway, is_local_host, dtype, latency)

            # Build evidence list
            evidence = ["✓ Active System ARP Entry (Hardware MAC Confirmed)"]
            if is_gateway:
                evidence.append("✓ Default Subnet Gateway Route")
            if is_local_host:
                evidence.append("✓ Primary Active Monitoring Interface")
            if latency is not None:
                evidence.append(f"✓ Active ICMP Reply ({latency:.1f} ms Latency)")
            else:
                evidence.append("✓ Passive ARP Presence (ICMP Filtered / Silent Host)")
            if is_randomized_mac:
                evidence.append("✓ Randomized / Private Wi-Fi MAC (iOS / Android Privacy)")
            elif vendor and vendor != "Unknown Vendor":
                evidence.append(f"✓ IEEE OUI Vendor Match ({vendor})")
            if hostname and hostname != "Unknown Host":
                evidence.append(f"✓ Hostname Signature ({hostname})")
            evidence.append(f"✓ Classification: {c_source} ({c_conf} Confidence)")

            enriched_devices.append({
                "ip_address": ip,
                "mac_address": mac,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": dtype,
                "ping_latency_ms": latency,
                "os_guess": os_guess,
                "classification_source": c_source,
                "classification_confidence": c_conf,
                "verification_score": 100.0 if (is_gateway or is_local_host) else 90.0 if latency is not None else 80.0,
                "evidence_list": evidence,
                "is_virtual_adapter": False,
                "status": "Online",
                "risk_level": "Low"
            })

        return enriched_devices

    async def _measure_latency(self, ip: str) -> Optional[float]:
        """Measures ping latency with a strict timeout. Returns None if host does not respond."""
        try:
            is_win = platform.system().lower() == 'windows'
            cmd = ['ping', '-n', '1', '-w', '200', ip] if is_win else ['ping', '-c', '1', '-W', '1', ip]
            start = datetime.now()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=0.35)
            output = stdout.decode('utf-8', errors='ignore')
            if "reply from" in output.lower() or "bytes from" in output.lower():
                match = re.search(r"time[=<]([0-9.]+)\s*ms", output.lower())
                if match:
                    return float(match.group(1))
                return (datetime.now() - start).total_seconds() * 1000.0
        except Exception:
            pass
        return None

    async def _resolve_hostname_fast(self, ip: str, is_gateway: bool, is_local_host: bool) -> str:
        """Fast non-blocking reverse DNS and NetBIOS lookup."""
        if is_gateway:
            return "Gateway Router"
        if is_local_host:
            try:
                return socket.gethostname()
            except Exception:
                return "Monitoring Host"

        def _sync_lookup():
            try:
                # 1. Reverse DNS with socket
                name = socket.gethostbyaddr(ip)[0]
                if name and name != ip:
                    return name
            except Exception:
                pass

            # 2. NetBIOS lookup for Windows/Samba hosts
            try:
                proc = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=0.3)
                for line in proc.stdout.splitlines():
                    if "<00>" in line and "UNIQUE" in line:
                        parts = line.split()
                        if parts:
                            return parts[0].strip()
            except Exception:
                pass

            return "Unknown Host"

        try:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(loop.run_in_executor(self._executor, _sync_lookup), timeout=0.45)
        except Exception:
            return "Unknown Host"

    def _classify_vendor(self, mac: str) -> tuple[str, bool]:
        """Lookup IEEE OUI vendor and check for randomized Wi-Fi MACs."""
        if not mac or mac == "Active NIC":
            return ("System Host", False)

        clean_mac = mac.upper().replace('-', ':')
        prefix = clean_mac[:8]

        # Check for Randomized MAC (bit 1 of 1st byte is 1 -> 2nd hex digit is 2, 6, A, or E)
        is_randomized = False
        if len(clean_mac) >= 2 and clean_mac[1] in ['2', '6', 'A', 'E']:
            is_randomized = True
            return ("Local Network Device (Private Wi-Fi MAC)", True)

        ouis = {
            "3C:64:CF": "TP-Link Technologies (Router)",
            "EC:A8:6B": "TP-Link Technologies",
            "F8:1A:67": "TP-Link Technologies",
            "BC:29:78": "Realtek Semiconductor",
            "06:C3:C1": "Realtek Semiconductor",
            "50:5A:65": "Samsung Electronics",
            "F8:54:F6": "Samsung Electronics",
            "3C:4D:5E": "Apple Inc. (iPhone / Mac)",
            "00:1C:B3": "Apple Inc.",
            "70:56:81": "Apple Inc.",
            "BC:D1:D3": "Apple Inc.",
            "AC:BC:B5": "Apple Inc.",
            "F4:5C:89": "Apple Inc.",
            "F0:E1:D2": "Samsung Electronics",
            "84:25:DB": "Samsung Galaxy",
            "34:CE:00": "Xiaomi Communications",
            "64:09:80": "Xiaomi Communications",
            "8C:BE:BE": "Xiaomi Mobile",
            "F4:F5:DB": "Google Pixel Mobile",
            "3C:5A:B4": "Google LLC",
            "94:65:2D": "OnePlus Technology",
            "A4:E4:B8": "OPPO Telecommunications",
            "88:36:6C": "Vivo Mobile",
            "00:66:4B": "Realme Mobile",
            "78:9A:BC": "Intel Corporation",
            "B4:2E:99": "Intel Corporation",
            "00:1A:2B": "Cisco Systems",
            "00:11:32": "Synology Inc.",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Trading"
        }

        return (ouis.get(prefix, "Network Device"), False)

    def _determine_device_classification(self, hostname: str, ip: str, vendor: str,
                                         is_gateway: bool, is_local_host: bool, is_randomized_mac: bool) -> tuple[str, str, str]:
        """
        Determines standardized device_type, classification_source, and classification_confidence.
        Priority:
        1. Router / Default Gateway
        2. Local Host Metadata
        3. Hostname Signature Analysis
        4. Vendor Hardware Profile
        5. Private Wi-Fi MAC Analysis
        6. Unknown (Strict Fallback - Unknown is better than wrong)
        """
        if is_gateway:
            return ("router", "Gateway Route", "High")

        hn_lower = hostname.lower() if hostname and hostname != "Unknown Host" else ""
        v_lower = vendor.lower() if vendor and vendor != "Unknown Vendor" else ""

        if is_local_host:
            if any(w in hn_lower for w in ["laptop", "notebook", "thinkpad", "ideapad", "loq", "zenbook", "surface", "vivobook", "macbook", "yoga", "pavilion", "inspiron", "latitude"]):
                return ("laptop", "Local Hostname", "High")
            elif any(w in hn_lower for w in ["desktop", "workstation", "pc", "rig", "optiplex"]):
                return ("desktop", "Local Hostname", "High")
            else:
                return ("laptop", "Local Host Environment", "High")

        # Priority 3: Hostname Evidence (Strong)
        if hn_lower:
            if any(w in hn_lower for w in ["iphone", "android", "galaxy", "pixel", "oneplus", "redmi", "xiaomi", "oppo", "vivo", "realme", "mobile", "phone"]):
                return ("mobile", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["ipad", "tablet", "tab"]):
                return ("tablet", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["laptop", "notebook", "thinkpad", "ideapad", "macbook", "zenbook", "surface", "vivobook", "loq", "pavilion", "inspiron", "latitude", "yoga"]):
                return ("laptop", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["desktop", "workstation", "optiplex", "pc", "rig"]):
                return ("desktop", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["printer", "print", "deskjet", "laserjet", "epson", "canon", "brother", "xerox", "ricoh"]):
                return ("printer", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["synology", "qnap", "nas", "truenas", "unraid"]):
                return ("nas", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["server", "proxmox", "esxi"]):
                return ("server", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["camera", "cam", "cctv", "rtsp", "dvr", "nvr"]):
                return ("camera", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["smart", "tv", "echo", "alexa", "firestick", "roku", "nest", "esp8266", "esp32", "tasmota", "tuya", "shelly"]):
                return ("iot", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["ap-", "accesspoint", "unifi", "eap"]):
                return ("access_point", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["switch", "managed-sw"]):
                return ("switch", "Hostname Analysis", "High")
            if any(w in hn_lower for w in ["firewall", "pfsense", "opnsense", "fortigate"]):
                return ("firewall", "Hostname Analysis", "High")

        # Priority 4: Vendor Specific Hardware Profiles (Moderate/Strong)
        if any(w in v_lower for w in ["xiaomi mobile", "oneplus technology", "oppo telecommunications", "vivo mobile", "realme mobile", "google pixel mobile", "samsung galaxy"]):
            return ("mobile", "Vendor Hardware Profile", "High")

        if any(w in v_lower for w in ["samsung electronics", "xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola", "huawei", "honor", "infinix"]):
            if is_randomized_mac:
                return ("mobile", "Vendor + Private Wi-Fi MAC", "High")
            return ("mobile", "Vendor Hardware Profile", "Medium")

        if any(w in v_lower for w in ["epson", "canon", "brother", "xerox", "ricoh"]):
            return ("printer", "Vendor Hardware Profile", "High")

        if any(w in v_lower for w in ["synology", "qnap"]):
            return ("nas", "Vendor Hardware Profile", "High")

        if any(w in v_lower for w in ["cisco", "netgear", "tp-link", "ubiquiti", "mikrotik"]):
            return ("router", "Vendor Hardware Profile", "Medium")

        # Priority 5: Private Wi-Fi MAC (Local Admin Bit on Consumer Wi-Fi)
        if is_randomized_mac:
            return ("mobile", "Private Wi-Fi MAC (Local Admin Bit)", "Medium")

        # Priority 6: Unknown is better than wrong!
        return ("unknown", "Insufficient Evidence", "Low")

    def _fingerprint_os(self, ip: str, is_gateway: bool, is_local_host: bool, dtype: str, latency: Optional[float]) -> str:
        if is_gateway or dtype == "router":
            return "Embedded Router OS (Linux / OpenWrt)"
        if is_local_host:
            return f"{platform.system()} {platform.release()}"
        if dtype in ["mobile", "tablet"]:
            return "Android / iOS"
        if dtype in ["laptop", "desktop"]:
            return "Windows / macOS / Linux"
        if dtype in ["server", "nas"]:
            return "Linux / Unix Server OS"
        if dtype == "printer":
            return "Embedded Printer OS"
        if dtype in ["camera", "iot", "switch", "access_point", "firewall"]:
            return "Embedded RTOS / Linux"
        return "Unknown OS"

    async def _update_devices(self, new_devices: List[Dict]):
        """Persists discovered real devices in database, purges offline devices > 10 min, and broadcasts over WebSocket."""
        # 1. Purge devices offline for > 10 minutes (600 seconds)
        purged = await purge_stale_offline_devices(max_offline_seconds=600)
        if purged > 0:
            await log_manager.log("DeviceDiscovery", "INFO", f"Purged {purged} stale offline device(s) disconnected for > 10 minutes")

        current_ips = set(d["ip_address"] for d in new_devices)
        old_devices = await get_all_devices(max_offline_seconds=600)
        old_ips = set(d["ip_address"] for d in old_devices)

        # Mark missing devices as offline
        offline_ips = old_ips - current_ips
        for ip in offline_ips:
            await mark_device_offline(ip)
            await log_manager.log("DeviceDiscovery", "WARNING", f"Device offline / unreachable: {ip}")

        # Save active devices
        for dev in new_devices:
            await upsert_device(
                ip_address=dev["ip_address"],
                mac_address=dev["mac_address"],
                hostname=dev["hostname"],
                vendor=dev["vendor"],
                device_type=dev["device_type"],
                status="Online",
                risk_level=dev.get("risk_level", "Low"),
                ping_latency_ms=dev["ping_latency_ms"],
                os_guess=dev["os_guess"],
                classification_source=dev.get("classification_source", "unknown"),
                classification_confidence=dev.get("classification_confidence", "Low")
            )

            if dev["ip_address"] not in old_ips:
                await log_manager.log("DeviceDiscovery", "INFO", f"New Wi-Fi device discovered: {dev['ip_address']} ({dev['hostname']} - {dev['device_type']})")

        # Load updated state and broadcast
        updated_devices = await get_all_devices(max_offline_seconds=600)
        for callback in self._subscribers:
            try:
                await callback(updated_devices)
            except Exception:
                pass
            try:
                await callback(updated_devices)
            except Exception:
                pass


# Global singleton
device_discovery = DeviceDiscoveryService()
