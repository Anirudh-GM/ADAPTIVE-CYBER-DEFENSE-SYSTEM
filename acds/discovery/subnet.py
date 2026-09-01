"""
ACDS Subnet & Network Interface Detection Module
Accurately identifies active network interfaces, local IPv4 addresses, subnet masks,
CIDR prefixes, default gateways, and usable IP ranges.
"""

from dataclasses import dataclass, field
import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class SubnetInfo:
    """Structured network interface and subnet configuration."""
    interface_name: str
    local_ip: str
    netmask: str
    cidr_prefix: int
    cidr_notation: str
    network_address: str
    broadcast_address: str
    default_gateway: Optional[str] = None
    usable_ips: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interface_name": self.interface_name,
            "local_ip": self.local_ip,
            "netmask": self.netmask,
            "cidr_prefix": self.cidr_prefix,
            "cidr_notation": self.cidr_notation,
            "network_address": self.network_address,
            "broadcast_address": self.broadcast_address,
            "default_gateway": self.default_gateway,
            "usable_count": len(self.usable_ips),
        }


def _mask_to_cidr(netmask_str: str) -> int:
    """Convert IPv4 netmask string (e.g. 255.255.255.0) to CIDR prefix integer."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask_str}").prefixlen
    except Exception:
        return 24


def parse_ipconfig_windows() -> List[Dict[str, Any]]:
    """Parse Windows ipconfig /all output to extract adapters with IP, mask, and gateway."""
    adapters = []
    try:
        proc = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=4)
        out = proc.stdout
    except Exception:
        return adapters

    current_adapter: Optional[Dict[str, Any]] = None

    in_gateway_block = False
    for line in out.splitlines():
        line_clean = line.strip()
        # Adapter header (e.g. "Wireless LAN adapter Wi-Fi:" or "Ethernet adapter Ethernet:")
        if line and not line.startswith(" ") and ("adapter" in line.lower() or "interface" in line.lower()):
            if current_adapter and current_adapter.get("ip"):
                adapters.append(current_adapter)
            adapter_name = line.split("adapter")[-1].strip().rstrip(":")
            current_adapter = {
                "name": adapter_name or "Network Adapter",
                "ip": None,
                "mask": "255.255.255.0",
                "gateway": None,
                "is_disconnected": False,
            }
            in_gateway_block = False
            continue

        if not current_adapter:
            continue

        if "Media State" in line and "disconnected" in line.lower():
            current_adapter["is_disconnected"] = True

        if "IPv4 Address" in line or "IP Address" in line:
            in_gateway_block = False
            m = re.search(r":\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
            if m:
                cand_ip = m.group(1).strip()
                if not cand_ip.startswith("127.") and not cand_ip.startswith("169.254."):
                    current_adapter["ip"] = cand_ip

        if "Subnet Mask" in line:
            in_gateway_block = False
            m = re.search(r":\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
            if m:
                current_adapter["mask"] = m.group(1).strip()

        if "Default Gateway" in line:
            in_gateway_block = True
            m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
            if m:
                cand_gw = m.group(1).strip()
                if not cand_gw.startswith("0.0.0.0"):
                    current_adapter["gateway"] = cand_gw
            continue

        if in_gateway_block and line_clean:
            m = re.search(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line_clean)
            if m:
                cand_gw = m.group(1).strip()
                if not cand_gw.startswith("0.0.0.0"):
                    current_adapter["gateway"] = cand_gw
                    in_gateway_block = False
        elif not line_clean:
            in_gateway_block = False

    if current_adapter and current_adapter.get("ip"):
        adapters.append(current_adapter)

    return adapters


def get_default_gateway_socket() -> Tuple[Optional[str], Optional[str]]:
    """Determine outbound local IP and default gateway candidate via socket routing test."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip, None
    except Exception:
        return None, None


def detect_active_subnet(fallback_prefix: str = "192.168.1.") -> SubnetInfo:
    """
    Detect the active network interface and calculate full subnet boundaries.
    Prioritizes interfaces with active default gateways and routable IPv4 addresses.
    """
    system = platform.system()
    chosen_ip: Optional[str] = None
    chosen_mask: str = "255.255.255.0"
    chosen_gw: Optional[str] = None
    chosen_iface: str = "Local Network Interface"

    # Step 1: Detect outbound routing IP via socket probe
    sock_ip, _ = get_default_gateway_socket()

    if system == "Windows":
        adapters = parse_ipconfig_windows()
        
        # If we have an outbound socket IP, find the adapter holding that IP
        if sock_ip:
            matching_ad = [a for a in adapters if a.get("ip") == sock_ip and not a.get("is_disconnected")]
            if matching_ad:
                ad = matching_ad[0]
                chosen_ip = ad["ip"]
                chosen_mask = ad["mask"] or "255.255.255.0"
                chosen_gw = ad.get("gateway")
                chosen_iface = ad["name"]

        # If not found by socket IP, find adapter with active default gateway
        if not chosen_ip:
            gw_adapters = [a for a in adapters if a.get("gateway") and not a.get("is_disconnected") and a.get("ip")]
            if gw_adapters:
                def adapter_rank(ad):
                    name = ad["name"].lower()
                    if "wi-fi" in name or "wireless" in name or "ethernet" in name:
                        return 0
                    return 1

                gw_adapters.sort(key=adapter_rank)
                ad = gw_adapters[0]
                chosen_ip = ad["ip"]
                chosen_mask = ad["mask"] or "255.255.255.0"
                chosen_gw = ad["gateway"]
                chosen_iface = ad["name"]

        # If still not found, take first valid non-disconnected adapter
        if not chosen_ip and adapters:
            valid_ads = [a for a in adapters if a.get("ip") and not a.get("is_disconnected")]
            if valid_ads:
                ad = valid_ads[0]
                chosen_ip = ad["ip"]
                chosen_mask = ad["mask"] or "255.255.255.0"
                chosen_gw = ad.get("gateway")
                chosen_iface = ad["name"]

    if not chosen_ip and sock_ip:
        chosen_ip = sock_ip
        chosen_iface = "Default Socket Interface"

    if not chosen_ip:
        chosen_ip = f"{fallback_prefix.rstrip('.')} .7" if '.' in fallback_prefix else "192.168.1.7"
        chosen_ip = chosen_ip.replace(" ", "")

    cidr_prefix = _mask_to_cidr(chosen_mask)

    try:
        # Build IP network object
        iface_net = ipaddress.IPv4Interface(f"{chosen_ip}/{cidr_prefix}").network
        network_addr = str(iface_net.network_address)
        broadcast_addr = str(iface_net.broadcast_address)
        cidr_notation = f"{network_addr}/{cidr_prefix}"
        
        # Limit usable hosts to max 254 (safe /24 bounds)
        usable_ips = [str(ip) for ip in iface_net.hosts()][:254]
    except Exception:
        # Fallback to manual /24 calculation
        parts = chosen_ip.split(".")
        base = f"{parts[0]}.{parts[1]}.{parts[2]}"
        network_addr = f"{base}.0"
        broadcast_addr = f"{base}.255"
        cidr_notation = f"{base}.0/24"
        cidr_prefix = 24
        usable_ips = [f"{base}.{i}" for i in range(1, 255)]

    if not chosen_gw:
        # Infer standard default gateway as .1 if not explicitly known
        parts = chosen_ip.split(".")
        chosen_gw = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    return SubnetInfo(
        interface_name=chosen_iface,
        local_ip=chosen_ip,
        netmask=chosen_mask,
        cidr_prefix=cidr_prefix,
        cidr_notation=cidr_notation,
        network_address=network_addr,
        broadcast_address=broadcast_addr,
        default_gateway=chosen_gw,
        usable_ips=usable_ips,
    )
