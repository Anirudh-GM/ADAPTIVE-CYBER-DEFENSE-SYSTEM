"""
ACDS Hardware, OS & Device Fingerprinting Engine
Infers operating system, device classification, mobile detection, and criticality rating
using multi-factor evidence (TTL heuristics, hostname tokens, banners, open ports, and MAC OUIs).
"""

import re
from typing import Dict, List, Optional, Set, Tuple, Any
from acds.core.constants import (
    MOBILE_OUI_PREFIXES,
    APPLE_OUI_PREFIXES,
    PHONE_VENDORS,
    CRITICALITY_LABELS,
)


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    """Look up the manufacturer of a MAC address using the local OUI table."""
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return MOBILE_OUI_PREFIXES.get(prefix)


def is_apple_vendor(mac: Optional[str]) -> bool:
    """Check if the MAC OUI belongs to Apple."""
    if not mac:
        return False
    return mac.upper()[:8] in APPLE_OUI_PREFIXES


def ttl_to_os(ttl: Optional[int]) -> Tuple[str, float, str]:
    """
    Map IP TTL response value to baseline OS guess and weight.
    Returns (os_guess, confidence_weight, evidence_string).
    """
    if ttl is None:
        return 'unknown', 0.0, 'No ping response / TTL unavailable'
    if ttl <= 64:
        return 'linux', 0.60, f'TTL={ttl} (typically Linux/macOS/Android baseline <= 64)'
    if ttl <= 128:
        return 'windows', 0.60, f'TTL={ttl} (typically Windows baseline <= 128)'
    return 'network_device', 0.40, f'TTL={ttl} (typically Cisco/network hardware baseline > 128)'


def is_tablet_device(hostname: Optional[str]) -> bool:
    """Check if hostname indicates a tablet device."""
    if not hostname:
        return False
    name = hostname.lower()
    return any(t in name for t in ['ipad', 'tablet', 'tab-', 'galaxy-tab', 'lenovo-tab', 'kindle', 'fire-hd'])


def is_mobile_device(hostname: Optional[str], ip: str, mac: Optional[str] = None) -> bool:
    """
    Check if a device is a mobile phone or tablet using hostname patterns and MAC OUI vendor.
    """
    if hostname:
        h = hostname.lower()
        if any(w in h for w in [
            'iphone', 'ipad', 'android', 'phone', 'galaxy', 'redmi', 'oneplus',
            'pixel', 'oppo', 'vivo', 'realme', 'mobile', 'tablet', 'tab-',
        ]):
            return True

    if mac:
        vendor = mac_vendor(mac)
        if vendor in PHONE_VENDORS:
            if vendor == 'Apple':
                # Apple also manufactures Macs; check hostname/heuristics
                if hostname:
                    h = hostname.lower()
                    if any(w in h for w in ['iphone', 'ipad', 'ios']):
                        return True
                    if any(w in h for w in ['macbook', 'imac', 'mac-pro', 'mac-mini', 'mac']):
                        return False
            else:
                return True
    return False


def infer_os_type(
    ip: str,
    ttl: Optional[int],
    hostname: Optional[str],
    mac: Optional[str],
    mac_vendor_: Optional[str],
    services: List[str],
    banner_map: Optional[Dict[str, str]] = None,
    local_system_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Multi-factor OS inference engine combining TTL, hostname, open services,
    banner version tokens, and MAC OUI with explicit evidence trails.
    """
    scores: Dict[str, float] = {'windows': 0.0, 'linux': 0.0, 'macos': 0.0, 'unknown': 0.0}
    evidence: List[str] = []
    banner_map = banner_map or {}

    def add(os_name: str, weight: float, reason: str):
        scores[os_name] = scores.get(os_name, 0.0) + weight
        evidence.append(f"[{os_name.upper()} +{int(weight*100)}%] {reason}")

    # 1. TTL Evidence
    if ttl is not None:
        os_guess, conf, reason = ttl_to_os(ttl)
        if os_guess in ('linux', 'windows'):
            add(os_guess, conf, reason)

    # 2. Hostname Evidence
    if hostname:
        h = hostname.lower()
        if any(w in h for w in ['win', 'desktop-', 'laptop-', 'workstation', 'msft', 'corp-pc']):
            add('windows', 0.85, f"Hostname '{hostname}' indicates Windows workstation")
        if any(w in h for w in ['ubuntu', 'debian', 'centos', 'rhel', 'fedora', 'arch', 'kali', 'server', 'linux']):
            add('linux', 0.85, f"Hostname '{hostname}' indicates Linux system")
        if any(w in h for w in ['macbook', 'imac', 'mac-mini', 'darwin', 'apple']):
            add('macos', 0.90, f"Hostname '{hostname}' indicates Apple macOS system")

    # 3. Banner Evidence
    for svc, raw_banner in banner_map.items():
        if raw_banner:
            b_lower = raw_banner.lower()
            if any(dist in b_lower for dist in ['ubuntu', 'debian', 'centos', 'redhat', 'fedora', 'linux']):
                add('linux', 0.95, f"{svc} banner contains Linux distro token: '{raw_banner[:40]}'")
            if 'microsoft' in b_lower or 'iis' in b_lower or 'win32' in b_lower:
                add('windows', 0.95, f"{svc} banner contains Microsoft token: '{raw_banner[:40]}'")

    # 4. Service Footprint Evidence
    if 'RDP' in services:
        add('windows', 0.75, "RDP service (port 3389) strongly indicates Windows")
    if 'NetBIOS' in services or 'RPC' in services:
        add('windows', 0.40, "NetBIOS/RPC active on system")
    if 'SSH' in services and 'RDP' not in services:
        add('linux', 0.45, "SSH service active without RDP indicates Linux/Unix")

    # 5. MAC OUI Evidence
    if is_apple_vendor(mac):
        add('macos', 0.70, f"MAC vendor is Apple ({mac})")

    # Pick highest scoring OS
    best_os = max(scores, key=lambda k: scores[k])
    total_weight = scores[best_os]

    if total_weight <= 0.0:
        return {'os': 'unknown', 'confidence': 0.0, 'evidence': ['Insufficient telemetry to determine OS']}

    normalized_conf = min(0.99, round(total_weight / (total_weight + 0.3), 2))
    return {
        'os': best_os,
        'confidence': normalized_conf,
        'evidence': evidence,
    }


def classify_device(
    hostname: Optional[str],
    os_type: str,
    os_confidence: float,
    is_mobile: bool,
    services: List[str],
    open_ports: List[int],
    mac: Optional[str] = None,
    is_gateway: bool = False,
    mac_vendor_name: Optional[str] = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Classify device role and asset type with confidence and evidence."""
    evidence: List[str] = []
    vendor = mac_vendor_name or mac_vendor(mac)

    # 1. Default Gateway / Perimeter Router Check
    if is_gateway:
        evidence.append("Active Subnet Default Gateway (primary egress router)")
        if vendor:
            evidence.append(f"Hardware vendor: {vendor}")
        return {'device_type': 'Router / Gateway', 'confidence': 0.95, 'evidence': evidence}

    # 2. Hardware Vendor / Mobile Signature Check
    if is_mobile:
        dtype = 'Tablet' if is_tablet_device(hostname) else 'Mobile Device'
        evidence.append(f"Classified as {dtype} based on hardware vendor ({vendor or 'Mobile'}) / wireless signature")
        if not open_ports:
            evidence.append("No standard server ports exposed (typical for client mobile OS)")
        return {'device_type': dtype, 'confidence': 0.90, 'evidence': evidence}

    # 3. Smart TV / Media Devices
    if hostname:
        h_lower = hostname.lower()
        if any(t in h_lower for t in ['tv', 'roku', 'bravia', 'chromecast', 'firetv', 'appletv', 'smarttv']):
            evidence.append(f"Hostname '{hostname}' indicates Smart TV / Media Streamer")
            return {'device_type': 'Smart TV / Media', 'confidence': 0.88, 'evidence': evidence}

    if vendor:
        v_lower = vendor.lower()
        if any(t in v_lower for t in ['roku', 'lg electronics', 'sony', 'chromecast', 'fire tv']):
            evidence.append(f"MAC vendor '{vendor}' indicates Smart TV / Media Streamer")
            return {'device_type': 'Smart TV / Media', 'confidence': 0.85, 'evidence': evidence}

        # 4. IoT Devices (Espressif, Tuya, Raspberry Pi)
        if any(t in v_lower for t in ['espressif', 'tuya', 'raspberry pi']):
            evidence.append(f"Hardware manufacturer '{vendor}' indicates embedded IoT / Microcontroller")
            return {'device_type': 'IoT Device', 'confidence': 0.92, 'evidence': evidence}

        # 5. Network Routers / Switches / APs
        if any(t in v_lower for t in ['tp-link', 'netgear', 'd-link', 'asus', 'cisco', 'trendnet', 'mikrotik', 'ubiquiti']):
            evidence.append(f"Hardware manufacturer '{vendor}' indicates Network Appliance / AP")
            return {'device_type': 'Network Appliance', 'confidence': 0.88, 'evidence': evidence}

    # 6. Database Servers
    if any(db in services for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        evidence.append(f"Exposes database services ({', '.join(services)})")
        return {'device_type': 'Database Server', 'confidence': 0.95, 'evidence': evidence}

    # 7. Web / Application Servers
    if any(w in services for w in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt']) and len(open_ports) >= 2:
        evidence.append(f"Exposes web server services ({', '.join(services)})")
        return {'device_type': 'Web Server', 'confidence': 0.90, 'evidence': evidence}

    # 8. Linux Server / Workstation
    if 'SSH' in services or os_type == 'linux':
        evidence.append(f"Operating system {os_type} with services {', '.join(services) or 'none'}")
        dtype = 'Linux Server' if len(services) > 1 else 'Linux Workstation'
        return {'device_type': dtype, 'confidence': 0.85, 'evidence': evidence}

    # 9. Windows Server / Workstation
    if os_type == 'windows':
        dtype = 'Windows Server' if any(s in services for s in ['RPC', 'SMB', 'RDP']) and len(open_ports) > 3 else 'Windows Workstation'
        evidence.append(f"Windows system with {len(open_ports)} open port(s)")
        return {'device_type': dtype, 'confidence': 0.85, 'evidence': evidence}

    # 10. Mac Computer
    if os_type == 'macos':
        return {'device_type': 'Mac Computer', 'confidence': 0.85, 'evidence': ['Apple macOS platform']}

    # 11. Devices without open ports but observed on LAN
    if not open_ports:
        evidence.append("Observed on local subnet via Layer-2 ARP • No tested TCP ports open")
        if vendor:
            evidence.append(f"Hardware manufacturer: {vendor}")
        return {'device_type': 'Network Device', 'confidence': 0.60, 'evidence': evidence}

    return {'device_type': 'Network Device', 'confidence': 0.50, 'evidence': ['Generic network asset']}


def calculate_criticality(
    device_type: str,
    services: List[str],
    open_ports: List[int],
    os_type: str,
) -> Dict[str, Any]:
    """
    Calculate asset criticality rating (1 to 5 stars) with explanation and confidence.
    """
    evidence = []

    if device_type == 'Database Server' or any(db in services for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        evidence.append("Database / High-Value Data Store — Critical 5★ rating")
        return {'level': 5, 'label': 'CRITICAL', 'confidence': 0.95, 'evidence': evidence}

    if device_type in ('Web Server', 'Linux Server', 'Windows Server') or len(open_ports) >= 4:
        evidence.append("Multi-service production server — High 4★ rating")
        return {'level': 4, 'label': 'HIGH', 'confidence': 0.90, 'evidence': evidence}

    if device_type in ('Windows Workstation', 'Linux Workstation', 'Mac Computer'):
        evidence.append("User desktop / corporate endpoint — Medium 3★ rating")
        return {'level': 3, 'label': 'MEDIUM', 'confidence': 0.80, 'evidence': evidence}

    if device_type in ('Mobile Device', 'Tablet'):
        evidence.append("Personal mobile / BYOD peripheral — Low 2★ rating")
        return {'level': 2, 'label': 'LOW', 'confidence': 0.85, 'evidence': evidence}

    evidence.append("Standard network node — Low 2★ rating")
    return {'level': 2, 'label': 'LOW', 'confidence': 0.70, 'evidence': evidence}


def format_device_display_name(hostname: Optional[str], device_type: str, ip: str) -> str:
    """Format human-readable device display name for UI dropdowns and labels."""
    if hostname and hostname != ip:
        return f"{hostname} ({device_type})"
    return f"{device_type} ({ip})"
