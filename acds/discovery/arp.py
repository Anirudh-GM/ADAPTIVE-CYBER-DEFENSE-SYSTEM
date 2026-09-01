"""
ACDS Layered ARP Discovery & Hardware MAC Resolution Engine
Implements native active Layer-2 SendARP broadcast probing (Windows iphlpapi),
cross-platform ARP cache parsing, and MAC address resolution.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import platform
import re
import socket
import struct
import subprocess
from typing import Dict, List, Optional, Set, Tuple


def ip_in_subnet(ip: str, base_ip: str) -> bool:
    """Check if an IP belongs to the target /24 subnet."""
    prefix = base_ip.rstrip('.')
    return ip.startswith(prefix + '.')


def send_arp_single_windows(ip_str: str) -> Optional[str]:
    """
    Execute active Layer-2 SendARP probe on Windows via iphlpapi.dll.
    Directly queries the target hardware MAC without requiring ICMP or administrative privileges.
    """
    if platform.system() != "Windows":
        return None
    try:
        iphlpapi = ctypes.windll.iphlpapi
        dest_ip = struct.unpack('<I', socket.inet_aton(ip_str))[0]
        mac_buf = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
        if res == 0:
            mac_bytes = bytes(mac_buf)[:mac_len.value]
            mac_str = ':'.join(f'{b:02X}' for b in mac_bytes)
            if mac_str not in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                return mac_str
    except Exception:
        pass
    return None


def active_arp_discovery(
    ip_list: List[str],
    max_workers: int = 50,
) -> Dict[str, str]:
    """
    Concurrently probe all target IPs using native active Layer-2 ARP.
    Discovers active devices even if ICMP ping and all TCP ports are firewalled.
    """
    discovered: Dict[str, str] = {}
    system = platform.system()

    if system == "Windows":
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(send_arp_single_windows, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    mac = future.result()
                    if mac:
                        discovered[ip] = mac
                except Exception:
                    pass
    return discovered


def parse_arp_table(output: str, subnet_prefix: str) -> Dict[str, str]:
    """Parse system arp -a CLI output into {ip: mac} dictionary."""
    arp_map = {}
    mac_regex = re.compile(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})')

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        ip_cand = parts[0].strip('()')
        if not ip_cand.startswith(subnet_prefix):
            for p in parts:
                cleaned = p.strip('()')
                if cleaned.startswith(subnet_prefix):
                    ip_cand = cleaned
                    break
            else:
                continue

        m = mac_regex.search(line)
        if m:
            mac_str = m.group(0).replace('-', ':').upper()
            if mac_str not in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                arp_map[ip_cand] = mac_str
    return arp_map


def read_system_arp_cache(subnet_prefix: str) -> Dict[str, str]:
    """Execute system arp -a command and return parsed {ip: mac} map."""
    try:
        proc = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
        return parse_arp_table(proc.stdout, subnet_prefix)
    except Exception:
        return {}


def read_arp_map(subnet_prefix: str) -> Dict[str, str]:
    """Backward-compatible wrapper for read_system_arp_cache."""
    return read_system_arp_cache(subnet_prefix)


def combined_arp_discovery(
    ip_list: List[str],
    subnet_prefix: str,
    max_workers: int = 50,
) -> Dict[str, str]:
    """
    Combined Layer-2 ARP discovery:
    Executes Active SendARP probing followed by System ARP cache reconciliation.
    """
    active_results = active_arp_discovery(ip_list, max_workers=max_workers)
    cache_results = read_system_arp_cache(subnet_prefix)

    # Merge: active SendARP takes precedence, cache supplements
    merged = dict(cache_results)
    merged.update(active_results)
    return merged


def lookup_mac_windows(ip: str) -> Optional[str]:
    """Single-host MAC lookup on Windows using SendARP or arp -a."""
    mac = send_arp_single_windows(ip)
    if mac:
        return mac
    if platform.system() != "Windows":
        return None
    try:
        proc = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
        m = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', proc.stdout)
        if m:
            mac_cand = m.group(0).replace('-', ':').upper()
            if mac_cand not in ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00'):
                return mac_cand
    except Exception:
        pass
    return None
