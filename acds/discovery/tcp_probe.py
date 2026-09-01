"""
ACDS Fast TCP Discovery Probe Engine
Provides non-blocking, multi-threaded TCP connection checks across common LAN ports
to identify active devices that filter ICMP echo requests or Layer-2 broadcast.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from typing import List, Set

COMMON_LAN_DISCOVERY_PORTS: List[int] = [
    80, 443, 53, 8080, 445, 139, 8008, 62078,
]


def _probe_host_tcp(ip: str, ports: List[int], timeout: float = 0.20) -> bool:
    """Check if any of the target ports accept a TCP connection."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def quick_tcp_probe(
    ip_list: List[str],
    ports: List[int] = COMMON_LAN_DISCOVERY_PORTS,
    timeout: float = 0.20,
    max_workers: int = 50,
) -> Set[str]:
    """
    Perform fast concurrent TCP discovery probing across candidate IP addresses.
    Returns set of responsive IP addresses.
    """
    responsive: Set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_host_tcp, ip, ports, timeout): ip for ip in ip_list}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    responsive.add(ip)
            except Exception:
                pass
    return responsive
