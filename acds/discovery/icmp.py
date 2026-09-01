"""
ACDS Multi-Threaded ICMP Probe Engine
Performs concurrent ICMP echo sweeps across candidate IP addresses
and extracts Time-To-Live (TTL) values for OS fingerprinting.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import re
import subprocess
from typing import Dict, List, Optional, Tuple


def ping_single(ip: str, timeout_ms: int = 600) -> Tuple[str, bool, Optional[int]]:
    """
    Ping a single IP address and extract responsiveness + TTL.
    Returns (ip, is_alive, ttl).
    """
    system = platform.system()
    param = "-n" if system == "Windows" else "-c"
    timeout_param = "-w" if system == "Windows" else "-W"
    timeout_val = str(timeout_ms) if system == "Windows" else str(max(1, timeout_ms // 1000))

    try:
        res = subprocess.run(
            ["ping", param, "1", timeout_param, timeout_val, ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=(timeout_ms / 1000.0) + 1.0,
        )
        if res.returncode == 0:
            ttl = None
            m = re.search(r"TTL=(\d+)", res.stdout, re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
            return ip, True, ttl
    except Exception:
        pass
    return ip, False, None


def icmp_sweep(
    ip_list: List[str],
    timeout_ms: int = 600,
    max_workers: int = 50,
) -> Dict[str, Optional[int]]:
    """
    Concurrently sweep IP addresses using ICMP echo requests.
    Returns {ip: ttl} for all responsive hosts.
    """
    results: Dict[str, Optional[int]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_single, ip, timeout_ms): ip for ip in ip_list}
        for future in as_completed(futures):
            ip, is_alive, ttl = future.result()
            if is_alive:
                results[ip] = ttl
    return results
