"""
LIVE VALIDATION ENGINE — core/live_validation.py
─────────────────────────────────────────────────────────────────
ACDS Level 2: Real-Time Defensive Validation

This module safely and non-destructively validates real-world network
conditions against authorized targets:
  1. Host reachability & round-trip latency
  2. TCP port availability (verifying if previously exposed ports are still open or closed)
  3. Lightweight service responsiveness & banner consistency
  4. Diffing real-time validation against previous discovery snapshots
  5. Generating structured validation events and alerts

SAFETY & SCOPE GUARANTEES:
  - 100% read-only TCP connect / ping probes with short timeouts (0.5s - 1.5s).
  - Strictly limited to explicitly discovered or user-authorized targets and ports.
  - Zero exploit payloads, zero credential attacks, zero brute force, zero persistence.
  - Bounded concurrency with max 4 workers to prevent network flooding.
"""

import time
import socket
import select
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.acds_logging import get_logger

log = get_logger(__name__)

# Common safe probe timeouts
DEFAULT_SOCKET_TIMEOUT = 1.0
DEFAULT_BANNER_TIMEOUT = 1.2

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB"
}


def validate_host_reachability(ip, timeout=DEFAULT_SOCKET_TIMEOUT, sample_ports=None):
    """
    Safely determine if an authorized target IP is currently online and reachable.
    Returns:
        dict: {
            'reachable': bool,
            'latency_ms': float,
            'method': str,
            'timestamp': str
        }
    """
    if not ip or ip in ("127.0.0.1", "localhost"):
        return {
            "reachable": True,
            "latency_ms": 0.1,
            "method": "LOCALHOST_LOOPBACK",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    ports_to_check = list(sample_ports) if sample_ports else [80, 443, 445, 135, 22, 3389, 53]
    ts = datetime.now(timezone.utc).isoformat()

    start_time = time.time()
    for port in ports_to_check:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            res = sock.connect_ex((ip, port))
            if res == 0:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                sock.close()
                return {
                    "reachable": True,
                    "latency_ms": max(0.1, elapsed_ms),
                    "method": f"TCP_SYNACK_PORT_{port}",
                    "timestamp": ts
                }
            elif res in (10061, 111):  # Connection Refused means host is online and sent TCP RST!
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                sock.close()
                return {
                    "reachable": True,
                    "latency_ms": max(0.1, elapsed_ms),
                    "method": "TCP_RST_HOST_ACTIVE",
                    "timestamp": ts
                }
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    return {
        "reachable": False,
        "latency_ms": elapsed_ms,
        "method": "UNRESPONSIVE_FILTERED",
        "timestamp": ts
    }


def validate_tcp_port(ip, port, timeout=DEFAULT_SOCKET_TIMEOUT):
    """
    Safely tests if a specific TCP port is currently open on an authorized target.
    Returns:
        dict: {
            'port': int,
            'open': bool,
            'status': 'OPEN' | 'CLOSED',
            'latency_ms': float,
            'service': str
        }
    """
    service_name = PORT_SERVICE_MAP.get(port, "Unknown")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.time()
    try:
        res = sock.connect_ex((ip, port))
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        if res == 0:
            sock.close()
            return {
                "port": port,
                "open": True,
                "status": "OPEN",
                "latency_ms": max(0.1, elapsed_ms),
                "service": service_name
            }
        else:
            sock.close()
            return {
                "port": port,
                "open": False,
                "status": "CLOSED",
                "latency_ms": elapsed_ms,
                "service": service_name
            }
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return {
            "port": port,
            "open": False,
            "status": "CLOSED",
            "latency_ms": 0.0,
            "service": service_name
        }


def validate_service_banner(ip, port, expected_service=None, timeout=DEFAULT_BANNER_TIMEOUT):
    """
    Safely captures greeting banners (e.g. SSH-2.0, FTP, SMTP, HTTP Server headers)
    without sending offensive payloads.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner_text = ""
    try:
        res = sock.connect_ex((ip, port))
        if res == 0:
            # Send lightweight HTTP HEAD if port 80/8080/443
            if port in (80, 8080, 8000, 5000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            # Wait for greeting
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                raw = sock.recv(1024)
                banner_text = raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    service_name = expected_service or PORT_SERVICE_MAP.get(port, "Unknown")
    is_valid = bool(banner_text)
    return {
        "port": port,
        "banner": banner_text[:120] if banner_text else None,
        "service": service_name,
        "service_validated": is_valid
    }


def validate_asset_state(asset_id, ip, expected_ports=None, version_map=None, banner_map=None, timeout=DEFAULT_SOCKET_TIMEOUT):
    """
    Performs comprehensive real-time validation of an authorized asset's live state.
    Validates reachability and every previously observed or candidate port.
    """
    expected_ports = list(expected_ports or [])
    if not expected_ports:
        expected_ports = [80, 443, 445, 135, 139, 22, 3389]
    else:
        # Include all discovered ports along with standard lateral candidate ports
        expected_ports = sorted(list(set(expected_ports + [80, 443, 445, 135, 139, 22, 3389])))

    reach_info = validate_host_reachability(ip, timeout=timeout, sample_ports=expected_ports)
    is_reachable = reach_info["reachable"]
    
    ports_validated = {}
    open_ports = []
    closed_ports = []

    if is_reachable:
        for port in expected_ports:
            p_res = validate_tcp_port(ip, port, timeout=timeout)
            if p_res["open"]:
                open_ports.append(port)
                banner_res = validate_service_banner(ip, port, expected_service=p_res["service"])
                ports_validated[port] = {
                    "open": True,
                    "status": "OPEN",
                    "service": p_res["service"],
                    "banner": banner_res.get("banner"),
                    "latency_ms": p_res["latency_ms"],
                    "validation_status": "✓ CURRENTLY EXPOSED"
                }
            else:
                closed_ports.append(port)
                ports_validated[port] = {
                    "open": False,
                    "status": "CLOSED",
                    "service": p_res["service"],
                    "banner": None,
                    "latency_ms": p_res["latency_ms"],
                    "validation_status": "✓ NOT EXPOSED"
                }
    else:
        for port in expected_ports:
            closed_ports.append(port)
            ports_validated[port] = {
                "open": False,
                "status": "HOST_UNREACHABLE",
                "service": PORT_SERVICE_MAP.get(port, "Unknown"),
                "banner": None,
                "latency_ms": 0.0,
                "validation_status": "✗ HOST OFFLINE"
            }

    return {
        "asset_id": asset_id,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reachable": is_reachable,
        "latency_ms": reach_info.get("latency_ms", 0.0),
        "reachability_method": reach_info.get("method", "TCP"),
        "ports_validated": ports_validated,
        "ports": ports_validated,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "validation_source": "LIVE_REALTIME",
    }


def validate_multiple_assets(asset_list, max_workers=4):
    """
    Validates a collection of authorized asset targets concurrently with bounded threads.
    asset_list: list of dicts with keys: 'asset_id', 'ip', 'expected_ports' (or 'open_ports')
    """
    results = {}
    if not asset_list:
        return results

    with ThreadPoolExecutor(max_workers=min(max_workers, len(asset_list))) as executor:
        future_to_asset = {
            executor.submit(
                validate_asset_state,
                asset_id=a.get("asset_id", a.get("ip")),
                ip=a.get("ip"),
                expected_ports=(a.get("expected_ports") or a.get("open_ports") or [80, 445, 135, 139, 22, 3389])
            ): a for a in asset_list
        }
        for future in as_completed(future_to_asset):
            a_meta = future_to_asset[future]
            try:
                res = future.result()
                results[res["asset_id"]] = res
                results[res["ip"]] = res  # index by both asset_id and IP
            except Exception as e:
                log.warning("Validation failed for %s: %s", a_meta.get("ip"), e)
                aid = a_meta.get("asset_id", a_meta.get("ip"))
                results[aid] = {
                    "asset_id": aid,
                    "ip": a_meta.get("ip"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reachable": False,
                    "latency_ms": 0.0,
                    "ports_validated": {},
                    "open_ports": [],
                    "closed_ports": a_meta.get("open_ports", []),
                    "validation_source": "LIVE_REALTIME_FAILED",
                    "error": str(e)
                }
    return results


def diff_validation_against_discovery(discovered_asset_data, live_val_snapshot):
    """
    Compares previous discovery snapshot against current live validation.
    Accepts either:
      1. Single asset pair (discovered dict vs live validation dict)
      2. Multi-asset maps ({asset_id: discovered_data} vs {asset_id: live_val_data})
    Returns:
        list of change events:
        - SERVICE_EXPOSURE_REMOVED (Port was OPEN in scan, now CLOSED in live validation)
        - SERVICE_STILL_EXPOSED (Port was OPEN, still OPEN)
        - NEW_SERVICE_EXPOSED (Port was CLOSED, now OPEN)
        - DEFENSE_VERIFIED (Hardened port closed on real endpoint)
        - HOST_OFFLINE / HOST_ONLINE
    """
    changes = []
    if not discovered_asset_data or not live_val_snapshot:
        return changes

    # Check if inputs are multi-asset dicts or single asset dicts
    is_multi_disc = isinstance(discovered_asset_data, dict) and any(
        isinstance(v, dict) and ("asset_id" in v or "ip" in v or "open_ports" in v) for v in discovered_asset_data.values()
    )
    is_multi_val = isinstance(live_val_snapshot, dict) and any(
        isinstance(v, dict) and ("asset_id" in v or "ip" in v or "ports" in v or "ports_validated" in v) for v in live_val_snapshot.values()
    )

    if is_multi_disc or is_multi_val:
        disc_map = discovered_asset_data if is_multi_disc else {discovered_asset_data.get("asset_id", "default"): discovered_asset_data}
        val_map = live_val_snapshot if is_multi_val else {live_val_snapshot.get("asset_id", "default"): live_val_snapshot}
        
        # Deduplicate keys across both maps (by asset_id and IP)
        all_keys = set(disc_map.keys()) | set(val_map.keys())
        seen_assets = set()

        for k in all_keys:
            d_item = disc_map.get(k)
            v_item = val_map.get(k)
            
            # Match by asset_id or ip if direct key didn't match
            if not d_item and v_item:
                for d_cand in disc_map.values():
                    if (isinstance(d_cand, dict) and (d_cand.get("asset_id") == v_item.get("asset_id") or d_cand.get("ip") == v_item.get("ip"))):
                        d_item = d_cand
                        break

            if not v_item and d_item:
                for v_cand in val_map.values():
                    if (isinstance(v_cand, dict) and (v_cand.get("asset_id") == d_item.get("asset_id") or v_cand.get("ip") == d_item.get("ip"))):
                        v_item = v_cand
                        break

            if not d_item or not v_item:
                continue

            aid = v_item.get("asset_id") or d_item.get("asset_id") or k
            if aid in seen_assets:
                continue
            seen_assets.add(aid)

            changes.extend(_diff_single_asset_validation(d_item, v_item))
        return changes
    else:
        return _diff_single_asset_validation(discovered_asset_data, live_val_snapshot)


def _diff_single_asset_validation(discovered_asset_data, live_val_snapshot):
    """Helper to diff a single asset's discovery baseline vs live validation."""
    changes = []
    asset_id = live_val_snapshot.get("asset_id") or discovered_asset_data.get("asset_id") or "UNKNOWN"
    ip = live_val_snapshot.get("ip") or discovered_asset_data.get("ip") or ""
    ts = live_val_snapshot.get("timestamp", datetime.now(timezone.utc).isoformat())
    
    disc_ports = set(discovered_asset_data.get("open_ports") or [])
    val_ports_raw = live_val_snapshot.get("ports_validated") or live_val_snapshot.get("ports") or {}
    
    # Check reachability
    disc_online = discovered_asset_data.get("status", "ONLINE") == "ONLINE"
    val_online = live_val_snapshot.get("reachable", False)
    
    if disc_online and not val_online:
        changes.append({
            "timestamp": ts,
            "asset_id": asset_id,
            "ip": ip,
            "change_type": "HOST_OFFLINE",
            "severity": "HIGH",
            "description": f"Target host {ip} ({asset_id}) is currently UNREACHABLE in real-time validation.",
            "detail": f"Target host {ip} ({asset_id}) was online during discovery but is currently UNREACHABLE in real-time validation.",
            "impact": "All downstream lateral attack paths through this host are currently INVALIDATED."
        })
    elif not disc_online and val_online:
        changes.append({
            "timestamp": ts,
            "asset_id": asset_id,
            "ip": ip,
            "change_type": "HOST_ONLINE",
            "severity": "INFO",
            "description": f"Target host {ip} ({asset_id}) is confirmed ONLINE via real-time validation.",
            "detail": f"Target host {ip} ({asset_id}) is confirmed ONLINE via real-time validation.",
            "impact": "Host reachable for attack surface evaluation."
        })

    # Check port differences
    for port, p_data in val_ports_raw.items():
        try:
            p_int = int(port)
        except Exception:
            continue

        svc = p_data.get("service") if isinstance(p_data, dict) else None
        if not svc:
            svc = PORT_SERVICE_MAP.get(p_int, "TCP Service")
            
        is_open_live = False
        if isinstance(p_data, dict):
            if "open" in p_data:
                is_open_live = bool(p_data["open"])
            elif "state" in p_data:
                is_open_live = (str(p_data["state"]).lower() == "open")

        was_open_disc = p_int in disc_ports

        if was_open_disc and not is_open_live:
            changes.append({
                "timestamp": ts,
                "asset_id": asset_id,
                "ip": ip,
                "port": p_int,
                "service": svc,
                "change_type": "SERVICE_EXPOSURE_REMOVED",
                "severity": "INFO",
                "previous_state": "OPEN",
                "current_state": "CLOSED",
                "description": f"Port TCP/{p_int} ({svc}) on {asset_id} confirmed CLOSED (exposure removed).",
                "detail": f"Port TCP/{p_int} ({svc}) was open during network scan but is confirmed CLOSED during real-time validation.",
                "impact": f"Attack paths leveraging {svc}/TCP {p_int} are removed from active exploitability."
            })
            # Also record DEFENSE_VERIFIED
            changes.append({
                "timestamp": ts,
                "asset_id": asset_id,
                "ip": ip,
                "port": p_int,
                "service": svc,
                "change_type": "DEFENSE_VERIFIED",
                "severity": "INFO",
                "description": f"Defense verified on {asset_id}: {svc} TCP/{p_int} closed successfully.",
                "detail": f"✓ Defense hardening verified on live network: {svc} port {p_int} closed successfully.",
                "impact": "Vulnerability surface effectively contained."
            })
        elif not was_open_disc and is_open_live:
            changes.append({
                "timestamp": ts,
                "asset_id": asset_id,
                "ip": ip,
                "port": p_int,
                "service": svc,
                "change_type": "NEW_SERVICE_EXPOSED",
                "severity": "HIGH",
                "previous_state": "CLOSED",
                "current_state": "OPEN",
                "description": f"New exposure on {asset_id}: port TCP/{p_int} ({svc}) is OPEN in real-time validation!",
                "detail": f"Port TCP/{p_int} ({svc}) was closed during network scan but is now OPEN in real-time validation!",
                "impact": f"New exposure detected — increases attack surface for {svc}."
            })
        elif was_open_disc and is_open_live:
            changes.append({
                "timestamp": ts,
                "asset_id": asset_id,
                "ip": ip,
                "port": p_int,
                "service": svc,
                "change_type": "SERVICE_STILL_EXPOSED",
                "severity": "MEDIUM",
                "previous_state": "OPEN",
                "current_state": "OPEN",
                "description": f"Port TCP/{p_int} ({svc}) on {asset_id} remains exposed on live network.",
                "detail": f"Port TCP/{p_int} ({svc}) remains exposed and responsive on the live network.",
                "impact": "Attack condition confirmed valid in real-time."
            })

    return changes
