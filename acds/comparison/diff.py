"""
ACDS Scan-to-Scan Change Detection & Differential Engine
Compares historical scan snapshots (Scan N vs Scan N-1) to detect new/removed devices,
port mutations, software version upgrades/downgrades, newly introduced vs resolved CVEs,
and network-wide risk score deltas.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
import networkx as nx


@dataclass
class AssetDiff:
    """Represents detected mutations on a specific network asset."""
    ip: str
    hostname: Optional[str]
    change_type: str  # NEW_DEVICE | REMOVED_DEVICE | PORTS_CHANGED | VERSION_CHANGED | RISK_CHANGED | UNCHANGED
    details: List[str] = field(default_factory=list)
    risk_before: Optional[float] = None
    risk_after: Optional[float] = None
    risk_delta: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "change_type": self.change_type,
            "details": list(self.details),
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "risk_delta": self.risk_delta,
        }


@dataclass
class ScanComparisonResult:
    """Full differential report between two scan sessions."""
    previous_scan_time: str
    current_scan_time: str
    new_devices: List[Dict[str, Any]] = field(default_factory=list)
    removed_devices: List[Dict[str, Any]] = field(default_factory=list)
    modified_devices: List[AssetDiff] = field(default_factory=list)
    new_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    resolved_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_delta_summary: Dict[str, Any] = field(default_factory=dict)
    summary_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_scan_time": self.previous_scan_time,
            "current_scan_time": self.current_scan_time,
            "new_devices": self.new_devices,
            "removed_devices": self.removed_devices,
            "modified_devices": [d.to_dict() for d in self.modified_devices],
            "new_vulnerabilities": self.new_vulnerabilities,
            "resolved_vulnerabilities": self.resolved_vulnerabilities,
            "risk_delta_summary": self.risk_delta_summary,
            "summary_counts": self.summary_counts,
        }


def _extract_asset_map(data: Any) -> Dict[str, Dict[str, Any]]:
    """Helper to convert graph or list into an IP-keyed dictionary."""
    result = {}
    if isinstance(data, nx.DiGraph):
        for node, d in data.nodes(data=True):
            if d.get("node_type") == "honeypot":
                continue
            ip = d.get("ip", str(node))
            result[ip] = dict(d, node_key=node)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                ip = item.get("ip") or item.get("node_key") or "unknown"
                result[ip] = dict(item)
            elif isinstance(item, tuple) and len(item) >= 1:
                ip = item[0]
                result[ip] = {
                    "ip": ip,
                    "hostname": item[1] if len(item) > 1 else None,
                    "os": item[2] if len(item) > 2 else "unknown",
                    "open_ports": item[8] if len(item) > 8 else [],
                    "services": item[9] if len(item) > 9 else [],
                    "version_map": item[10] if len(item) > 10 else {},
                    "device_type": item[12] if len(item) > 12 else "Network Device",
                    "risk_score": 0.0,
                }
    elif isinstance(data, dict):
        result = dict(data)
    return result


def compare_scans(
    previous_scan_data: Any,
    current_scan_data: Any,
    prev_time: str = "Previous Scan",
    curr_time: str = "Current Scan",
) -> ScanComparisonResult:
    """
    Perform forensic differential comparison between two scan sessions.
    """
    prev_map = _extract_asset_map(previous_scan_data)
    curr_map = _extract_asset_map(current_scan_data)

    prev_ips = set(prev_map.keys())
    curr_ips = set(curr_map.keys())

    new_ips = sorted(list(curr_ips - prev_ips))
    removed_ips = sorted(list(prev_ips - curr_ips))
    common_ips = sorted(list(prev_ips & curr_ips))

    new_devices = []
    for ip in new_ips:
        d = curr_map[ip]
        new_devices.append({
            "ip": ip,
            "hostname": d.get("hostname") or d.get("display_name") or ip,
            "device_type": d.get("device_type", "Network Device"),
            "risk_score": float(d.get("risk_score", 0.0)),
            "open_ports": list(d.get("open_ports", [])),
        })

    removed_devices = []
    for ip in removed_ips:
        d = prev_map[ip]
        removed_devices.append({
            "ip": ip,
            "hostname": d.get("hostname") or d.get("display_name") or ip,
            "device_type": d.get("device_type", "Network Device"),
            "risk_score": float(d.get("risk_score", 0.0)),
            "last_ports": list(d.get("open_ports", [])),
        })

    modified_devices: List[AssetDiff] = []
    all_prev_cves: Set[Tuple[str, str]] = set()  # (ip, cve_id)
    all_curr_cves: Set[Tuple[str, str]] = set()

    for ip in prev_ips:
        for cve in prev_map[ip].get("cve_findings", []):
            all_prev_cves.add((ip, cve.get("cve_id", "Unknown")))

    for ip in curr_ips:
        for cve in curr_map[ip].get("cve_findings", []):
            all_curr_cves.add((ip, cve.get("cve_id", "Unknown")))

    for ip in common_ips:
        p = prev_map[ip]
        c = curr_map[ip]
        details = []

        p_ports = set(p.get("open_ports", []))
        c_ports = set(c.get("open_ports", []))

        if p_ports != c_ports:
            opened = sorted(list(c_ports - p_ports))
            closed = sorted(list(p_ports - c_ports))
            if opened:
                details.append(f"Port(s) opened: {opened}")
            if closed:
                details.append(f"Port(s) closed: {closed}")

        p_vers = p.get("version_map", {})
        c_vers = c.get("version_map", {})
        for svc, ver in c_vers.items():
            if svc in p_vers and p_vers[svc] != ver:
                details.append(f"Version changed on {svc}: {p_vers[svc]} -> {ver}")

        p_risk = float(p.get("risk_score", 0.0))
        c_risk = float(c.get("risk_score", 0.0))
        risk_delta = round(c_risk - p_risk, 1)

        if abs(risk_delta) >= 1.0:
            sign = "+" if risk_delta > 0 else ""
            details.append(f"Risk shift: {p_risk} -> {c_risk} ({sign}{risk_delta})")

        if details:
            diff_item = AssetDiff(
                ip=ip,
                hostname=c.get("hostname") or c.get("display_name") or ip,
                change_type="MODIFIED",
                details=details,
                risk_before=p_risk,
                risk_after=c_risk,
                risk_delta=risk_delta,
            )
            modified_devices.append(diff_item)

    # Vulnerability deltas
    new_cve_tuples = all_curr_cves - all_prev_cves
    resolved_cve_tuples = all_prev_cves - all_curr_cves

    new_vulnerabilities = [{"ip": ip, "cve_id": cve} for ip, cve in sorted(new_cve_tuples)]
    resolved_vulnerabilities = [{"ip": ip, "cve_id": cve} for ip, cve in sorted(resolved_cve_tuples)]

    # Risk summary
    prev_avg_risk = round(sum(float(d.get("risk_score", 0.0)) for d in prev_map.values()) / max(len(prev_map), 1), 1)
    curr_avg_risk = round(sum(float(d.get("risk_score", 0.0)) for d in curr_map.values()) / max(len(curr_map), 1), 1)
    net_risk_delta = round(curr_avg_risk - prev_avg_risk, 1)

    risk_summary = {
        "previous_average_risk": prev_avg_risk,
        "current_average_risk": curr_avg_risk,
        "risk_delta": net_risk_delta,
        "risk_direction": "IMPROVED" if net_risk_delta < 0 else "INCREASED" if net_risk_delta > 0 else "UNCHANGED",
    }

    counts = {
        "new_devices_count": len(new_devices),
        "removed_devices_count": len(removed_devices),
        "modified_devices_count": len(modified_devices),
        "new_vulnerabilities_count": len(new_vulnerabilities),
        "resolved_vulnerabilities_count": len(resolved_vulnerabilities),
        "total_previous_assets": len(prev_map),
        "total_current_assets": len(curr_map),
    }

    return ScanComparisonResult(
        previous_scan_time=prev_time,
        current_scan_time=curr_time,
        new_devices=new_devices,
        removed_devices=removed_devices,
        modified_devices=modified_devices,
        new_vulnerabilities=new_vulnerabilities,
        resolved_vulnerabilities=resolved_vulnerabilities,
        risk_delta_summary=risk_summary,
        summary_counts=counts,
    )
