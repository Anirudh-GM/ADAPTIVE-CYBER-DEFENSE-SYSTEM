"""
ACDS Continuous Asset Inventory Tracker
Maintains persistent asset records across scan sessions, tracks first/last seen timestamps,
computes lifecycle status (NEW, ACTIVE, MISSING, CHANGED), and detects state changes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any, Tuple
import networkx as nx


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class InventoryAsset:
    """Represents a tracked asset in the continuous inventory."""
    asset_id: str
    ip: str
    hostname: Optional[str]
    display_name: str
    mac: Optional[str]
    mac_vendor: Optional[str]
    os: str
    os_confidence: float
    device_type: str
    role: str
    criticality: int
    criticality_label: str
    risk_score: float
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    status: str = "NEW"  # NEW | ACTIVE | MISSING | CHANGED
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)
    changes_detected: List[str] = field(default_factory=list)
    scan_history_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "hostname": self.hostname,
            "display_name": self.display_name,
            "mac": self.mac,
            "mac_vendor": self.mac_vendor,
            "os": self.os,
            "os_confidence": self.os_confidence,
            "device_type": self.device_type,
            "role": self.role,
            "criticality": self.criticality,
            "criticality_label": self.criticality_label,
            "risk_score": self.risk_score,
            "open_ports": list(self.open_ports),
            "services": list(self.services),
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "changes_detected": list(self.changes_detected),
            "scan_history_count": self.scan_history_count,
        }


class AssetInventoryTracker:
    """
    Central asset state manager for ACDS.
    Reconciles new scan results against previous inventory snapshots.
    """

    def __init__(self, initial_assets: Optional[Dict[str, InventoryAsset]] = None):
        self._inventory: Dict[str, InventoryAsset] = dict(initial_assets or {})

    @property
    def inventory(self) -> Dict[str, InventoryAsset]:
        return dict(self._inventory)

    @staticmethod
    def derive_asset_id(ip: str, mac: Optional[str] = None) -> str:
        """Generate a consistent unique identifier for an asset."""
        if mac and mac.upper() not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            return f"MAC-{mac.upper().replace(':', '')}"
        return f"IP-{ip.replace('.', '_')}"

    def update_from_graph(self, G: nx.DiGraph, timestamp: Optional[str] = None) -> Dict[str, InventoryAsset]:
        """Update inventory state from a NetworkX topology graph."""
        scanned_assets: List[Dict[str, Any]] = []
        for node, data in G.nodes(data=True):
            if data.get("node_type") == "honeypot":
                continue
            scanned_assets.append({
                "ip": data.get("ip", node),
                "hostname": data.get("hostname"),
                "display_name": data.get("display_name", node),
                "mac": data.get("mac"),
                "mac_vendor": data.get("mac_vendor"),
                "os": data.get("os", "unknown"),
                "os_confidence": data.get("os_confidence", 0.0),
                "device_type": data.get("device_type", "Network Device"),
                "role": data.get("role", "Workstation"),
                "criticality": data.get("criticality", 3),
                "criticality_label": data.get("criticality_label", "MEDIUM"),
                "risk_score": data.get("risk_score", 0.0),
                "open_ports": data.get("open_ports", []),
                "services": data.get("services", []),
            })
        return self.update_from_scan(scanned_assets, timestamp=timestamp)

    def update_from_scan(
        self,
        scanned_assets: List[Dict[str, Any]],
        timestamp: Optional[str] = None,
    ) -> Dict[str, InventoryAsset]:
        """
        Reconcile current scan against historical inventory.
        Detects NEW, ACTIVE, CHANGED, and MISSING assets.
        """
        now = timestamp or _now_iso()
        seen_asset_ids: Set[str] = set()

        for raw in scanned_assets:
            ip = raw.get("ip", "")
            mac = raw.get("mac")
            asset_id = self.derive_asset_id(ip, mac)
            seen_asset_ids.add(asset_id)

            hostname = raw.get("hostname")
            display = raw.get("display_name") or hostname or ip
            vendor = raw.get("mac_vendor")
            os_name = raw.get("os", "unknown")
            os_conf = raw.get("os_confidence", 0.0)
            dev_type = raw.get("device_type", "Network Device")
            role = raw.get("role", "Workstation")
            crit = int(raw.get("criticality", 3))
            crit_lbl = raw.get("criticality_label") or ("CRITICAL" if crit == 5 else "HIGH" if crit == 4 else "MEDIUM" if crit == 3 else "LOW")
            risk = float(raw.get("risk_score", 0.0))
            ports = sorted(list(raw.get("open_ports", [])))
            services = sorted(list(raw.get("services", [])))

            if asset_id not in self._inventory:
                # Brand new asset discovered
                new_asset = InventoryAsset(
                    asset_id=asset_id,
                    ip=ip,
                    hostname=hostname,
                    display_name=display,
                    mac=mac,
                    mac_vendor=vendor,
                    os=os_name,
                    os_confidence=os_conf,
                    device_type=dev_type,
                    role=role,
                    criticality=crit,
                    criticality_label=crit_lbl,
                    risk_score=risk,
                    open_ports=ports,
                    services=services,
                    status="NEW",
                    first_seen=now,
                    last_seen=now,
                    changes_detected=["First discovered on subnet"],
                    scan_history_count=1,
                )
                self._inventory[asset_id] = new_asset
            else:
                # Existing asset present: check for changes
                existing = self._inventory[asset_id]
                changes = []

                if existing.ip != ip:
                    changes.append(f"IP address changed: {existing.ip} -> {ip}")
                if existing.hostname != hostname and hostname:
                    changes.append(f"Hostname updated: {existing.hostname} -> {hostname}")
                if set(existing.open_ports) != set(ports):
                    opened = sorted(list(set(ports) - set(existing.open_ports)))
                    closed = sorted(list(set(existing.open_ports) - set(ports)))
                    if opened:
                        changes.append(f"New ports opened: {opened}")
                    if closed:
                        changes.append(f"Ports closed: {closed}")
                if set(existing.services) != set(services):
                    changes.append(f"Services changed: {existing.services} -> {services}")
                if abs(existing.risk_score - risk) >= 5.0:
                    delta = round(risk - existing.risk_score, 1)
                    sign = "+" if delta > 0 else ""
                    changes.append(f"Risk score shifted: {existing.risk_score} -> {risk} ({sign}{delta})")

                existing.ip = ip
                existing.hostname = hostname or existing.hostname
                existing.display_name = display
                existing.mac = mac or existing.mac
                existing.mac_vendor = vendor or existing.mac_vendor
                existing.os = os_name
                existing.os_confidence = os_conf
                existing.device_type = dev_type
                existing.role = role
                existing.criticality = crit
                existing.criticality_label = crit_lbl
                existing.risk_score = risk
                existing.open_ports = ports
                existing.services = services
                existing.last_seen = now
                existing.scan_history_count += 1

                if changes:
                    existing.status = "CHANGED"
                    existing.changes_detected = changes
                else:
                    existing.status = "ACTIVE"
                    existing.changes_detected = []

        # Mark assets missing from current scan
        for asset_id, asset in self._inventory.items():
            if asset_id not in seen_asset_ids:
                asset.status = "MISSING"
                asset.changes_detected = [f"Unresponsive in latest scan (last seen {asset.last_seen})"]

        return self.inventory

    def get_summary(self) -> Dict[str, Any]:
        """Compute aggregate inventory breakdown metrics."""
        total = len(self._inventory)
        new_cnt = sum(1 for a in self._inventory.values() if a.status == "NEW")
        active_cnt = sum(1 for a in self._inventory.values() if a.status == "ACTIVE")
        missing_cnt = sum(1 for a in self._inventory.values() if a.status == "MISSING")
        changed_cnt = sum(1 for a in self._inventory.values() if a.status == "CHANGED")
        critical_cnt = sum(1 for a in self._inventory.values() if a.criticality >= 4)
        avg_risk = round(sum(a.risk_score for a in self._inventory.values()) / max(total, 1), 1)

        return {
            "total_assets": total,
            "new_assets": new_cnt,
            "active_assets": active_cnt,
            "missing_assets": missing_cnt,
            "changed_assets": changed_cnt,
            "critical_assets": critical_cnt,
            "average_risk": avg_risk,
        }

    def to_inventory_table(self) -> List[Dict[str, Any]]:
        """Return formatted asset list for table presentation."""
        return [
            {
                "IP": a.ip,
                "Hostname": a.hostname or "—",
                "Type": a.device_type,
                "Role": a.role,
                "Criticality": f"{a.criticality}-Star ({a.criticality_label})",
                "Risk": round(a.risk_score, 1),
                "Status": a.status,
                "Ports": ", ".join(map(str, a.open_ports)) if a.open_ports else "None",
                "Services": ", ".join(a.services) if a.services else "None",
                "Last Seen": a.last_seen,
            }
            for a in sorted(self._inventory.values(), key=lambda item: (-item.risk_score, item.ip))
        ]
