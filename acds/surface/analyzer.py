"""
ACDS Attack Surface Management & Exposure Hierarchy Analyzer
Evaluates enterprise exposure metrics, categorizes open services, identifies high-risk
administrative & database protocols, and builds hierarchical drill-down trees.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx

INTERNET_FACING_PORTS: Set[int] = {80, 443, 8080, 8443, 53, 25}
HIGH_RISK_PORTS: Set[int] = {21, 23, 135, 139, 445, 3389, 5900}
DATABASE_PORTS: Set[int] = {3306, 5432, 6379, 27017}
SENSITIVE_PORTS: Set[int] = HIGH_RISK_PORTS | DATABASE_PORTS | {22}


@dataclass
class AttackSurfaceMetrics:
    """Quantitative organization attack surface metrics."""
    total_assets: int
    exposed_assets: int
    unexposed_assets: int
    open_services_count: int
    internet_facing_count: int
    high_risk_services_count: int
    database_services_count: int
    vulnerable_services_count: int
    critical_exposure_count: int
    attack_surface_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_assets": self.total_assets,
            "exposed_assets": self.exposed_assets,
            "unexposed_assets": self.unexposed_assets,
            "open_services_count": self.open_services_count,
            "internet_facing_count": self.internet_facing_count,
            "high_risk_services_count": self.high_risk_services_count,
            "database_services_count": self.database_services_count,
            "vulnerable_services_count": self.vulnerable_services_count,
            "critical_exposure_count": self.critical_exposure_count,
            "attack_surface_ratio": self.attack_surface_ratio,
        }


def analyze_attack_surface(network_data: Any) -> Dict[str, Any]:
    """
    Analyze the full attack surface from a NetworkX graph or list of asset dictionaries.
    Produces summary metrics and categorical drill-down records.
    """
    nodes_data = []

    if isinstance(network_data, nx.DiGraph):
        for node, data in network_data.nodes(data=True):
            if data.get("node_type") == "honeypot":
                continue
            nodes_data.append(dict(data, node_name=node))
    elif isinstance(network_data, list):
        nodes_data = list(network_data)
    elif isinstance(network_data, dict):
        nodes_data = list(network_data.values())

    total_assets = len(nodes_data)
    exposed_assets = 0
    unexposed_assets = 0
    open_services_count = 0
    internet_facing_count = 0
    high_risk_services_count = 0
    database_services_count = 0
    vulnerable_services_count = 0
    critical_exposure_count = 0

    drill_down_records: List[Dict[str, Any]] = []

    for nd in nodes_data:
        ip = nd.get("ip", nd.get("node_name", "Unknown"))
        host = nd.get("display_name") or nd.get("hostname") or ip
        crit = int(nd.get("criticality", 3))
        risk = float(nd.get("risk_score", 0.0))
        ports = list(nd.get("open_ports", []))
        services = list(nd.get("services", []))
        version_map = nd.get("version_map", {})
        cve_findings = nd.get("cve_findings", [])

        if not ports:
            unexposed_assets += 1
            drill_down_records.append({
                "category": "Client / Internal Endpoints",
                "host": host,
                "ip": ip,
                "port": 0,
                "service": "None (Client / Firewalled)",
                "version": "—",
                "cve_count": 0,
                "top_cve": "None",
                "cvss": 0.0,
                "risk_score": risk,
                "criticality": crit,
                "exposure_level": "LOW",
            })
            continue

        exposed_assets += 1
        open_services_count += len(ports)
        has_critical_exposure_on_host = False

        for i, port in enumerate(ports):
            svc_name = services[i] if i < len(services) else f"Port-{port}"
            ver_str = version_map.get(svc_name, "—")
            
            # Match CVEs for this service
            svc_cves = [c for c in cve_findings if c.get("service") == svc_name or c.get("port") == port]
            top_cve = svc_cves[0]["cve_id"] if svc_cves else "None"
            top_cvss = svc_cves[0]["cvss"] if svc_cves else 0.0

            if svc_cves:
                vulnerable_services_count += 1

            # Determine Exposure Category
            if port in INTERNET_FACING_PORTS:
                cat = "Internet-Facing Web & Public Services"
                internet_facing_count += 1
            elif port in HIGH_RISK_PORTS:
                cat = "High-Risk Remote Administrative Services"
                high_risk_services_count += 1
                if crit >= 4:
                    has_critical_exposure_on_host = True
            elif port in DATABASE_PORTS:
                cat = "Database & High-Value Data Stores"
                database_services_count += 1
                if crit >= 4:
                    has_critical_exposure_on_host = True
            else:
                cat = "Standard LAN Internal Services"

            drill_down_records.append({
                "category": cat,
                "host": host,
                "ip": ip,
                "port": port,
                "service": svc_name,
                "version": ver_str,
                "cve_count": len(svc_cves),
                "top_cve": top_cve,
                "cvss": top_cvss,
                "risk_score": risk,
                "criticality": crit,
                "exposure_level": "CRITICAL" if (crit >= 4 and port in SENSITIVE_PORTS) else "HIGH" if (port in SENSITIVE_PORTS or top_cvss >= 7.0) else "MEDIUM",
            })

        if has_critical_exposure_on_host:
            critical_exposure_count += 1

    ratio = round(exposed_assets / max(total_assets, 1), 2)

    metrics = AttackSurfaceMetrics(
        total_assets=total_assets,
        exposed_assets=exposed_assets,
        unexposed_assets=unexposed_assets,
        open_services_count=open_services_count,
        internet_facing_count=internet_facing_count,
        high_risk_services_count=high_risk_services_count,
        database_services_count=database_services_count,
        vulnerable_services_count=vulnerable_services_count,
        critical_exposure_count=critical_exposure_count,
        attack_surface_ratio=ratio,
    )

    # Sort drill-down records by risk priority
    drill_down_records.sort(key=lambda r: (-r["risk_score"], -r["cvss"], r["category"], r["ip"]))

    return {
        "metrics": metrics.to_dict(),
        "drill_down_tree": drill_down_records,
        "critical_exposures": [r for r in drill_down_records if r["exposure_level"] == "CRITICAL"],
    }
