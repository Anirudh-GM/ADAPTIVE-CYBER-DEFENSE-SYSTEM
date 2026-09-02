"""
ACDS Organization Security Posture Scoring Engine
Evaluates enterprise cybersecurity health (0 to 100) across 4 foundational pillars:
1. Vulnerability Management
2. Network Exposure
3. Asset Security
4. Service & Deception Security
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx


@dataclass
class SecurityPostureReport:
    """Consolidated organization cybersecurity health report."""
    overall_score: float
    rating_label: str  # CRITICAL | POOR | NEEDS IMPROVEMENT | ACCEPTABLE | STRONG
    vulnerability_score: float
    exposure_score: float
    asset_security_score: float
    service_security_score: float
    pillar_breakdown: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    key_weaknesses: List[str] = field(default_factory=list)
    top_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "rating_label": self.rating_label,
            "vulnerability_score": self.vulnerability_score,
            "exposure_score": self.exposure_score,
            "asset_security_score": self.asset_security_score,
            "service_security_score": self.service_security_score,
            "pillar_breakdown": self.pillar_breakdown,
            "key_weaknesses": self.key_weaknesses,
            "top_recommendations": self.top_recommendations,
        }


def calculate_security_posture(
    network_data: Any,
    prioritized_findings: Optional[List[Any]] = None,
) -> SecurityPostureReport:
    """
    Calculate organization-wide security posture score (0 to 100).
    Higher score indicates better security hygiene and lower adversary risk.
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

    total_assets = max(len(nodes_data), 1)

    # ── PILLAR 1: VULNERABILITY MANAGEMENT (Weight: 30%) ──────────────────
    # Based on CVE density, CVSS severity, and unpatched findings
    all_cves = []
    for nd in nodes_data:
        all_cves.extend(nd.get("cve_findings", []))

    crit_cves = sum(1 for c in all_cves if c.get("cvss", 0.0) >= 9.0)
    high_cves = sum(1 for c in all_cves if 7.0 <= c.get("cvss", 0.0) < 9.0)
    med_cves = sum(1 for c in all_cves if c.get("cvss", 0.0) < 7.0)

    # Penalty formula: start at 100, deduct for vulnerabilities
    vuln_deduction = (crit_cves * 18.0) + (high_cves * 8.0) + (med_cves * 2.5)
    vuln_score = max(10.0, min(100.0, round(100.0 - (vuln_deduction / max(total_assets * 0.4, 1.0)), 1)))

    # ── PILLAR 2: NETWORK EXPOSURE (Weight: 25%) ──────────────────────────
    # Based on sensitive ports, cleartext protocols, and open service ratio
    total_open_ports = sum(len(nd.get("open_ports", [])) for nd in nodes_data)
    sensitive_ports_seen = 0
    for nd in nodes_data:
        for p in nd.get("open_ports", []):
            if p in (21, 23, 135, 139, 445, 3389, 5900, 3306, 5432, 6379, 27017):
                sensitive_ports_seen += 1

    exp_deduction = (sensitive_ports_seen * 12.0) + (total_open_ports * 1.5)
    exp_score = max(15.0, min(100.0, round(100.0 - (exp_deduction / max(total_assets * 0.5, 1.0)), 1)))

    # ── PILLAR 3: ASSET SECURITY (Weight: 25%) ────────────────────────────
    # Based on crown jewel protection, OS identification, and workstation hygiene
    crit_assets = [nd for nd in nodes_data if int(nd.get("criticality", 3)) >= 4]
    unprotected_crit_assets = sum(1 for nd in crit_assets if float(nd.get("risk_score", 0.0)) >= 60.0)

    asset_deduction = (unprotected_crit_assets * 20.0) + (len(crit_assets) * 2.0)
    asset_score = max(20.0, min(100.0, round(100.0 - (asset_deduction / max(len(crit_assets) or 1, 1)), 1)))

    # ── PILLAR 4: SERVICE & DECEPTION SECURITY (Weight: 20%) ──────────────
    # Legacy services vs hardened configurations
    legacy_services = 0
    for nd in nodes_data:
        for s in nd.get("services", []):
            if s in ("Telnet", "FTP", "NetBIOS", "RPC"):
                legacy_services += 1

    svc_deduction = legacy_services * 15.0
    svc_score = max(25.0, min(100.0, round(100.0 - (svc_deduction / max(total_assets * 0.3, 1.0)), 1)))

    # ── OVERALL AGGREGATION ───────────────────────────────────────────────
    overall = round(
        (vuln_score * 0.30) +
        (exp_score * 0.25) +
        (asset_score * 0.25) +
        (svc_score * 0.20),
        1
    )
    overall = max(0.0, min(100.0, overall))

    # Rating label
    if overall >= 85.0:
        rating = "STRONG"
    elif overall >= 75.0:
        rating = "ACCEPTABLE"
    elif overall >= 60.0:
        rating = "NEEDS IMPROVEMENT"
    elif overall >= 40.0:
        rating = "POOR"
    else:
        rating = "CRITICAL"

    # Compile weaknesses and recommendations
    weaknesses = []
    recs = []

    if crit_cves > 0:
        weaknesses.append(f"{crit_cves} Critical Severity CVE(s) detected with CVSS >= 9.0")
        recs.append("Emergency patch deployment for critical remote code execution findings")
    if sensitive_ports_seen > 0:
        weaknesses.append(f"{sensitive_ports_seen} sensitive administrative / database port(s) exposed across subnet")
        recs.append("Implement firewall rules and network segmentation to restrict admin ports")
    if legacy_services > 0:
        weaknesses.append(f"{legacy_services} unencrypted legacy service(s) running (Telnet/FTP/NetBIOS)")
        recs.append("Disable legacy protocols and migrate to modern encrypted equivalents (SSH/SFTP)")
    if unprotected_crit_assets > 0:
        weaknesses.append(f"{unprotected_crit_assets} high-criticality asset(s) have elevated risk scores (>= 60)")
        recs.append("Isolate core database and server assets into dedicated protected VLANs")

    if not weaknesses:
        weaknesses.append("No critical security gaps detected on current subnet")
        recs.append("Maintain routine patch management cadence and periodic network scanning")

    breakdown = {
        "Vulnerability Management": {
            "score": vuln_score, "weight": 0.30,
            "status": "Good" if vuln_score >= 75 else "Warning" if vuln_score >= 50 else "Critical",
            "detail": f"{len(all_cves)} total CVEs ({crit_cves} critical, {high_cves} high)",
        },
        "Network Exposure": {
            "score": exp_score, "weight": 0.25,
            "status": "Good" if exp_score >= 75 else "Warning" if exp_score >= 50 else "Critical",
            "detail": f"{total_open_ports} open ports ({sensitive_ports_seen} sensitive/administrative)",
        },
        "Asset Security": {
            "score": asset_score, "weight": 0.25,
            "status": "Good" if asset_score >= 75 else "Warning" if asset_score >= 50 else "Critical",
            "detail": f"{len(crit_assets)} critical assets ({unprotected_crit_assets} elevated risk)",
        },
        "Service & Deception Security": {
            "score": svc_score, "weight": 0.20,
            "status": "Good" if svc_score >= 75 else "Warning" if svc_score >= 50 else "Critical",
            "detail": f"{legacy_services} unencrypted legacy service instances",
        },
    }

    return SecurityPostureReport(
        overall_score=overall,
        rating_label=rating,
        vulnerability_score=vuln_score,
        exposure_score=exp_score,
        asset_security_score=asset_score,
        service_security_score=svc_score,
        pillar_breakdown=breakdown,
        key_weaknesses=weaknesses,
        top_recommendations=recs,
    )
