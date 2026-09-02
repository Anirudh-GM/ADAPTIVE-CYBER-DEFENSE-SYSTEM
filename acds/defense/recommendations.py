"""
ACDS SME-Readable Defense Recommendations Engine
Translates technical vulnerability findings, open port exposures, and attack paths
into plain-English, actionable security recommendations tailored for non-technical SME leadership.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx


@dataclass
class SMERecommendation:
    """Structured, business-oriented security recommendation."""
    action_id: str
    title: str
    priority_tier: str  # CRITICAL | HIGH | MEDIUM | LOW
    affected_asset: str
    affected_ip: str
    technical_reason: str
    business_impact: str
    recommended_action: str
    expected_impact: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "title": self.title,
            "priority_tier": self.priority_tier,
            "affected_asset": self.affected_asset,
            "affected_ip": self.affected_ip,
            "technical_reason": self.technical_reason,
            "business_impact": self.business_impact,
            "recommended_action": self.recommended_action,
            "expected_impact": self.expected_impact,
        }


def generate_sme_recommendations(
    network_data: Any,
    prioritized_findings: Optional[List[Any]] = None,
    limit: int = 10,
) -> List[SMERecommendation]:
    """
    Generate Top Actionable SME Recommendations answering: 'What should the SME fix first?'
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

    recommendations: List[SMERecommendation] = []
    rec_idx = 1
    seen_recommendation_keys: Set[str] = set()

    # 1. Process Prioritized Findings first if available
    if prioritized_findings:
        for vdef in prioritized_findings:
            cve_id = getattr(vdef, "cve_id", "Unknown CVE")
            prio_lvl = getattr(vdef, "priority_level", "P3")
            tier = "CRITICAL" if prio_lvl == "P1" else "HIGH" if prio_lvl == "P2" else "MEDIUM" if prio_lvl == "P3" else "LOW"
            prod = getattr(vdef, "product", "software")
            ver = getattr(vdef, "version", "")
            rec_fix = getattr(vdef, "recommended_remediation", f"Apply security patch for {cve_id}")

            for host_key, actx in getattr(vdef, "affected_assets", {}).items():
                host_disp = actx.host
                host_ip = actx.ip
                dedup_key = f"{cve_id}_{host_ip}"
                if dedup_key in seen_recommendation_keys:
                    continue
                seen_recommendation_keys.add(dedup_key)

                crit = actx.criticality
                crit_desc = "critical database / core server" if crit >= 5 else "production server" if crit >= 4 else "workstation"

                tech_reason = f"{prod} {ver} on {host_disp} ({host_ip}) is vulnerable to {cve_id} (CVSS {vdef.cvss})"
                biz_impact = (
                    f"Adversary could exploit {cve_id} on this {crit_desc} to execute unauthorized code, "
                    f"access sensitive business data, or disrupt operations."
                )
                exp_impact = f"Neutralizes remote exploit vector for {cve_id}; directly lowers asset risk."

                rec = SMERecommendation(
                    action_id=f"REC-{rec_idx:03d}",
                    title=f"Patch {prod} on {host_disp}",
                    priority_tier=tier,
                    affected_asset=host_disp,
                    affected_ip=host_ip,
                    technical_reason=tech_reason,
                    business_impact=biz_impact,
                    recommended_action=rec_fix,
                    expected_impact=exp_impact,
                )
                recommendations.append(rec)
                rec_idx += 1

    # 2. Process High-Risk Port Exposures from network nodes
    for nd in nodes_data:
        ip = nd.get("ip", nd.get("node_name", "Unknown"))
        host = nd.get("display_name") or nd.get("hostname") or ip
        crit = int(nd.get("criticality", 3))
        ports = list(nd.get("open_ports", []))
        services = list(nd.get("services", []))

        # Check for SMB / NetBIOS
        if 445 in ports or 139 in ports:
            key = f"SMB_{ip}"
            if key not in seen_recommendation_keys:
                seen_recommendation_keys.add(key)
                recommendations.append(SMERecommendation(
                    action_id=f"REC-{rec_idx:03d}",
                    title=f"Restrict SMB File Sharing on {host}",
                    priority_tier="HIGH" if crit >= 4 else "MEDIUM",
                    affected_asset=host,
                    affected_ip=ip,
                    technical_reason=f"Windows SMB/NetBIOS (port 445/139) is open to the entire local subnet",
                    business_impact="Exposed SMB shares allow lateral worm propagation and credential theft if a single laptop is compromised.",
                    recommended_action="Disable SMBv1, enforce SMB signing, and block port 445 at the host firewall between endpoints.",
                    expected_impact="Prevents unauthorized cross-workstation lateral movement.",
                ))
                rec_idx += 1

        # Check for Telnet / Cleartext FTP
        if 23 in ports or 21 in ports:
            proto = "Telnet (port 23)" if 23 in ports else "FTP (port 21)"
            key = f"CLEARTEXT_{ip}"
            if key not in seen_recommendation_keys:
                seen_recommendation_keys.add(key)
                recommendations.append(SMERecommendation(
                    action_id=f"REC-{rec_idx:03d}",
                    title=f"Decommission Unencrypted {proto} on {host}",
                    priority_tier="HIGH",
                    affected_asset=host,
                    affected_ip=ip,
                    technical_reason=f"{proto} transmits usernames, passwords, and data in plain cleartext across the network.",
                    business_impact="Any device on the Wi-Fi or LAN can eavesdrop on administrative credentials.",
                    recommended_action=f"Disable {proto} service immediately and migrate administrative workflows to encrypted SSH/SFTP.",
                    expected_impact="Eliminates credential interception vulnerabilities.",
                ))
                rec_idx += 1

        # Check for Exposed Database Ports
        db_ports = [p for p in ports if p in (3306, 5432, 6379, 27017)]
        if db_ports:
            key = f"DB_{ip}"
            if key not in seen_recommendation_keys:
                seen_recommendation_keys.add(key)
                recommendations.append(SMERecommendation(
                    action_id=f"REC-{rec_idx:03d}",
                    title=f"Isolate Database Server {host}",
                    priority_tier="CRITICAL" if crit >= 4 else "HIGH",
                    affected_asset=host,
                    affected_ip=ip,
                    technical_reason=f"Database ports ({', '.join(map(str, db_ports))}) are directly exposed on the network",
                    business_impact="Direct database exposure increases risk of unauthorized data dumping and ransomware targeting customer records.",
                    recommended_action="Bind database listeners to localhost/127.0.0.1 and restrict remote access strictly to application servers via firewall.",
                    expected_impact="Protects crown-jewel business data stores from direct LAN attack.",
                ))
                rec_idx += 1

    # Sort recommendations: CRITICAL -> HIGH -> MEDIUM -> LOW
    tier_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recommendations.sort(key=lambda r: (tier_order.get(r.priority_tier, 4), r.affected_ip))

    return recommendations[:limit]
