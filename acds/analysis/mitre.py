"""
ACDS MITRE ATT&CK Contextual Correlation Engine
Maps observed network services, exposed ports, and version characteristics to
MITRE ATT&CK Enterprise Matrix techniques with clear technical accuracy disclaimers.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx

MITRE_DISCLAIMER = (
    "Potential technique association based on observed network characteristics and exposed services. "
    "Indicates exposure to the technique; does not claim an active adversary intrusion has occurred."
)

TECHNIQUE_CATALOG: Dict[str, Dict[str, str]] = {
    "FTP": {
        "id": "T1021", "name": "Remote Services: FTP", "tactic": "Lateral Movement",
        "countermeasure": "Disable unencrypted FTP; enforce SFTP with SSH key authentication.",
    },
    "SSH": {
        "id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement",
        "countermeasure": "Disable password authentication; enforce SSH key pairs and restrict to admin VLAN.",
    },
    "Telnet": {
        "id": "T1021", "name": "Remote Services: Telnet (Cleartext)", "tactic": "Lateral Movement",
        "countermeasure": "Immediately terminate Telnet services and replace with encrypted SSH.",
    },
    "HTTP": {
        "id": "T1190", "name": "Exploit Public-Facing Application: HTTP", "tactic": "Initial Access",
        "countermeasure": "Deploy Web Application Firewall (WAF), enforce HTTPS, and patch web server.",
    },
    "HTTPS": {
        "id": "T1190", "name": "Exploit Public-Facing Application: HTTPS", "tactic": "Initial Access",
        "countermeasure": "Maintain current TLS configuration, disable deprecated ciphers, and apply CVE patches.",
    },
    "SMB": {
        "id": "T1021.002", "name": "Remote Services: SMB / Windows Admin Shares", "tactic": "Lateral Movement",
        "countermeasure": "Disable SMBv1, enforce SMB signing, and block port 445 between workstation subnets.",
    },
    "RPC": {
        "id": "T1021", "name": "Remote Services: MS-RPC", "tactic": "Lateral Movement",
        "countermeasure": "Restrict RPC endpoints to domain controllers and isolate from general endpoints.",
    },
    "NetBIOS": {
        "id": "T1046", "name": "Network Service Discovery: NetBIOS Name Service", "tactic": "Discovery",
        "countermeasure": "Disable NetBIOS over TCP/IP across corporate endpoints.",
    },
    "RDP": {
        "id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement",
        "countermeasure": "Enforce Multi-Factor Authentication (MFA), Network Level Authentication (NLA), and VPN-only access.",
    },
    "VNC": {
        "id": "T1021.005", "name": "Remote Services: VNC", "tactic": "Lateral Movement",
        "countermeasure": "Tunnel VNC sessions through SSH or VPN; require strong authentication.",
    },
    "MySQL": {
        "id": "T1210", "name": "Exploitation of Remote Services: MySQL Database", "tactic": "Lateral Movement",
        "countermeasure": "Bind MySQL to localhost/internal sockets; restrict remote DB access via firewall.",
    },
    "PostgreSQL": {
        "id": "T1210", "name": "Exploitation of Remote Services: PostgreSQL Database", "tactic": "Lateral Movement",
        "countermeasure": "Configure pg_hba.conf to enforce TLS and restrict client IP subnets.",
    },
    "Redis": {
        "id": "T1210", "name": "Exploitation of Remote Services: Redis Data Store", "tactic": "Lateral Movement",
        "countermeasure": "Enable requirepass authentication; bind to 127.0.0.1; block public port 6379.",
    },
    "MongoDB": {
        "id": "T1210", "name": "Exploitation of Remote Services: MongoDB", "tactic": "Lateral Movement",
        "countermeasure": "Enable role-based authorization; block unauthenticated remote access.",
    },
}


@dataclass
class MITRETechniqueFinding:
    """Contextual mapping between an observed asset characteristic and a MITRE technique."""
    technique_id: str
    technique_name: str
    tactic: str
    observed_signal: str
    affected_host: str
    affected_ip: str
    port: int
    risk_level: str
    contextual_association: str
    recommended_countermeasure: str
    disclaimer: str = MITRE_DISCLAIMER

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "observed_signal": self.observed_signal,
            "affected_host": self.affected_host,
            "affected_ip": self.affected_ip,
            "port": self.port,
            "risk_level": self.risk_level,
            "contextual_association": self.contextual_association,
            "recommended_countermeasure": self.recommended_countermeasure,
            "disclaimer": self.disclaimer,
        }


def correlate_mitre_techniques(network_data: Any) -> List[MITRETechniqueFinding]:
    """
    Extract and correlate potential MITRE ATT&CK techniques from observed network assets.
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

    findings: List[MITRETechniqueFinding] = []

    for nd in nodes_data:
        ip = nd.get("ip", nd.get("node_name", "Unknown"))
        host = nd.get("display_name") or nd.get("hostname") or ip
        crit = int(nd.get("criticality", 3))
        ports = list(nd.get("open_ports", []))
        services = list(nd.get("services", []))
        cves = nd.get("cve_findings", [])

        for i, port in enumerate(ports):
            svc_name = services[i] if i < len(services) else f"Port-{port}"
            tech_info = TECHNIQUE_CATALOG.get(svc_name)

            if tech_info:
                # Determine risk level from host criticality and CVE presence
                svc_cves = [c for c in cves if c.get("service") == svc_name or c.get("port") == port]
                top_cvss = max((c.get("cvss", 0.0) for c in svc_cves), default=0.0)

                risk_lvl = (
                    "CRITICAL" if (crit >= 4 and top_cvss >= 9.0)
                    else "HIGH" if (crit >= 4 or top_cvss >= 7.0 or svc_name in ["Telnet", "SMB", "RDP"])
                    else "MEDIUM"
                )

                assoc = f"Observed {svc_name} service listening on port {port} ({len(svc_cves)} CVE(s) identified)"

                item = MITRETechniqueFinding(
                    technique_id=tech_info["id"],
                    technique_name=tech_info["name"],
                    tactic=tech_info["tactic"],
                    observed_signal=f"{svc_name} exposed on port {port}",
                    affected_host=host,
                    affected_ip=ip,
                    port=port,
                    risk_level=risk_lvl,
                    contextual_association=assoc,
                    recommended_countermeasure=tech_info["countermeasure"],
                )
                findings.append(item)

    # Sort by risk severity: CRITICAL -> HIGH -> MEDIUM
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (severity_rank.get(f.risk_level, 4), f.technique_id, f.affected_ip))
    return findings
