"""
ACDS v4.0 — PHASE 6: SME Multi-Node Lab

Defines an isolated virtual SME lab topology for validation of the
attack graph model.  IPs are discovered dynamically at runtime — none
are hardcoded.  Supports VirtualBox Host-only / Internal networking.

Lab nodes:
  • Employee Workstation   (endpoint)
  • File Server            (file share)
  • Web Server             (web)
  • Database Server        (database)
  • Admin PC               (endpoint — privileged)

The lab is used ONLY to validate the model, never to attack real hosts.
All simulated propagation occurs inside the NetworkX graph model.

SIMULATION ONLY — no real exploitation, no real traffic generation.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

# ─────────────────────────────────────────────────────────────────
# SME LAB TOPOLOGY TEMPLATE
# IPs are left blank — filled in dynamically from ARP/ICMP discovery
# on the VirtualBox host-only adapter, or mapped from the real scan.
# ─────────────────────────────────────────────────────────────────

SME_LAB_NODES: List[Dict[str, Any]] = [
    {
        "role": "Employee Workstation",
        "node_type": "endpoint",
        "criticality": 2,
        "typical_ports": [22, 3389, 445, 139],
        "typical_services": ["SSH", "RDP", "SMB", "NetBIOS"],
        "display_icon": "🖥",
        "description": "Standard employee workstation — typical lateral-movement entry point.",
        "vlan_group": "WORKSTATIONS",
        "ip_placeholder": "192.168.56.10",  # example VirtualBox host-only range
    },
    {
        "role": "File Server",
        "node_type": "fileserver",
        "criticality": 4,
        "typical_ports": [445, 139, 22],
        "typical_services": ["SMB", "NetBIOS", "SSH"],
        "display_icon": "🗄",
        "description": "Shared file server — high value; SMB exposure enables T1021.002.",
        "vlan_group": "SERVERS",
        "ip_placeholder": "192.168.56.20",
    },
    {
        "role": "Web Server",
        "node_type": "webserver",
        "criticality": 3,
        "typical_ports": [80, 443, 22, 8080],
        "typical_services": ["HTTP", "HTTPS", "SSH"],
        "display_icon": "🌐",
        "description": "Public-facing web server — initial access risk (T1190).",
        "vlan_group": "DMZ",
        "ip_placeholder": "192.168.56.30",
    },
    {
        "role": "Database Server",
        "node_type": "database",
        "criticality": 5,
        "typical_ports": [3306, 5432, 22],
        "typical_services": ["MySQL", "PostgreSQL", "SSH"],
        "display_icon": "🗃",
        "description": "Database server — critical asset; exposure to any network path is HIGH risk.",
        "vlan_group": "SERVERS",
        "ip_placeholder": "192.168.56.40",
    },
    {
        "role": "Admin PC",
        "node_type": "admin",
        "criticality": 5,
        "typical_ports": [22, 3389, 5900],
        "typical_services": ["SSH", "RDP", "VNC"],
        "display_icon": "👑",
        "description": "Admin workstation — highest privilege, credentials exposure gives full network access.",
        "vlan_group": "MANAGEMENT",
        "ip_placeholder": "192.168.56.50",
    },
]

# Expected attack paths in the SME lab (for model validation)
SME_LAB_EXPECTED_PATHS: List[Dict[str, Any]] = [
    {
        "name": "Workstation → File Server via SMB",
        "src_role": "Employee Workstation",
        "dst_role": "File Server",
        "port": 445,
        "service": "SMB",
        "mitre": "T1021.002",
        "expected_result": "COMPROMISE POSSIBLE (SIMULATION)",
        "defense": "VLAN Segmentation between WORKSTATIONS and SERVERS",
    },
    {
        "name": "Web Server → Database via MySQL",
        "src_role": "Web Server",
        "dst_role": "Database Server",
        "port": 3306,
        "service": "MySQL",
        "mitre": "T1210",
        "expected_result": "COMPROMISE POSSIBLE (SIMULATION)",
        "defense": "Firewall Rule: restrict MySQL to web server IP only",
    },
    {
        "name": "Workstation → Admin PC via RDP",
        "src_role": "Employee Workstation",
        "dst_role": "Admin PC",
        "port": 3389,
        "service": "RDP",
        "mitre": "T1021.001",
        "expected_result": "COMPROMISE POSSIBLE (SIMULATION)",
        "defense": "Close Port / Host Isolation on Admin PC",
    },
    {
        "name": "File Server → Database via SMB/internal",
        "src_role": "File Server",
        "dst_role": "Database Server",
        "port": 445,
        "service": "SMB",
        "mitre": "T1021.002",
        "expected_result": "COMPROMISE POSSIBLE (SIMULATION)",
        "defense": "VLAN Segmentation + Firewall between SERVERS segment",
    },
]


def build_lab_graph_nodes(discovered_ips: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Build the SME lab node list, binding dynamically discovered IPs.

    Args:
        discovered_ips: Dict mapping role → real IP (from discovery scan).
                        If None, placeholder IPs are used for demo only.

    Returns:
        List of node dicts ready to inject into build_dynamic_graph().
    """
    discovered_ips = discovered_ips or {}
    nodes = []
    for template in SME_LAB_NODES:
        role = template["role"]
        ip = discovered_ips.get(role, template["ip_placeholder"])
        node = {
            "ip": ip,
            "hostname": role.lower().replace(" ", "-"),
            "display_name": role,
            "node_type": template["node_type"],
            "criticality": template["criticality"],
            "open_ports": template["typical_ports"][:],
            "services": template["typical_services"][:],
            "icon": template["display_icon"],
            "description": template["description"],
            "vlan_group": template["vlan_group"],
            "lab_node": True,
            "vulnerability": 0.4 + (template["criticality"] - 2) * 0.08,
            "cve_findings": [],
            "vendor": "SME-Lab",
            "device_type": template["node_type"],
            "os_guess": "Unknown (Lab)",
            "risk_score": 0,
            "exposure_level": 0.5,
        }
        nodes.append(node)
    return nodes


def validate_lab_paths(G, expected_paths: Optional[List] = None) -> List[Dict[str, Any]]:
    """
    Phase 6: Validate that the model contains the expected attack paths
    for the SME lab topology.

    Returns a validation report — each path marked as FOUND / MISSING.
    All validation is against the in-memory graph model, not real traffic.
    """
    import networkx as nx
    expected_paths = expected_paths or SME_LAB_EXPECTED_PATHS
    report = []

    # Build IP→node map from graph
    ip_to_node = {data.get("ip", ""): n for n, data in G.nodes(data=True)}
    role_to_node = {data.get("display_name", ""): n for n, data in G.nodes(data=True)}

    for path_spec in expected_paths:
        src_role = path_spec["src_role"]
        dst_role = path_spec["dst_role"]
        src_node = role_to_node.get(src_role)
        dst_node = role_to_node.get(dst_role)

        if not src_node or not dst_node:
            report.append({**path_spec, "status": "MISSING (node not in graph)", "color": "#3d6a8a"})
            continue

        found = G.has_edge(src_node, dst_node)
        if found:
            edge_data = G[src_node][dst_node]
            intelligence = edge_data.get(0, edge_data).get("edge_intelligence") if isinstance(edge_data, dict) else {}
            result = intelligence.get("result", "MODELED") if intelligence else "PATH EXISTS (SIMULATION)"
            report.append({
                **path_spec,
                "status": "FOUND",
                "model_result": result,
                "color": "#00ff88",
            })
        else:
            report.append({**path_spec, "status": "MISSING (no edge in graph)", "color": "#ff3355"})

    return report


def render_lab_validation_html(report: List[Dict[str, Any]]) -> str:
    """Render the SME lab path validation report as HTML."""
    if not report:
        return "<div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.7rem'>No validation data.</div>"

    rows = ""
    for entry in report:
        color = entry.get("color", "#ffd700")
        status = entry.get("status", "UNKNOWN")
        mitre = entry.get("mitre", "")
        defense = entry.get("defense", "")
        model_result = entry.get("model_result", entry.get("expected_result", ""))
        rows += f"""
<tr style='border-bottom:1px solid #142a3a;font-family:Share Tech Mono;font-size:0.68rem'>
  <td style='padding:6px 10px;color:#e0f4ff'>{entry.get('name','')}</td>
  <td style='padding:6px 10px;color:#7ab8d4'>TCP/{entry.get('port','')} ({entry.get('service','')})</td>
  <td style='padding:6px 10px;color:#ff8c00'>{mitre}</td>
  <td style='padding:6px 10px;color:{color};font-weight:bold'>{status}</td>
  <td style='padding:6px 10px;color:#7ab8d4;font-size:0.62rem'>{defense}</td>
</tr>"""

    return f"""
<div style='background:#091520;border:1px solid #1a3a5c;padding:12px;border-radius:4px;margin:8px 0'>
  <div style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.72rem;font-weight:bold;margin-bottom:10px'>
    🧪 SME LAB — MODEL VALIDATION REPORT
  </div>
  <table style='width:100%;border-collapse:collapse'>
    <thead><tr style='color:#00d4ff;border-bottom:1px solid #00d4ff;font-family:Share Tech Mono;font-size:0.65rem'>
      <th style='text-align:left;padding:6px 10px'>Attack Path</th>
      <th style='text-align:left;padding:6px 10px'>Vector</th>
      <th style='text-align:left;padding:6px 10px'>MITRE</th>
      <th style='text-align:left;padding:6px 10px'>Status</th>
      <th style='text-align:left;padding:6px 10px'>Recommended Defense</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div style='color:#ff3355;font-family:Share Tech Mono;font-size:0.6rem;margin-top:8px'>
    SIMULATION ONLY — All path validation is against the in-memory graph model.
    No real network traffic is generated. No real exploitation occurs.
  </div>
</div>
"""
