"""
ACDS v4.0 — PHASE 1: Advanced Attack Path Intelligence
ACDS v4.0 — PHASE 11: MITRE Enhancement

Every graph edge becomes fully explainable with:
 - Source / Target asset
 - Port / Service / Protocol
 - Reachability (REAL OBSERVATION)
 - Live port state (REAL-TIME VALIDATION)
 - Vulnerability condition
 - MITRE technique + reason it applies
 - Defense state
 - Probability
 - Human-readable reason

Phase 11: MITRE techniques are only assigned when supporting conditions exist.
Never assign a technique without evidence.

SIMULATION ONLY — no real exploitation.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────
# MITRE ATT&CK TECHNIQUE REGISTRY
# Conditions are the required observable service/port/CVE evidence.
# Without satisfying conditions, a technique is NOT assigned.
# ─────────────────────────────────────────────────────────────────

MITRE_TECHNIQUE_CONDITIONS: Dict[str, Dict[str, Any]] = {
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "required_ports": [445, 139],
        "required_services": ["SMB", "NetBIOS"],
        "reason_template": "SMB (port {port}) is open and reachable — enables lateral movement via Windows file shares without credentials in legacy environments.",
        "tactic": "Lateral Movement",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "required_ports": [3389],
        "required_services": ["RDP"],
        "reason_template": "RDP (port 3389) is exposed — allows interactive GUI-based lateral movement if credentials are obtained or weak.",
        "tactic": "Lateral Movement",
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "required_ports": [22],
        "required_services": ["SSH"],
        "reason_template": "SSH (port 22) is open — enables remote shell access; exploitable via credential reuse, key theft, or known SSH vulnerabilities.",
        "tactic": "Lateral Movement",
    },
    "T1021.005": {
        "name": "Remote Services: VNC",
        "required_ports": [5900],
        "required_services": ["VNC"],
        "reason_template": "VNC (port 5900) is exposed — often unencrypted; allows full graphical remote control.",
        "tactic": "Lateral Movement",
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "required_ports": [3306, 5432, 27017, 6379],
        "required_services": ["MySQL", "PostgreSQL", "MongoDB", "Redis"],
        "reason_template": "{service} (port {port}) is reachable from the network — database services are high-value exploitation targets when exposed.",
        "tactic": "Lateral Movement",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "required_ports": [80, 443, 8080, 8443],
        "required_services": ["HTTP", "HTTPS", "HTTP-Alt", "HTTPS-Alt"],
        "reason_template": "Web service on port {port} is externally reachable — exploit public-facing web application vulnerabilities to gain initial access.",
        "tactic": "Initial Access",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "required_ports": [135, 139],
        "required_services": ["RPC", "NetBIOS"],
        "reason_template": "NetBIOS/RPC (port {port}) is responding — enables network service enumeration and lateral movement preparation.",
        "tactic": "Discovery",
    },
    "T1071.003": {
        "name": "Application Layer Protocol: Mail Protocols",
        "required_ports": [25, 110, 143],
        "required_services": ["SMTP", "POP3", "IMAP"],
        "reason_template": "Mail protocol port {port} ({service}) is open — can be used for data exfiltration or phishing infrastructure.",
        "tactic": "Command and Control",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "required_ports": [53],
        "required_services": ["DNS"],
        "reason_template": "DNS (port 53) is reachable — potential for DNS tunneling or abuse of recursive resolver.",
        "tactic": "Command and Control",
    },
    "T1021": {
        "name": "Remote Services (Generic)",
        "required_ports": [21, 23],
        "required_services": ["FTP", "Telnet"],
        "reason_template": "{service} (port {port}) is active — legacy protocol with no encryption; plaintext credentials interceptable.",
        "tactic": "Lateral Movement",
    },
}

# Port → primary technique mapping
PORT_TECHNIQUE_MAP: Dict[int, str] = {
    21: "T1021", 22: "T1021.004", 23: "T1021", 25: "T1071.003",
    53: "T1071.004", 80: "T1190", 110: "T1071.003", 135: "T1046",
    139: "T1046", 143: "T1071.003", 443: "T1190", 445: "T1021.002",
    3306: "T1210", 3389: "T1021.001", 5432: "T1210",
    5900: "T1021.005", 6379: "T1210", 8080: "T1190",
    8443: "T1190", 27017: "T1210",
}


def resolve_mitre_technique(
    port: int,
    service: str,
    cve_id: Optional[str] = None,
    cvss: Optional[float] = None,
) -> Dict[str, str]:
    """
    Phase 11: Resolve the correct MITRE technique for a given port/service.
    Only returns a technique when the port/service conditions are satisfied.
    Never fabricates a technique without supporting evidence.

    Returns:
        {
            'technique_id': str,
            'technique_name': str,
            'tactic': str,
            'reason': str,
            'applies': bool,
        }
    """
    technique_id = PORT_TECHNIQUE_MAP.get(port)
    if not technique_id:
        return {
            "technique_id": "N/A",
            "technique_name": "No matching technique",
            "tactic": "N/A",
            "reason": f"Port {port} ({service}) does not map to a documented MITRE technique in this context.",
            "applies": False,
        }

    meta = MITRE_TECHNIQUE_CONDITIONS.get(technique_id, {})
    port_matches = port in meta.get("required_ports", [])
    service_matches = service in meta.get("required_services", [])

    if not (port_matches or service_matches):
        return {
            "technique_id": "N/A",
            "technique_name": "Condition not satisfied",
            "tactic": "N/A",
            "reason": f"Port {port} / service {service} does not satisfy required conditions for any documented technique.",
            "applies": False,
        }

    reason_template = meta.get("reason_template", "Service is exposed and reachable.")
    reason = reason_template.format(port=port, service=service)

    if cve_id and cvss is not None:
        reason += f" Additionally, {cve_id} (CVSS {cvss}) is confirmed on this service, increasing exploitation probability."

    return {
        "technique_id": technique_id,
        "technique_name": meta.get("name", technique_id),
        "tactic": meta.get("tactic", "Lateral Movement"),
        "reason": reason,
        "applies": True,
    }


def build_explainable_edge(
    src_node: str,
    dst_node: str,
    src_data: Dict[str, Any],
    dst_data: Dict[str, Any],
    port: int,
    service: str,
    live_port_state: Optional[str] = None,
    live_host_reachable: Optional[bool] = None,
    defense_applied: Optional[str] = None,
    prob: float = 0.0,
) -> Dict[str, Any]:
    """
    Phase 1: Build a fully explainable edge description for every attack graph edge.

    Returns a structured dict with all required fields for the UI to explain
    WHY every edge exists, what conditions are satisfied, and what the result is.

    SIMULATION ONLY — this describes a modeled path, not a real attack.
    """
    src_display = src_data.get("display_name") or src_node
    dst_display = dst_data.get("display_name") or dst_node
    src_ip = src_data.get("ip", "")
    dst_ip = dst_data.get("ip", "")

    # CVE context from destination asset
    cve_findings = dst_data.get("cve_findings") or []
    top_cve = cve_findings[0] if cve_findings else None
    cve_id = top_cve.get("cve_id") if top_cve else None
    cvss = top_cve.get("cvss") if top_cve else None

    # Resolve MITRE technique with evidence check
    mitre = resolve_mitre_technique(port, service, cve_id, cvss)

    # Reachability determination
    reachability = "POTENTIAL REACHABILITY (Modeled)"  # default — observation only
    if live_host_reachable is True:
        reachability = "CONFIRMED REACHABLE (Live Validated)"
    elif live_host_reachable is False:
        reachability = "OFFLINE (Live Validated — Not Reachable)"

    # Live port state
    port_state_label = "UNKNOWN (using discovery snapshot)"
    if live_port_state == "open":
        port_state_label = "OPEN (Live Validated)"
    elif live_port_state == "closed":
        port_state_label = "CLOSED (Live Validated — Defense Effective)"

    # Vulnerability condition
    vuln_condition = "NONE"
    if top_cve:
        vuln_condition = f"{cve_id} (CVSS {cvss}) — CONFIRMED"
    elif port in {445, 139, 3389, 22, 3306, 5432, 27017, 6379, 5900}:
        vuln_condition = f"SENSITIVE PORT EXPOSURE (TCP {port}/{service})"
    elif dst_data.get("exposure_level", 0) >= 0.25:
        vuln_condition = "WEAK CONFIGURATION / Exposed Listener"

    # Defense state
    if defense_applied:
        defense_label = f"ACTIVE: {defense_applied}"
    elif dst_data.get("isolated"):
        defense_label = "ACTIVE: Host Isolation"
    else:
        defense_label = "NONE"

    # Result determination
    if defense_label != "NONE" and defense_label != "ACTIVE: None":
        result = "BLOCKED (SIMULATION)"
        result_color = "#00ff88"
    elif live_port_state == "closed":
        result = "BLOCKED (Port Closed) (SIMULATION)"
        result_color = "#00ff88"
    elif live_host_reachable is False:
        result = "BLOCKED (Host Offline) (SIMULATION)"
        result_color = "#3d6a8a"
    elif vuln_condition != "NONE" and mitre["applies"]:
        result = "COMPROMISE POSSIBLE (SIMULATION)"
        result_color = "#ff3355"
    else:
        result = "COMPROMISE UNLIKELY (Insufficient Conditions) (SIMULATION)"
        result_color = "#ffd700"

    # Human-readable reason
    reason = (
        f"{src_display} → {dst_display} via {service} (TCP {port}). "
        f"Reachability: {reachability}. "
        f"Port Status: {port_state_label}. "
        f"Vulnerability Condition: {vuln_condition}. "
    )
    if mitre["applies"]:
        reason += f"MITRE {mitre['technique_id']} applies: {mitre['reason']} "
    reason += f"Defense: {defense_label}. Result: {result}."

    return {
        # Core edge identifiers
        "source_asset": src_display,
        "source_ip": src_ip,
        "target_asset": dst_display,
        "target_ip": dst_ip,
        # Observed data (REAL OBSERVATION)
        "port": port,
        "service": service,
        "protocol": "TCP",
        # Live validation data (REAL-TIME VALIDATION)
        "reachability": reachability,
        "live_port_state": port_state_label,
        # Vulnerability / condition
        "vulnerability_condition": vuln_condition,
        "cve_id": cve_id,
        "cvss": cvss,
        # MITRE data (Phase 11 — only when conditions satisfied)
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "mitre_reason": mitre["reason"],
        "mitre_applies": mitre["applies"],
        # Defense
        "defense_state": defense_label,
        # Result
        "probability": round(prob * 100),
        "result": result,
        "result_color": result_color,
        # Full human-readable explanation (SIMULATION label always present)
        "human_reason": reason,
        "simulation_label": "SIMULATION — NO REAL EXPLOITATION",
    }


def enrich_graph_edges(G, live_validation: Optional[Dict] = None) -> None:
    """
    Phase 1: Walk every edge in G and attach a full explainable edge dict.
    Mutates edge data in-place — adds 'edge_intelligence' key.

    Called after build_dynamic_graph() or build_network() to make every
    edge explainable in the UI without changing existing edge attributes.
    """
    from core.database import generate_asset_id  # avoid circular import at module level

    live_validation = live_validation or {}

    for src, dst, data in G.edges(data=True):
        src_data = G.nodes.get(src, {})
        dst_data = G.nodes.get(dst, {})

        port = data.get("access_port") or data.get("port") or 0
        service = data.get("access_vector_service") or data.get("connection", "TCP").split("/")[0].upper()

        # Resolve live state for this specific edge
        dst_ip = dst_data.get("ip", "")
        dst_aid = dst_data.get("asset_id", "")
        lv = live_validation.get(dst_aid) or live_validation.get(dst_ip) or {}
        live_host_reachable = lv.get("reachable") if lv else None
        ports_val = lv.get("ports_validated") or lv.get("ports") or {}
        port_entry = ports_val.get(port) or ports_val.get(str(port))
        live_port_state = None
        if port_entry:
            raw = port_entry.get("state") or ("open" if port_entry.get("open") else "closed")
            live_port_state = str(raw).lower() if raw else None

        defense_applied = None
        if dst_data.get("isolated"):
            defense_applied = "Host Isolation"

        prob = data.get("success_prob", 0.0)

        intelligence = build_explainable_edge(
            src, dst, src_data, dst_data,
            port=port, service=service,
            live_port_state=live_port_state,
            live_host_reachable=live_host_reachable,
            defense_applied=defense_applied,
            prob=prob,
        )
        data["edge_intelligence"] = intelligence


def render_edge_explanation_html(edge_data: Dict[str, Any]) -> str:
    """
    Render a human-readable HTML card explaining a single graph edge.
    Used in the UI's Attack Path Intelligence panel.
    """
    ei = edge_data.get("edge_intelligence")
    if not ei:
        return "<div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.7rem'>No edge intelligence available.</div>"

    result_color = ei.get("result_color", "#ffd700")
    mitre_block = ""
    if ei.get("mitre_applies"):
        mitre_block = (
            f"<div style='margin:4px 0'>"
            f"<span style='color:#ff8c00'>MITRE {ei['mitre_technique_id']}</span> — "
            f"<span style='color:#e0f4ff'>{ei['mitre_technique_name']}</span><br>"
            f"<span style='color:#7ab8d4;font-size:0.65rem'>{ei['mitre_reason']}</span>"
            f"</div>"
        )
    else:
        mitre_block = "<div style='color:#3d6a8a;font-size:0.65rem'>MITRE technique: conditions not satisfied — not assigned.</div>"

    return f"""
<div style='background:#091520;border:1px solid #1a3a5c;border-left:4px solid {result_color};
     padding:12px 16px;margin:6px 0;font-family:Share Tech Mono;font-size:0.72rem;line-height:1.7;border-radius:4px'>
  <div style='color:{result_color};font-weight:bold;margin-bottom:6px;font-family:Orbitron,monospace;font-size:0.8rem'>
    {ei['source_asset']} → {ei['target_asset']}
  </div>
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Port / Service:</span>
       <span style='color:#e0f4ff'>TCP/{ei['port']} ({ei['service']})</span></div>
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Reachability:</span>
       <span style='color:#7ab8d4'>{ei['reachability']}</span></div>
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Live Port State:</span>
       <span style='color:#7ab8d4'>{ei['live_port_state']}</span></div>
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Vuln Condition:</span>
       <span style='color:#ff8c00'>{ei['vulnerability_condition']}</span></div>
  {mitre_block}
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Defense:</span>
       <span style='color:#00ff88'>{ei['defense_state']}</span></div>
  <div><span style='color:#3d6a8a;width:140px;display:inline-block'>Probability:</span>
       <span style='color:#e0f4ff'>{ei['probability']}%</span></div>
  <div style='margin-top:8px;padding:6px 8px;background:rgba(0,0,0,0.3);border-radius:3px'>
    <span style='color:{result_color};font-weight:bold'>RESULT: {ei['result']}</span>
  </div>
  <div style='color:#ff3355;font-size:0.6rem;margin-top:4px'>{ei['simulation_label']}</div>
</div>
"""
