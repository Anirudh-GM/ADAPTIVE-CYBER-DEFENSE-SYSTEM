"""
ACDS v4.0 — PHASE 4: Advanced Defense Optimization

Extends the existing greedy optimizer in app.py with:
  - 8 defense action types: Patch, Close Port, Disable Service,
    Firewall Rule, VLAN Segmentation, Host Isolation,
    Monitoring, Honeypot Placement
  - Per-defense calculation of: cost, risk reduction, blast radius
    reduction, attack paths removed, critical assets protected
  - Budget-constrained optimal combination (knapsack greedy)
  - Explanation of WHY each defense was selected

SIMULATION ONLY — all defense actions are applied to the in-memory
graph model, not to real network infrastructure.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from core.acds_logging import get_logger

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────
# DEFENSE ACTION CATALOG (v4.0 — 8 types)
# ─────────────────────────────────────────────────────────────────

DEFENSE_TYPES = {
    "patch": {
        "label": "Patch / Update",
        "description": "Apply vendor security patch to eliminate confirmed CVE(s).",
        "icon": "🔧",
        "base_cost": 12,
        "risk_reduction_multiplier": 0.40,
        "blast_radius_factor": 0.15,
        "paths_removed_factor": 0.10,
        "mitre_tactic": "Initial Access / Exploitation — removes CVE attack surface",
    },
    "close_port": {
        "label": "Close Port",
        "description": "Disable or firewall an unnecessary open port to remove attack surface.",
        "icon": "🚪",
        "base_cost": 8,
        "risk_reduction_multiplier": 0.25,
        "blast_radius_factor": 0.20,
        "paths_removed_factor": 0.20,
        "mitre_tactic": "Lateral Movement — T1021 attack surface reduction",
    },
    "disable_service": {
        "label": "Disable Service",
        "description": "Stop and disable an unnecessary or insecure service.",
        "icon": "⛔",
        "base_cost": 10,
        "risk_reduction_multiplier": 0.30,
        "blast_radius_factor": 0.20,
        "paths_removed_factor": 0.20,
        "mitre_tactic": "Initial Access / Lateral Movement — removes service exposure",
    },
    "firewall_rule": {
        "label": "Firewall Rule",
        "description": "Add ACL/firewall rule to restrict inbound/outbound traffic.",
        "icon": "🛡",
        "base_cost": 15,
        "risk_reduction_multiplier": 0.20,
        "blast_radius_factor": 0.25,
        "paths_removed_factor": 0.30,
        "mitre_tactic": "Lateral Movement — network filtering blocks T1021 paths",
    },
    "vlan_segmentation": {
        "label": "VLAN Segmentation",
        "description": "Isolate asset group into a separate VLAN with ACL enforcement.",
        "icon": "🌐",
        "base_cost": 25,
        "risk_reduction_multiplier": 0.15,
        "blast_radius_factor": 0.40,
        "paths_removed_factor": 0.45,
        "mitre_tactic": "Lateral Movement — T1021 containment via network segmentation",
    },
    "host_isolation": {
        "label": "Host Isolation",
        "description": "Quarantine a specific compromised or vulnerable host.",
        "icon": "🔒",
        "base_cost": 18,
        "risk_reduction_multiplier": 0.35,
        "blast_radius_factor": 0.50,
        "paths_removed_factor": 0.55,
        "mitre_tactic": "Lateral Movement — T1599 network boundary enforced",
    },
    "monitoring": {
        "label": "Deploy Monitoring / SIEM",
        "description": "Deploy IDS/SIEM for continuous detection of lateral movement.",
        "icon": "📡",
        "base_cost": 30,
        "risk_reduction_multiplier": 0.12,
        "blast_radius_factor": 0.10,
        "paths_removed_factor": 0.05,
        "mitre_tactic": "Discovery / Lateral Movement — T1046 detection coverage",
    },
    "honeypot": {
        "label": "Honeypot Placement",
        "description": "Deploy a decoy asset to detect and delay lateral movement.",
        "icon": "🍯",
        "base_cost": 22,
        "risk_reduction_multiplier": 0.10,
        "blast_radius_factor": 0.15,
        "paths_removed_factor": 0.08,
        "mitre_tactic": "Detection — deception layer for Discovery / Lateral Movement",
    },
}


def calculate_defense_impact(
    action_type: str,
    node_data: Dict[str, Any],
    G: "nx.DiGraph",
    risk_score: float,
    compromised_nodes: list,
) -> Dict[str, Any]:
    """
    Calculate the concrete impact of a specific defense action for a specific node.

    Returns:
        {
            'cost': int,
            'risk_reduction': float,
            'blast_radius_reduction': float,
            'attack_paths_removed': int,
            'critical_assets_protected': int,
            'efficiency': float,
            'why_selected_explanation': str,
        }
    """
    dtype = DEFENSE_TYPES.get(action_type, DEFENSE_TYPES["patch"])
    node = node_data.get("display_name", "Asset")
    crit = node_data.get("criticality", 2)
    vuln = node_data.get("vulnerability", 0.3)
    risk_comp = node_data.get("risk_score", 0)

    # Cost scales with criticality and action type
    cost = int(dtype["base_cost"] + crit * 3)

    # Risk reduction: based on multiplier × node risk contribution
    risk_reduction = round(risk_comp * dtype["risk_reduction_multiplier"], 1)

    # Blast radius reduction: how much this removes from lateral movement model
    blast_reduction = round(risk_score * dtype["blast_radius_factor"] * (crit / 5.0), 1)

    # Attack paths removed: count edges TO/FROM this node that would be blocked
    node_id = node_data.get("_node_id")
    paths_removed = 0
    critical_protected = 0

    if node_id and G is not None:
        # Count edges removed by this action
        in_edges = list(G.in_edges(node_id))
        out_edges = list(G.out_edges(node_id))

        if action_type in ("host_isolation", "vlan_segmentation"):
            paths_removed = len(in_edges) + len(out_edges)
        elif action_type in ("close_port", "disable_service", "firewall_rule"):
            paths_removed = max(1, int(len(in_edges) * dtype["paths_removed_factor"]))
        else:
            paths_removed = max(0, int((len(in_edges) + len(out_edges)) * dtype["paths_removed_factor"]))

        # Critical assets now protected (no longer reachable from compromised nodes)
        try:
            reachable_via_node = set()
            for n in compromised_nodes:
                for path in nx.all_simple_paths(G, n, node_id, cutoff=3):
                    reachable_via_node.update(path)
            critical_protected = sum(
                1 for n in reachable_via_node
                if G.nodes[n].get("criticality", 0) >= 4
                and G.nodes[n].get("node_type") != "honeypot"
            )
        except Exception:
            critical_protected = 1 if crit >= 4 else 0

    efficiency = round(risk_reduction / max(cost, 1), 3)

    # Explanation of why this defense was selected
    why = (
        f"{dtype['icon']} {dtype['label']}: "
        f"Reduces risk by {risk_reduction:.0f}pts "
        f"(cost: {cost} units, efficiency: {efficiency:.3f}). "
        f"Removes ~{paths_removed} attack path(s), "
        f"blast radius reduction: {blast_reduction:.0f}pts, "
        f"critical assets protected: {critical_protected}. "
        f"MITRE coverage: {dtype['mitre_tactic']}. "
        f"SIMULATION — modeled impact on in-memory graph."
    )

    return {
        "cost": cost,
        "risk_reduction": risk_reduction,
        "blast_radius_reduction": blast_reduction,
        "attack_paths_removed": paths_removed,
        "critical_assets_protected": critical_protected,
        "efficiency": efficiency,
        "why_selected_explanation": why,
        "action_type": action_type,
        "defense_type_meta": dtype,
    }


def generate_v4_defense_actions(
    G: "nx.DiGraph",
    compromised_nodes: list,
    risk_score: float,
) -> List[Dict[str, Any]]:
    """
    Phase 4: Generate the full v4.0 defense action catalog for all compromised nodes.
    Each action includes: type, cost, risk reduction, blast radius, paths removed,
    critical assets protected, and WHY it was recommended.

    Returns actions sorted by efficiency (risk_reduction / cost).
    """
    actions = []
    seen_keys = set()

    for node in compromised_nodes:
        if node not in G.nodes:
            continue
        nd = G.nodes[node]
        if nd.get("node_type") == "honeypot":
            continue

        nd["_node_id"] = node  # temporary for impact calculation

        crit = nd.get("criticality", 2)
        vuln = nd.get("vulnerability", 0.3)
        display = nd.get("display_name", node)
        open_ports = nd.get("open_ports") or []
        services = nd.get("services") or []
        cve_findings = nd.get("cve_findings") or []

        # 1. PATCH — if CVEs present
        if cve_findings:
            key = f"patch:{node}"
            if key not in seen_keys:
                seen_keys.add(key)
                impact = calculate_defense_impact("patch", nd, G, risk_score, compromised_nodes)
                actions.append({
                    "action": f"🔧 Patch {display[:28]}",
                    "node": node,
                    "type": "patch",
                    "description": f"Patch {len(cve_findings)} confirmed CVE(s) on {display}. "
                                   f"Eliminates: {', '.join(c['cve_id'] for c in cve_findings[:3])}.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "HIGH" if crit >= 4 else "MEDIUM",
                })

        # 2. CLOSE PORT — for sensitive ports
        sensitive_ports = [p for p in open_ports if p in {21, 23, 135, 139, 445, 3389, 5900, 6379}]
        for port in sensitive_ports[:2]:
            key = f"close_port:{node}:{port}"
            if key not in seen_keys:
                seen_keys.add(key)
                from app import PORT_SERVICE_MAP
                svc = PORT_SERVICE_MAP.get(port, f"port {port}")
                impact = calculate_defense_impact("close_port", nd, G, risk_score, compromised_nodes)
                impact["cost"] = int(8 + crit * 2)
                impact["risk_reduction"] = round(max(vuln, 0.2) * 1.6, 1)
                impact["efficiency"] = round(impact["risk_reduction"] / max(impact["cost"], 1), 3)
                impact["why_selected_explanation"] = (
                    f"🚪 Close Port {port} ({svc}) on {display}: removes attack surface for "
                    f"{svc} lateral movement (T1021.002). Cost: {impact['cost']} units. "
                    f"SIMULATION — applied to in-memory model only."
                )
                actions.append({
                    "action": f"🚪 Close port {port} ({svc}) on {display[:22]}",
                    "node": node,
                    "type": "close_port",
                    "description": f"Close or firewall {svc} (port {port}) on {display} — not required for business operations.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "HIGH" if port in {445, 3389, 23} else "MEDIUM",
                })

        # 3. DISABLE SERVICE — for dangerous services
        dangerous_svcs = [s for s in services if s in {"Telnet", "FTP", "VNC", "Redis", "MongoDB"}]
        for svc in dangerous_svcs[:1]:
            key = f"disable_svc:{node}:{svc}"
            if key not in seen_keys:
                seen_keys.add(key)
                impact = calculate_defense_impact("disable_service", nd, G, risk_score, compromised_nodes)
                impact["why_selected_explanation"] = (
                    f"⛔ Disable {svc} on {display}: legacy/insecure service with no modern equivalent. "
                    f"Eliminates {svc} lateral movement attack surface."
                )
                actions.append({
                    "action": f"⛔ Disable {svc} on {display[:28]}",
                    "node": node,
                    "type": "disable_service",
                    "description": f"Stop and disable {svc} service on {display} — replace with secure alternative.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "HIGH",
                })

        # 4. HOST ISOLATION — for critical compromised nodes
        if crit >= 4:
            key = f"isolate:{node}"
            if key not in seen_keys:
                seen_keys.add(key)
                impact = calculate_defense_impact("host_isolation", nd, G, risk_score, compromised_nodes)
                actions.append({
                    "action": f"🔒 Isolate {display[:30]}",
                    "node": node,
                    "type": "isolate",
                    "description": f"Quarantine {display} from the network — blocks ALL lateral movement to/from this critical asset.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "CRITICAL",
                })

        # 5. FIREWALL RULE — for any SMB/RDP exposure
        if any(p in open_ports for p in [445, 3389]):
            key = f"firewall:{node}"
            if key not in seen_keys:
                seen_keys.add(key)
                impact = calculate_defense_impact("firewall_rule", nd, G, risk_score, compromised_nodes)
                actions.append({
                    "action": f"🛡 Firewall {display[:28]} (SMB/RDP)",
                    "node": node,
                    "type": "firewall_rule",
                    "description": f"Add ACL rules to restrict SMB/RDP access on {display} to authorized hosts only.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "HIGH",
                })

    # 6. VLAN SEGMENTATION — global action
    key = "vlan_seg:ALL"
    if key not in seen_keys:
        seen_keys.add(key)
        impact = calculate_defense_impact("vlan_segmentation", {"display_name": "ALL", "criticality": 4, "vulnerability": 0.5, "risk_score": risk_score, "_node_id": None}, None, risk_score, [])
        impact["risk_reduction"] = round(risk_score * 0.15, 1)
        impact["blast_radius_reduction"] = round(risk_score * 0.35, 1)
        impact["attack_paths_removed"] = max(3, len(compromised_nodes) * 2)
        impact["critical_assets_protected"] = sum(1 for n in G.nodes if G.nodes[n].get("criticality", 0) >= 4 and G.nodes[n].get("node_type") != "honeypot")
        impact["why_selected_explanation"] = (
            f"🌐 VLAN Segmentation: splits workstations, servers, and databases into separate VLANs with ACLs. "
            f"Removes {impact['attack_paths_removed']} lateral movement paths, "
            f"protects {impact['critical_assets_protected']} critical asset(s). "
            f"Highest blast-radius reduction of all controls. SIMULATION — modeled impact on in-memory graph."
        )
        actions.append({
            "action": "🌐 VLAN Segmentation (All Segments)",
            "node": "ALL",
            "type": "vlan_segmentation",
            "description": "Separate workstations, servers, and databases into isolated VLANs with ACL enforcement.",
            **impact,
            "state": "RECOMMENDED",
            "priority": "HIGH",
        })

    # 7. MONITORING — global
    key = "monitor:ALL"
    if key not in seen_keys:
        seen_keys.add(key)
        impact = calculate_defense_impact("monitoring", {"display_name": "ALL", "criticality": 3, "vulnerability": 0.3, "risk_score": risk_score, "_node_id": None}, None, risk_score, [])
        impact["risk_reduction"] = round(risk_score * 0.12, 1)
        impact["why_selected_explanation"] = (
            f"📡 Deploy Monitoring/SIEM: provides detection coverage for T1046/T1021 lateral movement "
            f"across all segments. Reduces effective risk by detection-driven deterrence. "
            f"SIMULATION — modeled deterrence, not real deployment."
        )
        actions.append({
            "action": "📡 Deploy IDS / SIEM Monitoring",
            "node": "ALL",
            "type": "ids",
            "description": "Deploy network IDS (Snort/Suricata) and SIEM (Wazuh/Splunk) across LAN.",
            **impact,
            "state": "RECOMMENDED",
            "priority": "MEDIUM",
        })

    # 8. HONEYPOT — near highest-value compromised asset
    candidates = [n for n in compromised_nodes if G.nodes.get(n, {}).get("node_type") != "honeypot"]
    if candidates:
        top_node = max(candidates, key=lambda n: G.nodes[n].get("criticality", 0))
        td = G.nodes[top_node]
        top_display = td.get("display_name", top_node)
        if td.get("criticality", 0) >= 4:
            key = f"honeypot:{top_node}"
            if key not in seen_keys:
                seen_keys.add(key)
                impact = calculate_defense_impact("honeypot", {**td, "_node_id": top_node}, G, risk_score, compromised_nodes)
                impact["why_selected_explanation"] = (
                    f"🍯 Honeypot near {top_display}: deploys a decoy adjacent to the highest-value asset. "
                    f"Detects lateral movement 1-2 hops earlier, enabling faster incident response. "
                    f"SIMULATION — modeled detection improvement, not real deployment."
                )
                actions.append({
                    "action": f"🍯 Honeypot near {top_display[:28]}",
                    "node": top_node,
                    "type": "honeypot_placement",
                    "description": f"Deploy decoy adjacent to {top_display} to detect lateral movement toward this critical asset.",
                    **impact,
                    "state": "RECOMMENDED",
                    "priority": "MEDIUM",
                })

    # Assign relative priority tiers
    if actions:
        sorted_by_eff = sorted(actions, key=lambda a: a.get("efficiency", 0), reverse=True)
        n = len(sorted_by_eff)
        top_n = max(1, n // 3)
        for i, a in enumerate(sorted_by_eff):
            if a.get("priority") not in ("CRITICAL",):
                a["priority"] = "HIGH" if i < top_n else ("MEDIUM" if i < (2 * top_n) else "LOW")

    # Final sort: efficiency descending
    actions.sort(key=lambda a: (
        {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(a.get("priority", "LOW"), 1),
        a.get("efficiency", 0)
    ), reverse=True)

    return actions


def render_defense_action_card_v4(action: Dict[str, Any]) -> str:
    """Render a v4.0 defense action card with full impact breakdown."""
    priority = action.get("priority", "MEDIUM")
    pri_colors = {"CRITICAL": "#ff3355", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#3d6a8a"}
    color = pri_colors.get(priority, "#ffd700")
    state = action.get("state", "RECOMMENDED")
    state_color = "#00ff88" if state == "APPLIED TO SIMULATION MODEL" else "#7ab8d4" if state == "SELECTED" else "#3d6a8a"

    return f"""
<div style='background:#091520;border:1px solid {color};border-left:4px solid {color};
     padding:10px 14px;margin:6px 0;font-family:Share Tech Mono;font-size:0.72rem;border-radius:4px'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>
    <span style='color:{color};font-weight:bold'>{action.get('action','')}</span>
    <span style='color:{state_color};font-size:0.62rem'>{state}</span>
  </div>
  <div style='color:#7ab8d4;font-size:0.68rem;margin-bottom:6px'>{action.get('description','')}</div>
  <div style='display:flex;gap:10px;flex-wrap:wrap'>
    <span style='color:#3d6a8a'>Cost: <span style='color:#e0f4ff'>{action.get('cost',0)} units</span></span>
    <span style='color:#3d6a8a'>Risk Reduction: <span style='color:#00ff88'>-{action.get('risk_reduction',0):.0f}pts</span></span>
    <span style='color:#3d6a8a'>Blast Radius: <span style='color:#00ff88'>-{action.get('blast_radius_reduction',0):.0f}pts</span></span>
    <span style='color:#3d6a8a'>Paths Removed: <span style='color:#00ff88'>{action.get('attack_paths_removed',0)}</span></span>
    <span style='color:#3d6a8a'>Critical Protected: <span style='color:#00ff88'>{action.get('critical_assets_protected',0)}</span></span>
    <span style='color:#3d6a8a'>Efficiency: <span style='color:#00d4ff'>{action.get('efficiency',0):.3f}</span></span>
  </div>
  <div style='color:#3d6a8a;font-size:0.62rem;margin-top:6px'>{action.get('why_selected_explanation','')}</div>
  <div style='color:#ff3355;font-size:0.58rem;margin-top:2px'>SIMULATION — applied to in-memory model only</div>
</div>
"""
