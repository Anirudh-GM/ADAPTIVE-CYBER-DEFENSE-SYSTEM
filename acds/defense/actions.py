"""
ACDS Defense Action Generation & Model Mutation Engine
Generates candidates for Patching, Isolation, Least Privilege, IDS/SIEM, and VLAN Segmentation,
and mutates in-memory network graph models upon defense application.
"""

from typing import Dict, List, Optional, Set, Tuple, Any
import networkx as nx

from acds.core.constants import (
    DEFENSE_STATE_RECOMMENDED,
    DEFENSE_STATE_SELECTED,
    DEFENSE_STATE_APPLIED,
)
from acds.vulnerability.risk import recompute_node_risk


def get_defense_actions(
    G: nx.DiGraph,
    compromised_nodes: Set[str],
    risk_score: float,
    adaptive_multipliers: Optional[Dict[str, float]] = None,
    prioritized_vulnerabilities: Optional[List[Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Generate candidate defense actions for compromised and high-risk nodes.
    Ranks by efficiency ratio (risk_reduction / cost).
    Incorporates priority weighting from P1-P4 vulnerability definitions.
    """
    actions = []
    seen_fixes = set()
    adaptive_multipliers = adaptive_multipliers or {}

    # Map priority boosts from prioritized vulnerabilities
    prio_boost_map = {}
    if prioritized_vulnerabilities:
        for v in prioritized_vulnerabilities:
            p_level = getattr(v, "priority_level", "P4")
            boost = 1.50 if p_level == "P1" else 1.25 if p_level == "P2" else 1.05 if p_level == "P3" else 1.00
            for actx in getattr(v, "affected_assets", {}).values():
                host = getattr(actx, "host", "") or getattr(actx, "asset_id", "")
                prio_boost_map[host] = max(prio_boost_map.get(host, 1.0), boost)

    for node in compromised_nodes:
        if node not in G.nodes or G.nodes[node].get("node_type") == "honeypot":
            continue
        nd = G.nodes[node]
        crit = nd.get("criticality", 2)
        vuln = nd.get("vulnerability", 0.3)
        display = nd.get("display_name", node)
        multiplier = adaptive_multipliers.get(node, 1.0) * prio_boost_map.get(node, prio_boost_map.get(display, 1.0))

        # 1. Patch Actions
        for fix in nd.get("fixes", []):
            if fix in seen_fixes:
                continue
            seen_fixes.add(fix)
            fix_cost = int(12 + crit * 4)
            fix_reduction = round(vuln * crit * 3.5 * multiplier, 1)
            actions.append({
                "action": f"Fix: {fix[:60]}{'...' if len(fix) > 60 else ''}",
                "node": node,
                "type": "patch",
                "cost": fix_cost,
                "risk_reduction": fix_reduction,
                "efficiency": round(fix_reduction / fix_cost, 3),
                "description": fix,
                "state": DEFENSE_STATE_RECOMMENDED,
            })

        # 2. Isolation Actions
        for weakness in nd.get("weaknesses", [])[:2]:
            isolate_cost = int(18 + crit * 6)
            isolate_reduction = round(crit * 2.8 * multiplier, 1)
            action_key = f"Block: {weakness[:40]}"
            if action_key in seen_fixes:
                continue
            seen_fixes.add(action_key)
            actions.append({
                "action": action_key,
                "node": node,
                "type": "isolate",
                "cost": isolate_cost,
                "risk_reduction": isolate_reduction,
                "efficiency": round(isolate_reduction / isolate_cost, 3),
                "description": f"Segment or firewall {display} to block: {weakness}",
                "state": DEFENSE_STATE_RECOMMENDED,
            })

        # 3. Least Privilege / MFA Actions
        if crit >= 4:
            priv_cost = int(10 + crit * 3)
            priv_reduction = round(crit * 3.2, 1)
            actions.append({
                "action": f"Least Privilege on {display[:30]}",
                "node": node,
                "type": "privilege",
                "cost": priv_cost,
                "risk_reduction": priv_reduction,
                "efficiency": round(priv_reduction / priv_cost, 3),
                "description": f"Remove admin rights on {display}; enforce MFA and PAM",
                "state": DEFENSE_STATE_RECOMMENDED,
            })

    # 4. Global IDS / SIEM Deployment
    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS / SIEM",
        "node": "ALL",
        "type": "ids",
        "cost": ids_cost,
        "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Detect lateral movement (Snort/Suricata/Wazuh) across the LAN",
        "state": DEFENSE_STATE_RECOMMENDED,
    })

    # 5. Global VLAN Segmentation
    segment_cost = 25
    segment_reduction = round(risk_score * 0.15, 1)
    actions.append({
        "action": "Network Segmentation (VLANs)",
        "node": "ALL",
        "type": "isolate",
        "cost": segment_cost,
        "risk_reduction": segment_reduction,
        "efficiency": round(segment_reduction / segment_cost, 3),
        "description": "Split workstations, servers, and databases into separate VLANs with ACLs",
        "state": DEFENSE_STATE_RECOMMENDED,
    })

    actions.sort(key=lambda x: x["efficiency"], reverse=True)
    return actions


def apply_defense_actions(
    G: nx.DiGraph,
    selected_actions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], bool, bool]:
    """
    Mutate in-memory NetworkX model according to applied defenses.
    Returns (applied_actions, ids_deployed, segmentation_applied).
    """
    applied = []
    ids_deployed = False
    segmentation_applied = False

    for action in selected_actions:
        node = action.get("node")
        atype = action.get("type")

        if atype == "ids" and node == "ALL":
            ids_deployed = True
        elif atype == "isolate" and node == "ALL":
            segmentation_applied = True
        elif node in G.nodes:
            nd = G.nodes[node]
            comps = nd.get("risk_components")

            if atype == "patch" and comps:
                # Patch clears confirmed CVEs and reduces vulnerability component to 0
                nd["cve_findings"] = []
                comps['vulnerability']['normalized_score'] = 0.0
                recompute_node_risk(nd)

            elif atype == "isolate" and comps:
                # Isolation disables network exposure
                nd["isolated"] = True
                comps['network_exposure']['normalized_score'] = 0.0
                recompute_node_risk(nd)

            elif atype == "privilege" and comps:
                # Least privilege reduces criticality impact by 40%
                comps['criticality']['normalized_score'] = round(comps['criticality']['normalized_score'] * 0.6, 1)
                recompute_node_risk(nd)

        applied.append({**action, "state": DEFENSE_STATE_APPLIED})

    return applied, ids_deployed, segmentation_applied
