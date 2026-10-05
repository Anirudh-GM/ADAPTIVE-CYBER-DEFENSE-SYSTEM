"""
ACDS v4.0 — PHASE 2: Graph-Aware Risk Prioritization

Replaces simple CVSS ranking with a graph-topology-aware priority score
that considers:
  - CVSS (vulnerability severity)
  - Network exposure (reachability from other assets)
  - Number of attack paths leading to this asset
  - Downstream critical assets reachable FROM this asset
  - Blast radius contribution
  - Propagation confidence

Every asset receives an explainable priority breakdown showing exactly
WHY it is ranked High or Critical.

SIMULATION ONLY — graph topology is modeled, not real traffic.
"""

from __future__ import annotations
import networkx as nx
from typing import Any, Dict, List, Optional, Tuple


# Component weights for graph-aware priority score (ACDS design choice, not industry standard)
PRIORITY_WEIGHT_CVSS = 0.28            # raw CVE severity
PRIORITY_WEIGHT_EXPOSURE = 0.15       # how many assets can reach this one
PRIORITY_WEIGHT_REACHABILITY = 0.12   # reachability validation state
PRIORITY_WEIGHT_ATTACK_PATHS = 0.18   # number of distinct paths reaching this asset
PRIORITY_WEIGHT_DOWNSTREAM = 0.12     # critical assets reachable FROM this asset
PRIORITY_WEIGHT_BLAST_RADIUS = 0.08   # simulated blast-radius contribution
PRIORITY_WEIGHT_CONFIDENCE = 0.07     # propagation confidence modifier

# Caps for normalization (ACDS design constants)
MAX_ATTACK_PATHS = 20        # paths beyond this → score saturates
MAX_DOWNSTREAM_CRITICAL = 5  # critical downstream assets beyond this → saturates
MAX_EXPOSURE_ASSETS = 10     # peers that can reach this asset → saturates


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def calculate_graph_aware_priority(
    node: str,
    node_data: Dict[str, Any],
    G: "nx.DiGraph",
) -> Dict[str, Any]:
    """
    Calculate a graph-aware priority score (0-100) for a single asset.

    Returns a breakdown dict with per-component contributions and an
    explanation of why the priority is what it is.
    """
    # ── 1. CVSS Component ──────────────────────────────────────────
    cve_findings = node_data.get("cve_findings") or []
    max_cvss = max((float(c.get("cvss", 0)) for c in cve_findings), default=0.0)
    # CVSS 0-10 → 0-100; weighted contribution
    cvss_score = (max_cvss / 10.0) * 100.0
    cvss_contrib = round(cvss_score * PRIORITY_WEIGHT_CVSS, 2)
    cvss_explain = (
        f"Highest confirmed CVSS: {max_cvss} → {cvss_score:.0f}/100 "
        f"(×{PRIORITY_WEIGHT_CVSS} weight = {cvss_contrib:.1f}pts)"
        if cve_findings else
        f"No version-specific CVE found (CVSS=0, contrib=0)"
    )

    # ── 2. Network Exposure Component ─────────────────────────────
    # How many OTHER assets have an edge leading TO this node (i.e., can reach it)
    in_degree = G.in_degree(node)
    exposure_score = _clamp((in_degree / MAX_EXPOSURE_ASSETS) * 100)
    exposure_contrib = round(exposure_score * PRIORITY_WEIGHT_EXPOSURE, 2)
    exposure_explain = (
        f"{in_degree} asset(s) have a modeled path to this node → "
        f"{exposure_score:.0f}/100 (×{PRIORITY_WEIGHT_EXPOSURE} = {exposure_contrib:.1f}pts)"
    )

    # ── 3. Reachability Component ──────────────────────────────────
    # Risk component from asset_risk_components if available
    comps = node_data.get("risk_components") or {}
    network_exp_comp = comps.get("network_exposure", {}).get("normalized_score", 50.0)
    reach_score = _clamp(network_exp_comp)
    reach_contrib = round(reach_score * PRIORITY_WEIGHT_REACHABILITY, 2)
    reach_explain = (
        f"Network exposure component: {reach_score:.0f}/100 "
        f"(×{PRIORITY_WEIGHT_REACHABILITY} = {reach_contrib:.1f}pts)"
    )

    # ── 4. Attack Paths Component ──────────────────────────────────
    # Count simple paths FROM any other node TO this node (capped)
    other_nodes = [n for n in G.nodes if n != node and G.nodes[n].get("node_type") != "honeypot"]
    path_count = 0
    for src in other_nodes[:15]:  # limit for performance
        try:
            paths = list(nx.all_simple_paths(G, src, node, cutoff=4))
            path_count += len(paths)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
    path_score = _clamp((min(path_count, MAX_ATTACK_PATHS) / MAX_ATTACK_PATHS) * 100)
    path_contrib = round(path_score * PRIORITY_WEIGHT_ATTACK_PATHS, 2)
    path_explain = (
        f"{path_count} modeled attack path(s) reach this asset (capped at {MAX_ATTACK_PATHS}) → "
        f"{path_score:.0f}/100 (×{PRIORITY_WEIGHT_ATTACK_PATHS} = {path_contrib:.1f}pts)"
    )

    # ── 5. Downstream Critical Assets Component ───────────────────
    # How many CRITICAL assets are reachable FROM this node
    downstream_critical = 0
    try:
        reachable = nx.descendants(G, node)
        downstream_critical = sum(
            1 for n in reachable
            if G.nodes[n].get("criticality", 0) >= 4
            and G.nodes[n].get("node_type") != "honeypot"
        )
    except nx.NetworkXError:
        pass
    downstream_score = _clamp((min(downstream_critical, MAX_DOWNSTREAM_CRITICAL) / MAX_DOWNSTREAM_CRITICAL) * 100)
    downstream_contrib = round(downstream_score * PRIORITY_WEIGHT_DOWNSTREAM, 2)
    downstream_explain = (
        f"{downstream_critical} critical asset(s) reachable downstream from this node → "
        f"{downstream_score:.0f}/100 (×{PRIORITY_WEIGHT_DOWNSTREAM} = {downstream_contrib:.1f}pts)"
    )

    # ── 6. Blast Radius Contribution ──────────────────────────────
    # Use asset's own risk_score as a proxy for blast-radius impact
    risk_score = node_data.get("risk_score", 0.0)
    blast_score = _clamp(risk_score)
    blast_contrib = round(blast_score * PRIORITY_WEIGHT_BLAST_RADIUS, 2)
    blast_explain = (
        f"Asset Risk Score {risk_score:.0f}/100 used as blast-radius proxy → "
        f"(×{PRIORITY_WEIGHT_BLAST_RADIUS} = {blast_contrib:.1f}pts)"
    )

    # ── 7. Propagation Confidence Modifier ────────────────────────
    # Confidence = CVE count × criticality signal
    cve_count = len(cve_findings)
    criticality = node_data.get("criticality", 2)
    confidence_raw = min(1.0, (cve_count * 0.15) + (criticality / 5.0) * 0.5)
    confidence_score = _clamp(confidence_raw * 100)
    confidence_contrib = round(confidence_score * PRIORITY_WEIGHT_CONFIDENCE, 2)
    confidence_explain = (
        f"{cve_count} CVE(s), criticality={criticality} → confidence {confidence_score:.0f}/100 "
        f"(×{PRIORITY_WEIGHT_CONFIDENCE} = {confidence_contrib:.1f}pts)"
    )

    # ── Total Priority Score ───────────────────────────────────────
    total = (
        cvss_contrib + exposure_contrib + reach_contrib +
        path_contrib + downstream_contrib + blast_contrib + confidence_contrib
    )
    total = _clamp(total)

    # Priority label
    if total >= 80:
        priority_label = "CRITICAL"
        priority_color = "#ff3355"
    elif total >= 60:
        priority_label = "HIGH"
        priority_color = "#ff8c00"
    elif total >= 35:
        priority_label = "MEDIUM"
        priority_color = "#ffd700"
    else:
        priority_label = "LOW"
        priority_color = "#00ff88"

    return {
        "node": node,
        "display_name": node_data.get("display_name", node),
        "ip": node_data.get("ip", ""),
        "priority_score": round(total, 1),
        "priority_label": priority_label,
        "priority_color": priority_color,
        "components": {
            "cvss": {"score": round(cvss_score, 1), "contribution": cvss_contrib, "explanation": cvss_explain, "weight": PRIORITY_WEIGHT_CVSS},
            "exposure": {"score": round(exposure_score, 1), "contribution": exposure_contrib, "explanation": exposure_explain, "weight": PRIORITY_WEIGHT_EXPOSURE},
            "reachability": {"score": round(reach_score, 1), "contribution": reach_contrib, "explanation": reach_explain, "weight": PRIORITY_WEIGHT_REACHABILITY},
            "attack_paths": {"score": round(path_score, 1), "contribution": path_contrib, "explanation": path_explain, "weight": PRIORITY_WEIGHT_ATTACK_PATHS},
            "downstream_critical": {"score": round(downstream_score, 1), "contribution": downstream_contrib, "explanation": downstream_explain, "weight": PRIORITY_WEIGHT_DOWNSTREAM},
            "blast_radius": {"score": round(blast_score, 1), "contribution": blast_contrib, "explanation": blast_explain, "weight": PRIORITY_WEIGHT_BLAST_RADIUS},
            "confidence": {"score": round(confidence_score, 1), "contribution": confidence_contrib, "explanation": confidence_explain, "weight": PRIORITY_WEIGHT_CONFIDENCE},
        },
        "summary_why": (
            f"Priority is {priority_label} because: "
            f"CVSS={round(cvss_score,0)}/100, "
            f"Exposure={round(exposure_score,0)}/100, "
            f"Attack paths={path_count}, "
            f"Downstream critical={downstream_critical}, "
            f"Asset risk={risk_score:.0f}/100."
        ),
        "simulation_label": "SIMULATION — graph topology is modeled, not observed traffic",
    }


def rank_all_assets_by_priority(G: "nx.DiGraph") -> List[Dict[str, Any]]:
    """
    Compute graph-aware priority for every non-honeypot asset in G.
    Returns a sorted list (highest priority first) with full component breakdowns.
    """
    results = []
    for node, data in G.nodes(data=True):
        if data.get("node_type") == "honeypot":
            continue
        priority = calculate_graph_aware_priority(node, data, G)
        results.append(priority)

    results.sort(key=lambda x: x["priority_score"], reverse=True)
    return results


def render_priority_breakdown_html(priority: Dict[str, Any]) -> str:
    """Render an explainable priority card for the UI."""
    comps = priority.get("components", {})
    color = priority.get("priority_color", "#ffd700")
    label = priority.get("priority_label", "?")
    score = priority.get("priority_score", 0)
    display = priority.get("display_name", "Asset")
    ip = priority.get("ip", "")

    rows = ""
    for comp_key, comp_data in comps.items():
        rows += (
            f"<tr style='border-bottom:1px solid #142a3a'>"
            f"<td style='padding:4px 8px;color:#7ab8d4;text-transform:capitalize'>{comp_key.replace('_',' ')}</td>"
            f"<td style='padding:4px 8px;color:#e0f4ff;text-align:right'>{comp_data['score']:.0f}/100</td>"
            f"<td style='padding:4px 8px;color:#00d4ff;text-align:right'>{comp_data['contribution']:.1f}pts</td>"
            f"<td style='padding:4px 8px;color:#3d6a8a;font-size:0.62rem'>{comp_data['explanation']}</td>"
            f"</tr>"
        )

    return f"""
<div style='background:#091520;border:1px solid #1a3a5c;border-left:4px solid {color};
     padding:12px 16px;margin:8px 0;border-radius:4px'>
  <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:8px'>
    <span style='color:{color};font-family:Orbitron,monospace;font-weight:bold'>{display} ({ip})</span>
    <span style='color:{color};font-family:Orbitron,monospace;font-size:1.1rem'>{score:.0f}/100 — {label}</span>
  </div>
  <div style='color:#7ab8d4;font-family:Share Tech Mono;font-size:0.68rem;margin-bottom:8px'>{priority.get('summary_why','')}</div>
  <table style='width:100%;border-collapse:collapse;font-family:Share Tech Mono;font-size:0.68rem'>
    <thead><tr style='color:#00d4ff;border-bottom:1px solid #00d4ff'>
      <th style='text-align:left;padding:4px 8px'>Component</th>
      <th style='text-align:right;padding:4px 8px'>Score</th>
      <th style='text-align:right;padding:4px 8px'>Contribution</th>
      <th style='text-align:left;padding:4px 8px'>Explanation</th>
    </tr></thead>
    <tbody>{rows}</tbody>
    <tfoot><tr style='border-top:1px solid #1a3a5c'>
      <td colspan='2' style='padding:4px 8px;color:#00d4ff;font-weight:bold'>TOTAL</td>
      <td style='padding:4px 8px;color:#00ff88;font-weight:bold;text-align:right'>{score:.1f}pts</td>
      <td></td>
    </tr></tfoot>
  </table>
  <div style='color:#ff3355;font-size:0.6rem;margin-top:6px'>{priority.get('simulation_label','')}</div>
</div>
"""
