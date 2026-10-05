"""
ACDS v4.0 — PHASE 5: Closed-Loop Adaptive Defense

Implements the full adaptive cycle:

  Observe → Assess → Model → Simulate → Rank Risk → Select Defense
  → Apply Model → Re-Validate → Re-Simulate → Measure → Continue Monitoring

Displays BEFORE vs AFTER for:
  - Overall Risk
  - Blast Radius
  - Attack Paths
  - Critical Assets
  - Risk Reduction
  - Cost

Always labelled as SIMULATED. Never claims real-world effect.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.acds_logging import get_logger

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────
# ADAPTIVE CYCLE STAGES
# ─────────────────────────────────────────────────────────────────

CYCLE_STAGES = [
    {"id": 1, "name": "OBSERVE",         "icon": "👁", "description": "Discover assets, services, open ports via passive scanning"},
    {"id": 2, "name": "ASSESS",          "icon": "📋", "description": "Fingerprint assets, grab banners, identify OS/device type"},
    {"id": 3, "name": "MODEL",           "icon": "🗺", "description": "Build attack graph with explainable edges (Phase 1)"},
    {"id": 4, "name": "SIMULATE",        "icon": "⚔", "description": "Run decision-based propagation simulation (MITRE-based)"},
    {"id": 5, "name": "RANK RISK",       "icon": "📊", "description": "Graph-aware multi-factor risk prioritization (Phase 2)"},
    {"id": 6, "name": "SELECT DEFENSE",  "icon": "🎯", "description": "Budget-constrained defense optimization (Phase 4)"},
    {"id": 7, "name": "APPLY MODEL",     "icon": "🔧", "description": "Apply defenses to in-memory model — SIMULATION ONLY"},
    {"id": 8, "name": "RE-VALIDATE",     "icon": "⚡", "description": "Real-time port/host validation of applied model state"},
    {"id": 9, "name": "RE-SIMULATE",     "icon": "🔁", "description": "Re-run attack simulation with defenses in place"},
    {"id": 10, "name": "MEASURE",        "icon": "📏", "description": "Compare BEFORE vs AFTER: risk, blast radius, paths"},
    {"id": 11, "name": "MONITORING",     "icon": "🛰", "description": "Continuous monitoring — detect topology changes → restart cycle"},
]


def get_cycle_stage_status(session_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Determine which cycle stages are complete/active/pending based on session state.
    Returns annotated stage list with status and completion timestamp.
    """
    stages = []
    for stage in CYCLE_STAGES:
        sid = stage["id"]
        status = "PENDING"
        ts = None

        if sid == 1:
            status = "COMPLETE" if session_state.get("last_scan_devices") or session_state.get("network_mode") == "Simulated Lab" else "PENDING"
        elif sid == 2:
            status = "COMPLETE" if session_state.get("G") and len(list(session_state["G"].nodes())) > 0 else "PENDING"
        elif sid == 3:
            status = "COMPLETE" if session_state.get("G") and session_state["G"].number_of_edges() > 0 else "PENDING"
        elif sid == 4:
            status = "COMPLETE" if session_state.get("simulation_done") else "PENDING"
        elif sid == 5:
            status = "COMPLETE" if session_state.get("simulation_done") else "PENDING"
        elif sid == 6:
            status = "COMPLETE" if session_state.get("selected_defenses") else "PENDING"
        elif sid == 7:
            status = "COMPLETE" if session_state.get("applied_defenses") else "PENDING"
        elif sid == 8:
            status = "COMPLETE" if session_state.get("live_validation_results") else ("ACTIVE" if session_state.get("applied_defenses") else "PENDING")
        elif sid == 9:
            status = "COMPLETE" if (session_state.get("applied_defenses") and session_state.get("post_defense_stats")) else "PENDING"
        elif sid == 10:
            status = "COMPLETE" if (session_state.get("risk_before_defense") is not None and session_state.get("applied_defenses")) else "PENDING"
        elif sid == 11:
            status = "ACTIVE" if session_state.get("monitoring_enabled") else "PENDING"

        stages.append({**stage, "status": status, "timestamp": ts})

    return stages


def compute_before_after_comparison(
    before_risk: Optional[float],
    after_risk: Optional[float],
    before_blast: Optional[Dict],
    after_blast: Optional[Dict],
    before_overall: Optional[Dict],
    after_overall: Optional[Dict],
    applied_defenses: Optional[List],
) -> Dict[str, Any]:
    """
    Phase 5: Compute the full BEFORE vs AFTER comparison.
    All values are from the simulation model — never real network state.
    """
    if before_risk is None:
        return {"status": "NO_BASELINE", "message": "Run a simulation first to establish the BEFORE baseline."}

    before_bd = before_blast or {}
    after_bd = after_blast or {}
    before_ov = before_overall or {}
    after_ov = after_overall or {}

    def _delta(b, a):
        if b is None or a is None:
            return None
        return round(a - b, 1)

    def _pct_change(b, a):
        if b is None or a is None or b == 0:
            return None
        return round((a - b) / b * 100, 1)

    total_cost = sum(d.get("cost", 0) for d in (applied_defenses or []))
    total_reduction = sum(d.get("risk_reduction", 0) for d in (applied_defenses or []))

    metrics = {
        "overall_risk": {
            "before": before_ov.get("overall_score"),
            "after": after_ov.get("overall_score"),
            "delta": _delta(before_ov.get("overall_score"), after_ov.get("overall_score")),
            "pct_change": _pct_change(before_ov.get("overall_score"), after_ov.get("overall_score")),
            "label": "Overall Risk", "lower_is_better": True,
        },
        "blast_radius": {
            "before": before_risk,
            "after": after_risk,
            "delta": _delta(before_risk, after_risk),
            "pct_change": _pct_change(before_risk, after_risk),
            "label": "Blast Radius", "lower_is_better": True,
        },
        "attack_paths": {
            "before": before_bd.get("systems_controlled", before_bd.get("compromised_count", 0)),
            "after": after_bd.get("systems_controlled", after_bd.get("compromised_count", 0)) if after_bd else None,
            "delta": _delta(
                before_bd.get("systems_controlled", 0),
                after_bd.get("systems_controlled", 0) if after_bd else None,
            ),
            "label": "Reachable Nodes", "lower_is_better": True,
        },
        "critical_assets": {
            "before": before_bd.get("critical_assets_reached", 0),
            "after": after_bd.get("critical_assets_reached", 0) if after_bd else None,
            "delta": _delta(
                before_bd.get("critical_assets_reached", 0),
                after_bd.get("critical_assets_reached", 0) if after_bd else None,
            ),
            "label": "Critical Assets Reachable", "lower_is_better": True,
        },
        "attack_depth": {
            "before": before_bd.get("max_lateral_hops", 0),
            "after": after_bd.get("max_lateral_hops", 0) if after_bd else None,
            "delta": _delta(
                before_bd.get("max_lateral_hops", 0),
                after_bd.get("max_lateral_hops", 0) if after_bd else None,
            ),
            "label": "Attack Depth (hops)", "lower_is_better": True,
        },
    }

    # Overall assessment
    risk_delta = metrics["blast_radius"]["delta"]
    if risk_delta is not None and risk_delta < -15:
        assessment = "SIGNIFICANT IMPROVEMENT"
        assessment_color = "#00ff88"
    elif risk_delta is not None and risk_delta < -5:
        assessment = "MODERATE IMPROVEMENT"
        assessment_color = "#7ab8d4"
    elif risk_delta is not None and risk_delta < 0:
        assessment = "MARGINAL IMPROVEMENT"
        assessment_color = "#ffd700"
    elif applied_defenses:
        assessment = "MINIMAL CHANGE — consider higher-impact defenses"
        assessment_color = "#ff8c00"
    else:
        assessment = "NO DEFENSES APPLIED"
        assessment_color = "#3d6a8a"

    return {
        "status": "COMPLETE" if applied_defenses else "PARTIAL",
        "metrics": metrics,
        "total_defense_cost": total_cost,
        "total_risk_reduction": round(total_reduction, 1),
        "defenses_applied": len(applied_defenses or []),
        "assessment": assessment,
        "assessment_color": assessment_color,
        "simulation_label": "SIMULATION — NO REAL ATTACK TRAFFIC. Applied to in-memory model only.",
    }


def render_adaptive_cycle_html(stages: List[Dict]) -> str:
    """Render the adaptive cycle pipeline as a horizontal flow diagram."""
    status_colors = {
        "COMPLETE": "#00ff88",
        "ACTIVE": "#ffd700",
        "PENDING": "#3d6a8a",
    }
    status_icons = {
        "COMPLETE": "✓",
        "ACTIVE": "▶",
        "PENDING": "○",
    }

    items = []
    for i, stage in enumerate(stages):
        status = stage.get("status", "PENDING")
        color = status_colors[status]
        icon = status_icons[status]
        is_last = i == len(stages) - 1

        items.append(f"""
<div style='display:flex;flex-direction:column;align-items:center;min-width:80px;flex:1'>
  <div style='width:36px;height:36px;border-radius:50%;background:rgba({
    "0,255,136" if status=="COMPLETE" else "255,215,0" if status=="ACTIVE" else "61,106,138"
  },0.15);border:2px solid {color};display:flex;align-items:center;justify-content:center;
  font-size:0.85rem;color:{color}'>{stage["icon"]}</div>
  <div style='color:{color};font-family:Orbitron,monospace;font-size:0.52rem;letter-spacing:1px;
  margin-top:4px;text-align:center;line-height:1.3'>{stage["name"]}</div>
  <div style='color:{color};font-size:0.7rem'>{icon}</div>
</div>
{"<div style='flex:0 0 auto;width:20px;height:2px;background:#1a3a5c;margin-top:18px'></div>" if not is_last else ""}""")

    return f"""
<div style='background:#06111a;border:1px solid #1a3a5c;padding:16px 12px;border-radius:6px;
     overflow-x:auto;margin-bottom:16px'>
  <div style='color:#00d4ff;font-family:Orbitron,monospace;font-size:0.7rem;font-weight:bold;
  margin-bottom:12px;letter-spacing:2px'>🔄 ADAPTIVE DEFENSE CYCLE</div>
  <div style='display:flex;align-items:flex-start;gap:0;min-width:700px'>
    {"".join(items)}
  </div>
  <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.58rem;margin-top:8px'>
    SIMULATION ONLY — Cycle stages reflect modeled posture changes, not real network state.
  </div>
</div>
"""


def render_before_after_v4(comparison: Dict[str, Any]) -> str:
    """Render the v4.0 BEFORE vs AFTER comparison as styled HTML."""
    if comparison.get("status") == "NO_BASELINE":
        return f"<div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.72rem'>{comparison['message']}</div>"

    metrics = comparison.get("metrics", {})
    assessment = comparison.get("assessment", "N/A")
    assessment_color = comparison.get("assessment_color", "#ffd700")

    cards = []
    for key, m in metrics.items():
        before = m.get("before")
        after = m.get("after")
        delta = m.get("delta")
        lower_is_better = m.get("lower_is_better", True)

        if before is None:
            continue

        if after is None:
            # No AFTER yet
            cards.append(f"""
<div style='flex:1;min-width:130px;background:#0d1f2d;border:1px solid #1a3a5c;
     padding:10px;text-align:center;border-radius:4px'>
  <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.6rem;margin-bottom:4px'>{m["label"]}</div>
  <div style='color:#ffd700;font-family:Orbitron,monospace;font-size:1.1rem'>{before}</div>
  <div style='color:#3d6a8a;font-size:0.6rem;margin-top:2px'>no AFTER yet</div>
</div>""")
        else:
            improved = (delta <= 0) if lower_is_better else (delta >= 0)
            border_color = "#00ff88" if improved else "#ff3355"
            delta_color = "#00ff88" if improved else "#ff3355"
            delta_str = f"{'+' if delta > 0 else ''}{delta}"
            cards.append(f"""
<div style='flex:1;min-width:130px;background:#0d1f2d;border:1px solid {border_color};
     padding:10px;text-align:center;border-radius:4px'>
  <div style='color:#3d6a8a;font-family:Share Tech Mono;font-size:0.6rem;margin-bottom:4px'>{m["label"]}</div>
  <div style='font-family:Orbitron,monospace;font-size:0.9rem;margin-top:4px'>
    <span style='color:#ff3355'>{before}</span>
    <span style='color:#3d6a8a;font-size:0.75rem'> → </span>
    <span style='color:#00ff88'>{after}</span>
  </div>
  <div style='color:{delta_color};font-family:Share Tech Mono;font-size:0.68rem;margin-top:2px'>{delta_str}</div>
</div>""")

    summary = (
        f"<div style='background:rgba({'0,255,136' if '#00ff88' in assessment_color else '255,140,0'},0.08);"
        f"border:1px solid {assessment_color};padding:8px 12px;margin-top:10px;"
        f"font-family:Share Tech Mono;font-size:0.72rem;color:{assessment_color};border-radius:4px'>"
        f"ASSESSMENT: {assessment} &nbsp;|&nbsp; "
        f"Defenses applied: {comparison.get('defenses_applied',0)} &nbsp;|&nbsp; "
        f"Total cost: {comparison.get('total_defense_cost',0)} units &nbsp;|&nbsp; "
        f"Risk reduction: -{comparison.get('total_risk_reduction',0):.0f}pts"
        f"</div>"
    )

    simulation_label = f"<div style='color:#ff3355;font-size:0.6rem;margin-top:6px'>{comparison.get('simulation_label','SIMULATION ONLY — modeled impact, not real network')}</div>"

    return f"""
<div>
  <div style='display:flex;gap:8px;flex-wrap:wrap'>{" ".join(cards)}</div>
  {summary}
  {simulation_label}
</div>
"""
