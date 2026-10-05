"""
ACDS v4.0 — PHASE 9: Historical Security Intelligence

Uses SQLite history to build trends and visualize security evolution.

Stores and analyzes:
  - Risk trend (overall + per-asset)
  - Asset trend (count over time)
  - Attack-path trend
  - Exposure trend
  - Defense effectiveness

Provides visualization data for trend charts.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.acds_logging import get_logger

log = get_logger(__name__)


def get_overall_risk_trend(db_module, limit: int = 30) -> List[Dict[str, Any]]:
    """
    Fetch the overall risk trend from the risk_history table.
    Returns a list of {timestamp, overall_risk, blast_radius} dicts,
    newest last (for charting).
    """
    try:
        rows = db_module.get_risk_history_summary(limit=limit)
        return rows
    except Exception as exc:
        log.warning("Could not fetch overall risk trend: %s", exc)
        return []


def get_asset_count_trend(db_module, limit: int = 30) -> List[Dict[str, Any]]:
    """
    Fetch asset count over time from scan_snapshots.
    Returns [{timestamp, total_assets}] newest last.
    """
    try:
        return db_module.get_asset_count_trend(limit=limit)
    except Exception as exc:
        log.warning("Could not fetch asset count trend: %s", exc)
        return []


def get_attack_path_trend(session_state) -> List[Dict[str, Any]]:
    """
    Build attack-path count trend from in-session scan history.
    Each scan history entry carries the attack stats from that run.
    """
    scan_history = session_state.get("scan_history") or []
    result = []
    for entry in scan_history:
        result.append({
            "timestamp": (entry.get("timestamp") or datetime.now(timezone.utc)).isoformat()
            if hasattr(entry.get("timestamp"), "isoformat") else str(entry.get("timestamp", "")),
            "scan_id": entry.get("scan_id", 0),
            "asset_count": entry.get("asset_count", 0),
            "avg_risk": entry.get("average_risk", 0),
            "critical": entry.get("critical_count", 0),
            "high": entry.get("high_count", 0),
        })
    return result


def build_exposure_trend_from_history(risk_rows: List[Dict]) -> Dict[str, List]:
    """
    Build chart-ready series from risk history rows.
    Returns {'labels': [...], 'overall_risk': [...], 'blast_radius': [...]}
    """
    labels = []
    overall = []
    blast = []
    for row in risk_rows:
        ts = (row.get("timestamp") or "")[:16].replace("T", " ")
        labels.append(ts)
        overall.append(row.get("overall_risk") or 0)
        blast.append(row.get("blast_radius") or 0)
    return {"labels": labels, "overall_risk": overall, "blast_radius": blast}


def calculate_defense_effectiveness(
    before_stats: Optional[Dict],
    after_stats: Optional[Dict],
    applied_defenses: List[Dict],
) -> Dict[str, Any]:
    """
    Phase 9: Calculate defense effectiveness metrics from before/after stats.

    Returns:
        {
            'risk_reduction': float,
            'paths_blocked': int,
            'critical_assets_protected': int,
            'blast_radius_reduction': float,
            'cost_efficiency': float,  # risk_reduction / total_cost
            'effectiveness_label': str,
        }
    """
    if not before_stats or not after_stats:
        return {
            "risk_reduction": 0.0, "paths_blocked": 0,
            "critical_assets_protected": 0, "blast_radius_reduction": 0.0,
            "cost_efficiency": 0.0, "effectiveness_label": "N/A — simulation not run",
        }

    risk_reduction = max(0, (before_stats.get("risk_score", 0) or 0) - (after_stats.get("risk_score", 0) or 0))
    paths_before = before_stats.get("systems_controlled", before_stats.get("compromised_count", 0))
    paths_after = after_stats.get("systems_controlled", after_stats.get("compromised_count", 0))
    paths_blocked = max(0, paths_before - paths_after)
    crit_before = before_stats.get("critical_assets_reached", 0)
    crit_after = after_stats.get("critical_assets_reached", 0)
    crit_protected = max(0, crit_before - crit_after)
    blast_before = before_stats.get("spread", 0)
    blast_after = after_stats.get("spread", 0)
    blast_reduction = max(0, blast_before - blast_after)

    total_cost = sum(a.get("cost", 0) for a in (applied_defenses or []))
    cost_efficiency = round(risk_reduction / total_cost, 2) if total_cost > 0 else 0.0

    if risk_reduction >= 30:
        label = "HIGHLY EFFECTIVE"
    elif risk_reduction >= 15:
        label = "EFFECTIVE"
    elif risk_reduction >= 5:
        label = "PARTIALLY EFFECTIVE"
    else:
        label = "MINIMAL EFFECT"

    return {
        "risk_reduction": round(risk_reduction, 1),
        "paths_blocked": paths_blocked,
        "critical_assets_protected": crit_protected,
        "blast_radius_reduction": round(blast_reduction, 1),
        "cost_efficiency": cost_efficiency,
        "total_cost": total_cost,
        "effectiveness_label": label,
        "simulation_label": "SIMULATION ONLY",
    }


def render_historical_trend_html(
    risk_rows: List[Dict],
    asset_trend: List[Dict],
    defense_eff: Dict,
) -> str:
    """
    Render a compact historical intelligence summary as HTML.
    Full charts are rendered via Streamlit's chart_display_v0 in the UI.
    """
    trend_data = build_exposure_trend_from_history(risk_rows)
    current_risk = trend_data["overall_risk"][-1] if trend_data["overall_risk"] else 0
    prev_risk = trend_data["overall_risk"][-2] if len(trend_data["overall_risk"]) > 1 else current_risk
    trend_dir = "↑" if current_risk > prev_risk else ("↓" if current_risk < prev_risk else "→")
    trend_color = "#ff3355" if current_risk > prev_risk else "#00ff88"

    eff = defense_eff
    eff_label = eff.get("effectiveness_label", "N/A")

    return f"""
<div style='background:#091520;border:1px solid #1a3a5c;padding:12px 16px;border-radius:4px;
     font-family:Share Tech Mono;font-size:0.72rem;'>
  <div style='color:#00d4ff;font-family:Orbitron,monospace;font-weight:bold;margin-bottom:8px'>
    📊 SECURITY INTELLIGENCE SUMMARY
  </div>
  <div style='display:flex;gap:12px;flex-wrap:wrap'>
    <div style='flex:1;min-width:120px;background:#0d1f2d;padding:8px;border-radius:3px'>
      <div style='color:#3d6a8a;font-size:0.62rem'>CURRENT OVERALL RISK</div>
      <div style='color:{trend_color};font-size:1.1rem;font-family:Orbitron,monospace'>{current_risk:.0f} {trend_dir}</div>
    </div>
    <div style='flex:1;min-width:120px;background:#0d1f2d;padding:8px;border-radius:3px'>
      <div style='color:#3d6a8a;font-size:0.62rem'>DATA POINTS</div>
      <div style='color:#e0f4ff;font-size:1.1rem;font-family:Orbitron,monospace'>{len(risk_rows)}</div>
    </div>
    <div style='flex:1;min-width:120px;background:#0d1f2d;padding:8px;border-radius:3px'>
      <div style='color:#3d6a8a;font-size:0.62rem'>DEFENSE EFFECTIVENESS</div>
      <div style='color:#00ff88;font-size:0.85rem;font-family:Orbitron,monospace'>{eff_label}</div>
    </div>
    <div style='flex:1;min-width:120px;background:#0d1f2d;padding:8px;border-radius:3px'>
      <div style='color:#3d6a8a;font-size:0.62rem'>RISK REDUCTION</div>
      <div style='color:#00ff88;font-size:1.1rem;font-family:Orbitron,monospace'>-{eff.get('risk_reduction',0):.0f}pts</div>
    </div>
  </div>
  <div style='color:#3d6a8a;font-size:0.62rem;margin-top:6px'>SIMULATION ONLY — Trend data from monitoring passes and simulations.</div>
</div>
"""
