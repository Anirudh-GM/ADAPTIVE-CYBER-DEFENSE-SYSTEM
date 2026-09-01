"""
ACDS Experiment Metrics & Statistical Evaluation Engine
Computes statistical benchmarks (mean risk, variance, standard deviation, compromise rates)
and exports results to JSON and CSV formats.
"""

import csv
import io
import json
import math
from typing import Dict, List, Any


def compute_batch_statistics(simulation_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate descriptive statistics across a batch of simulation runs."""
    if not simulation_results:
        return {}

    n = len(simulation_results)
    risks = [r.get("risk_score", 0.0) for r in simulation_results]
    spreads = [r.get("blast_details", {}).get("spread", 0.0) for r in simulation_results]
    depths = [r.get("blast_details", {}).get("depth", 0.0) for r in simulation_results]
    controlled = [r.get("blast_details", {}).get("systems_controlled", 0) for r in simulation_results]
    critical_compromised = [r.get("blast_details", {}).get("critical_assets_reached", 0) for r in simulation_results]
    honeypot_hits = sum(1 for r in simulation_results if r.get("honeypot_triggered", False))

    mean_risk = sum(risks) / n
    variance_risk = sum((x - mean_risk) ** 2 for x in risks) / n if n > 1 else 0.0
    std_risk = math.sqrt(variance_risk)

    mean_spread = sum(spreads) / n
    mean_depth = sum(depths) / n
    mean_controlled = sum(controlled) / n
    critical_rate = (sum(1 for c in critical_compromised if c > 0) / n) * 100.0
    honeypot_detection_rate = (honeypot_hits / n) * 100.0

    return {
        "num_runs": n,
        "mean_risk": round(mean_risk, 2),
        "std_risk": round(std_risk, 2),
        "min_risk": round(min(risks), 2),
        "max_risk": round(max(risks), 2),
        "mean_spread_pct": round(mean_spread, 2),
        "mean_depth_pct": round(mean_depth, 2),
        "mean_systems_controlled": round(mean_controlled, 2),
        "critical_compromise_rate_pct": round(critical_rate, 2),
        "honeypot_detection_rate_pct": round(honeypot_detection_rate, 2),
    }


def export_experiment_results_csv(results: List[Dict[str, Any]]) -> str:
    """Export batch experiment results to CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Run_ID", "Seed", "Entry_Node", "Risk_Score", "Spread_Pct", "Critical_Impact_Pct",
        "Depth_Pct", "Systems_Controlled", "Critical_Reached", "Honeypot_Triggered"
    ])
    for i, r in enumerate(results, 1):
        bd = r.get("blast_details", {})
        writer.writerow([
            i,
            r.get("seed", "N/A"),
            r.get("entry_node", "N/A"),
            r.get("risk_score", 0.0),
            bd.get("spread", 0.0),
            bd.get("critical_impact", 0.0),
            bd.get("depth", 0.0),
            bd.get("systems_controlled", 0),
            bd.get("critical_assets_reached", 0),
            r.get("honeypot_triggered", False),
        ])
    return buf.getvalue()


def export_experiment_results_json(stats: Dict[str, Any], runs: List[Dict[str, Any]]) -> str:
    """Export batch summary and individual run details to JSON string."""
    data = {
        "summary_statistics": stats,
        "individual_runs": runs,
    }
    return json.dumps(data, indent=2)
