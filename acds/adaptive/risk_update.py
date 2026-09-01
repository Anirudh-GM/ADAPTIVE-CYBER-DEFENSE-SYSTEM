"""
ACDS Adaptive Risk Update Engine
Applies mathematically transparent risk updates to network assets based on honeypot behavioral feedback.
"""

from typing import Dict, List, Tuple, Any
import networkx as nx
from acds.vulnerability.risk import severity_from_score


def apply_adaptive_risk_updates(
    G: nx.DiGraph,
    feedback_signals: Dict[str, Any],
) -> Dict[str, Tuple[float, float, float]]:
    """
    Apply adaptive risk delta to graph nodes based on honeypot observations.
    Returns {node: (original_risk, updated_risk, delta)}.
    """
    changes: Dict[str, Tuple[float, float, float]] = {}
    affected_map = feedback_signals.get("affected_nodes", {})

    for node, info in affected_map.items():
        if node in G.nodes:
            nd = G.nodes[node]
            orig_risk = float(nd.get("risk_score", 0.0))
            delta = float(info.get("adaptive_risk_delta", 0.0))

            updated_risk = min(100.0, round(orig_risk + delta, 1))
            nd["risk_score"] = updated_risk
            nd["risk_severity"] = severity_from_score(updated_risk)
            nd["vulnerability"] = round(updated_risk / 100.0, 3)
            nd["adaptive_delta"] = delta
            nd["adaptive_reason"] = info.get("reason", "Honeypot telemetry feedback")

            changes[node] = (orig_risk, updated_risk, delta)

    return changes
