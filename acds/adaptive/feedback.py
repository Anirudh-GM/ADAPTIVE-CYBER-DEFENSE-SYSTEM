"""
ACDS Adaptive Feedback Engine
Translates honeypot behavioral observations into dynamic risk modifiers and defense weighting signals.
"""

from typing import Dict, List, Set, Tuple, Any
import networkx as nx

from acds.honeypot.behavior import AttackerBehaviorProfile


def compute_adaptive_feedback_signals(
    G: nx.DiGraph,
    behavior_profiles: Dict[str, AttackerBehaviorProfile],
) -> Dict[str, Any]:
    """
    Evaluate honeypot telemetry against network assets to compute target-specific risk boosts
    and defense priority multipliers.
    """
    targeted_services: Set[str] = set()
    targeted_ports: Set[int] = set()
    high_threat_origins: Set[str] = set()

    for origin, prof in behavior_profiles.items():
        targeted_services.update(prof.targeted_services)
        targeted_ports.update(prof.targeted_ports)
        if prof.total_interactions >= 2 or prof.attack_velocity > 1.0:
            high_threat_origins.add(origin)

    affected_nodes: Dict[str, Dict[str, Any]] = {}

    for node, data in G.nodes(data=True):
        if data.get("node_type") == "honeypot":
            continue

        node_services = set(data.get("services", []))
        node_ports = set(data.get("open_ports", []))

        # Check overlap with services/ports actively targeted by the attacker
        matched_services = node_services.intersection(targeted_services)
        matched_ports = node_ports.intersection(targeted_ports)

        if matched_services or matched_ports:
            # Targeted service penalty
            service_risk_delta = min(15.0, len(matched_services) * 5.0 + len(matched_ports) * 3.0)
            defense_multiplier = 1.35  # Boost priority of defending these nodes

            affected_nodes[node] = {
                "matched_services": list(matched_services),
                "matched_ports": list(matched_ports),
                "adaptive_risk_delta": service_risk_delta,
                "defense_multiplier": defense_multiplier,
                "reason": f"Exposes actively probed services ({', '.join(matched_services) or ', '.join(str(p) for p in matched_ports)})",
            }

    # Also include the lateral staging origin as high-priority defense target
    for origin in behavior_profiles.keys():
        if origin in G.nodes and G.nodes[origin].get("node_type") != "honeypot":
            if origin not in affected_nodes:
                affected_nodes[origin] = {
                    "matched_services": [],
                    "matched_ports": [],
                    "adaptive_risk_delta": 10.0,
                    "defense_multiplier": 1.35,
                    "reason": f"Active lateral staging host that probed decoy honeypot",
                }

    return {
        "targeted_services": list(targeted_services),
        "targeted_ports": list(targeted_ports),
        "high_threat_origins": list(high_threat_origins),
        "affected_nodes": affected_nodes,
        "total_affected_assets": len(affected_nodes),
    }
