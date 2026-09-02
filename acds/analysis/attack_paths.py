"""
ACDS Analytical Attack Path & Reachability Engine
Performs passive structural graph analysis to identify paths from initial footholds to crown jewels.
Provides explainable "WHY" breakdowns of structural reachability without active exploitation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx


@dataclass
class AnalyticalAttackPath:
    """Represents a passive, risk-weighted analytical attack route."""
    path_id: str
    entry_node: str
    target_node: str
    nodes: List[str]
    hop_count: int
    target_criticality: int
    target_role: str
    path_feasibility_score: float  # 0 to 100
    business_impact: str  # CRITICAL | HIGH | MEDIUM
    weakest_link_node: str
    weakest_link_service: str
    weakest_link_port: int
    why_explanation: str
    recommended_choke_point: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "entry_node": self.entry_node,
            "target_node": self.target_node,
            "nodes": self.nodes,
            "hop_count": self.hop_count,
            "target_criticality": self.target_criticality,
            "target_role": self.target_role,
            "path_feasibility_score": self.path_feasibility_score,
            "business_impact": self.business_impact,
            "weakest_link_node": self.weakest_link_node,
            "weakest_link_service": self.weakest_link_service,
            "weakest_link_port": self.weakest_link_port,
            "why_explanation": self.why_explanation,
            "recommended_choke_point": self.recommended_choke_point,
        }


def analyze_attack_paths(
    G: nx.DiGraph,
    entry_node: Optional[str] = None,
    max_hops: int = 5,
) -> List[AnalyticalAttackPath]:
    """
    Perform passive structural path computation between entry nodes and critical assets.
    Computes path feasibility, weakest link identification, and plain-English WHY explanations.
    """
    if not G or len(G.nodes) == 0:
        return []

    real_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") != "honeypot"]
    if not real_nodes:
        return []

    # Potential entry points: perimeter nodes, web servers, or user-selected entry
    if entry_node and entry_node in G:
        candidate_entries = [entry_node]
    else:
        # Default to lowest criticality / workstation nodes or web servers
        candidate_entries = [
            n for n in real_nodes
            if int(G.nodes[n].get("criticality", 3)) <= 3
            or any(s in G.nodes[n].get("services", []) for s in ["HTTP", "HTTPS", "HTTP-Alt"])
        ]
        if not candidate_entries:
            candidate_entries = [real_nodes[0]]

    # Target nodes: Criticality 4★ or 5★ assets (Databases, Servers)
    critical_targets = [
        n for n in real_nodes
        if int(G.nodes[n].get("criticality", 3)) >= 4
    ]
    if not critical_targets:
        # If no 4★/5★, pick highest criticality available
        highest_crit = max(int(G.nodes[n].get("criticality", 1)) for n in real_nodes)
        critical_targets = [n for n in real_nodes if int(G.nodes[n].get("criticality", 1)) == highest_crit]

    paths_found: List[AnalyticalAttackPath] = []
    path_idx = 1

    for start in candidate_entries:
        for target in critical_targets:
            if start == target:
                continue

            try:
                # Find shortest structural simple paths up to max_hops
                simple_paths = list(nx.all_simple_paths(G, source=start, target=target, cutoff=max_hops))
            except (nx.NetworkXNoPath, nx.NodeNotFound, Exception):
                continue

            for p in simple_paths[:3]:  # Top 3 most direct paths
                tgt_data = G.nodes[target]
                tgt_crit = int(tgt_data.get("criticality", 3))
                tgt_role = tgt_data.get("role", "Server")

                # Evaluate weakest link along path
                weakest_node = start
                weakest_risk = 0.0
                weakest_svc = "LAN Reachability"
                weakest_port = 0

                cumulative_risk = 0.0

                for hop in p:
                    hop_data = G.nodes[hop]
                    h_risk = float(hop_data.get("risk_score", 0.0))
                    cumulative_risk += h_risk
                    if h_risk >= weakest_risk:
                        weakest_risk = h_risk
                        weakest_node = hop
                        svcs = hop_data.get("services", [])
                        ports = hop_data.get("open_ports", [])
                        weakest_svc = svcs[0] if svcs else "LAN Foothold"
                        weakest_port = ports[0] if ports else 0

                # Path feasibility score (0 to 100)
                mean_path_risk = cumulative_risk / max(len(p), 1)
                hop_penalty = max(0.0, (len(p) - 1) * 6.0)
                feasibility = max(10.0, min(100.0, round(mean_path_risk - hop_penalty + (tgt_crit * 5.0), 1)))

                impact = "CRITICAL" if tgt_crit == 5 else "HIGH" if tgt_crit == 4 else "MEDIUM"

                start_disp = G.nodes[start].get("display_name", start)
                target_disp = G.nodes[target].get("display_name", target)
                weak_disp = G.nodes[weakest_node].get("display_name", weakest_node)

                # Construct plain-English WHY explanation
                why_reasons = []
                why_reasons.append(f"Entry foothold established at {start_disp}")
                if len(p) > 2:
                    intermediates = [G.nodes[n].get("display_name", n) for n in p[1:-1]]
                    why_reasons.append(f"Lateral movement possible through {', '.join(intermediates)}")
                why_reasons.append(f"Weakest link is {weak_disp} (Risk {weakest_risk:.1f}) exposing {weakest_svc}")
                why_reasons.append(f"Target {target_disp} is a {tgt_crit}-Star ({tgt_role}) holding sensitive organizational assets")

                why_str = " | ".join(why_reasons)

                # Choke point defense recommendation
                choke_defense = f"Isolate {weak_disp} or apply network segmentation between {start_disp} and {target_disp} to break the attack chain"

                path_obj = AnalyticalAttackPath(
                    path_id=f"PATH-{path_idx:03d}",
                    entry_node=start,
                    target_node=target,
                    nodes=p,
                    hop_count=len(p) - 1,
                    target_criticality=tgt_crit,
                    target_role=tgt_role,
                    path_feasibility_score=feasibility,
                    business_impact=impact,
                    weakest_link_node=weakest_node,
                    weakest_link_service=weakest_svc,
                    weakest_link_port=weakest_port,
                    why_explanation=why_str,
                    recommended_choke_point=choke_defense,
                )
                paths_found.append(path_obj)
                path_idx += 1

    # Sort paths by feasibility score descending
    paths_found.sort(key=lambda item: (-item.path_feasibility_score, item.hop_count))
    return paths_found
