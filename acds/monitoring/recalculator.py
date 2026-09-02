"""
ACDS Dynamic Graph & Real-Time Risk Recalculator
Executes automated recalculation of node risk scores, overall ACDS blast risk,
security posture scores, analytical attack paths, and optimal defense actions upon network mutations.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
import networkx as nx

from acds.vulnerability.risk import recompute_node_risk
from acds.vulnerability.blast_radius import calculate_overall_acds_risk
from acds.posture.scorer import calculate_security_posture, SecurityPostureReport
from acds.analysis.attack_paths import analyze_attack_paths, AnalyticalAttackPath
from acds.defense.recommendations import generate_sme_recommendations, SMERecommendation
from acds.defense.actions import get_defense_actions
from acds.defense.optimizer import greedy_defense_selection


@dataclass
class DynamicRecalculationResult:
    """Full recalculated state resulting from a network change."""
    previous_overall_risk: float
    new_overall_risk: float
    risk_delta: float
    previous_posture_score: float
    new_posture_score: float
    posture_delta: float
    posture_rating: str
    attack_paths: List[AnalyticalAttackPath]
    top_recommendations: List[SMERecommendation]
    recommended_defense_actions: List[Dict[str, Any]]
    defense_budget_used: int
    defense_estimated_reduction: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_overall_risk": self.previous_overall_risk,
            "new_overall_risk": self.new_overall_risk,
            "risk_delta": self.risk_delta,
            "previous_posture_score": self.previous_posture_score,
            "new_posture_score": self.new_posture_score,
            "posture_delta": self.posture_delta,
            "posture_rating": self.posture_rating,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "top_recommendations": [r.to_dict() for r in self.top_recommendations],
            "recommended_defense_actions": self.recommended_defense_actions,
            "defense_budget_used": self.defense_budget_used,
            "defense_estimated_reduction": self.defense_estimated_reduction,
        }


def recalculate_dynamic_state(
    G: nx.DiGraph,
    entry_point: Optional[str] = None,
    defense_budget: int = 80,
    previous_risk: Optional[float] = None,
    previous_posture: Optional[float] = None,
    prioritized_vulnerabilities: Optional[List[Any]] = None,
) -> DynamicRecalculationResult:
    """
    Perform a complete real-time re-assessment of risk, posture, attack paths, and defense optimization.
    """
    # 1. Recalculate individual node risks across the graph
    for node in list(G.nodes()):
        recompute_node_risk(G.nodes[node])

    # 2. Overall ACDS Risk calculation
    real_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") != "honeypot"]
    asset_scores = [float(G.nodes[n].get("risk_score", 0.0)) for n in real_nodes]
    new_overall_risk = round(sum(asset_scores) / max(len(asset_scores), 1), 1)
    prev_risk = previous_risk if previous_risk is not None else new_overall_risk
    risk_delta = round(new_overall_risk - prev_risk, 1)

    # 3. Security Posture Score & Pillars
    posture_report = calculate_security_posture(G, prioritized_findings=prioritized_vulnerabilities)
    new_posture = posture_report.overall_score
    prev_posture = previous_posture if previous_posture is not None else new_posture
    posture_delta = round(new_posture - prev_posture, 1)

    # 4. Analytical Attack Paths (Passive Structural)
    attack_paths = analyze_attack_paths(G, entry_node=entry_point)

    # 5. SME-Readable Recommendations
    top_recs = generate_sme_recommendations(G, prioritized_findings=prioritized_vulnerabilities, limit=5)

    # 6. Knapsack Defense Optimization on Current Live State
    compromised_sample = {attack_paths[0].entry_node} if attack_paths else set()
    if attack_paths:
        compromised_sample.add(attack_paths[0].weakest_link_node)

    candidate_defenses = get_defense_actions(
        G,
        compromised_nodes=compromised_sample,
        risk_score=new_overall_risk,
        prioritized_vulnerabilities=prioritized_vulnerabilities,
    )
    selected_defenses, total_red, rem_budget = greedy_defense_selection(candidate_defenses, budget=defense_budget)

    return DynamicRecalculationResult(
        previous_overall_risk=prev_risk,
        new_overall_risk=new_overall_risk,
        risk_delta=risk_delta,
        previous_posture_score=prev_posture,
        new_posture_score=new_posture,
        posture_delta=posture_delta,
        posture_rating=posture_report.rating_label,
        attack_paths=attack_paths,
        top_recommendations=top_recs,
        recommended_defense_actions=selected_defenses,
        defense_budget_used=defense_budget - rem_budget,
        defense_estimated_reduction=round(total_red, 1),
    )
