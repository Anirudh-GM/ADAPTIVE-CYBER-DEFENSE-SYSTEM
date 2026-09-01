"""
ACDS Headless Experiment & Monte Carlo Runner
Executes programmatic simulation sweeps, seed sweeps, budget evaluation benchmarks,
and academic research experiments.
"""

from typing import Dict, List, Optional, Any
import networkx as nx

from acds.core.graph import build_network, build_synthetic_sme_network
from acds.defense.actions import get_defense_actions, apply_defense_actions
from acds.defense.optimizer import greedy_defense_selection
from acds.experiments.metrics import compute_batch_statistics
from acds.simulation.attack_engine import simulate_attack
from acds.simulation.comparison import compare_simulations
from acds.vulnerability.blast_radius import calculate_risk


def run_monte_carlo_attack_sweep(
    G: Optional[nx.DiGraph] = None,
    entry_node: Optional[str] = None,
    num_runs: int = 50,
    base_seed: int = 100,
) -> Dict[str, Any]:
    """
    Run Monte Carlo simulation sweep over random seeds from a fixed entry point.
    """
    if G is None:
        G = build_network()

    if entry_node is None:
        candidates = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
        entry_node = candidates[1] if len(candidates) > 1 else candidates[0]

    runs = []
    for i in range(num_runs):
        seed = base_seed + i
        # Clone graph to avoid state bleed
        g_clone = G.copy()
        for n in g_clone.nodes:
            g_clone.nodes[n]["compromised"] = False

        timeline, compromised, honeypot_triggered, attack_stats = simulate_attack(
            g_clone, entry_node, seed=seed, ids_deployed=False, segmentation_applied=False
        )
        risk_score, blast_details = calculate_risk(
            g_clone, compromised, timeline, honeypot_triggered, attack_stats
        )
        runs.append({
            "run_id": i + 1,
            "seed": seed,
            "entry_node": entry_node,
            "risk_score": risk_score,
            "blast_details": blast_details,
            "honeypot_triggered": honeypot_triggered,
            "attack_stats": attack_stats,
        })

    stats = compute_batch_statistics(runs)
    return {
        "summary": stats,
        "runs": runs,
    }


def run_defense_budget_sweep(
    G: Optional[nx.DiGraph] = None,
    entry_node: Optional[str] = None,
    budgets: Optional[List[int]] = None,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """
    Evaluate defense optimization effectiveness across varying budget constraints.
    """
    if G is None:
        G = build_network()

    if entry_node is None:
        candidates = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
        entry_node = candidates[1] if len(candidates) > 1 else candidates[0]

    budgets = budgets or [0, 15, 30, 50, 75, 100]

    # 1. Baseline Pre-Defense Run
    base_g = G.copy()
    timeline_base, comp_base, hp_base, stats_base = simulate_attack(
        base_g, entry_node, seed=seed, ids_deployed=False, segmentation_applied=False
    )
    base_risk, base_blast = calculate_risk(base_g, comp_base, timeline_base, hp_base, stats_base)

    results = []
    for budget in budgets:
        # Clone graph for defense application
        g_def = G.copy()
        actions = get_defense_actions(g_def, comp_base, base_risk)
        selected, reduction, remaining = greedy_defense_selection(actions, budget)

        applied, ids_dep, seg_app = apply_defense_actions(g_def, selected)

        # Re-simulate
        tl_after, comp_after, hp_after, stats_after = simulate_attack(
            g_def, entry_node, seed=seed, ids_deployed=ids_dep, segmentation_applied=seg_app
        )
        risk_after, blast_after = calculate_risk(g_def, comp_after, tl_after, hp_after, stats_after)

        comp = compare_simulations(base_risk, risk_after, base_blast, blast_after, budget_used=budget - remaining)

        results.append({
            "budget": budget,
            "budget_used": budget - remaining,
            "risk_before": base_risk,
            "risk_after": risk_after,
            "risk_reduction_pct": comp.risk_reduction_pct,
            "systems_before": comp.systems_compromised_before,
            "systems_after": comp.systems_compromised_after,
            "critical_before": comp.critical_reached_before,
            "critical_after": comp.critical_reached_after,
            "applied_count": len(applied),
        })

    return results
