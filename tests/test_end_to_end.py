"""
End-to-End Integration Test for the Complete ACDS Pipeline.
Validates full workflow: Discovery/Modeling -> Attack Simulation -> Honeypot Trigger ->
Adaptive Risk Update -> Defense Optimization -> Model Mutation -> Re-simulation -> Risk Reduction -> Persistence.
"""

import os
import tempfile
import pytest

from acds.core.graph import build_network
from acds.honeypot.behavior import extract_attacker_behavior
from acds.adaptive.feedback import compute_adaptive_feedback_signals
from acds.adaptive.risk_update import apply_adaptive_risk_updates
from acds.defense.actions import get_defense_actions, apply_defense_actions
from acds.defense.optimizer import greedy_defense_selection
from acds.persistence.database import init_database
from acds.persistence.repositories import ScanRepository, SimulationRepository
from acds.reporting.reports import build_executive_summary
from acds.simulation.attack_engine import simulate_attack
from acds.simulation.comparison import compare_simulations
from acds.vulnerability.blast_radius import calculate_risk, calculate_overall_acds_risk


def test_complete_acds_lifecycle_pipeline():
    # 1. Initialize Network Model
    G = build_network()
    assert len(G.nodes) == 7

    # 2. Pre-Defense Simulation Run
    seed = 42
    entry_node = "User-PC"
    timeline_pre, comp_pre, hp_pre, stats_pre = simulate_attack(
        G, entry_node=entry_node, seed=seed, ids_deployed=False, segmentation_applied=False
    )
    risk_pre, blast_pre = calculate_risk(G, comp_pre, timeline_pre, hp_pre, stats_pre)
    overall_pre = calculate_overall_acds_risk(G, risk_pre)

    assert risk_pre > 0.0
    assert overall_pre['overall_score'] is not None

    # 3. Honeypot Behavioral Feedback & Adaptive Risk
    hp_events = stats_pre.get("honeypot_observations", [])
    if hp_pre:
        behavior_profiles = extract_attacker_behavior(hp_events)
        feedback_signals = compute_adaptive_feedback_signals(G, behavior_profiles)
        adaptive_changes = apply_adaptive_risk_updates(G, feedback_signals)
        assert isinstance(adaptive_changes, dict)

    # 4. Defense Optimization
    budget = 50
    candidates = get_defense_actions(G, comp_pre, risk_pre)
    assert len(candidates) > 0

    selected, total_reduction, remaining_budget = greedy_defense_selection(candidates, budget=budget)
    assert len(selected) > 0
    assert remaining_budget >= 0

    # 5. Apply Defenses & Mutate Model
    applied, ids_dep, seg_app = apply_defense_actions(G, selected)
    assert len(applied) == len(selected)

    # 6. Post-Defense Re-Simulation Run
    timeline_post, comp_post, hp_post, stats_post = simulate_attack(
        G, entry_node=entry_node, seed=seed, ids_deployed=ids_dep, segmentation_applied=seg_app
    )
    risk_post, blast_post = calculate_risk(G, comp_post, timeline_post, hp_post, stats_post)
    overall_post = calculate_overall_acds_risk(G, risk_post)

    # 7. Before vs After Comparison
    comparison = compare_simulations(
        risk_pre, risk_post, blast_pre, blast_post,
        budget_used=budget - remaining_budget,
        applied_actions=applied,
    )

    assert comparison.risk_after <= comparison.risk_before
    assert comparison.risk_reduction_pct >= 0.0

    # 8. Executive Reporting
    summary = build_executive_summary(G, comp_post, risk_post, blast_post, entry_node)
    assert "SIMULATION ONLY" in summary

    # 9. Persistence in SQLite
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        init_database(db_path)
        scan_repo = ScanRepository(db_path)
        sim_repo = SimulationRepository(db_path)

        scan_id = scan_repo.save_scan_session(G, scan_type="Lifecycle E2E Test")
        assert scan_id > 0

        sim_id = sim_repo.save_simulation_run(
            entry_node=entry_node,
            seed=seed,
            risk_score=risk_post,
            blast_details=blast_post,
            honeypot_triggered=hp_post,
            ids_deployed=ids_dep,
            segmentation_applied=seg_app,
            applied_defenses=applied,
        )
        assert sim_id > 0
    finally:
        try:
            os.unlink(db_path)
        except OSError:
            pass
