"""
Unit tests for Defense Application & Graph Model Mutation.
"""

import pytest
from acds.core.graph import build_network
from acds.defense.actions import apply_defense_actions
from acds.simulation.attack_engine import simulate_attack
from acds.simulation.comparison import compare_simulations
from acds.vulnerability.blast_radius import calculate_risk


def test_apply_patch_defense_mutates_model():
    G = build_network()
    # Add a confirmed finding to Server
    G.nodes["Server"]["cve_findings"] = [{'cve_id': 'CVE-2021-41773', 'cvss': 7.5}]
    G.nodes["Server"]["risk_components"]["vulnerability"]["normalized_score"] = 75.0
    G.nodes["Server"]["risk_score"] = 75.0

    actions = [{"action": "Patch Server", "node": "Server", "type": "patch", "cost": 20, "risk_reduction": 15.0}]
    applied, ids_dep, seg_app = apply_defense_actions(G, actions)

    assert len(applied) == 1
    assert applied[0]["state"] == "APPLIED TO SIMULATION MODEL"
    assert len(G.nodes["Server"]["cve_findings"]) == 0
    assert G.nodes["Server"]["risk_components"]["vulnerability"]["normalized_score"] == 0.0


def test_apply_isolate_defense_mutates_model():
    G = build_network()
    actions = [{"action": "Isolate Database", "node": "Database", "type": "isolate", "cost": 30, "risk_reduction": 20.0}]
    applied, _, _ = apply_defense_actions(G, actions)

    assert G.nodes["Database"]["isolated"] is True
    assert G.nodes["Database"]["risk_components"]["network_exposure"]["normalized_score"] == 0.0


def test_re_simulation_after_defense_shows_risk_reduction():
    G = build_network()
    seed = 42

    # Baseline run
    tl_before, comp_before, hp_before, stats_before = simulate_attack(G, entry_node="User-PC", seed=seed)
    risk_before, blast_before = calculate_risk(G, comp_before, tl_before, hp_before, stats_before)

    # Apply defenses (Isolate Database, Patch Server, Global IDS)
    actions = [
        {"action": "Isolate Database", "node": "Database", "type": "isolate", "cost": 30, "risk_reduction": 20.0},
        {"action": "Deploy IDS", "node": "ALL", "type": "ids", "cost": 30, "risk_reduction": 10.0},
    ]
    applied, ids_dep, seg_app = apply_defense_actions(G, actions)

    # Re-simulate on mutated model with same seed
    tl_after, comp_after, hp_after, stats_after = simulate_attack(
        G, entry_node="User-PC", seed=seed, ids_deployed=ids_dep, segmentation_applied=seg_app
    )
    risk_after, blast_after = calculate_risk(G, comp_after, tl_after, hp_after, stats_after)

    comp = compare_simulations(risk_before, risk_after, blast_before, blast_after, budget_used=60)

    assert comp.risk_after <= comp.risk_before
    assert comp.risk_reduction_pct >= 0.0
