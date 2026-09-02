"""
Tests for ACDS Dynamic Graph & Risk Recalculator
Validates dynamic state re-assessment upon graph mutation, recalculating risk, posture, and knapsack defenses.
"""

import pytest
import networkx as nx
from acds.monitoring.recalculator import recalculate_dynamic_state, DynamicRecalculationResult
from acds.core.graph import build_network


def test_dynamic_recalculation_on_network_graph():
    """Verify recalculation updates risk, posture, paths, and generates knapsack defense recommendations."""
    G = build_network()

    res = recalculate_dynamic_state(
        G=G,
        entry_point="User-PC",
        defense_budget=80,
        previous_risk=30.0,
        previous_posture=85.0,
    )

    assert isinstance(res, DynamicRecalculationResult)
    assert 0.0 <= res.new_overall_risk <= 100.0
    assert 0.0 <= res.new_posture_score <= 100.0
    assert len(res.attack_paths) > 0
    assert len(res.top_recommendations) > 0
    assert len(res.recommended_defense_actions) > 0
    assert res.defense_budget_used <= 80
    assert res.defense_estimated_reduction > 0.0
