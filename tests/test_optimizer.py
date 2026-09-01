"""
Unit tests for ACDS Heuristic Defense Optimizer.
"""

import pytest
from acds.core.graph import build_network
from acds.defense.actions import get_defense_actions
from acds.defense.optimizer import greedy_defense_selection


def test_defense_action_generation():
    G = build_network()
    actions = get_defense_actions(G, {"Server", "Database"}, risk_score=75.0)

    assert len(actions) > 0
    for a in actions:
        assert "action" in a
        assert "cost" in a
        assert "risk_reduction" in a
        assert "efficiency" in a
        assert a["cost"] > 0
        assert a["efficiency"] == round(a["risk_reduction"] / a["cost"], 3)


def test_greedy_defense_selection_budget_constraint():
    actions = [
        {"action": "Action A", "cost": 30, "risk_reduction": 15.0, "efficiency": 0.50},
        {"action": "Action B", "cost": 20, "risk_reduction": 16.0, "efficiency": 0.80},
        {"action": "Action C", "cost": 10, "risk_reduction": 10.0, "efficiency": 1.00},
    ]

    selected, total_red, remaining = greedy_defense_selection(actions, budget=30)

    # Best efficiency: Action C (cost 10, rem 20), then Action B (cost 20, rem 0)
    assert len(selected) == 2
    assert selected[0]["action"] == "Action C"
    assert selected[1]["action"] == "Action B"
    assert remaining == 0
    assert total_red == 26.0
