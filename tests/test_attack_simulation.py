"""
Unit tests for ACDS Time-Based Attack Simulation Engine.
"""

import pytest
import networkx as nx
from acds.core.graph import build_network
from acds.simulation.attack_engine import simulate_attack, simulate_attack_step_generator


def test_simulate_attack_basic():
    G = build_network()
    timeline, compromised, honeypot_triggered, stats = simulate_attack(
        G, entry_node="User-PC", seed=42
    )

    assert len(timeline) > 0
    assert "User-PC" in compromised
    assert stats["total_systems"] > 0
    assert stats["systems_controlled"] >= 1
    assert "max_lateral_hops" in stats
    assert "attack_paths" in stats


def test_simulation_determinism_with_seed():
    G1 = build_network()
    G2 = build_network()

    tl1, comp1, hp1, st1 = simulate_attack(G1, entry_node="User-PC", seed=1234)
    tl2, comp2, hp2, st2 = simulate_attack(G2, entry_node="User-PC", seed=1234)

    assert comp1 == comp2
    assert hp1 == hp2
    assert len(tl1) == len(tl2)
    assert st1["systems_controlled"] == st2["systems_controlled"]


def test_simulate_attack_step_generator():
    G = build_network()
    steps = list(simulate_attack_step_generator(G, entry_node="User-PC", seed=42))

    assert len(steps) > 0
    first_step, first_state, first_event = steps[0]

    assert first_step["node"] == "User-PC"
    assert first_step["timestep"] == 1
    assert first_step["success"] is True
    assert first_event.event_type.value == "INITIAL_COMPROMISE"


def test_isolation_blocks_attack():
    G = build_network()
    # Isolate Server
    G.nodes["Server"]["isolated"] = True

    timeline, compromised, _, _ = simulate_attack(G, entry_node="User-PC", seed=42)

    # Server should be blocked and not compromised
    assert "Server" not in compromised
    blocked_entries = [t for t in timeline if t.get("mitre_code") == "T1599"]
    assert len(blocked_entries) > 0
