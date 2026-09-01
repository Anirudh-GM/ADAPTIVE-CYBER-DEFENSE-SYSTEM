"""
Unit tests for ACDS Blast Radius & Overall Risk Synthesis.
"""

import pytest
from acds.core.graph import build_network
from acds.vulnerability.blast_radius import calculate_risk, calculate_overall_acds_risk


def test_blast_radius_calculation():
    G = build_network()
    compromised = {"User-PC", "Server"}
    timeline = [
        {"timestep": 1, "node": "User-PC"},
        {"timestep": 2, "node": "Server"},
    ]

    score, details = calculate_risk(G, compromised, timeline, honeypot_triggered=False)
    assert 0.0 <= score <= 100.0
    assert details["compromised_count"] == 2
    assert "spread" in details
    assert "critical_impact" in details
    assert "depth" in details


def test_blast_radius_honeypot_penalty():
    G = build_network()
    compromised = {"User-PC", "Honeypot"}
    timeline = [{"timestep": 1, "node": "User-PC"}, {"timestep": 2, "node": "Honeypot"}]

    score_without, _ = calculate_risk(G, {"User-PC"}, timeline, honeypot_triggered=False)
    score_with, _ = calculate_risk(G, {"User-PC"}, timeline, honeypot_triggered=True)

    assert score_with == min(100.0, score_without + 15.0)


def test_overall_acds_risk_synthesis():
    G = build_network()

    # Pre-simulation (partial)
    partial = calculate_overall_acds_risk(G, blast_radius_score=None)
    assert partial['status'] == 'PARTIAL — SIMULATION NOT RUN'
    assert partial['overall_score'] is None

    # Complete (after simulation)
    complete = calculate_overall_acds_risk(G, blast_radius_score=50.0)
    assert complete['status'] == 'COMPLETE'
    assert complete['overall_score'] is not None
    assert 0.0 <= complete['overall_score'] <= 100.0
