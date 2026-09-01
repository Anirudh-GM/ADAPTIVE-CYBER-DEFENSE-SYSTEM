"""
Unit tests for ACDS Adaptive Feedback Engine & Dynamic Risk Updates.
"""

import pytest
from acds.core.graph import build_network
from acds.honeypot.behavior import extract_attacker_behavior
from acds.adaptive.feedback import compute_adaptive_feedback_signals
from acds.adaptive.risk_update import apply_adaptive_risk_updates


def test_adaptive_feedback_signal_generation():
    G = build_network()
    events = [
        {"source": "User-PC", "honeypot": "Honeypot", "port": 21, "vector": "FTP Decoy Probe", "timestep": 2}
    ]
    profiles = extract_attacker_behavior(events)
    signals = compute_adaptive_feedback_signals(G, profiles)

    assert "FTP" in signals["targeted_services"]
    assert 21 in signals["targeted_ports"]


def test_apply_adaptive_risk_updates():
    G = build_network()
    # Give File-Server an FTP service for test
    G.nodes["File-Server"]["services"].append("FTP")
    orig_risk = G.nodes["File-Server"]["risk_score"]

    events = [
        {"source": "User-PC", "honeypot": "Honeypot", "port": 21, "vector": "FTP Decoy Probe", "timestep": 2}
    ]
    profiles = extract_attacker_behavior(events)
    signals = compute_adaptive_feedback_signals(G, profiles)

    changes = apply_adaptive_risk_updates(G, signals)

    assert "File-Server" in changes
    old_r, new_r, delta = changes["File-Server"]
    assert new_r > old_r
    assert delta > 0
    assert G.nodes["File-Server"]["risk_score"] == new_r
