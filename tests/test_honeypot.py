"""
Unit tests for ACDS Honeypot & Decoy System.
"""

import pytest
from acds.core.graph import build_network
from acds.honeypot.detector import is_honeypot_node, get_honeypot_nodes, configure_honeypot_node
from acds.honeypot.behavior import extract_attacker_behavior


def test_honeypot_detection_and_nodes():
    G = build_network()
    assert is_honeypot_node(G, "Honeypot") is True
    assert is_honeypot_node(G, "User-PC") is False

    honeypots = get_honeypot_nodes(G)
    assert "Honeypot" in honeypots


def test_configure_custom_honeypot_node():
    G = build_network()
    configure_honeypot_node(G, "Decoy-SQL", ip="192.168.1.95", services=["MySQL", "SSH"], open_ports=[3306, 22])

    assert is_honeypot_node(G, "Decoy-SQL") is True
    assert G.nodes["Decoy-SQL"]["ip"] == "192.168.1.95"
    assert G.nodes["Decoy-SQL"]["criticality"] == 1


def test_extract_attacker_behavior():
    events = [
        {"source": "Compromised-PC", "honeypot": "Honeypot", "port": 21, "vector": "FTP brute force", "timestep": 2},
        {"source": "Compromised-PC", "honeypot": "Honeypot", "port": 21, "vector": "FTP exploit", "timestep": 3},
    ]
    profiles = extract_attacker_behavior(events)

    assert "Compromised-PC" in profiles
    prof = profiles["Compromised-PC"]
    assert prof.total_interactions == 2
    assert 21 in prof.targeted_ports
    assert "FTP" in prof.targeted_services
    assert prof.attack_velocity > 0
