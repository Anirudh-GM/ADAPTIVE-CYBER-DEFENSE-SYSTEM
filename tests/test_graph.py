"""
Unit tests for ACDS Network Graph Modeling.
"""

import pytest
import networkx as nx
from acds.core.graph import build_network, build_dynamic_graph, build_synthetic_sme_network


def test_build_simulated_network():
    G = build_network()
    assert isinstance(G, nx.DiGraph)
    assert len(G.nodes) == 7
    assert "Firewall" in G.nodes
    assert "User-PC" in G.nodes
    assert "Admin-PC" in G.nodes
    assert "Server" in G.nodes
    assert "File-Server" in G.nodes
    assert "Database" in G.nodes
    assert "Honeypot" in G.nodes

    # Check node attributes
    for node, data in G.nodes(data=True):
        assert "ip" in data
        assert "role" in data
        assert "criticality" in data
        assert "risk_score" in data
        assert "risk_components" in data
        assert "node_type" in data
        assert "compromised" in data

    # Check edges exist
    assert len(G.edges) > 0
    for u, v, ed in G.edges(data=True):
        assert "success_prob" in ed
        assert "mitre_code" in ed


def test_build_synthetic_sme_network_15_nodes():
    G = build_synthetic_sme_network(num_nodes=15)
    assert isinstance(G, nx.DiGraph)
    assert len(G.nodes) == 15
    assert "Firewall" in G.nodes
    assert "Web-Server" in G.nodes
    assert "DB-Primary" in G.nodes
    assert "Honeypot-LAN" in G.nodes
    assert len(G.edges) > 0


def test_build_dynamic_graph_from_devices():
    devices = [
        ("192.168.1.10", "workstation.lan", "windows", 0.85, ["TTL=128"], False,
         "00:11:22:33:44:55", None, [445, 3389], ["SMB", "RDP"], {}, {},
         "Windows Workstation", "workstation.lan (Windows Workstation)", 0.85, []),
        ("192.168.1.20", "db.lan", "linux", 0.90, ["TTL=64"], False,
         "00:11:22:33:44:66", None, [3306, 22], ["MySQL", "SSH"], {}, {},
         "Database Server", "db.lan (Database Server)", 0.95, []),
    ]
    G = build_dynamic_graph(devices)
    assert len(G.nodes) == 2
    assert len(G.edges) > 0
