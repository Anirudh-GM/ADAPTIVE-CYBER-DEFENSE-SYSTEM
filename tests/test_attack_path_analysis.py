"""
Tests for ACDS Risk-Based Analytical Attack Path Engine
Validates passive structural path computation, weakest link identification, and WHY explanations.
"""

import pytest
import networkx as nx
from acds.analysis.attack_paths import analyze_attack_paths, AnalyticalAttackPath


def test_attack_path_analysis_and_why_explanation():
    """Verify structural path finding, weakest link identification, and plain-English WHY trail."""
    G = nx.DiGraph()
    # Topology: Workstation (Entry) -> Server (Intermediate) -> Database (Target)
    G.add_node("Workstation", display_name="Workstation-01", criticality=2, risk_score=25.0, services=["LAN"], open_ports=[])
    G.add_node("Server", display_name="App-Server-01", criticality=4, risk_score=75.0, services=["HTTP", "SSH"], open_ports=[80, 22])
    G.add_node("Database", display_name="Prod-DB-01", criticality=5, risk_score=90.0, services=["MySQL"], open_ports=[3306])

    G.add_edge("Workstation", "Server")
    G.add_edge("Server", "Database")

    paths = analyze_attack_paths(G, entry_node="Workstation")
    assert len(paths) >= 1

    top_path = paths[0]
    assert isinstance(top_path, AnalyticalAttackPath)
    assert top_path.entry_node == "Workstation"
    assert top_path.target_node == "Database"
    assert top_path.hop_count == 2
    assert top_path.target_criticality == 5
    assert top_path.business_impact == "CRITICAL"
    assert top_path.weakest_link_node in ["Server", "Database"]

    assert "Entry foothold established" in top_path.why_explanation
    assert "Prod-DB-01" in top_path.why_explanation
    assert len(top_path.recommended_choke_point) > 0
