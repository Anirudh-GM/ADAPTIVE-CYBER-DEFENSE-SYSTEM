"""
Tests for ACDS Organization Security Posture Scoring Engine
Validates posture score bounds (0 to 100), rating labels, and 4 pillar calculations.
"""

import pytest
import networkx as nx
from acds.posture.scorer import calculate_security_posture, SecurityPostureReport


def test_security_posture_calculation_and_pillars():
    """Verify security posture score reflects vulnerabilities, exposure, and legacy protocols."""
    G = nx.DiGraph()
    # High-risk network
    G.add_node("192.168.1.1", ip="192.168.1.1", display_name="Server-01", criticality=4, risk_score=85.0, open_ports=[21, 23, 80], services=["FTP", "Telnet", "HTTP"], cve_findings=[{"cvss": 9.8, "cve_id": "CVE-2021-41773"}])
    G.add_node("192.168.1.2", ip="192.168.1.2", display_name="Workstation-01", criticality=3, risk_score=60.0, open_ports=[445], services=["SMB"], cve_findings=[])

    report = calculate_security_posture(G)
    assert isinstance(report, SecurityPostureReport)
    assert 0.0 <= report.overall_score <= 100.0
    assert report.rating_label in ["CRITICAL", "POOR", "NEEDS IMPROVEMENT", "ACCEPTABLE", "STRONG"]

    # Pillar breakdown checks
    breakdown = report.pillar_breakdown
    assert "Vulnerability Management" in breakdown
    assert "Network Exposure" in breakdown
    assert "Asset Security" in breakdown
    assert "Service & Deception Security" in breakdown

    assert len(report.key_weaknesses) > 0
    assert len(report.top_recommendations) > 0


def test_clean_hardened_network_scores_high_posture():
    """Verify hardened network achieves strong posture rating."""
    G = nx.DiGraph()
    G.add_node("192.168.1.10", ip="192.168.1.10", display_name="Secure-Web", criticality=4, risk_score=20.0, open_ports=[443], services=["HTTPS"], cve_findings=[])
    G.add_node("192.168.1.20", ip="192.168.1.20", display_name="Client-PC", criticality=3, risk_score=10.0, open_ports=[], services=[], cve_findings=[])

    report = calculate_security_posture(G)
    assert report.overall_score >= 80.0
    assert report.rating_label in ["STRONG", "ACCEPTABLE"]
