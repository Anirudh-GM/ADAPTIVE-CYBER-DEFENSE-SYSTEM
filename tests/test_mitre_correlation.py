"""
Tests for ACDS Contextual MITRE ATT&CK Correlation Engine
Validates technique mapping (T1046, T1021, T1190, T1210), risk severity, and technical disclaimers.
"""

import pytest
import networkx as nx
from acds.analysis.mitre import correlate_mitre_techniques, MITRETechniqueFinding, MITRE_DISCLAIMER


def test_mitre_technique_correlation_and_disclaimer():
    """Verify open services map to MITRE ATT&CK techniques with required disclaimers."""
    G = nx.DiGraph()
    G.add_node("192.168.1.10", ip="192.168.1.10", display_name="Web-Server", criticality=4, open_ports=[80, 445, 3306], services=["HTTP", "SMB", "MySQL"], cve_findings=[{"service": "HTTP", "cvss": 9.8}])

    findings = correlate_mitre_techniques(G)
    assert len(findings) == 3

    tech_ids = {f.technique_id for f in findings}
    assert "T1190" in tech_ids  # HTTP
    assert "T1021.002" in tech_ids  # SMB
    assert "T1210" in tech_ids  # MySQL

    # Verify disclaimer is present on all findings
    for f in findings:
        assert isinstance(f, MITRETechniqueFinding)
        assert f.disclaimer == MITRE_DISCLAIMER
        assert "Potential technique association" in f.disclaimer
        assert len(f.recommended_countermeasure) > 0
