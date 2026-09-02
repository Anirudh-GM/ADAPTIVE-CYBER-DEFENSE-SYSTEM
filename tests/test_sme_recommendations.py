"""
Tests for ACDS SME-Readable Defense Recommendations Engine
Validates recommendation generation, priority tiers (CRITICAL, HIGH, MEDIUM), and plain-English structure.
"""

import pytest
import networkx as nx
from acds.defense.recommendations import generate_sme_recommendations, SMERecommendation


def test_sme_recommendation_generation():
    """Verify SME recommendations format technical reasons into clear business impact and actions."""
    G = nx.DiGraph()
    G.add_node("192.168.1.10", ip="192.168.1.10", display_name="SRV-DB", criticality=5, open_ports=[3306, 445], services=["MySQL", "SMB"], cve_findings=[])
    G.add_node("192.168.1.20", ip="192.168.1.20", display_name="Legacy-FTP", criticality=3, open_ports=[21], services=["FTP"], cve_findings=[])

    recs = generate_sme_recommendations(G)
    assert len(recs) >= 2

    # High-priority database isolation recommendation
    db_rec = next((r for r in recs if "Database" in r.title or "DB" in r.affected_asset), None)
    assert db_rec is not None
    assert db_rec.priority_tier == "CRITICAL"
    assert "data dumping" in db_rec.business_impact.lower() or "business data" in db_rec.business_impact.lower()
    assert "bind database listeners" in db_rec.recommended_action.lower() or "firewall" in db_rec.recommended_action.lower()

    # Cleartext FTP decommission recommendation
    ftp_rec = next((r for r in recs if "FTP" in r.title or "21" in r.technical_reason), None)
    assert ftp_rec is not None
    assert ftp_rec.priority_tier == "HIGH"
    assert "plain cleartext" in ftp_rec.technical_reason.lower() or "cleartext" in ftp_rec.technical_reason.lower()
