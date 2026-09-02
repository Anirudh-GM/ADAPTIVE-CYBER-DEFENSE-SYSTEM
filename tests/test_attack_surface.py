"""
Tests for ACDS Attack Surface Management & Hierarchy Analyzer
Validates attack surface exposure counts, categories, and drill-down tree generation.
"""

import pytest
import networkx as nx
from acds.surface.analyzer import analyze_attack_surface, AttackSurfaceMetrics


def test_attack_surface_metrics_and_hierarchy():
    """Verify attack surface categorization, sensitive ports, and drill-down tree."""
    G = nx.DiGraph()
    G.add_node("192.168.1.1", ip="192.168.1.1", display_name="Gateway", criticality=4, risk_score=50.0, open_ports=[53, 80, 443], services=["DNS", "HTTP", "HTTPS"], cve_findings=[])
    G.add_node("192.168.1.10", ip="192.168.1.10", display_name="DB-01", criticality=5, risk_score=85.0, open_ports=[3306], services=["MySQL"], cve_findings=[{"service": "MySQL", "port": 3306, "cve_id": "CVE-2020-14539", "cvss": 9.8}])
    G.add_node("192.168.1.20", ip="192.168.1.20", display_name="Phone-01", criticality=2, risk_score=15.0, open_ports=[], services=[], cve_findings=[])

    res = analyze_attack_surface(G)
    metrics = res["metrics"]

    assert metrics["total_assets"] == 3
    assert metrics["exposed_assets"] == 2
    assert metrics["unexposed_assets"] == 1
    assert metrics["open_services_count"] == 4
    assert metrics["internet_facing_count"] == 3  # DNS (53), HTTP (80), HTTPS (443)
    assert metrics["database_services_count"] == 1  # MySQL (3306)
    assert metrics["vulnerable_services_count"] == 1  # MySQL with CVE-2020-14539
    assert metrics["critical_exposure_count"] == 1  # DB-01 (5★ with database port)

    drill = res["drill_down_tree"]
    assert len(drill) == 5  # 3 ports on Gateway + 1 port on DB-01 + 1 client endpoint
    # Highest risk item first
    assert drill[0]["host"] == "DB-01"
    assert drill[0]["service"] == "MySQL"
    assert drill[0]["top_cve"] == "CVE-2020-14539"
