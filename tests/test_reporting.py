"""
Unit tests for ACDS Reporting & Data Export Engine.
"""

import pytest
from acds.core.graph import build_network
from acds.reporting.reports import (
    generate_attack_log,
    build_executive_summary,
    get_asset_metrics,
    build_executive_report_text,
)
from acds.reporting.exports import (
    export_asset_inventory_csv,
    export_vulnerability_report_csv,
)


def test_get_asset_metrics():
    G = build_network()
    metrics = get_asset_metrics(G)

    assert metrics["assets"] == 7
    assert metrics["servers"] >= 2
    assert "average_risk" in metrics
    assert "critical" in metrics


def test_export_asset_inventory_csv():
    G = build_network()
    csv_str = export_asset_inventory_csv(G)

    assert "IP,Hostname,MAC,Vendor,OS" in csv_str
    assert "192.168.1.10" in csv_str
    assert "192.168.1.30" in csv_str


def test_export_vulnerability_report_csv():
    G = build_network()
    csv_str = export_vulnerability_report_csv(G)
    assert "Asset,CVE,CVSS,Severity,Product" in csv_str


def test_build_executive_summary():
    G = build_network()
    summary = build_executive_summary(
        G,
        compromised={"User-PC", "Server", "Database"},
        risk_score=72.0,
        blast_details={"total_real_nodes": 6},
        entry_node="User-PC",
    )
    assert "SIMULATION ONLY" in summary
    assert "User-PC" in summary
    assert "72.0" in summary or "72" in summary


def test_generate_attack_log():
    timeline = [
        {"node": "User-PC", "from_node": None, "timestep": 1, "mitre_code": "T1078", "mitre_desc": "Initial Foothold", "access_vector": "Phishing", "success": True}
    ]
    log = generate_attack_log(timeline, honeypot_triggered=True)

    assert len(log) == 2
    assert log[0]["target"] == "User-PC"
    assert log[1]["target"] == "Honeypot"
