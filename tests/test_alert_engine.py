"""
Tests for ACDS Real-Time Alert Engine
Validates alert generation from scan diffs, severity rankings, honeypot alerts, and risk surge thresholds.
"""

import pytest
from acds.comparison.diff import ScanComparisonResult, AssetDiff
from acds.alerts.engine import AlertEngine, SecurityAlert


def test_alert_generation_from_diff():
    """Verify alerts are correctly created for new devices, sensitive ports, CVEs, and risk shifts."""
    engine = AlertEngine(risk_delta_threshold=10.0)

    diff = ScanComparisonResult(
        previous_scan_time="2026-09-02 10:00:00 UTC",
        current_scan_time="2026-09-02 10:05:00 UTC",
        new_devices=[
            {"ip": "192.168.1.50", "hostname": "Rogue-Laptop", "device_type": "Workstation", "risk_score": 65.0, "open_ports": [445]},
        ],
        removed_devices=[
            {"ip": "192.168.1.99", "hostname": "Old-Printer", "device_type": "Printer"},
        ],
        modified_devices=[
            AssetDiff(
                ip="192.168.1.20",
                hostname="Web-Server",
                change_type="MODIFIED",
                details=["Port(s) opened: [3306]", "Version changed on HTTP: 2.4.49 -> 2.4.51"],
                risk_before=40.0,
                risk_after=65.0,
                risk_delta=25.0,
            ),
        ],
        new_vulnerabilities=[
            {"ip": "192.168.1.20", "cve_id": "CVE-2021-41773"},
        ],
        resolved_vulnerabilities=[
            {"ip": "192.168.1.10", "cve_id": "CVE-2017-0144"},
        ],
    )

    alerts = engine.generate_alerts_from_diff(diff)
    assert len(alerts) >= 5

    # Check that highest severity alert is first
    assert alerts[0].severity in ["CRITICAL", "HIGH"]

    types = {a.alert_type for a in alerts}
    assert "NEW_ASSET" in types
    assert "REMOVED_ASSET" in types
    assert "NEW_PORT" in types
    assert "SERVICE_MUTATION" in types
    assert "RISK_INCREASE" in types
    assert "NEW_CVE" in types
    assert "RESOLVED_CVE" in types


def test_honeypot_deception_alert():
    """Verify deception alert triggered when decoy is probed."""
    engine = AlertEngine()
    alert = engine.generate_honeypot_alert(
        adversary_entry="User-PC",
        honeypot_node="Honeypot-01",
        targeted_services=["FTP", "Telnet"],
    )

    assert isinstance(alert, SecurityAlert)
    assert alert.alert_type == "HONEYPOT_TRIGGERED"
    assert alert.severity == "CRITICAL"
    assert "User-PC" in alert.description
    assert "Honeypot-01" in alert.description
