"""
Tests for ACDS Scan-to-Scan Change Detection & Diff Engine
Validates detection of new/removed devices, port changes, software version shifts, and risk score deltas.
"""

import pytest
from acds.comparison.diff import compare_scans, ScanComparisonResult


def test_scan_diff_detects_new_and_removed_devices():
    """Verify added and removed devices between scan snapshots."""
    scan_prev = [
        {"ip": "192.168.1.1", "hostname": "Router", "open_ports": [80], "risk_score": 30.0},
        {"ip": "192.168.1.10", "hostname": "Old-PC", "open_ports": [445], "risk_score": 50.0},
    ]
    scan_curr = [
        {"ip": "192.168.1.1", "hostname": "Router", "open_ports": [80], "risk_score": 30.0},
        {"ip": "192.168.1.20", "hostname": "New-Server", "open_ports": [443, 3306], "risk_score": 75.0},
    ]

    res = compare_scans(scan_prev, scan_curr, prev_time="Scan 1", curr_time="Scan 2")
    assert isinstance(res, ScanComparisonResult)

    assert len(res.new_devices) == 1
    assert res.new_devices[0]["ip"] == "192.168.1.20"

    assert len(res.removed_devices) == 1
    assert res.removed_devices[0]["ip"] == "192.168.1.10"

    assert res.summary_counts["new_devices_count"] == 1
    assert res.summary_counts["removed_devices_count"] == 1


def test_scan_diff_detects_port_mutations_and_risk_deltas():
    """Verify port open/close and risk score delta detection on existing hosts."""
    scan_prev = [
        {"ip": "192.168.1.5", "hostname": "App-Server", "open_ports": [80], "services": ["HTTP"], "version_map": {"HTTP": "2.4.49"}, "risk_score": 40.0, "cve_findings": []},
    ]
    scan_curr = [
        {"ip": "192.168.1.5", "hostname": "App-Server", "open_ports": [80, 3306], "services": ["HTTP", "MySQL"], "version_map": {"HTTP": "2.4.51", "MySQL": "5.7"}, "risk_score": 70.0, "cve_findings": [{"cve_id": "CVE-2020-14539"}]},
    ]

    res = compare_scans(scan_prev, scan_curr)
    assert len(res.modified_devices) == 1
    mod = res.modified_devices[0]

    assert mod.ip == "192.168.1.5"
    assert mod.risk_delta == 30.0
    assert any("Port(s) opened: [3306]" in d for d in mod.details)
    assert any("Version changed on HTTP: 2.4.49 -> 2.4.51" in d for d in mod.details)

    assert len(res.new_vulnerabilities) == 1
    assert res.new_vulnerabilities[0]["cve_id"] == "CVE-2020-14539"
