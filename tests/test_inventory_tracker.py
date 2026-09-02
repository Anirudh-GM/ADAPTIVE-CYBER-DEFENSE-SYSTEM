"""
Tests for ACDS Continuous Asset Inventory Tracker
Validates asset ID generation, lifecycle state transitions (NEW, ACTIVE, MISSING, CHANGED),
and aggregate inventory summary metrics.
"""

import pytest
from acds.inventory.tracker import InventoryAsset, AssetInventoryTracker


def test_asset_inventory_new_and_active_transitions():
    """Verify new assets are marked NEW on first scan and ACTIVE on second identical scan."""
    tracker = AssetInventoryTracker()

    scan_1 = [
        {"ip": "192.168.1.10", "hostname": "PC-01", "mac": "00:11:22:33:44:55", "os": "windows", "open_ports": [135, 445], "services": ["RPC", "SMB"], "criticality": 3, "risk_score": 45.0},
        {"ip": "192.168.1.20", "hostname": "SRV-01", "mac": "AA:BB:CC:DD:EE:FF", "os": "linux", "open_ports": [80, 443], "services": ["HTTP", "HTTPS"], "criticality": 4, "risk_score": 65.0},
    ]

    inv_1 = tracker.update_from_scan(scan_1, timestamp="2026-09-01 10:00:00 UTC")
    assert len(inv_1) == 2
    assert inv_1["MAC-001122334455"].status == "NEW"
    assert inv_1["MAC-AABBCCDDEEFF"].status == "NEW"
    assert inv_1["MAC-001122334455"].first_seen == "2026-09-01 10:00:00 UTC"

    summary_1 = tracker.get_summary()
    assert summary_1["total_assets"] == 2
    assert summary_1["new_assets"] == 2

    # Second scan: identical data -> status becomes ACTIVE
    scan_2 = [
        {"ip": "192.168.1.10", "hostname": "PC-01", "mac": "00:11:22:33:44:55", "os": "windows", "open_ports": [135, 445], "services": ["RPC", "SMB"], "criticality": 3, "risk_score": 45.0},
        {"ip": "192.168.1.20", "hostname": "SRV-01", "mac": "AA:BB:CC:DD:EE:FF", "os": "linux", "open_ports": [80, 443], "services": ["HTTP", "HTTPS"], "criticality": 4, "risk_score": 65.0},
    ]
    inv_2 = tracker.update_from_scan(scan_2, timestamp="2026-09-01 11:00:00 UTC")
    assert inv_2["MAC-001122334455"].status == "ACTIVE"
    assert inv_2["MAC-AABBCCDDEEFF"].status == "ACTIVE"
    assert inv_2["MAC-001122334455"].scan_history_count == 2
    assert inv_2["MAC-001122334455"].last_seen == "2026-09-01 11:00:00 UTC"


def test_asset_inventory_changed_and_missing_transitions():
    """Verify state changes (ports added, risk shifted) and missing asset detection."""
    tracker = AssetInventoryTracker()

    scan_1 = [
        {"ip": "192.168.1.10", "hostname": "PC-01", "mac": "00:11:22:33:44:55", "open_ports": [135], "services": ["RPC"], "risk_score": 30.0},
        {"ip": "192.168.1.30", "hostname": "CAM-01", "mac": "11:22:33:44:55:66", "open_ports": [80], "services": ["HTTP"], "risk_score": 40.0},
    ]
    tracker.update_from_scan(scan_1, timestamp="2026-09-01 10:00:00 UTC")

    # Second scan: PC-01 opens port 445 and risk jumps; CAM-01 is offline (missing)
    scan_2 = [
        {"ip": "192.168.1.10", "hostname": "PC-01", "mac": "00:11:22:33:44:55", "open_ports": [135, 445], "services": ["RPC", "SMB"], "risk_score": 60.0},
    ]
    inv_2 = tracker.update_from_scan(scan_2, timestamp="2026-09-01 11:00:00 UTC")

    assert inv_2["MAC-001122334455"].status == "CHANGED"
    assert any("New ports opened" in c for c in inv_2["MAC-001122334455"].changes_detected)
    assert any("Risk score shifted" in c for c in inv_2["MAC-001122334455"].changes_detected)

    assert inv_2["MAC-112233445566"].status == "MISSING"
    assert any("Unresponsive in latest scan" in c for c in inv_2["MAC-112233445566"].changes_detected)

    summary = tracker.get_summary()
    assert summary["changed_assets"] == 1
    assert summary["missing_assets"] == 1
    assert summary["total_assets"] == 2
