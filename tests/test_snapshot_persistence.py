"""
Tests for ACDS Snapshot & Alert Persistence
Validates saving/retrieving snapshots, alert persistence, and acknowledgment states.
"""

import os
import tempfile
import pytest
from acds.persistence.repositories import SnapshotRepository, AlertRepository, InventoryRepository


def test_snapshot_and_alert_repositories():
    """Verify SQLite persistence for snapshots, alerts, and inventory assets."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        snap_repo = SnapshotRepository(db_path=db_path)
        alert_repo = AlertRepository(db_path=db_path)
        inv_repo = InventoryRepository(db_path=db_path)

        # 1. Test Snapshots
        s_id = snap_repo.save_snapshot(
            snapshot_time="2026-09-02 12:00:00 UTC",
            scan_type="Periodic Monitor",
            asset_count=8,
            avg_risk=42.5,
            posture_score=78.0,
            diff_summary={"new_devices": 1},
        )
        assert s_id >= 1

        latest = snap_repo.get_latest_snapshot()
        assert latest is not None
        assert latest["asset_count"] == 8
        assert latest["posture_score"] == 78.0

        # 2. Test Alerts
        a_id = alert_repo.save_alert(
            alert_id="ALT-TEST-001",
            timestamp="2026-09-02 12:00:00 UTC",
            alert_type="NEW_PORT",
            severity="CRITICAL",
            title="Port 445 Opened",
            description="SMB port exposed to subnet",
            asset_ip="192.168.1.15",
            risk_before=30.0,
            risk_after=65.0,
        )
        assert a_id >= 1

        alerts = alert_repo.get_recent_alerts(limit=10, unacknowledged_only=True)
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "ALT-TEST-001"

        # Acknowledge alert
        alert_repo.acknowledge_alert("ALT-TEST-001")
        unack = alert_repo.get_recent_alerts(limit=10, unacknowledged_only=True)
        assert len(unack) == 0

        # 3. Test Inventory Assets
        inv_repo.save_inventory_assets({
            "MAC-001122": {
                "asset_id": "MAC-001122",
                "ip": "192.168.1.50",
                "hostname": "Test-PC",
                "display_name": "Test-PC",
                "mac": "00:11:22:33:44:55",
                "mac_vendor": "Dell",
                "os": "windows",
                "os_confidence": 0.85,
                "device_type": "Workstation",
                "role": "Workstation",
                "criticality": 3,
                "criticality_label": "MEDIUM",
                "risk_score": 45.0,
                "open_ports": [135, 445],
                "services": ["RPC", "SMB"],
                "status": "ACTIVE",
                "first_seen": "2026-09-02 10:00:00 UTC",
                "last_seen": "2026-09-02 12:00:00 UTC",
                "changes_detected": [],
                "scan_history_count": 2,
            }
        })
        inv_list = inv_repo.get_all_inventory_assets()
        assert len(inv_list) == 1
        assert inv_list[0]["ip"] == "192.168.1.50"
    finally:
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
        except Exception:
            pass

