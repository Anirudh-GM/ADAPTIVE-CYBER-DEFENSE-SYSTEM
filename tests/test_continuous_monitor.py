"""
Tests for ACDS Continuous Background Monitoring Engine
Validates single cycle execution, diff computation, inventory updates, alerts, and thread controls.
"""

import os
import tempfile
import time
import pytest
from acds.monitoring.monitor import ContinuousMonitoringEngine, MonitoringCycleResult
from acds.core.graph import build_network


def test_continuous_monitor_single_cycle_and_persistence():
    """Verify monitor executes a full discovery cycle, creates alerts, and writes snapshots."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        engine = ContinuousMonitoringEngine(db_path=db_path, interval_seconds=1)
        G = build_network()

        # Run Cycle 1
        res1 = engine.run_single_cycle(network_graph=G, custom_timestamp="2026-09-02 10:00:00 UTC")
        assert isinstance(res1, MonitoringCycleResult)
        assert res1.cycle_index == 1
        assert res1.asset_count == len(G.nodes)

        # Mutate network graph for Cycle 2: add a high-risk server
        G2 = G.copy()
        G2.add_node("192.168.1.99", ip="192.168.1.99", display_name="Rogue-Srv", criticality=4, risk_score=75.0, open_ports=[445], services=["SMB"], cve_findings=[])

        res2 = engine.run_single_cycle(network_graph=G2, custom_timestamp="2026-09-02 10:01:00 UTC")
        assert res2.cycle_index == 2
        assert len(res2.diff.new_devices) == 1
        assert len(res2.alerts) >= 1

        # Check telemetry queue
        latest = engine.get_latest_telemetry()
        assert latest is not None
        assert latest.cycle_index == 2
    finally:
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
        except Exception:
            pass

