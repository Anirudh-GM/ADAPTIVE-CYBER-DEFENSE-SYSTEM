"""
ACDS Continuous Background Monitoring Engine
Executes non-blocking periodic discovery, forensic scan diffing, real-time alert dispatch,
dynamic risk recalculation, and SQLite persistence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import queue
import threading
import time
from typing import Dict, List, Optional, Set, Callable, Any
import networkx as nx

from acds.inventory.tracker import AssetInventoryTracker
from acds.comparison.diff import compare_scans, ScanComparisonResult
from acds.alerts.engine import AlertEngine, SecurityAlert
from acds.monitoring.recalculator import recalculate_dynamic_state, DynamicRecalculationResult
from acds.persistence.repositories import (
    AlertRepository, SnapshotRepository, InventoryRepository, ScanRepository
)
from acds.core.graph import build_network


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class MonitoringCycleResult:
    """Consolidated outcome of an automated monitoring cycle."""
    cycle_index: int
    timestamp: str
    asset_count: int
    diff: ScanComparisonResult
    alerts: List[SecurityAlert]
    recalculation: DynamicRecalculationResult

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle_index": self.cycle_index,
            "timestamp": self.timestamp,
            "asset_count": self.asset_count,
            "diff": self.diff.to_dict(),
            "alerts": [a.to_dict() for a in self.alerts],
            "recalculation": self.recalculation.to_dict(),
        }


class ContinuousMonitoringEngine:
    """
    Decoupled continuous monitoring engine.
    Executes discovery cycles in background thread or synchronously on demand.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        interval_seconds: int = 60,
        risk_threshold: float = 10.0,
    ):
        self.db_path = db_path
        self.interval_seconds = interval_seconds
        self.risk_threshold = risk_threshold

        self.inventory_tracker = AssetInventoryTracker()
        self.alert_engine = AlertEngine(risk_delta_threshold=risk_threshold)

        self.alert_repo = AlertRepository(db_path)
        self.snapshot_repo = SnapshotRepository(db_path)
        self.inventory_repo = InventoryRepository(db_path)

        self._previous_graph: Optional[nx.DiGraph] = None
        self._previous_risk: float = 50.0
        self._previous_posture: float = 80.0
        self._cycle_count: int = 0

        self._is_running: bool = False
        self._is_paused: bool = False
        self._worker_thread: Optional[threading.Thread] = None
        self._telemetry_queue: queue.Queue = queue.Queue(maxsize=100)

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    def run_single_cycle(
        self,
        network_graph: Optional[nx.DiGraph] = None,
        custom_timestamp: Optional[str] = None,
    ) -> MonitoringCycleResult:
        """
        Execute a single end-to-end monitoring cycle:
        1. Discover/Ingest network graph
        2. Diff against previous snapshot
        3. Track inventory state (NEW, ACTIVE, MISSING, CHANGED)
        4. Generate prioritized security alerts
        5. Dynamically recalculate risk, posture & defenses
        6. Persist to SQLite
        """
        self._cycle_count += 1
        now = custom_timestamp or _now_iso()

        # 1. Acquire current network graph
        current_g = network_graph if network_graph is not None else (self._previous_graph or build_network())

        # 2. Reconcile Continuous Asset Inventory
        self.inventory_tracker.update_from_graph(current_g, timestamp=now)
        self.inventory_repo.save_inventory_assets(self.inventory_tracker.inventory)

        # 3. Diff against previous scan snapshot
        prev_g = self._previous_graph if self._previous_graph is not None else current_g
        diff = compare_scans(prev_g, current_g, prev_time="Previous Scan", curr_time=now)

        # 4. Generate Real-Time Alerts
        alerts = self.alert_engine.generate_alerts_from_diff(diff, timestamp=now)
        for alt in alerts:
            self.alert_repo.save_alert(
                alert_id=alt.alert_id,
                timestamp=alt.timestamp,
                alert_type=alt.alert_type,
                severity=alt.severity,
                title=alt.title,
                description=alt.description,
                asset_ip=alt.asset_ip,
                asset_name=alt.asset_name,
                details=alt.details,
                risk_before=alt.risk_before,
                risk_after=alt.risk_after,
            )

        # 5. Dynamic Recalculation
        recalc = recalculate_dynamic_state(
            G=current_g,
            previous_risk=self._previous_risk,
            previous_posture=self._previous_posture,
        )

        # 6. Save Scan Snapshot to SQLite
        self.snapshot_repo.save_snapshot(
            snapshot_time=now,
            scan_type="Continuous Monitor",
            asset_count=len(current_g.nodes),
            avg_risk=recalc.new_overall_risk,
            posture_score=recalc.new_posture_score,
            diff_summary=diff.to_dict(),
        )

        # Update internal state pointers
        self._previous_graph = current_g.copy()
        self._previous_risk = recalc.new_overall_risk
        self._previous_posture = recalc.new_posture_score

        result = MonitoringCycleResult(
            cycle_index=self._cycle_count,
            timestamp=now,
            asset_count=len(current_g.nodes),
            diff=diff,
            alerts=alerts,
            recalculation=recalc,
        )

        # Push to telemetry queue for frontend listeners
        try:
            self._telemetry_queue.put_nowait(result)
        except queue.Full:
            pass

        return result

    def _worker_loop(self, scan_callback: Optional[Callable[[], nx.DiGraph]] = None) -> None:
        """Background thread execution loop."""
        while self._is_running:
            if not self._is_paused:
                try:
                    g = scan_callback() if scan_callback else None
                    self.run_single_cycle(network_graph=g)
                except Exception:
                    pass

            for _ in range(self.interval_seconds):
                if not self._is_running:
                    break
                time.sleep(1)

    def start(self, scan_callback: Optional[Callable[[], nx.DiGraph]] = None) -> None:
        """Start the background monitoring thread."""
        if self._is_running:
            return
        self._is_running = True
        self._is_paused = False
        self._worker_thread = threading.Thread(
            target=self._worker_loop, args=(scan_callback,), daemon=True, name="ACDS-Monitor-Worker"
        )
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self._is_running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self._worker_thread = None

    def pause(self) -> None:
        """Pause monitoring cycles without terminating thread."""
        self._is_paused = True

    def resume(self) -> None:
        """Resume paused monitoring cycles."""
        self._is_paused = False

    def get_latest_telemetry(self) -> Optional[MonitoringCycleResult]:
        """Poll the latest telemetry update from background worker."""
        latest = None
        while not self._telemetry_queue.empty():
            try:
                latest = self._telemetry_queue.get_nowait()
            except queue.Empty:
                break
        return latest
