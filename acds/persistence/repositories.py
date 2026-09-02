"""
ACDS Persistence Repositories
Provides high-level data access methods for scans, assets, vulnerabilities, simulations, and defenses.
"""

from datetime import datetime, timezone
import json
from typing import Dict, List, Optional, Tuple, Any
import networkx as nx

from acds.persistence.database import get_db_connection, init_database


class ScanRepository:
    """Repository for managing scan sessions and discovered assets in SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_scan_session(
        self,
        G: nx.DiGraph,
        scan_type: str = "Real Network Scan",
        base_ip: Optional[str] = None,
    ) -> int:
        """Save network graph assets, vulnerabilities, and metrics into database."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()

        assets = list(G.nodes(data=True))
        risks = [float(d.get("risk_score", 0.0)) for _, d in assets]
        avg_risk = round(sum(risks) / len(risks), 1) if risks else 0.0
        critical = sum(1 for _, d in assets if d.get("risk_severity") == "CRITICAL")
        high = sum(1 for _, d in assets if d.get("risk_severity") == "HIGH")
        medium = sum(1 for _, d in assets if d.get("risk_severity") == "MEDIUM")
        low = sum(1 for _, d in assets if d.get("risk_severity") == "LOW")

        cursor.execute(
            """
            INSERT INTO scan_sessions (
                scan_type, base_ip, started_at, completed_at,
                asset_count, average_risk, critical_count, high_count, medium_count, low_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                base_ip or "N/A",
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
                len(assets),
                avg_risk,
                critical,
                high,
                medium,
                low,
            ),
        )
        scan_id = cursor.lastrowid

        for node_name, data in assets:
            cursor.execute(
                """
                INSERT INTO assets (
                    scan_id, ip, hostname, display_name, mac, mac_vendor,
                    os, os_confidence, device_type, device_confidence, role,
                    criticality, criticality_label, risk_score, risk_severity,
                    open_ports, services
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    data.get("ip", ""),
                    data.get("hostname") or "",
                    data.get("display_name") or node_name,
                    data.get("mac") or "",
                    data.get("mac_vendor") or "",
                    data.get("os", "unknown"),
                    data.get("os_confidence") or 0.0,
                    data.get("device_type") or "Unknown",
                    data.get("device_confidence") or 0.0,
                    data.get("role", "Workstation"),
                    data.get("criticality", 2),
                    data.get("criticality_label", "LOW"),
                    data.get("risk_score", 0.0),
                    data.get("risk_severity", "LOW"),
                    json.dumps(data.get("open_ports", [])),
                    json.dumps(data.get("services", [])),
                ),
            )
            asset_id = cursor.lastrowid

            for c in data.get("cve_findings", []):
                cursor.execute(
                    """
                    INSERT INTO vulnerabilities (
                        asset_id, ip, cve_id, cvss, severity, service, port, summary, source, detection_confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        asset_id,
                        data.get("ip", ""),
                        c.get("cve_id", "UNKNOWN"),
                        c.get("cvss", 0.0),
                        c.get("severity", "Unknown"),
                        c.get("service", ""),
                        c.get("port", 0),
                        c.get("summary", ""),
                        c.get("source", ""),
                        c.get("detection_confidence", ""),
                    ),
                )

        conn.commit()
        conn.close()
        return scan_id

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve most recent scan sessions from database."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_sessions ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class SimulationRepository:
    """Repository for recording attack simulation runs and applied defenses."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_simulation_run(
        self,
        entry_node: str,
        seed: Optional[int],
        risk_score: float,
        blast_details: Dict[str, Any],
        honeypot_triggered: bool,
        ids_deployed: bool,
        segmentation_applied: bool,
        applied_defenses: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """Persist simulation metrics and applied defense actions."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO simulation_runs (
                entry_node, seed, risk_score, blast_spread, blast_critical_impact,
                blast_depth, systems_controlled, critical_assets_reached,
                max_lateral_hops, honeypot_triggered, ids_deployed, segmentation_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_node,
                seed or 0,
                risk_score,
                blast_details.get("spread", 0.0),
                blast_details.get("critical_impact", 0.0),
                blast_details.get("depth", 0.0),
                blast_details.get("systems_controlled", 0),
                blast_details.get("critical_assets_reached", 0),
                blast_details.get("max_lateral_hops", 0),
                honeypot_triggered,
                ids_deployed,
                segmentation_applied,
            ),
        )
        sim_id = cursor.lastrowid

        for defense in applied_defenses or []:
            cursor.execute(
                """
                INSERT INTO applied_defenses (
                    simulation_id, action_name, target_node, action_type, cost, risk_reduction, efficiency
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sim_id,
                    defense.get("action", ""),
                    defense.get("node", ""),
                    defense.get("type", ""),
                    defense.get("cost", 0),
                    defense.get("risk_reduction", 0.0),
                    defense.get("efficiency", 0.0),
                ),
            )

        conn.commit()
        conn.close()
        return sim_id

    def get_recent_simulations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent simulation runs from database."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM simulation_runs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class VulnerabilityRepository:
    """Repository for storing and querying deduplicated vulnerabilities and scan-to-scan correlation."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_vulnerability_definitions(
        self,
        definitions: List[Any],
        scan_id: Optional[int] = None,
    ) -> None:
        """Persist or update deduplicated vulnerability definitions and asset bindings."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()

        for vdef in definitions:
            # Check if definition exists to update recurrence and last_seen
            cursor.execute("SELECT id, total_occurrences, first_seen FROM vulnerability_definitions WHERE definition_id = ?", (vdef.definition_id,))
            row = cursor.fetchone()

            if row:
                new_count = row["total_occurrences"] + 1
                cursor.execute(
                    """
                    UPDATE vulnerability_definitions SET
                        total_occurrences = ?,
                        last_seen = ?,
                        priority_score = ?,
                        priority_level = ?,
                        remediation_status = ?
                    WHERE definition_id = ?
                    """,
                    (
                        new_count,
                        vdef.last_seen,
                        vdef.priority_score,
                        vdef.priority_level,
                        vdef.remediation_status,
                        vdef.definition_id,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO vulnerability_definitions (
                        definition_id, cve_id, product, vendor, version,
                        cvss, severity, description, source, is_cve,
                        priority_score, priority_level, remediation_status,
                        total_occurrences, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vdef.definition_id,
                        vdef.cve_id,
                        vdef.product,
                        vdef.vendor,
                        vdef.version,
                        vdef.cvss,
                        vdef.severity,
                        vdef.description,
                        vdef.source,
                        vdef.is_cve,
                        vdef.priority_score,
                        vdef.priority_level,
                        vdef.remediation_status,
                        vdef.total_occurrences or 1,
                        vdef.first_seen,
                        vdef.last_seen,
                    ),
                )

            # Save asset contexts
            for actx in vdef.affected_assets.values():
                cursor.execute(
                    """
                    INSERT INTO asset_vulnerability_findings (
                        definition_id, asset_id, host, ip, ports, services,
                        criticality, network_exposure, is_isolated, on_attack_path,
                        occurrence_count, status, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vdef.definition_id,
                        actx.asset_id,
                        actx.host,
                        actx.ip,
                        json.dumps(actx.ports),
                        json.dumps(actx.services),
                        actx.criticality,
                        actx.network_exposure,
                        actx.is_isolated,
                        actx.on_attack_path,
                        actx.occurrence_count,
                        actx.status,
                        actx.first_seen,
                        actx.last_seen,
                    ),
                )

                if scan_id is not None:
                    cursor.execute(
                        """
                        INSERT INTO finding_occurrences (definition_id, asset_id, scan_id)
                        VALUES (?, ?, ?)
                        """,
                        (vdef.definition_id, actx.asset_id, scan_id),
                    )

        conn.commit()
        conn.close()

    def get_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Retrieve all stored vulnerability definitions."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulnerability_definitions ORDER BY priority_score DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class AlertRepository:
    """Repository for managing security alerts generated during live monitoring."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_alert(
        self,
        alert_id: str,
        timestamp: str,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        asset_ip: Optional[str] = None,
        asset_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_before: Optional[float] = None,
        risk_after: Optional[float] = None,
    ) -> int:
        """Insert a security alert record into the database."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO alerts (
                alert_id, timestamp, alert_type, severity, asset_ip, asset_name,
                title, description, details_json, risk_before, risk_after, acknowledged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                timestamp,
                alert_type,
                severity,
                asset_ip or "",
                asset_name or "",
                title,
                description,
                json.dumps(details or {}),
                risk_before,
                risk_after,
                False,
            ),
        )
        row_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_recent_alerts(self, limit: int = 25, unacknowledged_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        query = "SELECT * FROM alerts"
        params = []
        if unacknowledged_only:
            query += " WHERE acknowledged = FALSE"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.get("details_json") or "{}")
            result.append(d)
        return result

    def acknowledge_alert(self, alert_id: str) -> None:
        """Mark an alert as acknowledged."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET acknowledged = TRUE WHERE alert_id = ?", (alert_id,))
        conn.commit()
        conn.close()


class CveCacheRepository:
    """Repository for caching NVD / CVE lookup queries in local SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def get_cached_cves(self, query_key: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve cached CVE list if within TTL."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT cve_json, fetched_at, ttl_hours FROM cve_cache WHERE query_key = ?", (query_key,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        # Check TTL
        try:
            fetched = datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00"))
            age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600.0
            if age_hours > row["ttl_hours"]:
                return None
            return json.loads(row["cve_json"])
        except Exception:
            return json.loads(row["cve_json"])

    def set_cached_cves(
        self,
        query_key: str,
        cves: List[Dict[str, Any]],
        source: str = "NVD",
        ttl_hours: int = 24,
    ) -> None:
        """Store CVE results in cache."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO cve_cache (query_key, cve_json, source, fetched_at, ttl_hours)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                query_key,
                json.dumps(cves),
                source,
                datetime.now(timezone.utc).isoformat(),
                ttl_hours,
            ),
        )
        conn.commit()
        conn.close()


class SnapshotRepository:
    """Repository for storing and diffing network scan snapshots."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_snapshot(
        self,
        snapshot_time: str,
        scan_type: str,
        asset_count: int,
        avg_risk: float,
        posture_score: float,
        diff_summary: Optional[Dict[str, Any]] = None,
        full_data: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Save a scan snapshot."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_snapshots (
                snapshot_time, scan_type, asset_count, avg_risk, posture_score,
                diff_summary_json, full_data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_time,
                scan_type,
                asset_count,
                avg_risk,
                posture_score,
                json.dumps(diff_summary or {}),
                json.dumps(full_data or {}),
            ),
        )
        row_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_latest_snapshot(self) -> Optional[Dict[str, Any]]:
        """Fetch the most recent scan snapshot."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_snapshots ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["diff_summary"] = json.loads(d.get("diff_summary_json") or "{}")
        d["full_data"] = json.loads(d.get("full_data_json") or "{}")
        return d

    def get_all_snapshots(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Fetch list of recent snapshots."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, snapshot_time, scan_type, asset_count, avg_risk, posture_score FROM scan_snapshots ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]


class InventoryRepository:
    """Repository for syncing persistent asset inventory records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        init_database(db_path)

    def save_inventory_assets(self, assets: Dict[str, Any]) -> None:
        """Persist or update inventory assets."""
        def _get_val(obj: Any, key: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        for a in assets.values():
            cursor.execute(
                """
                INSERT OR REPLACE INTO inventory_assets (
                    asset_id, ip, hostname, display_name, mac, mac_vendor, os, os_confidence,
                    device_type, role, criticality, criticality_label, risk_score,
                    open_ports_json, services_json, status, first_seen, last_seen,
                    changes_detected_json, scan_history_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _get_val(a, "asset_id", ""),
                    _get_val(a, "ip", ""),
                    _get_val(a, "hostname"),
                    _get_val(a, "display_name", ""),
                    _get_val(a, "mac"),
                    _get_val(a, "mac_vendor"),
                    _get_val(a, "os", "unknown"),
                    _get_val(a, "os_confidence", 0.0),
                    _get_val(a, "device_type", "Network Device"),
                    _get_val(a, "role", "Workstation"),
                    _get_val(a, "criticality", 3),
                    _get_val(a, "criticality_label", "MEDIUM"),
                    _get_val(a, "risk_score", 0.0),
                    json.dumps(_get_val(a, "open_ports", [])),
                    json.dumps(_get_val(a, "services", [])),
                    _get_val(a, "status", "NEW"),
                    _get_val(a, "first_seen", ""),
                    _get_val(a, "last_seen", ""),
                    json.dumps(_get_val(a, "changes_detected", [])),
                    _get_val(a, "scan_history_count", 1),
                ),
            )
        conn.commit()
        conn.close()

    def get_all_inventory_assets(self) -> List[Dict[str, Any]]:
        """Retrieve all inventory assets from database."""
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM inventory_assets ORDER BY risk_score DESC")
        rows = cursor.fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            d["open_ports"] = json.loads(d.get("open_ports_json") or "[]")
            d["services"] = json.loads(d.get("services_json") or "[]")
            d["changes_detected"] = json.loads(d.get("changes_detected_json") or "[]")
            result.append(d)
        return result

