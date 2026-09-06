"""
ACDS v3.0 — SPRINT 1: PERSISTENT MONITORING DATA LAYER
core/database.py
─────────────────────────────────────────────────────────────────
This is a SEPARATE persistence layer from data/database.py (which
stores scan/asset_snapshot/honeypot_events rows for the existing
Change Detection + Adaptive Honeypot panels — untouched by Sprint 1).

data/database.py answers: "what did each *scan* look like?"
core/database.py answers:  "what does each *asset* look like right
                             now, and how did it get there?"

It gives ACDS a true persistent asset inventory:
  - Every device ever seen keeps a single row in `assets` for its
    lifetime (matched by MAC address when available, else IP).
  - Devices that stop responding are marked OFFLINE, never deleted.
  - `services` holds the CURRENT open-port/service/version/banner
    set per asset (one row per asset+port, upserted every scan).
  - `scan_snapshots` records one row per completed monitoring pass
    (subnet, duration, how many assets were seen).
  - `asset_history` / `service_history` append-only logs give a
    full timeline per asset/service across every snapshot, instead
    of only ever knowing the latest state.

Stdlib-only (sqlite3), no Streamlit imports — safe to unit test and
reuse from a background scheduler fragment.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone

from core import change_detector
from core.acds_logging import get_logger

log = get_logger(__name__)

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DB_DIR, "acds.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address         TEXT,
    mac_address        TEXT,
    hostname           TEXT,
    vendor             TEXT,
    operating_system   TEXT,
    device_type        TEXT,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'ONLINE',   -- ONLINE / OFFLINE
    current_risk       REAL,
    criticality        TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_ip  ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac_address);

CREATE TABLE IF NOT EXISTS services (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       INTEGER NOT NULL REFERENCES assets(id),
    port           INTEGER NOT NULL,
    protocol       TEXT DEFAULT 'tcp',
    service        TEXT,
    version        TEXT,
    banner         TEXT,
    discovered_at  TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_services_asset_port ON services(asset_id, port);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time      TEXT NOT NULL,
    subnet         TEXT,
    duration       REAL,
    total_assets   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS asset_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       INTEGER NOT NULL REFERENCES assets(id),
    snapshot_id    INTEGER NOT NULL REFERENCES scan_snapshots(snapshot_id),
    ip             TEXT,
    mac            TEXT,
    hostname       TEXT,
    os             TEXT,
    device_type    TEXT,
    status         TEXT
);

CREATE INDEX IF NOT EXISTS idx_asset_history_asset    ON asset_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_history_snapshot ON asset_history(snapshot_id);

CREATE TABLE IF NOT EXISTS service_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       INTEGER NOT NULL REFERENCES assets(id),
    snapshot_id    INTEGER NOT NULL REFERENCES scan_snapshots(snapshot_id),
    port           INTEGER,
    service        TEXT,
    version        TEXT
);

CREATE INDEX IF NOT EXISTS idx_service_history_asset    ON service_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_service_history_snapshot ON service_history(snapshot_id);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 2 — PHASE 4: RISK HISTORY
-- One row per asset per completed recalculation pass, PLUS one
-- "summary" row (asset_id IS NULL) carrying the Overall ACDS Risk for
-- that same pass, so a trend line can be drawn without averaging
-- per-asset rows. Never overwritten / never deleted — append-only.
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    asset_id       INTEGER REFERENCES assets(id),   -- NULL for the summary/overall row
    asset_ip       TEXT,
    asset_risk     REAL,
    blast_radius   REAL,
    overall_risk   REAL,
    is_summary     INTEGER NOT NULL DEFAULT 0,
    trigger        TEXT
);

CREATE INDEX IF NOT EXISTS idx_risk_history_asset ON risk_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_risk_history_time  ON risk_history(timestamp);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 2 — PHASE 7: REAL-TIME ALERT ENGINE
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    severity       TEXT NOT NULL,   -- INFO / LOW / MEDIUM / HIGH / CRITICAL
    alert_type     TEXT NOT NULL,   -- NEW_CVE / RISK_INCREASE / CRITICAL_ASSET_EXPOSED /
                                     -- NEW_EXPOSURE_PATH / HONEYPOT_PATH / RISK_DECREASE
    asset          TEXT,
    title          TEXT,
    description    TEXT,
    old_value      TEXT,
    new_value      TEXT,
    acknowledged     INTEGER NOT NULL DEFAULT 0,
    acknowledged_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_time     ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ack      ON alerts(acknowledged);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 3 — PHASE 5: LIVE RECENT CHANGES PANEL (persisted)
-- record_monitoring_scan() already computed a structured diff via
-- change_detector.detect_asset_service_changes() every pass, but
-- only ever returned it to the caller for a session-only display.
-- This table makes that diff durable so the "Recent Changes" timeline
-- survives restarts and reflects true SQLite history, not just this
-- session's last pass, per the sprint spec.
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_changes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id    INTEGER REFERENCES scan_snapshots(snapshot_id),
    timestamp      TEXT NOT NULL,
    change_type    TEXT NOT NULL,   -- NEW_ASSET / REMOVED_ASSET / NEW_PORT / CLOSED_PORT /
                                     -- SERVICE_CHANGED / VERSION_CHANGED
    asset          TEXT,
    severity       TEXT NOT NULL,
    detail         TEXT
);

CREATE INDEX IF NOT EXISTS idx_network_changes_time ON network_changes(timestamp);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 3 — PHASE 8: SETTINGS PANEL — persisted key/value config.
-- Simple key/value store (values stored as JSON text) so new settings
-- can be added later without another schema migration.
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 3 — PHASE 7: OPERATIONAL RELIABILITY — local CVE cache.
-- NVD has no API key configured here, so it rate-limits aggressively;
-- this table lets a version string looked up once survive app
-- restarts instead of re-querying NVD (or silently going without CVE
-- data) every single session. One row per unique version_string
-- lookup key, overwritten on refresh.
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_cache (
    version_string   TEXT PRIMARY KEY,
    cves_json        TEXT NOT NULL,   -- JSON-encoded list of CVE dicts
    source           TEXT NOT NULL,   -- nvd_live / offline_table
    fetched_at       TEXT NOT NULL
);

-- ─────────────────────────────────────────────────────────────────
-- SPRINT 2 — PHASE 9: CVE / VULNERABILITY LIFECYCLE HISTORY
-- ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    asset_ip       TEXT,
    cve_id         TEXT,
    event_type     TEXT NOT NULL,   -- DISCOVERED / RESOLVED / CVSS_CHANGED / VERSION_CHANGED
    cvss           REAL,
    detail         TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve_history_time  ON cve_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_cve_history_asset ON cve_history(asset_ip);
"""


def get_connection(db_path=DEFAULT_DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DEFAULT_DB_PATH):
    """Automatically initialize the database if it does not exist yet
    (Phase 1 requirement). Safe to call every app run — CREATE TABLE
    IF NOT EXISTS / CREATE INDEX IF NOT EXISTS are idempotent."""
    conn = get_connection(db_path)
    try:
        # Migrate BEFORE executescript: on a pre-Sprint-3 database the
        # `alerts` table already exists without the new columns, and
        # CREATE TABLE IF NOT EXISTS is then a no-op — so the CREATE INDEX
        # on `acknowledged` further down in SCHEMA would fail with "no
        # such column" unless the column is added first.
        _migrate_schema(conn)
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _migrate_schema(conn):
    """Sprint 3 — Phase 6: databases created before this sprint have an
    `alerts` table without the acknowledgement columns. CREATE TABLE IF
    NOT EXISTS never alters an existing table, so add them here with a
    guarded ALTER TABLE — safe to run on every startup, and a no-op on a
    brand-new database (the table doesn't exist yet, SCHEMA creates it
    with these columns already included)."""
    tables = {row["name"] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "alerts" not in tables:
        return
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "acknowledged" not in existing_cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0")
    if "acknowledged_at" not in existing_cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")


def _find_asset(conn, mac, ip):
    """Match key priority: MAC address first (stable across DHCP lease
    changes), falling back to IP address for devices with no readable
    MAC (e.g. scanning machine itself, or ARP not available)."""
    row = None
    if mac:
        row = conn.execute("SELECT * FROM assets WHERE mac_address = ?", (mac,)).fetchone()
    if row is None and ip:
        row = conn.execute(
            "SELECT * FROM assets WHERE ip_address = ? AND mac_address IS ?", (ip, mac)
        ).fetchone()
    return row


def record_monitoring_scan(devices, subnet, duration, db_path=DEFAULT_DB_PATH):
    """Persist one completed monitoring pass (Phases 2/3/4).

    devices: list of dicts, each shaped like:
        {
          'ip': str, 'mac': str|None, 'hostname': str|None,
          'vendor': str|None, 'os': str|None, 'device_type': str|None,
          'criticality': str|None, 'current_risk': float|None,
          'ports': [ {'port': int, 'protocol': 'tcp', 'service': str,
                       'version': str|None, 'banner': str|None}, ... ],
        }

    Returns (changes, snapshot_id):
        changes      - list of structured change dicts from
                        core.change_detector.detect_asset_service_changes
                        (NEW_ASSET / REMOVED_ASSET / NEW_PORT /
                        CLOSED_PORT / SERVICE_CHANGED / VERSION_CHANGED)
        snapshot_id  - the new scan_snapshots row id
    """
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()

        cur = conn.execute(
            "INSERT INTO scan_snapshots (scan_time, subnet, duration, total_assets) VALUES (?,?,?,?)",
            (now, subnet, duration, len(devices)),
        )
        snapshot_id = cur.lastrowid

        # ---- Capture state BEFORE this scan (for the change detector) ----
        previous_assets = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM assets").fetchall()}
        previous_services = {}
        for row in conn.execute("SELECT * FROM services").fetchall():
            previous_services.setdefault(row["asset_id"], {})[row["port"]] = dict(row)

        before_state = {
            "assets": {
                aid: {"ip": a["ip_address"], "mac": a["mac_address"],
                      "hostname": a["hostname"], "status": a["status"]}
                for aid, a in previous_assets.items()
            },
            "services": {
                aid: {p: {"service": s["service"], "version": s["version"]} for p, s in ports.items()}
                for aid, ports in previous_services.items()
            },
        }

        # ---- Insert / update assets + services seen in THIS scan ----
        seen_ids = set()
        after_assets = {}
        after_services = {}

        for dev in devices:
            ip = dev.get("ip")
            mac = dev.get("mac") or None
            row = _find_asset(conn, mac, ip)

            if row is None:
                cur = conn.execute(
                    "INSERT INTO assets (ip_address, mac_address, hostname, vendor, operating_system, "
                    "device_type, first_seen, last_seen, status, current_risk, criticality) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (ip, mac, dev.get("hostname"), dev.get("vendor"), dev.get("os"),
                     dev.get("device_type"), now, now, "ONLINE",
                     dev.get("current_risk"), dev.get("criticality")),
                )
                asset_id = cur.lastrowid
            else:
                asset_id = row["id"]
                conn.execute(
                    "UPDATE assets SET ip_address=?, mac_address=COALESCE(?, mac_address), "
                    "hostname=?, vendor=?, operating_system=?, device_type=?, last_seen=?, "
                    "status='ONLINE', current_risk=?, criticality=? WHERE id=?",
                    (ip, mac, dev.get("hostname"), dev.get("vendor"), dev.get("os"),
                     dev.get("device_type"), now, dev.get("current_risk"), dev.get("criticality"),
                     asset_id),
                )
            seen_ids.add(asset_id)
            after_assets[asset_id] = {"ip": ip, "mac": mac, "hostname": dev.get("hostname"), "status": "ONLINE"}

            port_map = {}
            for svc in dev.get("ports", []):
                port = svc["port"]
                port_map[port] = {"service": svc.get("service"), "version": svc.get("version")}
                existing = conn.execute(
                    "SELECT id FROM services WHERE asset_id=? AND port=?", (asset_id, port)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE services SET protocol=?, service=?, version=?, banner=?, discovered_at=? "
                        "WHERE id=?",
                        (svc.get("protocol", "tcp"), svc.get("service"), svc.get("version"),
                         svc.get("banner"), now, existing["id"]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO services (asset_id, port, protocol, service, version, banner, "
                        "discovered_at) VALUES (?,?,?,?,?,?,?)",
                        (asset_id, port, svc.get("protocol", "tcp"), svc.get("service"),
                         svc.get("version"), svc.get("banner"), now),
                    )
                conn.execute(
                    "INSERT INTO service_history (asset_id, snapshot_id, port, service, version) "
                    "VALUES (?,?,?,?,?)",
                    (asset_id, snapshot_id, port, svc.get("service"), svc.get("version")),
                )

            # Ports that were open last time but are no longer reported open
            # are removed from the CURRENT `services` table (service_history
            # already has the permanent record from when they were seen).
            for old_port in list(previous_services.get(asset_id, {}).keys()):
                if old_port not in port_map:
                    conn.execute("DELETE FROM services WHERE asset_id=? AND port=?", (asset_id, old_port))

            after_services[asset_id] = port_map

            conn.execute(
                "INSERT INTO asset_history (asset_id, snapshot_id, ip, mac, hostname, os, device_type, "
                "status) VALUES (?,?,?,?,?,?,?,?)",
                (asset_id, snapshot_id, ip, mac, dev.get("hostname"), dev.get("os"),
                 dev.get("device_type"), "ONLINE"),
            )

        # ---- Assets known before but not seen this scan -> OFFLINE ----
        for aid, a in previous_assets.items():
            if aid in seen_ids:
                continue
            if a["status"] != "OFFLINE":
                conn.execute("UPDATE assets SET status='OFFLINE' WHERE id=?", (aid,))
            conn.execute(
                "INSERT INTO asset_history (asset_id, snapshot_id, ip, mac, hostname, os, device_type, "
                "status) VALUES (?,?,?,?,?,?,?,?)",
                (aid, snapshot_id, a["ip_address"], a["mac_address"], a["hostname"],
                 a["operating_system"], a["device_type"], "OFFLINE"),
            )
            after_assets[aid] = {"ip": a["ip_address"], "mac": a["mac_address"],
                                  "hostname": a["hostname"], "status": "OFFLINE"}
            after_services[aid] = previous_services.get(aid, {})

        conn.commit()

        after_state = {"assets": after_assets, "services": after_services}
        changes = change_detector.detect_asset_service_changes(before_state, after_state)
        record_network_changes(changes, snapshot_id, now, db_path=db_path)
        return changes, snapshot_id
    finally:
        conn.close()


def get_live_assets(db_path=DEFAULT_DB_PATH):
    """All assets ever seen, ONLINE first, for the Live Asset Inventory
    panel (Phase 6). Devices are never deleted, only marked OFFLINE."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM assets ORDER BY (status = 'ONLINE') DESC, ip_address"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_asset_services(asset_id, db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM services WHERE asset_id = ? ORDER BY port", (asset_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_snapshots(limit=20, db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scan_snapshots ORDER BY snapshot_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _change_detail_text(c):
    """Render a core.change_detector change dict into a short human line,
    matching the sprint's example format (e.g. 'Port 445 Opened')."""
    t = c["type"]
    if t == "NEW_ASSET":
        return f"New device joined the network"
    if t == "REMOVED_ASSET":
        return f"Device went offline"
    if t == "NEW_PORT":
        return f"Port {c.get('port')} Opened" + (f" ({c['service']})" if c.get('service') else "")
    if t == "CLOSED_PORT":
        return f"Port {c.get('port')} Closed" + (f" ({c['service']})" if c.get('service') else "")
    if t == "SERVICE_CHANGED":
        return f"Service on port {c.get('port')} changed: {c.get('before_service')} → {c.get('after_service')}"
    if t == "VERSION_CHANGED":
        return f"{c.get('service')} version changed on port {c.get('port')}: {c.get('before_version')} → {c.get('after_version')}"
    return t


def record_network_changes(changes, snapshot_id, timestamp, db_path=DEFAULT_DB_PATH):
    """Persist the structured diff from change_detector.detect_asset_service_changes()
    so the Recent Changes panel (Phase 5) reads real SQLite history instead
    of only the most recent in-session pass."""
    if not changes:
        return
    conn = get_connection(db_path)
    try:
        for c in changes:
            conn.execute(
                "INSERT INTO network_changes (snapshot_id, timestamp, change_type, asset, severity, detail) "
                "VALUES (?,?,?,?,?,?)",
                (snapshot_id, timestamp, c["type"], c.get("asset"), c.get("severity", "LOW"),
                 _change_detail_text(c)),
            )
        conn.commit()
    finally:
        conn.close()


def get_recent_timeline(limit=40, db_path=DEFAULT_DB_PATH):
    """Sprint 3 — Phase 5: unified Recent Changes timeline, read entirely
    from SQLite. Merges asset/port/service-level changes (network_changes)
    with risk-level events (alerts: RISK_INCREASE / RISK_DECREASE) into one
    time-ordered feed, since the sprint's example timeline mixes both kinds
    of events ("New Asset", "Port Opened", "Overall Risk Increased").
    Returns rows shaped: {timestamp, kind, severity, asset, detail}."""
    conn = get_connection(db_path)
    try:
        rows = []
        for r in conn.execute(
            "SELECT timestamp, change_type AS kind, severity, asset, detail "
            "FROM network_changes ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall():
            rows.append(dict(r))
        for r in conn.execute(
            "SELECT timestamp, alert_type AS kind, severity, asset, "
            "title || COALESCE(' (' || old_value || ' → ' || new_value || ')', '') AS detail "
            "FROM alerts WHERE alert_type IN ('RISK_INCREASE','RISK_DECREASE') "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall():
            rows.append(dict(r))
        rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
        return rows[:limit]
    finally:
        conn.close()


def get_cached_cve_lookup(version_string, max_age_hours=24, db_path=DEFAULT_DB_PATH):
    """Sprint 3 — Phase 7: return (cves, source) from the persisted local
    cache if a fresh-enough entry exists, else None. Never raises — a
    corrupt/missing cache is treated as a cache miss, not a crash."""
    if not version_string:
        return None
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT cves_json, source, fetched_at FROM cve_cache WHERE version_string = ?",
            (version_string,),
        ).fetchone()
        if not row:
            return None
        try:
            fetched = datetime.fromisoformat(row["fetched_at"])
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600.0
            if age_hours > max_age_hours:
                return None
            return json.loads(row["cves_json"]), row["source"]
        except (ValueError, TypeError, json.JSONDecodeError):
            return None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def cache_cve_lookup(version_string, cves, source, db_path=DEFAULT_DB_PATH):
    """Persist a successful CVE lookup so it survives app restarts and
    doesn't re-hit NVD's rate limits for the same version string."""
    if not version_string:
        return
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO cve_cache (version_string, cves_json, source, fetched_at) VALUES (?,?,?,?) "
            "ON CONFLICT(version_string) DO UPDATE SET cves_json=excluded.cves_json, "
            "source=excluded.source, fetched_at=excluded.fetched_at",
            (version_string, json.dumps(cves), source, now),
        )
        conn.commit()
    except sqlite3.Error as exc:
        log.warning("cache_cve_lookup failed for %r: %s", version_string, exc)
    finally:
        conn.close()


DEFAULT_SETTINGS = {
    "monitoring_interval": "1m",        # 30s / 1m / 5m
    "scan_timeout_seconds": 0.6,        # per-port connect timeout
    "banner_timeout_seconds": 1.2,      # banner-grab read timeout
    "nvd_cache_hours": 24,              # local CVE cache TTL
    "risk_threshold_critical": 85,
    "risk_threshold_high": 65,
    "risk_threshold_medium": 35,
    "alert_severity_threshold": "LOW",  # minimum severity that gets persisted
    "default_budget": 50,
    "theme": "cyberpunk",               # only theme available; persisted for forward-compat
}


def get_setting(key, default=None, db_path=DEFAULT_DB_PATH):
    """Sprint 3 — Phase 8: read one persisted setting, JSON-decoded.
    Falls back to DEFAULT_SETTINGS[key], then to the explicit `default`
    argument, if nothing is stored yet or the value is corrupt."""
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return DEFAULT_SETTINGS.get(key, default)
        try:
            return json.loads(row["value_json"])
        except (ValueError, TypeError, json.JSONDecodeError):
            return DEFAULT_SETTINGS.get(key, default)
    except sqlite3.Error as exc:
        log.warning("get_setting(%r) failed, using default: %s", key, exc)
        return DEFAULT_SETTINGS.get(key, default)
    finally:
        conn.close()


def get_all_settings(db_path=DEFAULT_DB_PATH):
    """Returns the full effective settings dict — every DEFAULT_SETTINGS
    key present, overridden by whatever is actually persisted."""
    conn = get_connection(db_path)
    try:
        stored = {}
        try:
            for row in conn.execute("SELECT key, value_json FROM settings").fetchall():
                try:
                    stored[row["key"]] = json.loads(row["value_json"])
                except (ValueError, TypeError, json.JSONDecodeError):
                    continue
        except sqlite3.Error as exc:
            log.warning("get_all_settings failed, using defaults: %s", exc)
        merged = dict(DEFAULT_SETTINGS)
        merged.update(stored)
        return merged
    finally:
        conn.close()


def set_setting(key, value, db_path=DEFAULT_DB_PATH):
    """Persist one setting. Never raises — a failed settings write should
    degrade to 'setting didn't stick' rather than crash the Settings page."""
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at",
            (key, json.dumps(value), now),
        )
        conn.commit()
    except sqlite3.Error as exc:
        log.error("set_setting(%r) failed: %s", key, exc)
    finally:
        conn.close()


def get_asset_count(db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c, SUM(status='ONLINE') AS online FROM assets"
        ).fetchone()
        return {"total": row["c"] or 0, "online": row["online"] or 0}
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# SPRINT 3 — PHASE 3: keep `assets.current_risk` / `assets.criticality`
# in sync with the live risk model on EVERY recalculation pass (manual
# scan, monitoring pass, or simulation) — not just background monitoring
# passes. Without this, the Executive Dashboard's KPI cards and Top-10
# High-Risk Assets table would read NULLs whenever monitoring was never
# toggled on, even though a perfectly good live scan already happened.
# Upserts by IP so it works whether or not record_monitoring_scan() has
# ever run for this asset (never duplicates a row already present).
# ─────────────────────────────────────────────────────────────────
def update_asset_current_state(ip_snapshot, db_path=DEFAULT_DB_PATH):
    """ip_snapshot: dict keyed by IP -> {'hostname', 'risk_score',
    'risk_severity', ...} (the exact shape app._asset_risk_snapshot_from_graph
    already produces). Upserts assets.current_risk / .criticality /
    .hostname / .last_seen / .status for each IP."""
    if not ip_snapshot:
        return
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        for ip, d in ip_snapshot.items():
            if not ip:
                continue
            row = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (ip,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO assets (ip_address, hostname, first_seen, last_seen, status, "
                    "current_risk, criticality) VALUES (?,?,?,?,?,?,?)",
                    (ip, d.get("hostname"), now, now, "ONLINE",
                     d.get("risk_score"), d.get("criticality")),
                )
            else:
                conn.execute(
                    "UPDATE assets SET hostname=COALESCE(?, hostname), last_seen=?, status='ONLINE', "
                    "current_risk=?, criticality=? WHERE id=?",
                    (d.get("hostname"), now, d.get("risk_score"), d.get("criticality"), row["id"]),
                )
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# SPRINT 2 — PHASE 4: RISK HISTORY read/write
# ─────────────────────────────────────────────────────────────────

def record_risk_history(asset_rows, overall_risk, blast_radius, trigger, db_path=DEFAULT_DB_PATH):
    """Persist one completed recalculation pass (Phase 4/10).

    asset_rows: list of dicts {'asset_ip':.., 'asset_risk':..}
    overall_risk / blast_radius: the network-wide figures for this pass
        (blast_radius may be None if no simulation baseline exists yet).
    trigger: short label of what caused this pass, e.g. 'MANUAL_SCAN',
        'MONITORING', 'SIMULATION' — purely informational.

    Writes one row per asset PLUS one is_summary=1 row so trend charts
    can read the Overall ACDS Risk without averaging per-asset rows.
    Never overwrites — every call appends new rows (Phase 4 requirement).
    """
    conn = get_connection(db_path)
    try:
        now = datetime.now(timezone.utc).isoformat()
        for row in asset_rows:
            asset = conn.execute(
                "SELECT id FROM assets WHERE ip_address = ?", (row.get("asset_ip"),)
            ).fetchone()
            asset_id = asset["id"] if asset else None
            conn.execute(
                "INSERT INTO risk_history (timestamp, asset_id, asset_ip, asset_risk, blast_radius, "
                "overall_risk, is_summary, trigger) VALUES (?,?,?,?,?,?,0,?)",
                (now, asset_id, row.get("asset_ip"), row.get("asset_risk"), blast_radius,
                 overall_risk, trigger),
            )
        conn.execute(
            "INSERT INTO risk_history (timestamp, asset_id, asset_ip, asset_risk, blast_radius, "
            "overall_risk, is_summary, trigger) VALUES (?,NULL,NULL,NULL,?,?,1,?)",
            (now, blast_radius, overall_risk, trigger),
        )
        conn.commit()
        return now
    finally:
        conn.close()


def get_overall_risk_trend(limit=100, db_path=DEFAULT_DB_PATH):
    """Phase 8 widget 1 — Overall Risk Trend line chart source."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT timestamp, overall_risk, blast_radius FROM risk_history "
            "WHERE is_summary = 1 AND overall_risk IS NOT NULL "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return list(reversed([dict(r) for r in rows]))
    finally:
        conn.close()


def get_latest_asset_risk_rows(db_path=DEFAULT_DB_PATH):
    """Most recent per-asset risk_history rows (one per asset), used for
    Phase 8 widgets 2/3 (distribution + top-10 table)."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT rh.asset_ip, rh.asset_risk, rh.timestamp, a.hostname, a.criticality, a.last_seen
            FROM risk_history rh
            JOIN (
                SELECT asset_ip, MAX(id) AS max_id FROM risk_history
                WHERE is_summary = 0 AND asset_ip IS NOT NULL GROUP BY asset_ip
            ) latest ON latest.max_id = rh.id
            LEFT JOIN assets a ON a.ip_address = rh.asset_ip
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# SPRINT 2 — PHASE 7: ALERTS read/write
# ─────────────────────────────────────────────────────────────────

def create_alerts(alerts, db_path=DEFAULT_DB_PATH):
    """alerts: list of dicts with keys timestamp, severity, alert_type,
    asset, title, description, old_value, new_value.

    Sprint 3 — Phase 7 (operational reliability): guards against
    inserting an exact duplicate of an alert already raised in the last
    hour (same alert_type + asset + new_value) — defense-in-depth on
    top of alert_engine's diff-based design (which already shouldn't
    re-fire on an unchanged state), in case a caller ever re-runs the
    same comparison twice."""
    if not alerts:
        return
    conn = get_connection(db_path)
    try:
        cutoff = (datetime.now(timezone.utc).timestamp()) - 3600
        inserted = 0
        for a in alerts:
            dupe = conn.execute(
                "SELECT 1 FROM alerts WHERE alert_type = ? AND asset = ? AND "
                "COALESCE(new_value,'') = COALESCE(?,'') AND timestamp > ? LIMIT 1",
                (a.get("alert_type"), a.get("asset"), a.get("new_value"),
                 datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()),
            ).fetchone()
            if dupe:
                log.info("Skipped duplicate alert: %s / %s", a.get("alert_type"), a.get("asset"))
                continue
            conn.execute(
                "INSERT INTO alerts (timestamp, severity, alert_type, asset, title, description, "
                "old_value, new_value) VALUES (?,?,?,?,?,?,?,?)",
                (a.get("timestamp"), a.get("severity"), a.get("alert_type"), a.get("asset"),
                 a.get("title"), a.get("description"), a.get("old_value"), a.get("new_value")),
            )
            inserted += 1
        conn.commit()
        if inserted:
            log.info("Recorded %d new alert(s)", inserted)
    except sqlite3.Error as exc:
        log.error("create_alerts failed: %s", exc)
    finally:
        conn.close()


def get_alerts(limit=50, severity=None, alert_type=None, search=None, acknowledged=None,
                db_path=DEFAULT_DB_PATH):
    """Sprint 3 — Phase 6: extended for the Alert Center — `search` matches
    against asset / title / description / alert_type (covers IP, hostname,
    CVE, and alert-type search in one parameter since CVEs and hostnames
    both surface in those free-text fields); `acknowledged` (True/False)
    filters by acknowledgement state. All existing callers keep working
    unchanged since every new parameter defaults to "no filter"."""
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(1 if acknowledged else 0)
        if search:
            query += (" AND (asset LIKE ? OR title LIKE ? OR description LIKE ? OR alert_type LIKE ? "
                       "OR old_value LIKE ? OR new_value LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like, like, like, like])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def acknowledge_alert(alert_id, db_path=DEFAULT_DB_PATH):
    """Sprint 3 — Phase 6: mark an alert acknowledged. Never deletes —
    the row and its full history stay in place, only the acknowledgement
    flag/timestamp change."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), alert_id),
        )
        conn.commit()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# SPRINT 2 — PHASE 9: CVE / VULNERABILITY LIFECYCLE HISTORY
# ─────────────────────────────────────────────────────────────────

def record_cve_events(events, db_path=DEFAULT_DB_PATH):
    """events: list of dicts {timestamp, asset_ip, cve_id, event_type, cvss, detail}.

    Sprint 3 — Phase 7: skips a DISCOVERED event if that exact
    (asset_ip, cve_id) already has an unresolved DISCOVERED event on
    record — defense-in-depth against the same finding being logged
    twice (e.g. a rescan re-detecting a CVE that was never actually
    resolved). RESOLVED/other event types are always recorded since
    they represent a genuine state transition."""
    if not events:
        return
    conn = get_connection(db_path)
    try:
        recorded = 0
        for e in events:
            if e.get("event_type") == "DISCOVERED":
                dupe = conn.execute(
                    "SELECT 1 FROM cve_history WHERE asset_ip = ? AND cve_id = ? AND event_type = 'DISCOVERED' "
                    "AND NOT EXISTS (SELECT 1 FROM cve_history r WHERE r.asset_ip = cve_history.asset_ip "
                    "AND r.cve_id = cve_history.cve_id AND r.event_type = 'RESOLVED' AND r.id > cve_history.id) "
                    "LIMIT 1",
                    (e.get("asset_ip"), e.get("cve_id")),
                ).fetchone()
                if dupe:
                    log.info("Skipped duplicate CVE discovery: %s on %s", e.get("cve_id"), e.get("asset_ip"))
                    continue
            conn.execute(
                "INSERT INTO cve_history (timestamp, asset_ip, cve_id, event_type, cvss, detail) "
                "VALUES (?,?,?,?,?,?)",
                (e.get("timestamp"), e.get("asset_ip"), e.get("cve_id"), e.get("event_type"),
                 e.get("cvss"), e.get("detail")),
            )
            recorded += 1
        conn.commit()
        if recorded:
            log.info("Recorded %d CVE lifecycle event(s)", recorded)
    except sqlite3.Error as exc:
        log.error("record_cve_events failed: %s", exc)
    finally:
        conn.close()


def get_cve_timeline(limit=50, db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM cve_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
