"""
ACDS DATA LAYER — data/database.py
─────────────────────────────────────────────────────────────────
Priority 27 (mandatory): everything up to now lived only in
st.session_state, so scan history, change detection, and honeypot
activity were lost every time the Streamlit process restarted.

This module is a thin, dependency-free (stdlib sqlite3 only) local
persistence layer. It does NOT replace st.session_state for the
live in-app graph — the NetworkX graph stays in memory for
performance. It DOES persist:

  SCANS            - one row per completed scan (Real Network Scan
                      or Post-simulation / Post-defense snapshot),
                      mirrors the existing in-session scan_history
                      dict but survives restarts.
  ASSET_SNAPSHOTS   - one row per asset, per scan, so we can diff
                      "what did we see last time" vs "what do we
                      see now" (Priority 13, Change Detection).
  HONEYPOT_EVENTS   - one row per simulated/observed honeypot
                      interaction, persisted across sessions so the
                      Adaptive Honeypot feedback loop (Priority 19)
                      has real history to react to instead of a
                      single in-memory boolean.

Design notes:
  - SQLite file lives at data/acds.db (created on first use).
  - All functions accept an explicit db_path so tests / multiple
    instances don't collide, but default to the standard location.
  - No PII/secrets are stored — only network-observable fields the
    rest of the app already computes (IP, MAC, hostname, ports,
    services, versions, CVE IDs, risk scores).
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DB_DIR, "acds.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    scan_type      TEXT NOT NULL,
    asset_count    INTEGER NOT NULL,
    average_risk   REAL NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count     INTEGER NOT NULL,
    medium_count   INTEGER NOT NULL,
    low_count      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_snapshots (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(scan_id),
    ip             TEXT NOT NULL,
    mac            TEXT,
    hostname       TEXT,
    device_type    TEXT,
    os_type        TEXT,
    criticality    TEXT,
    risk_score     REAL,
    risk_severity  TEXT,
    open_ports     TEXT,   -- JSON list[int]
    services       TEXT,   -- JSON list[str]
    cve_ids        TEXT    -- JSON list[str]
);

CREATE INDEX IF NOT EXISTS idx_snapshot_scan ON asset_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_snapshot_ip ON asset_snapshots(ip);

CREATE TABLE IF NOT EXISTS honeypot_events (
    event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    source         TEXT,      -- entry node / simulated attacker origin
    decoy          TEXT,      -- which honeypot/decoy asset was touched
    event_type     TEXT,      -- e.g. 'simulated_probe', 'connection_attempt'
    details        TEXT,      -- free-text/JSON details
    risk_before    REAL,
    risk_after     REAL
);

CREATE INDEX IF NOT EXISTS idx_honeypot_ts ON honeypot_events(timestamp);
"""


def get_connection(db_path=DEFAULT_DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def save_scan(scan_type, metrics, assets, db_path=DEFAULT_DB_PATH):
    """Persist one scan + its per-asset snapshot rows.

    metrics: dict with keys assets/average_risk/critical/high/medium/low
             (same shape as get_asset_metrics() in app.py)
    assets:  list of dicts with keys ip, mac, hostname, device_type,
             os_type, criticality, risk_score, risk_severity,
             open_ports (list), services (list[str]), cve_ids (list[str])

    Returns the new scan_id.
    """
    conn = get_connection(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO scans (timestamp, scan_type, asset_count, average_risk, "
            "critical_count, high_count, medium_count, low_count) VALUES (?,?,?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                scan_type,
                metrics.get("assets", 0),
                metrics.get("average_risk", 0.0),
                metrics.get("critical", 0),
                metrics.get("high", 0),
                metrics.get("medium", 0),
                metrics.get("low", 0),
            ),
        )
        scan_id = cur.lastrowid
        for a in assets:
            conn.execute(
                "INSERT INTO asset_snapshots (scan_id, ip, mac, hostname, device_type, "
                "os_type, criticality, risk_score, risk_severity, open_ports, services, cve_ids) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id, a.get("ip"), a.get("mac"), a.get("hostname"),
                    a.get("device_type"), a.get("os_type"), a.get("criticality"),
                    a.get("risk_score"), a.get("risk_severity"),
                    json.dumps(a.get("open_ports", [])),
                    json.dumps(a.get("services", [])),
                    json.dumps(a.get("cve_ids", [])),
                ),
            )
        conn.commit()
        return scan_id
    finally:
        conn.close()


def get_scan_history(limit=50, db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scan_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_latest_scan_id(before_scan_id=None, db_path=DEFAULT_DB_PATH):
    """Return the most recent scan_id, optionally strictly before a given id
    (used to find 'the scan before this one' for change detection)."""
    conn = get_connection(db_path)
    try:
        if before_scan_id is None:
            row = conn.execute("SELECT MAX(scan_id) AS m FROM scans").fetchone()
        else:
            row = conn.execute(
                "SELECT MAX(scan_id) AS m FROM scans WHERE scan_id < ?", (before_scan_id,)
            ).fetchone()
        return row["m"] if row and row["m"] is not None else None
    finally:
        conn.close()


def get_snapshot(scan_id, db_path=DEFAULT_DB_PATH):
    if scan_id is None:
        return []
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM asset_snapshots WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["open_ports"] = json.loads(d["open_ports"] or "[]")
            d["services"] = json.loads(d["services"] or "[]")
            d["cve_ids"] = json.loads(d["cve_ids"] or "[]")
            out.append(d)
        return out
    finally:
        conn.close()


def log_honeypot_event(source, decoy, event_type, details, risk_before, risk_after,
                        db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO honeypot_events (timestamp, source, decoy, event_type, details, "
            "risk_before, risk_after) VALUES (?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), source, decoy, event_type,
             details, risk_before, risk_after),
        )
        conn.commit()
    finally:
        conn.close()


def get_honeypot_events(limit=200, db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM honeypot_events ORDER BY event_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_honeypot_event_count(db_path=DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM honeypot_events").fetchone()
        return row["c"] if row else 0
    finally:
        conn.close()
