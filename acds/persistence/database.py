"""
ACDS Zero-Dependency SQLite Database Engine
Manages local SQLite database schemas, migrations, and connections for persisting
network assets, scans, vulnerability findings, simulation runs, and defense histories.
"""

import os
import sqlite3
from typing import Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "acds_storage.db")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Get a SQLite database connection with row factory enabled."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: Optional[str] = None) -> None:
    """Initialize SQLite database tables if they do not already exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS scan_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_type TEXT NOT NULL,
        base_ip TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        asset_count INTEGER DEFAULT 0,
        average_risk REAL DEFAULT 0.0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        ip TEXT NOT NULL,
        hostname TEXT,
        display_name TEXT,
        mac TEXT,
        mac_vendor TEXT,
        os TEXT,
        os_confidence REAL,
        device_type TEXT,
        device_confidence REAL,
        role TEXT,
        criticality INTEGER,
        criticality_label TEXT,
        risk_score REAL,
        risk_severity TEXT,
        open_ports TEXT,
        services TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scan_sessions (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER,
        ip TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        cvss REAL,
        severity TEXT,
        service TEXT,
        port INTEGER,
        summary TEXT,
        source TEXT,
        detection_confidence TEXT,
        FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS simulation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entry_node TEXT NOT NULL,
        seed INTEGER,
        risk_score REAL,
        blast_spread REAL,
        blast_critical_impact REAL,
        blast_depth REAL,
        systems_controlled INTEGER,
        critical_assets_reached INTEGER,
        max_lateral_hops INTEGER,
        honeypot_triggered BOOLEAN,
        ids_deployed BOOLEAN,
        segmentation_applied BOOLEAN,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS applied_defenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        simulation_id INTEGER,
        action_name TEXT NOT NULL,
        target_node TEXT NOT NULL,
        action_type TEXT NOT NULL,
        cost INTEGER,
        risk_reduction REAL,
        efficiency REAL,
        FOREIGN KEY (simulation_id) REFERENCES simulation_runs (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS experiment_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_name TEXT NOT NULL,
        network_size INTEGER,
        num_simulations INTEGER,
        mean_risk REAL,
        mean_blast_spread REAL,
        mean_depth REAL,
        critical_compromise_rate REAL,
        mean_risk_reduction_pct REAL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vulnerability_definitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        definition_id TEXT UNIQUE NOT NULL,
        cve_id TEXT NOT NULL,
        product TEXT,
        vendor TEXT,
        version TEXT,
        cvss REAL,
        severity TEXT,
        description TEXT,
        source TEXT,
        is_cve BOOLEAN,
        priority_score REAL DEFAULT 0.0,
        priority_level TEXT DEFAULT 'P4',
        remediation_status TEXT DEFAULT 'ACTIVE',
        total_occurrences INTEGER DEFAULT 1,
        first_seen TEXT,
        last_seen TEXT
    );

    CREATE TABLE IF NOT EXISTS asset_vulnerability_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        definition_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        host TEXT NOT NULL,
        ip TEXT NOT NULL,
        ports TEXT,
        services TEXT,
        criticality INTEGER,
        network_exposure REAL,
        is_isolated BOOLEAN,
        on_attack_path BOOLEAN,
        occurrence_count INTEGER DEFAULT 1,
        status TEXT DEFAULT 'ACTIVE',
        first_seen TEXT,
        last_seen TEXT,
        FOREIGN KEY (definition_id) REFERENCES vulnerability_definitions (definition_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS finding_occurrences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        definition_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        scan_id INTEGER,
        observed_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()
