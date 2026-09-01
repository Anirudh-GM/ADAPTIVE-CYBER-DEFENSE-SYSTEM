"""
Unit tests for ACDS SQLite Persistence Engine.
"""

import os
import tempfile
import pytest
from acds.core.graph import build_network
from acds.persistence.database import init_database, get_db_connection
from acds.persistence.repositories import ScanRepository, SimulationRepository


@pytest.fixture
def temp_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    yield tmp.name
    try:
        os.unlink(tmp.name)
    except OSError:
        pass


def test_init_database(temp_db):
    init_database(temp_db)
    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cursor.fetchall()]
    conn.close()

    assert "scan_sessions" in tables
    assert "assets" in tables
    assert "vulnerabilities" in tables
    assert "simulation_runs" in tables
    assert "applied_defenses" in tables


def test_save_and_retrieve_scan(temp_db):
    repo = ScanRepository(temp_db)
    G = build_network()

    scan_id = repo.save_scan_session(G, scan_type="Simulated Lab", base_ip="192.168.1.")
    assert scan_id > 0

    recent = repo.get_recent_scans()
    assert len(recent) == 1
    assert recent[0]["scan_type"] == "Simulated Lab"
    assert recent[0]["asset_count"] == len(G.nodes)


def test_save_and_retrieve_simulation(temp_db):
    repo = SimulationRepository(temp_db)
    sim_id = repo.save_simulation_run(
        entry_node="User-PC",
        seed=42,
        risk_score=68.5,
        blast_details={"spread": 50.0, "critical_impact": 60.0, "depth": 40.0, "systems_controlled": 3},
        honeypot_triggered=False,
        ids_deployed=True,
        segmentation_applied=False,
        applied_defenses=[{"action": "Patch Server", "node": "Server", "type": "patch", "cost": 20, "risk_reduction": 15.0, "efficiency": 0.75}],
    )
    assert sim_id > 0

    recent = repo.get_recent_simulations()
    assert len(recent) == 1
    assert recent[0]["entry_node"] == "User-PC"
    assert recent[0]["risk_score"] == 68.5
