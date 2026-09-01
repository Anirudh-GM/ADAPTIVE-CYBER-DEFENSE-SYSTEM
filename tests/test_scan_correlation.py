"""
Unit tests for Scan-to-Scan Vulnerability Correlation in SQLite.
"""

import os
import tempfile
import pytest
from acds.persistence.database import init_database
from acds.persistence.repositories import VulnerabilityRepository
from acds.vulnerability.deduplication import deduplicate_findings
from acds.vulnerability.prioritization import prioritize_findings


@pytest.fixture
def temp_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    yield tmp.name
    try:
        os.unlink(tmp.name)
    except OSError:
        pass


def test_scan_to_scan_recurrence_increment(temp_db):
    init_database(temp_db)
    repo = VulnerabilityRepository(temp_db)

    raw_scan1 = [
        {'cve_id': 'CVE-2021-41773', 'cvss': 7.5, 'product': 'Apache', 'version': '2.4.49', 'port': 80, 'asset_id': 'srv1'},
    ]
    dedup1 = deduplicate_findings(raw_scan1)
    prio1 = prioritize_findings(dedup1.definitions)

    # Save Scan 1
    repo.save_vulnerability_definitions(prio1, scan_id=1)

    stored1 = repo.get_all_vulnerabilities()
    assert len(stored1) == 1
    assert stored1[0]['total_occurrences'] == 1

    # Save Scan 2 with the same vulnerability
    raw_scan2 = [
        {'cve_id': 'CVE-2021-41773', 'cvss': 7.5, 'product': 'Apache', 'version': '2.4.49', 'port': 80, 'asset_id': 'srv1'},
    ]
    dedup2 = deduplicate_findings(raw_scan2)
    prio2 = prioritize_findings(dedup2.definitions)

    repo.save_vulnerability_definitions(prio2, scan_id=2)

    stored2 = repo.get_all_vulnerabilities()
    assert len(stored2) == 1
    # Occurrence count incremented
    assert stored2[0]['total_occurrences'] == 2
