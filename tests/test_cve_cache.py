"""
Tests for ACDS SQLite CVE Caching
Validates that CVE lookups are cached locally in SQLite to prevent redundant network calls.
"""

import os
import tempfile
import pytest
from acds.persistence.repositories import CveCacheRepository
from acds.vulnerability.cve import lookup_cves_nvd


def test_sqlite_cve_cache_set_and_get():
    """Verify caching CVE list in SQLite and retrieving within TTL."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        repo = CveCacheRepository(db_path=db_path)
        assert repo.get_cached_cves("apache 2.4.49") is None

        dummy_cves = [
            {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "Critical", "summary": "Path traversal and RCE"}
        ]
        repo.set_cached_cves("apache 2.4.49", dummy_cves, source="test_cache", ttl_hours=24)

        cached = repo.get_cached_cves("apache 2.4.49")
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["id"] == "CVE-2021-41773"
    finally:
        try:
            if os.path.exists(db_path):
                os.unlink(db_path)
        except Exception:
            pass

