"""
Unit tests for ACDS CVE Lookup & Vulnerability Matching Engine.
"""

import pytest
from acds.vulnerability.cve import (
    cvss_severity_label,
    split_product_version,
    comparable_version,
    cpe_matches_product,
    lookup_cves_offline,
    get_real_cves,
    detection_confidence_label,
)


def test_cvss_severity_labels():
    assert cvss_severity_label(9.8) == "Critical"
    assert cvss_severity_label(7.5) == "High"
    assert cvss_severity_label(5.3) == "Medium"
    assert cvss_severity_label(2.1) == "Low"
    assert cvss_severity_label(None) == "Unknown"


def test_split_product_version():
    prod, ver = split_product_version("OpenSSH_7.2p2 Ubuntu-4ubuntu2.8")
    assert prod == "openssh"
    assert ver == "7.2p2"

    prod, ver = split_product_version("Apache/2.4.49 (Unix)")
    assert prod == "apache"
    assert ver == "2.4.49"

    prod, ver = split_product_version("vsftpd 2.3.4")
    assert prod == "vsftpd"
    assert ver == "2.3.4"


def test_comparable_version():
    assert comparable_version("2.4.49") < comparable_version("2.4.51")
    assert comparable_version("7.2") == comparable_version("7.2")


def test_offline_cve_fallback():
    cves = lookup_cves_offline("vsftpd 2.3.4")
    assert len(cves) > 0
    assert cves[0]['id'] == "CVE-2011-2523"
    assert cves[0]['cvss'] == 9.8

    cves_apache = lookup_cves_offline("Apache 2.4.49")
    assert len(cves_apache) > 0
    assert cves_apache[0]['id'] == "CVE-2021-41773"


def test_get_real_cves_offline_fallback():
    cves, source = get_real_cves("FTP", "vsftpd 2.3.4")
    assert len(cves) > 0
    assert source in ("nvd_live", "offline_table")


def test_detection_confidence_label():
    assert "High" in detection_confidence_label("nvd_live", True)
    assert "Medium" in detection_confidence_label("offline_table", True)
    assert "N/A" in detection_confidence_label("none", False)
