"""
Unit tests for Finding Lifecycle State Transitions.
"""

import pytest
from acds.vulnerability.deduplication import deduplicate_findings
from acds.vulnerability.lifecycle import (
    FindingStatus,
    update_finding_lifecycle,
)


def test_finding_lifecycle_transitions():
    raw_findings = [
        {'cve_id': 'CVE-2021-41773', 'cvss': 7.5, 'product': 'Apache', 'version': '2.4.49', 'port': 80, 'asset_id': 'srv1'},
    ]
    dedup = deduplicate_findings(raw_findings)
    vdef = list(dedup.definitions.values())[0]

    assert vdef.remediation_status == FindingStatus.ACTIVE.value

    # Transition to MITIGATION_RECOMMENDED
    t1 = update_finding_lifecycle(vdef, FindingStatus.MITIGATION_RECOMMENDED, reason="Knapsack recommended patch")
    assert vdef.remediation_status == FindingStatus.MITIGATION_RECOMMENDED.value
    assert vdef.affected_assets['srv1'].status == FindingStatus.MITIGATION_RECOMMENDED.value
    assert t1.previous_status == FindingStatus.ACTIVE

    # Transition to PATCHED upon defense application
    t2 = update_finding_lifecycle(vdef, FindingStatus.PATCHED, reason="Patch applied in model")
    assert vdef.remediation_status == FindingStatus.PATCHED.value
    assert t2.previous_status == FindingStatus.MITIGATION_RECOMMENDED

    # Transition to RESOLVED upon rescan
    t3 = update_finding_lifecycle(vdef, FindingStatus.RESOLVED, reason="Confirmed resolved in re-scan")
    assert vdef.remediation_status == FindingStatus.RESOLVED.value
