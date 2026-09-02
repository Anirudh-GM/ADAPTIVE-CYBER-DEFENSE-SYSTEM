"""
Tests for ACDS Adaptive Contextual Risk Scoring Engine
Validates that environmental context (Internet exposure, criticality, isolation, honeypot telemetry)
modifies operational risk for identical base CVSS scores.
"""

import pytest
from acds.vulnerability.adaptive_risk import calculate_adaptive_contextual_risk


def test_identical_cvss_produces_different_contextual_risks():
    """
    Verify the signature ACDS principle:
    Identical base CVSS 8.2 produces higher risk on public web server vs internal dev machine.
    """
    # Case A: Public Web Server (Internet-exposed, Criticality 4)
    public_web = calculate_adaptive_contextual_risk(
        base_cvss=8.2,
        asset_criticality=4,
        is_internet_exposed=True,
        is_segmented=False,
        is_isolated=False,
        has_sensitive_ports=False,
    )

    # Case B: Internal Development Machine (LAN only, Criticality 3)
    internal_dev = calculate_adaptive_contextual_risk(
        base_cvss=8.2,
        asset_criticality=3,
        is_internet_exposed=False,
        is_segmented=False,
        is_isolated=False,
        has_sensitive_ports=False,
    )

    # Case C: Isolated Host (Defense applied)
    isolated_host = calculate_adaptive_contextual_risk(
        base_cvss=8.2,
        asset_criticality=4,
        is_internet_exposed=False,
        is_segmented=False,
        is_isolated=True,
        has_sensitive_ports=False,
    )

    assert public_web["contextual_risk_score"] > internal_dev["contextual_risk_score"]
    assert internal_dev["contextual_risk_score"] > isolated_host["contextual_risk_score"]

    assert public_web["multipliers"]["exposure"] == 1.25
    assert internal_dev["multipliers"]["exposure"] == 1.00
    assert isolated_host["multipliers"]["exposure"] == 0.50


def test_honeypot_deception_elevates_risk():
    """Verify that adversary activity near an adjacent honeypot trap elevates contextual risk."""
    normal_risk = calculate_adaptive_contextual_risk(
        base_cvss=7.5,
        asset_criticality=4,
        honeypot_adjacent=False,
    )
    alert_risk = calculate_adaptive_contextual_risk(
        base_cvss=7.5,
        asset_criticality=4,
        honeypot_adjacent=True,
    )

    assert alert_risk["contextual_risk_score"] > normal_risk["contextual_risk_score"]
    assert alert_risk["multipliers"]["honeypot"] == 1.35
