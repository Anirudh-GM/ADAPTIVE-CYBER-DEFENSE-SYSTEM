"""
Unit tests for ACDS 5-Component Asset Risk Model.
"""

import pytest
from acds.vulnerability.risk import (
    calculate_asset_risk,
    calculate_vulnerability_score,
    calculate_service_exposure_score,
    calculate_sensitive_service_score,
    calculate_criticality_score,
    calculate_network_exposure_score,
    severity_from_score,
    recompute_node_risk,
)


def test_severity_thresholds():
    assert severity_from_score(95.0) == "CRITICAL"
    assert severity_from_score(85.0) == "CRITICAL"
    assert severity_from_score(75.0) == "HIGH"
    assert severity_from_score(65.0) == "HIGH"
    assert severity_from_score(45.0) == "MEDIUM"
    assert severity_from_score(35.0) == "MEDIUM"
    assert severity_from_score(20.0) == "LOW"
    assert severity_from_score(0.0) == "LOW"


def test_vulnerability_score_calculation():
    # Empty CVEs
    assert calculate_vulnerability_score([]) == 0.0

    # Max CVSS 9.8 -> 98.0
    cves = [{'cvss': 9.8}, {'cvss': 5.0}]
    assert calculate_vulnerability_score(cves) == 98.0


def test_service_exposure_score():
    assert calculate_service_exposure_score(0) == 0.0
    assert calculate_service_exposure_score(5) == 50.0
    assert calculate_service_exposure_score(10) == 100.0
    assert calculate_service_exposure_score(20) == 100.0  # Capped


def test_sensitive_service_score():
    score, detected = calculate_sensitive_service_score([22, 80])
    assert score == 0.0
    assert len(detected) == 0

    score, detected = calculate_sensitive_service_score([3306, 21, 3389, 445])
    assert score == 100.0
    assert len(detected) == 4


def test_5_component_asset_risk_formula():
    # Test formula: 40% vuln + 20% exposure + 15% sensitive + 15% crit + 10% network
    result = calculate_asset_risk(
        vulnerability_norm=100.0,
        service_exposure_norm=100.0,
        sensitive_services_norm=100.0,
        criticality_norm=100.0,
        network_exposure_norm=100.0,
    )
    assert result['score'] == 100.0
    assert result['severity'] == "CRITICAL"
    assert result['components']['vulnerability']['contribution'] == 40.0
    assert result['components']['service_exposure']['contribution'] == 20.0
    assert result['components']['sensitive_services']['contribution'] == 15.0
    assert result['components']['criticality']['contribution'] == 15.0
    assert result['components']['network_exposure']['contribution'] == 10.0


def test_recompute_node_risk():
    node_data = {
        'risk_components': {
            'vulnerability': {'normalized_score': 0.0, 'weight': 0.40, 'contribution': 0.0},
            'service_exposure': {'normalized_score': 50.0, 'weight': 0.20, 'contribution': 10.0},
            'sensitive_services': {'normalized_score': 0.0, 'weight': 0.15, 'contribution': 0.0},
            'criticality': {'normalized_score': 0.0, 'weight': 0.15, 'contribution': 0.0},
            'network_exposure': {'normalized_score': 0.0, 'weight': 0.10, 'contribution': 0.0},
        }
    }
    score = recompute_node_risk(node_data)
    assert score == 10.0
    assert node_data['risk_severity'] == "LOW"
    assert node_data['vulnerability'] == 0.10
