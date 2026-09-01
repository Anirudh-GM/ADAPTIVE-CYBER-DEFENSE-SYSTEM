"""
ACDS v2.1 Final Integration Test Suite
Verifies the complete end-to-end security decision support lifecycle:
Scanner -> Finding -> Deduplication -> Priority -> Remediation -> Attack Path -> Honeypot
-> Adaptive Risk -> Defense Optimization -> Model Mutation -> Re-Simulation -> Risk Reduction.
"""

import pytest
import networkx as nx

from acds.core.graph import build_network, build_synthetic_sme_network
from acds.vulnerability.deduplication import deduplicate_findings, calculate_deduplication_metrics
from acds.vulnerability.prioritization import prioritize_findings, get_top_priority_findings
from acds.vulnerability.lifecycle import FindingStatus, update_finding_lifecycle
from acds.simulation.attack_engine import simulate_attack
from acds.honeypot.behavior import extract_attacker_behavior
from acds.adaptive.feedback import compute_adaptive_feedback_signals
from acds.vulnerability.blast_radius import calculate_risk, calculate_overall_acds_risk
from acds.defense.actions import get_defense_actions, apply_defense_actions
from acds.defense.optimizer import greedy_defense_selection
from acds.simulation.comparison import compare_simulations


def test_complete_v21_security_intelligence_pipeline():
    # 1. Build Network with real vulnerability and exposure profiles
    G = build_network()
    assert len(G.nodes) == 7

    # 2. Extract Raw Findings
    raw_findings = []
    ctx_map = {}
    for node, data in G.nodes(data=True):
        ctx_map[node] = {
            'id': node,
            'ip': data.get('ip', ''),
            'display_name': data.get('display_name', node),
            'hostname': data.get('hostname', ''),
            'criticality': data.get('criticality', 2),
            'criticality_label': data.get('criticality_label', 'LOW'),
            'network_exposure': data.get('risk_components', {}).get('network_exposure', {}).get('normalized_score', 30.0),
            'isolated': data.get('isolated', False),
        }
        for c in data.get('cve_findings', []):
            rf = dict(c)
            rf['asset_id'] = node
            rf['host'] = data.get('display_name', node)
            rf['ip'] = data.get('ip', '')
            raw_findings.append(rf)

    assert len(raw_findings) > 0

    # 3. Deduplication Engine (VulnEx)
    dedup = deduplicate_findings(raw_findings, asset_context_map=ctx_map)
    assert dedup.raw_findings_count >= dedup.unique_vulnerabilities_count
    metrics = calculate_deduplication_metrics(dedup.raw_findings_count, dedup.unique_vulnerabilities_count)
    assert metrics['raw_findings'] == dedup.raw_findings_count
    assert metrics['unique_findings'] == dedup.unique_vulnerabilities_count

    # 4. Contextual Prioritization (Pre-simulation)
    prioritized_pre = prioritize_findings(dedup.definitions)
    assert len(prioritized_pre) > 0
    top_pre = get_top_priority_findings(prioritized_pre, limit=3)
    assert len(top_pre) > 0
    assert top_pre[0]['priority_level'] in ('P1', 'P2', 'P3')

    # 5. Baseline Attack Simulation
    timeline_pre, comp_pre, hp_pre, stats_pre = simulate_attack(
        G, entry_node="User-PC", seed=100, ids_deployed=False, segmentation_applied=False
    )
    risk_pre, blast_pre = calculate_risk(G, comp_pre, timeline_pre, hp_pre, stats_pre)
    overall_pre = calculate_overall_acds_risk(G, risk_pre)
    assert risk_pre > 0.0
    assert overall_pre['overall_score'] > 0.0

    # 6. Attack Path Escalation on Prioritization
    # Finding on compromised node or reachable route gets escalated
    prioritized_with_path = prioritize_findings(dedup.definitions, attack_path_nodes=comp_pre)
    assert len(prioritized_with_path) > 0

    # 7. Adaptive Honeypot Telemetry (Triggered Scenario)
    timeline_hp, comp_hp, hp_sprung, stats_hp = simulate_attack(
        G, entry_node="Server", seed=42, ids_deployed=False, segmentation_applied=False
    )
    risk_hp, blast_hp = calculate_risk(G, comp_hp, timeline_hp, hp_sprung, stats_hp)

    adaptive_multipliers = {}
    if hp_sprung:
        hp_obs = stats_hp.get("honeypot_observations", [])
        assert len(hp_obs) > 0
        profiles = extract_attacker_behavior(hp_obs)
        signals = compute_adaptive_feedback_signals(G, profiles)
        adaptive_multipliers = {n: d["defense_multiplier"] for n, d in signals.get("affected_nodes", {}).items()}
        assert len(adaptive_multipliers) > 0
        assert all(m >= 1.0 for m in adaptive_multipliers.values())

    # 8. Defense Optimization Consuming Prioritized Findings
    candidates = get_defense_actions(
        G, comp_pre, risk_pre, adaptive_multipliers=adaptive_multipliers, prioritized_vulnerabilities=prioritized_with_path
    )
    assert len(candidates) > 0
    selected, total_red, remaining = greedy_defense_selection(candidates, budget=60)
    assert len(selected) > 0

    # 9. Model Mutation & Lifecycle Transition
    applied, ids_dep, seg_app = apply_defense_actions(G, selected)
    assert len(applied) > 0

    # Update lifecycle state of patched definitions
    for act in applied:
        if act['type'] == 'patch':
            for vdef in dedup.definitions.values():
                if vdef.product in act['action'].lower():
                    update_finding_lifecycle(vdef, FindingStatus.PATCHED, reason="Patch applied in model")
                    assert vdef.remediation_status == FindingStatus.PATCHED.value

    # 10. Re-Simulation After Defense Application
    timeline_post, comp_post, hp_post, stats_post = simulate_attack(
        G, entry_node="User-PC", seed=100, ids_deployed=ids_dep, segmentation_applied=seg_app
    )
    risk_post, blast_post = calculate_risk(G, comp_post, timeline_post, hp_post, stats_post)

    # 11. Comparison & Measurable Risk Reduction
    comparison = compare_simulations(
        risk_pre, risk_post, blast_pre, blast_post, budget_used=60 - remaining, applied_actions=applied
    )
    assert comparison.risk_reduction_pct >= 0.0
    assert comparison.systems_compromised_after <= comparison.systems_compromised_before
