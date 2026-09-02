"""
ACDS v2.1 Live Demonstration Script:
Demonstrates the complete ACDS Core Engine v1 Pipeline:
Discover -> Understand -> Assess -> Prioritize -> Predict -> Defend -> Explain -> Report
"""

from acds.core.graph import build_network
from acds.inventory.tracker import AssetInventoryTracker
from acds.surface.analyzer import analyze_attack_surface
from acds.vulnerability.adaptive_risk import calculate_adaptive_contextual_risk
from acds.vulnerability.deduplication import deduplicate_findings
from acds.vulnerability.prioritization import prioritize_findings, get_top_priority_findings
from acds.posture.scorer import calculate_security_posture
from acds.analysis.attack_paths import analyze_attack_paths
from acds.analysis.mitre import correlate_mitre_techniques
from acds.defense.recommendations import generate_sme_recommendations
from acds.honeypot.behavior import extract_attacker_behavior
from acds.adaptive.feedback import compute_adaptive_feedback_signals
from acds.simulation.attack_engine import simulate_attack
from acds.vulnerability.blast_radius import calculate_risk
from acds.defense.actions import get_defense_actions, apply_defense_actions
from acds.defense.optimizer import greedy_defense_selection
from acds.simulation.comparison import compare_simulations


def run_full_demo(entry_point="User-PC", seed=100, budget=80):
    print("\n" + "=" * 76)
    print(f"  ACDS v2.1 CORE ENGINE v1 DEMO (Entry: {entry_point}, Seed: {seed}, Budget: {budget})")
    print("=" * 76)

    G = build_network()

    # ── 1. CONTINUOUS ASSET INVENTORY ─────────────────────────────────────
    tracker = AssetInventoryTracker()
    inventory = tracker.update_from_graph(G)
    inv_summary = tracker.get_summary()

    print(f"\n[1] Continuous Asset Inventory Tracker:")
    print(f"    - Total Tracked Assets: {inv_summary['total_assets']} ({inv_summary['new_assets']} New, {inv_summary['active_assets']} Active, {inv_summary['missing_assets']} Missing)")
    print(f"    - Criticality 4-Star/5-Star Assets: {inv_summary['critical_assets']} | Mean Asset Risk: {inv_summary['average_risk']:.1f}/100")
    for row in tracker.to_inventory_table()[:4]:
        print(f"      * {row['IP']:<15} | {row['Hostname']:<15} | {row['Type']:<18} | Risk: {row['Risk']:>4.1f} | Status: {row['Status']}")

    # ── 2. ATTACK SURFACE MANAGEMENT ──────────────────────────────────────
    surface = analyze_attack_surface(G)
    surf_metrics = surface["metrics"]
    print(f"\n[2] Attack Surface Management & Exposure Hierarchy:")
    print(f"    - Exposed Assets: {surf_metrics['exposed_assets']} / {surf_metrics['total_assets']} ({surf_metrics['attack_surface_ratio'] * 100:.0f}% Exposure Ratio)")
    print(f"    - Open Services: {surf_metrics['open_services_count']} (Internet-Facing: {surf_metrics['internet_facing_count']}, Database: {surf_metrics['database_services_count']}, High-Risk: {surf_metrics['high_risk_services_count']})")
    print(f"    - Vulnerable Services: {surf_metrics['vulnerable_services_count']} | Critical Exposures: {surf_metrics['critical_exposure_count']}")

    # ── 3. ADAPTIVE CONTEXTUAL RISK ENGINE ────────────────────────────────
    web_risk = calculate_adaptive_contextual_risk(8.2, asset_criticality=4, is_internet_exposed=True)
    dev_risk = calculate_adaptive_contextual_risk(8.2, asset_criticality=3, is_internet_exposed=False)
    print(f"\n[3] Adaptive Contextual Risk Engine (Environmental Placement Impact):")
    print(f"    - Public Web Server (CVSS 8.2 + Internet Facing): Risk = {web_risk['contextual_risk_score']:.1f} ({web_risk['severity']})")
    print(f"    - Internal Dev PC  (CVSS 8.2 + Internal Only):    Risk = {dev_risk['contextual_risk_score']:.1f} ({dev_risk['severity']})")

    # ── 4. VULNERABILITY DEDUPLICATION & PRIORITIZATION ───────────────────
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

    dedup_res = deduplicate_findings(raw_findings, asset_context_map=ctx_map)
    prioritized_vdefs = prioritize_findings(dedup_res.definitions)
    top_4 = get_top_priority_findings(prioritized_vdefs, limit=4)

    print(f"\n[4] Vulnerability Intelligence & Prioritization (VulnEx 6-Component):")
    print(f"    - Deduplication: {dedup_res.raw_findings_count} Raw Findings -> {dedup_res.unique_vulnerabilities_count} Unique ({dedup_res.deduplication_rate_pct}% dedup rate)")
    for i, t in enumerate(top_4, 1):
        assets_str = ", ".join(t['affected_assets'])
        print(f"      {i}. {t['cve_id']:<14} | {t['priority_level']:<2} (Score: {t['priority_score']:>4.1f}) | Host: {assets_str:<10} | Fix: {t['recommendation'][:55]}")

    # ── 5. SECURITY POSTURE SCORE ─────────────────────────────────────────
    posture = calculate_security_posture(G, prioritized_findings=prioritized_vdefs)
    print(f"\n[5] Organization Security Posture Scorer:")
    print(f"    - Overall Posture: {posture.overall_score:.1f} / 100 [{posture.rating_label}]")
    for pillar, p_data in posture.pillar_breakdown.items():
        print(f"      * {pillar:<28}: {p_data['score']:>4.1f} / 100 ({p_data['status']}) - {p_data['detail']}")

    # ── 6. ANALYTICAL ATTACK PATH ENGINE (Passive Reachability) ───────────
    attack_paths = analyze_attack_paths(G, entry_node=entry_point)
    print(f"\n[6] Risk-Based Analytical Attack Path Analyzer (Passive Structural):")
    print(f"    - Paths Identified to Crown Jewels: {len(attack_paths)}")
    if attack_paths:
        top_p = attack_paths[0]
        chain_str = " -> ".join(top_p.nodes)
        print(f"      * Most Critical Path: {chain_str} (Hops: {top_p.hop_count}, Feasibility: {top_p.path_feasibility_score:.1f}/100)")
        print(f"      * Why: {top_p.why_explanation}")
        print(f"      * Choke Point Countermeasure: {top_p.recommended_choke_point}")

    # ── 7. MITRE ATT&CK CONTEXTUAL CORRELATION ────────────────────────────
    mitre_findings = correlate_mitre_techniques(G)
    print(f"\n[7] Contextual MITRE ATT&CK Mapping (Observed Services):")
    for f in mitre_findings[:3]:
        print(f"      * {f.technique_id} ({f.technique_name}) on {f.affected_host} [{f.risk_level}]: {f.recommended_countermeasure}")

    # ── 8. SME DEFENSE RECOMMENDATIONS ────────────────────────────────────
    sme_recs = generate_sme_recommendations(G, prioritized_findings=prioritized_vdefs, limit=3)
    print(f"\n[8] SME-Readable Action Recommendations:")
    for rec in sme_recs:
        print(f"      [{rec.priority_tier}] {rec.title}: {rec.recommended_action}")
        print(f"          Reason: {rec.technical_reason}")
        print(f"          Business Impact: {rec.business_impact}")

    # ── 9. BASELINE SIMULATION & KNAPSACK OPTIMIZATION ────────────────────
    timeline_pre, comp_pre, hp_pre, stats_pre = simulate_attack(G, entry_node=entry_point, seed=seed)
    risk_pre, blast_pre = calculate_risk(G, comp_pre, timeline_pre, hp_pre, stats_pre)

    candidates = get_defense_actions(G, comp_pre, risk_pre, prioritized_vulnerabilities=prioritized_vdefs)
    selected, total_red, remaining = greedy_defense_selection(candidates, budget=budget)
    applied, ids_dep, seg_app = apply_defense_actions(G, selected)

    timeline_post, comp_post, hp_post, stats_post = simulate_attack(
        G, entry_node=entry_point, seed=seed, ids_deployed=ids_dep, segmentation_applied=seg_app
    )
    risk_post, blast_post = calculate_risk(G, comp_post, timeline_post, hp_post, stats_post)
    comp = compare_simulations(risk_pre, risk_post, blast_pre, blast_post, budget_used=budget - remaining, applied_actions=applied)

    print("\n" + "=" * 76)
    print("                    BEFORE VS AFTER VERIFICATION")
    print("=" * 76)
    print(f"  Metric                      | BEFORE           | AFTER")
    print(f"  ----------------------------+------------------+------------------")
    print(f"  Simulated Risk Score        | {risk_pre:>5.1f} / 100    | {risk_post:>5.1f} / 100")
    print(f"  Compromised Systems         | {comp.systems_compromised_before:>5} nodes      | {comp.systems_compromised_after:>5} nodes")
    print(f"  Critical Assets Reached     | {comp.critical_reached_before:>5} assets     | {comp.critical_reached_after:>5} assets")
    print(f"  Max Lateral Hops (Depth)    | {comp.max_depth_before:>5} hops       | {comp.max_depth_after:>5} hops")
    print(f"  Calculated Risk Reduction   |       --         | {comp.risk_reduction_pct:>5.1f}% REDUCTION")
    print("=" * 76 + "\n")

    # ── 10. REAL-TIME CONTINUOUS MONITORING & ALERT DISPATCH CYCLE ────────
    from acds.monitoring.monitor import ContinuousMonitoringEngine

    print("\n" + "=" * 76)
    print("  [10] REAL-TIME CONTINUOUS MONITORING & ALERT DISPATCH CYCLE")
    print("=" * 76)

    monitor = ContinuousMonitoringEngine()
    
    # Cycle 1: Baseline Network Snapshot
    cycle1 = monitor.run_single_cycle(network_graph=G, custom_timestamp="2026-09-02 12:00:00 UTC")
    print(f"\n[*] Cycle 1 Baseline Snapshot Saved:")
    print(f"    - Tracked Assets: {cycle1.asset_count} | Overall Risk: {cycle1.recalculation.new_overall_risk:.1f}/100 | Posture: {cycle1.recalculation.new_posture_score:.1f}/100")

    # Cycle 2: Network Mutation Event (Rogue device joins and Server opens Port 445)
    G_mutated = G.copy()
    G_mutated.add_node(
        "192.168.1.99",
        ip="192.168.1.99",
        display_name="Rogue-Laptop",
        device_type="Workstation",
        criticality=3,
        risk_score=68.0,
        open_ports=[445, 135],
        services=["SMB", "RPC"],
        cve_findings=[],
    )
    # Mutate Server ports
    if "Server" in G_mutated:
        G_mutated.nodes["Server"]["open_ports"] = [80, 22, 445]
        G_mutated.nodes["Server"]["services"] = ["HTTP", "SSH", "SMB"]
        G_mutated.nodes["Server"]["risk_score"] = 88.5

    cycle2 = monitor.run_single_cycle(network_graph=G_mutated, custom_timestamp="2026-09-02 12:05:00 UTC")
    print(f"\n[*] Cycle 2 Mutation Detected & Real-Time Re-Assessment:")
    print(f"    - Added Devices: {len(cycle2.diff.new_devices)} ({cycle2.diff.new_devices[0]['hostname']})")
    print(f"    - Risk Shift: {cycle2.recalculation.previous_overall_risk:.1f} -> {cycle2.recalculation.new_overall_risk:.1f} ({'+' if cycle2.recalculation.risk_delta > 0 else ''}{cycle2.recalculation.risk_delta} pts)")
    print(f"    - Real-Time Alerts Generated ({len(cycle2.alerts)}):")
    for alt in cycle2.alerts[:4]:
        print(f"      * [{alt.severity}] {alt.title}: {alt.description}")
        print(f"        -> Action: {alt.suggested_action}")
    print(f"    - Recalculated Optimal Defenses ({len(cycle2.recalculation.recommended_defense_actions)} actions, Budget Used: {cycle2.recalculation.defense_budget_used}):")
    for act in cycle2.recalculation.recommended_defense_actions[:3]:
        print(f"      * {act['action']} (Cost: {act['cost']}, Eff: {act['efficiency']:.2f})")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    run_full_demo(entry_point="User-PC", seed=100, budget=80)
