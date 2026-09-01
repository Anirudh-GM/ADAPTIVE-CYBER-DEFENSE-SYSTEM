"""
ACDS Live Demonstration Script:
Network Discovery -> Vulnerability Intelligence (Deduplication + Contextual Prioritization)
-> Simulation -> Honeypot Feedback -> Defense Optimization -> Re-simulation
"""

from acds.core.graph import build_network
from acds.honeypot.behavior import extract_attacker_behavior
from acds.adaptive.feedback import compute_adaptive_feedback_signals
from acds.simulation.attack_engine import simulate_attack
from acds.vulnerability.blast_radius import calculate_risk, calculate_overall_acds_risk
from acds.vulnerability.deduplication import deduplicate_findings
from acds.vulnerability.prioritization import prioritize_findings, get_top_priority_findings
from acds.defense.actions import get_defense_actions, apply_defense_actions
from acds.defense.optimizer import greedy_defense_selection
from acds.simulation.comparison import compare_simulations


def run_full_demo(entry_point="User-PC", seed=100, budget=80):
    print("\n" + "=" * 70)
    print(f"  ACDS v2.1 PIPELINE DEMO (Entry: {entry_point}, Seed: {seed}, Budget: {budget})")
    print("=" * 70)

    G = build_network()

    # 1. Vulnerability Normalization & Deduplication
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
    print(f"\n[1] Vulnerability Intelligence Layer (VulnEx Architecture):")
    print(f"    - Raw Findings Discovered: {dedup_res.raw_findings_count}")
    print(f"    - Unique Logical Vulnerabilities: {dedup_res.unique_vulnerabilities_count}")
    print(f"    - Duplicates Removed: {dedup_res.duplicates_removed_count} ({dedup_res.deduplication_rate_pct}% deduplication rate)")

    # 2. Contextual Prioritization
    prioritized_vdefs = prioritize_findings(dedup_res.definitions)
    top_5 = get_top_priority_findings(prioritized_vdefs, limit=5)
    print(f"\n[2] Top Contextual Remediation Targets (Severity, Attack Path & Criticality):")
    for i, t in enumerate(top_5, 1):
        assets_str = ", ".join(t['affected_assets'])
        print(f"    {i}. {t['cve_id']:<14} | {t['priority_level']:<2} (Score: {t['priority_score']:>4.1f}) | Host: {assets_str:<12} | Rec: {t['recommendation']}")

    # 3. Baseline Simulation
    timeline_pre, comp_pre, hp_pre, stats_pre = simulate_attack(
        G, entry_node=entry_point, seed=seed, ids_deployed=False, segmentation_applied=False
    )
    risk_pre, blast_pre = calculate_risk(G, comp_pre, timeline_pre, hp_pre, stats_pre)

    print(f"\n[3] Baseline Attack Simulation:")
    print(f"    - Compromised Assets ({len(comp_pre)}): {list(comp_pre)}")
    print(f"    - Honeypot Decoy Trap Sprung: {hp_pre}")
    print(f"    - Network Blast Radius: Spread={blast_pre['spread']}%, Critical Impact={blast_pre['critical_impact']}%, Depth={blast_pre['depth']}%")
    print(f"    - Pre-Defense Risk Score: {risk_pre}/100")

    # 4. Honeypot Behavioral Feedback
    adaptive_multipliers = {}
    if hp_pre:
        hp_obs = stats_pre.get("honeypot_observations", [])
        profiles = extract_attacker_behavior(hp_obs)
        signals = compute_adaptive_feedback_signals(G, profiles)
        adaptive_multipliers = {n: d["defense_multiplier"] for n, d in signals.get("affected_nodes", {}).items()}
        print(f"\n[4] Adaptive Honeypot Behavioral Telemetry:")
        print(f"    - Adversary Probed Protocols: {signals['targeted_services']}")
        print(f"    - Assets in Adversary's Path: {list(signals['affected_nodes'].keys())}")
        print(f"    - Defense Priority Multiplier (1.35x) applied to targeted nodes.")

    # 5. Defense Knapsack Optimization (Consumes Prioritized Vulnerabilities)
    print(f"\n[5] Defense Knapsack Optimization (Budget: {budget} units):")
    candidates = get_defense_actions(
        G, comp_pre, risk_pre, adaptive_multipliers=adaptive_multipliers, prioritized_vulnerabilities=prioritized_vdefs
    )
    selected, total_red, remaining = greedy_defense_selection(candidates, budget=budget)

    for i, act in enumerate(selected, 1):
        print(f"    {i}. {act['action']:<40} | Cost: {act['cost']:>2} | Est. Red: {act['risk_reduction']:>4.1f} | Eff: {act['efficiency']:.2f}")
    print(f"    => Budget Used: {budget - remaining} / {budget} units")

    # 6. Model Mutation & Re-Simulation
    applied, ids_dep, seg_app = apply_defense_actions(G, selected)
    timeline_post, comp_post, hp_post, stats_post = simulate_attack(
        G, entry_node=entry_point, seed=seed, ids_deployed=ids_dep, segmentation_applied=seg_app
    )
    risk_post, blast_post = calculate_risk(G, comp_post, timeline_post, hp_post, stats_post)

    # 7. Comparison
    comp = compare_simulations(risk_pre, risk_post, blast_pre, blast_post, budget_used=budget - remaining, applied_actions=applied)

    print("\n" + "=" * 70)
    print("                    BEFORE VS AFTER VERIFICATION")
    print("=" * 70)
    print(f"  Metric                      | BEFORE           | AFTER")
    print(f"  ----------------------------+------------------+------------------")
    print(f"  Simulated Risk Score        | {risk_pre:>5.1f} / 100    | {risk_post:>5.1f} / 100")
    print(f"  Compromised Systems         | {comp.systems_compromised_before:>5} nodes      | {comp.systems_compromised_after:>5} nodes")
    print(f"  Critical Assets Reached     | {comp.critical_reached_before:>5} assets     | {comp.critical_reached_after:>5} assets")
    print(f"  Max Lateral Hops (Depth)    | {comp.max_depth_before:>5} hops       | {comp.max_depth_after:>5} hops")
    print(f"  Calculated Risk Reduction   |       —          | {comp.risk_reduction_pct:>5.1f}% REDUCTION")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_full_demo(entry_point="User-PC", seed=100, budget=80)
