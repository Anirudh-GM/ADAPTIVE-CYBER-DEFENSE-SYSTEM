"""
ACDS Attack Simulation, Propagation Table & Risk Validation Regression Tests
───────────────────────────────────────────────────────────────────────────
Validates:
1. Timeline & Decision Log schema mapping (no fabricated defaults).
2. Successful modeled propagation event handling.
3. Failed/resisted modeled propagation attempt handling.
4. Explicitly blocked events (host isolation & VLAN segmentation).
5. Missing optional fields handling without fake fallbacks.
6. Empty timeline / edge cases.
7. Initial foothold isolation (not counted as lateral propagation).
8. Single-host environment (0 lateral hops, 100% scoped blast radius).
9. Multi-host blast-radius calculation with and without lateral reach.
10. Criticality inference and low-confidence handling.
11. Consistency across simulation outputs, dashboard metrics, and report generators.
12. Completed 0-event simulation vs unrun simulation state handling.
"""

import unittest
import networkx as nx
from app import (
    simulate_decision_based_propagation,
    simulate_attack,
    calculate_risk,
    calculate_overall_acds_risk,
    build_executive_report_text,
    calculate_criticality,
    calculate_criticality_score,
    build_dynamic_graph,
)


class TestAttackSimulationRegression(unittest.TestCase):

    def setUp(self):
        """Set up test graphs for single-host and multi-host scenarios."""
        # Single-host scenario (e.g. Kali target 192.168.93.129)
        self.single_host_graph = nx.DiGraph()
        self.single_host_graph.add_node(
            "192.168.93.129",
            ip="192.168.93.129",
            display_name="kali-linux (Linux Web Server)",
            asset_id="ASSET-KALI-001",
            services=["SSH", "HTTP"],
            open_ports=[22, 80],
            vulnerability=0.3,
            criticality=3,
            node_type="endpoint",
            role="Server",
            isolated=False,
            risk_score=14.1,
            cve_findings=[]
        )

        # Multi-host scenario (Web server -> DB server -> Workstation)
        self.multi_host_graph = nx.DiGraph()
        self.multi_host_graph.add_node(
            "HostA",
            ip="192.168.1.10",
            display_name="Web Server (HostA)",
            asset_id="ASSET-WEB-001",
            services=["HTTP", "SSH"],
            open_ports=[80, 22],
            vulnerability=0.7,
            criticality=3,
            node_type="endpoint",
            role="DMZ",
            isolated=False,
            risk_score=55.0,
            cve_findings=[{"cve_id": "CVE-2023-38606", "cvss": 7.5}]
        )
        self.multi_host_graph.add_node(
            "HostB",
            ip="192.168.1.20",
            display_name="Database Server (HostB)",
            asset_id="ASSET-DB-002",
            services=["MySQL"],
            open_ports=[3306],
            vulnerability=0.8,
            criticality=5,
            node_type="server",
            role="Database",
            isolated=False,
            risk_score=78.0,
            cve_findings=[{"cve_id": "CVE-2021-27928", "cvss": 9.8}]
        )
        self.multi_host_graph.add_node(
            "HostC",
            ip="192.168.1.30",
            display_name="Admin Workstation (HostC)",
            asset_id="ASSET-WS-003",
            services=["RDP"],
            open_ports=[3389],
            vulnerability=0.4,
            criticality=2,
            node_type="endpoint",
            role="Workstation",
            isolated=False,
            risk_score=35.0,
            cve_findings=[]
        )
        self.multi_host_graph.add_edge("HostA", "HostB", service="MySQL", port=3306, mitre_code="T1210")
        self.multi_host_graph.add_edge("HostB", "HostC", service="RDP", port=3389, mitre_code="T1021")

    def test_1_timeline_and_decision_log_valid_fields(self):
        """Case 1: Validate timeline and decision log schema contains valid data."""
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.multi_host_graph, "HostA", seed=42
        )
        self.assertGreater(len(timeline), 0)
        self.assertGreater(len(decision_log), 0)

        for entry in timeline:
            self.assertIn("node", entry)
            self.assertIn("timestep", entry)
            self.assertIn("mitre_code", entry)
            self.assertIn("success", entry)
            self.assertIsInstance(entry["success"], bool)

        for d in decision_log:
            self.assertIn("step", d)
            self.assertIn("source", d)
            self.assertIn("target", d)
            self.assertIn("decision", d)
            self.assertIn("probability", d)
            self.assertIn("reason", d)
            # Ensure no literal string 'None' as technique or status
            self.assertNotEqual(d["decision"], "None")
            self.assertNotEqual(d["probability"], "None")

    def test_2_successful_modeled_propagation(self):
        """Case 2: Validate successful modeled lateral propagation from HostA to HostB."""
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.multi_host_graph, "HostA", seed=42
        )
        self.assertIn("HostB", compromised)
        self.assertGreater(stats["max_lateral_hops"], 0)
        succ_entries = [d for d in decision_log if d["decision"] == "✓ COMPROMISE POSSIBLE" and d["step"] > 1]
        self.assertGreater(len(succ_entries), 0)
        succ_targets = {d["target"] for d in succ_entries}
        self.assertIn("Database Server (HostB)", succ_targets)

    def test_3_failed_modeled_propagation(self):
        """Case 3: Validate failed/resisted propagation when vulnerability/access is low."""
        G = nx.DiGraph()
        G.add_node("Host1", ip="10.0.0.1", display_name="Host 1", asset_id="A1",
                   services=["HTTP"], open_ports=[80], vulnerability=0.1, criticality=1, node_type="endpoint", role="A")
        G.add_node("Host2", ip="10.0.0.2", display_name="Host 2", asset_id="A2",
                   services=["Custom"], open_ports=[9999], vulnerability=0.05, criticality=1, node_type="endpoint", role="B")
        G.add_edge("Host1", "Host2", service="Custom", port=9999)

        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            G, "Host1", seed=42
        )
        self.assertNotIn("Host2", compromised)
        uncomp_decisions = [d for d in decision_log if not d["is_compromised"] and d["step"] > 1]
        self.assertGreater(len(uncomp_decisions), 0)
        self.assertIn("COMPROMISE NOT POSSIBLE", uncomp_decisions[0]["decision"])

    def test_4_explicitly_blocked_by_defense(self):
        """Case 4: Validate blocked events for isolated host and VLAN segmentation."""
        # Test 4a: Isolated target host
        self.multi_host_graph.nodes["HostB"]["isolated"] = True
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.multi_host_graph, "HostA", seed=42
        )
        self.assertNotIn("HostB", compromised)
        blocked_log = [d for d in decision_log if d["decision"] == "🛡 BLOCKED"]
        self.assertGreater(len(blocked_log), 0)
        self.assertIn("isolation", blocked_log[0]["reason"].lower())

        # Test 4b: VLAN segmentation
        self.multi_host_graph.nodes["HostB"]["isolated"] = False
        timeline2, decision_log2, compromised2, uncomp2, succ2, blk2, stats2 = simulate_decision_based_propagation(
            self.multi_host_graph, "HostA", seed=42, segmentation_applied=True
        )
        self.assertNotIn("HostB", compromised2)
        seg_blocked = [d for d in decision_log2 if d["decision"] == "🛡 BLOCKED"]
        self.assertGreater(len(seg_blocked), 0)
        self.assertIn("segmentation", seg_blocked[0]["reason"].lower())

    def test_5_missing_optional_fields_no_fabricated_defaults(self):
        """Case 5: Minimal graph node with no services or CVEs produces no fake defaults."""
        G = nx.DiGraph()
        G.add_node("BareNode", ip="10.0.0.99", criticality=1)
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            G, "BareNode", seed=42
        )
        self.assertEqual(len(decision_log), 1)
        first = decision_log[0]
        # Should not fabricate fake TCP/T1021
        self.assertEqual(first["source"], "EXTERNAL ATTACKER")
        self.assertIn("BareNode", first["target"])

    def test_6_empty_graph_and_missing_entry(self):
        """Case 6: Empty graph or missing entry point handles gracefully."""
        G = nx.DiGraph()
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            G, "NonExistent", seed=42
        )
        self.assertEqual(timeline, [])
        self.assertEqual(decision_log, [])
        self.assertEqual(len(compromised), 0)

    def test_7_initial_entry_not_counted_as_lateral_propagation(self):
        """Case 7: Initial foothold is marked step 1 and lateral hops is 0 if no neighbors reached."""
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.single_host_graph, "192.168.93.129", seed=42
        )
        self.assertEqual(stats["max_lateral_hops"], 0)
        self.assertEqual(len(compromised), 1)
        self.assertEqual(decision_log[0]["step"], 1)
        self.assertEqual(decision_log[0]["source"], "EXTERNAL ATTACKER")
        # Lateral events should be empty
        lateral_events = [d for d in decision_log if d["step"] > 1]
        self.assertEqual(len(lateral_events), 0)

    def test_8_single_host_environment_metrics(self):
        """Case 8: Single-host environment calculation and blast radius justification."""
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.single_host_graph, "192.168.93.129", seed=42
        )
        risk_score, blast_det = calculate_risk(
            self.single_host_graph, compromised, timeline, honeypot_triggered=False, attack_stats=stats
        )
        # In a 1-host scope where the 1 host is entry point, spread=100%, critical_impact=100%, depth=100% -> 100.0
        self.assertEqual(blast_det["spread"], 100.0)
        self.assertEqual(blast_det["max_lateral_hops"], 0)
        self.assertEqual(blast_det["systems_controlled"], 1)
        self.assertEqual(blast_det["total_real_nodes"], 1)

    def test_9_blast_radius_multi_host_scaling(self):
        """Case 9: Blast radius with partial vs full compromise."""
        # 1. Partial compromise (1 of 3 hosts)
        risk_partial, blast_partial = calculate_risk(
            self.multi_host_graph, {"HostA"},
            [{"timestep": 1}], honeypot_triggered=False,
            attack_stats={"systems_controlled": 1, "max_lateral_hops": 0, "critical_assets_reached": 0}
        )
        self.assertAlmostEqual(blast_partial["spread"], 33.3, places=1)
        self.assertLess(risk_partial, 100.0)

        # 2. Full compromise (3 of 3 hosts)
        risk_full, blast_full = calculate_risk(
            self.multi_host_graph, {"HostA", "HostB", "HostC"},
            [{"timestep": 1}, {"timestep": 2}, {"timestep": 3}], honeypot_triggered=False,
            attack_stats={"systems_controlled": 3, "max_lateral_hops": 2, "critical_assets_reached": 1}
        )
        self.assertEqual(blast_full["spread"], 100.0)
        self.assertGreater(risk_full, risk_partial)

    def test_10_low_confidence_criticality_classification(self):
        """Case 10: Inferred criticality properly classifies based on evidence."""
        res_ws = calculate_criticality("Windows Workstation", [], [445], "windows")
        res_db = calculate_criticality("Database Server", ["MySQL"], [3306], "linux")
        self.assertEqual(res_ws['level'], 3)
        self.assertEqual(res_db['level'], 5)
        score_ws = calculate_criticality_score(res_ws['level'])
        score_db = calculate_criticality_score(res_db['level'])
        self.assertLess(score_ws['score'], score_db['score'])

    def test_11_dashboard_and_report_consistency(self):
        """Case 11: Text report metrics match blast details and overall risk."""
        timeline, decision_log, compromised, uncomp, succ, blk, stats = simulate_decision_based_propagation(
            self.single_host_graph, "192.168.93.129", seed=42
        )
        risk_score, blast_det = calculate_risk(
            self.single_host_graph, compromised, timeline, honeypot_triggered=False, attack_stats=stats
        )
        overall = calculate_overall_acds_risk(self.single_host_graph, risk_score)

        report_text = build_executive_report_text(self.single_host_graph, risk_score, blast_det, overall, [])
        self.assertIn("100.0% of scoped assets", report_text)
        self.assertIn("0 lateral hop(s)", report_text)
        self.assertIn("Contained to initial foothold", report_text)
        self.assertIn(str(overall["overall_score"]), report_text)

    def test_12_simulation_not_run_vs_zero_events(self):
        """Case 12: Distinguish unrun simulation from completed 0-lateral-event simulation."""
        # Unrun simulation: blast_details is empty
        unrun_report = build_executive_report_text(self.single_host_graph, None, {}, None, [])
        self.assertIn("Simulation Status: Not run in this session", unrun_report)
        self.assertIn("Attack Depth & Blast Radius: N/A", unrun_report)

        # Completed simulation: blast_details has max_lateral_hops=0
        blast_det_zero = {
            "spread": 100.0, "critical_impact": 100.0, "depth": 100.0,
            "compromised_count": 1, "total_real_nodes": 1,
            "systems_controlled": 1, "max_lateral_hops": 0, "critical_assets_reached": 0
        }
        completed_report = build_executive_report_text(
            self.single_host_graph, 100.0, blast_det_zero, {"overall_score": 50.6, "status": "ELEVATED"}, []
        )
        self.assertIn("Simulation Status: Completed", completed_report)
        self.assertIn("Lateral Attack Depth: 0 lateral hop(s)", completed_report)


if __name__ == '__main__':
    unittest.main()
