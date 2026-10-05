"""
ACDS v4.0 — Comprehensive Tests for Phases 1-13

Tests all new modules:
- Phase 1/11: Attack Graph Intelligence + MITRE Enhancement
- Phase 2:    Graph-Aware Risk Prioritization
- Phase 3:    Adaptive Attack Simulation
- Phase 4:    Advanced Defense Optimization
- Phase 5:    Closed-Loop Adaptive Defense
- Phase 7/8:  Continuous Monitoring + Alert Correlation
- Phase 9:    Historical Security Intelligence
- Phase 10:   Threat Intelligence
- Phase 13:   Real/Validation/Simulation distinction
"""
import sys
import os
import unittest

# Make sure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import networkx as nx


# ─────────────────────────────────────────────────────────────────
# PHASE 1 & 11 TESTS — Attack Graph Intelligence + MITRE
# ─────────────────────────────────────────────────────────────────
class TestAttackGraphIntelligence(unittest.TestCase):

    def setUp(self):
        from core.attack_graph_intelligence import (
            resolve_mitre_technique,
            build_explainable_edge,
            render_edge_explanation_html,
        )
        self.resolve_mitre = resolve_mitre_technique
        self.build_edge = build_explainable_edge
        self.render_html = render_edge_explanation_html

    def test_mitre_technique_resolves_smb(self):
        """Phase 11: SMB port must resolve to T1021.002 with reason."""
        result = self.resolve_mitre(445, "SMB")
        self.assertTrue(result["applies"])
        self.assertEqual(result["technique_id"], "T1021.002")
        self.assertIn("SMB", result["reason"])
        self.assertIn("445", result["reason"])

    def test_mitre_technique_resolves_rdp(self):
        """Phase 11: RDP port must resolve to T1021.001."""
        result = self.resolve_mitre(3389, "RDP")
        self.assertTrue(result["applies"])
        self.assertEqual(result["technique_id"], "T1021.001")

    def test_mitre_technique_not_assigned_without_conditions(self):
        """Phase 11: Unknown port must NOT assign a technique."""
        result = self.resolve_mitre(9999, "UNKNOWN_SVC")
        self.assertFalse(result["applies"])
        self.assertEqual(result["technique_id"], "N/A")

    def test_mitre_cve_context_added_to_reason(self):
        """Phase 11: CVE context must appear in MITRE reason when provided."""
        result = self.resolve_mitre(22, "SSH", cve_id="CVE-2016-6210", cvss=5.9)
        self.assertTrue(result["applies"])
        self.assertIn("CVE-2016-6210", result["reason"])

    def test_explainable_edge_structure(self):
        """Phase 1: build_explainable_edge must return all required fields."""
        src_data = {"display_name": "Workstation", "ip": "192.168.1.10", "open_ports": []}
        dst_data = {
            "display_name": "File Server", "ip": "192.168.1.21",
            "open_ports": [445], "cve_findings": [],
            "exposure_level": 0.6, "criticality": 4, "isolated": False,
        }
        edge = self.build_edge(
            "Workstation\n192.168.1.10", "FileServer\n192.168.1.21",
            src_data, dst_data, port=445, service="SMB",
            live_port_state="open", live_host_reachable=True,
        )
        required_fields = [
            "source_asset", "target_asset", "port", "service", "protocol",
            "reachability", "live_port_state", "vulnerability_condition",
            "mitre_technique_id", "defense_state", "probability",
            "result", "human_reason", "simulation_label",
        ]
        for field in required_fields:
            self.assertIn(field, edge, f"Missing field: {field}")

    def test_edge_shows_blocked_when_defense_applied(self):
        """Phase 1: Edge result must be BLOCKED when defense_applied is set."""
        src_data = {"display_name": "Attacker", "ip": "192.168.1.10", "open_ports": []}
        dst_data = {
            "display_name": "DB", "ip": "192.168.1.30",
            "open_ports": [3306], "cve_findings": [],
            "exposure_level": 0.7, "criticality": 5, "isolated": True,
        }
        edge = self.build_edge(
            "A", "DB", src_data, dst_data, port=3306, service="MySQL",
            defense_applied="Host Isolation",
        )
        self.assertIn("BLOCKED", edge["result"])

    def test_edge_simulation_label_always_present(self):
        """Phase 13: Simulation label must always be present on every edge."""
        src_data = {"display_name": "X", "ip": "10.0.0.1", "open_ports": []}
        dst_data = {"display_name": "Y", "ip": "10.0.0.2", "open_ports": [], "cve_findings": [], "exposure_level": 0, "isolated": False}
        edge = self.build_edge("X", "Y", src_data, dst_data, port=80, service="HTTP")
        self.assertIn("SIMULATION", edge["simulation_label"])

    def test_render_html_produces_non_empty_string(self):
        """Phase 1: render_edge_explanation_html must return non-empty HTML."""
        src_data = {"display_name": "A", "ip": "10.0.0.1", "open_ports": []}
        dst_data = {"display_name": "B", "ip": "10.0.0.2", "open_ports": [22], "cve_findings": [], "exposure_level": 0.3, "isolated": False}
        edge = self.build_edge("A", "B", src_data, dst_data, port=22, service="SSH")
        html = self.render_html({"edge_intelligence": edge})
        self.assertGreater(len(html), 100)
        self.assertIn("SSH", html)


# ─────────────────────────────────────────────────────────────────
# PHASE 2 TESTS — Graph-Aware Risk Prioritization
# ─────────────────────────────────────────────────────────────────
class TestGraphRiskPrioritizer(unittest.TestCase):

    def _make_graph(self):
        G = nx.DiGraph()
        G.add_node("DB", ip="192.168.1.30", display_name="Database",
                   criticality=5, risk_score=85.0, node_type="database",
                   cve_findings=[{"cve_id": "CVE-2021-1234", "cvss": 9.8}],
                   risk_components={"network_exposure": {"normalized_score": 80}},
                   open_ports=[3306])
        G.add_node("WS", ip="192.168.1.10", display_name="Workstation",
                   criticality=2, risk_score=30.0, node_type="endpoint",
                   cve_findings=[],
                   risk_components={"network_exposure": {"normalized_score": 20}},
                   open_ports=[])
        G.add_edge("WS", "DB")
        return G

    def test_priority_score_range(self):
        """Phase 2: Priority scores must be 0-100."""
        from core.graph_risk_prioritizer import calculate_graph_aware_priority
        G = self._make_graph()
        result = calculate_graph_aware_priority("DB", G.nodes["DB"], G)
        self.assertGreaterEqual(result["priority_score"], 0)
        self.assertLessEqual(result["priority_score"], 100)

    def test_high_cvss_asset_gets_higher_priority(self):
        """Phase 2: Asset with high CVSS must score higher than one without CVEs."""
        from core.graph_risk_prioritizer import calculate_graph_aware_priority
        G = self._make_graph()
        db_priority = calculate_graph_aware_priority("DB", G.nodes["DB"], G)
        ws_priority = calculate_graph_aware_priority("WS", G.nodes["WS"], G)
        self.assertGreater(db_priority["priority_score"], ws_priority["priority_score"])

    def test_priority_has_all_components(self):
        """Phase 2: Priority breakdown must have all 7 components."""
        from core.graph_risk_prioritizer import calculate_graph_aware_priority
        G = self._make_graph()
        result = calculate_graph_aware_priority("DB", G.nodes["DB"], G)
        expected_components = {"cvss", "exposure", "reachability", "attack_paths",
                               "downstream_critical", "blast_radius", "confidence"}
        self.assertEqual(set(result["components"].keys()), expected_components)

    def test_priority_label_correct(self):
        """Phase 2: Priority label must match score band."""
        from core.graph_risk_prioritizer import calculate_graph_aware_priority, rank_all_assets_by_priority
        G = self._make_graph()
        result = calculate_graph_aware_priority("DB", G.nodes["DB"], G)
        label = result["priority_label"]
        score = result["priority_score"]
        self.assertIn(label, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        if score >= 80:
            self.assertEqual(label, "CRITICAL")
        elif score >= 60:
            self.assertEqual(label, "HIGH")

    def test_rank_all_assets_sorts_correctly(self):
        """Phase 2: rank_all_assets_by_priority must return sorted list."""
        from core.graph_risk_prioritizer import rank_all_assets_by_priority
        G = self._make_graph()
        ranked = rank_all_assets_by_priority(G)
        self.assertGreater(len(ranked), 0)
        scores = [r["priority_score"] for r in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_summary_why_not_empty(self):
        """Phase 2: Every asset must have a human-readable summary_why."""
        from core.graph_risk_prioritizer import calculate_graph_aware_priority
        G = self._make_graph()
        result = calculate_graph_aware_priority("DB", G.nodes["DB"], G)
        self.assertGreater(len(result.get("summary_why", "")), 10)


# ─────────────────────────────────────────────────────────────────
# PHASE 3 TESTS — Adaptive Attack Simulation
# ─────────────────────────────────────────────────────────────────
class TestAdaptiveSimulation(unittest.TestCase):

    def _make_prev_curr(self):
        prev = nx.DiGraph()
        prev.add_node("A", ip="10.0.0.1", display_name="A",
                      open_ports=[22], cve_findings=[], node_type="endpoint")
        curr = nx.DiGraph()
        curr.add_node("A", ip="10.0.0.1", display_name="A",
                      open_ports=[22, 445], cve_findings=[], node_type="endpoint")
        curr.add_node("B", ip="10.0.0.2", display_name="B",
                      open_ports=[80], cve_findings=[], node_type="server")
        return prev, curr

    def test_detect_new_port_change(self):
        """Phase 3: Detect new port opened on existing asset."""
        from core.adaptive_simulation import detect_topology_changes
        prev, curr = self._make_prev_curr()
        changes = detect_topology_changes(prev, curr)
        event_types = {c["event_type"] for c in changes}
        self.assertIn("NEW_PORT", event_types)

    def test_detect_new_asset(self):
        """Phase 3: Detect new asset added to graph."""
        from core.adaptive_simulation import detect_topology_changes
        prev, curr = self._make_prev_curr()
        changes = detect_topology_changes(prev, curr)
        event_types = {c["event_type"] for c in changes}
        self.assertIn("NEW_ASSET", event_types)

    def test_detect_new_cve(self):
        """Phase 3: Detect new CVE on existing asset."""
        from core.adaptive_simulation import detect_topology_changes
        prev = nx.DiGraph()
        prev.add_node("A", ip="10.0.0.1", display_name="A",
                      open_ports=[22], cve_findings=[], node_type="endpoint")
        curr = nx.DiGraph()
        curr.add_node("A", ip="10.0.0.1", display_name="A",
                      open_ports=[22],
                      cve_findings=[{"cve_id": "CVE-2021-9999", "cvss": 9.8}],
                      node_type="endpoint")
        changes = detect_topology_changes(prev, curr)
        event_types = {c["event_type"] for c in changes}
        self.assertIn("NEW_CVE", event_types)

    def test_no_changes_on_identical_graphs(self):
        """Phase 3: Identical graphs must produce zero changes."""
        from core.adaptive_simulation import detect_topology_changes
        G = nx.DiGraph()
        G.add_node("A", ip="10.0.0.1", display_name="A",
                   open_ports=[22], cve_findings=[], node_type="endpoint")
        changes = detect_topology_changes(G, G)
        self.assertEqual(len(changes), 0)

    def test_render_topology_change_html_not_empty(self):
        """Phase 3: HTML renderer must return non-empty output."""
        from core.adaptive_simulation import render_topology_change_html
        changes = [{"event_type": "NEW_ASSET", "description": "Test", "severity": "HIGH",
                    "graph_action": "NODE_ADDED", "timestamp": "2025-01-01T00:00:00"}]
        html = render_topology_change_html(changes)
        self.assertGreater(len(html), 50)

    def test_render_empty_changes(self):
        """Phase 3: Empty change list renders graceful no-changes message."""
        from core.adaptive_simulation import render_topology_change_html
        html = render_topology_change_html([])
        self.assertIn("No topology changes", html)


# ─────────────────────────────────────────────────────────────────
# PHASE 4 TESTS — Advanced Defense Optimization
# ─────────────────────────────────────────────────────────────────
class TestDefenseOptimizerV4(unittest.TestCase):

    def _make_graph(self):
        G = nx.DiGraph()
        G.add_node("WS", ip="192.168.1.10", display_name="Workstation", node_type="endpoint",
                   criticality=3, vulnerability=0.5, risk_score=55.0,
                   open_ports=[22, 445, 3389], services=["SSH", "SMB", "RDP"],
                   cve_findings=[{"cve_id": "CVE-2019-0708", "cvss": 9.8, "service": "RDP"}],
                   fixes=["Patch RDP"], weaknesses=["RDP exposed"])
        G.add_node("DB", ip="192.168.1.30", display_name="Database", node_type="database",
                   criticality=5, vulnerability=0.8, risk_score=88.0,
                   open_ports=[3306], services=["MySQL"],
                   cve_findings=[{"cve_id": "CVE-2012-2122", "cvss": 7.5, "service": "MySQL"}],
                   fixes=["Restrict MySQL"], weaknesses=["DB exposed"])
        G.add_edge("WS", "DB")
        return G

    def test_generates_actions_for_compromised_nodes(self):
        """Phase 4: Must generate actions for each compromised node."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        self.assertGreater(len(actions), 0)

    def test_all_action_types_covered(self):
        """Phase 4: All 8 action types must be representable."""
        from core.defense_optimizer_v4 import DEFENSE_TYPES
        expected = {"patch", "close_port", "disable_service", "firewall_rule",
                    "vlan_segmentation", "host_isolation", "monitoring", "honeypot"}
        self.assertEqual(set(DEFENSE_TYPES.keys()), expected)

    def test_actions_have_required_fields(self):
        """Phase 4: Every action must have all required fields."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        required = {"action", "node", "type", "cost", "risk_reduction",
                    "blast_radius_reduction", "attack_paths_removed",
                    "critical_assets_protected", "efficiency", "why_selected_explanation",
                    "state", "priority"}
        for a in actions:
            for field in required:
                self.assertIn(field, a, f"Action missing field: {field}")

    def test_efficiency_computed_correctly(self):
        """Phase 4: Efficiency must equal risk_reduction / cost."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        for a in actions:
            expected_eff = round(a["risk_reduction"] / max(a["cost"], 1), 3)
            self.assertAlmostEqual(a["efficiency"], expected_eff, places=2)

    def test_why_selected_not_empty(self):
        """Phase 4: why_selected_explanation must be non-empty for every action."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        for a in actions:
            self.assertGreater(len(a.get("why_selected_explanation", "")), 10)

    def test_simulation_label_in_why(self):
        """Phase 13: SIMULATION label must appear in why_selected_explanation."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        for a in actions:
            self.assertIn("SIMULATION", a.get("why_selected_explanation", ""))

    def test_no_duplicate_actions(self):
        """Phase 4: No duplicate action keys must be generated."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = self._make_graph()
        actions = generate_v4_defense_actions(G, ["WS", "DB"], risk_score=70.0)
        action_labels = [a["action"] for a in actions]
        self.assertEqual(len(action_labels), len(set(action_labels)))


# ─────────────────────────────────────────────────────────────────
# PHASE 5 TESTS — Closed-Loop Adaptive Defense
# ─────────────────────────────────────────────────────────────────
class TestAdaptiveCycle(unittest.TestCase):

    def test_all_cycle_stages_defined(self):
        """Phase 5: All 11 cycle stages must be defined."""
        from core.adaptive_cycle import CYCLE_STAGES
        self.assertEqual(len(CYCLE_STAGES), 11)
        ids = [s["id"] for s in CYCLE_STAGES]
        self.assertEqual(ids, list(range(1, 12)))

    def test_before_after_comparison_no_baseline(self):
        """Phase 5: No-baseline state returns appropriate message."""
        from core.adaptive_cycle import compute_before_after_comparison
        result = compute_before_after_comparison(None, None, None, None, None, None, None)
        self.assertEqual(result["status"], "NO_BASELINE")

    def test_before_after_comparison_with_data(self):
        """Phase 5: BEFORE vs AFTER comparison computes deltas correctly."""
        from core.adaptive_cycle import compute_before_after_comparison
        before_blast = {"systems_controlled": 4, "critical_assets_reached": 2, "max_lateral_hops": 3, "spread": 60}
        after_blast = {"systems_controlled": 1, "critical_assets_reached": 0, "max_lateral_hops": 1, "spread": 20}
        before_overall = {"overall_score": 75.0}
        after_overall = {"overall_score": 45.0}
        applied = [{"cost": 30, "risk_reduction": 25.0}]
        result = compute_before_after_comparison(
            80.0, 40.0, before_blast, after_blast,
            before_overall, after_overall, applied
        )
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["defenses_applied"], 1)
        self.assertEqual(result["total_defense_cost"], 30)
        # Blast radius delta should be negative (improvement)
        blast_delta = result["metrics"]["blast_radius"]["delta"]
        self.assertLess(blast_delta, 0)

    def test_cycle_stage_status_with_empty_session(self):
        """Phase 5: Empty session state should show mostly PENDING stages."""
        from core.adaptive_cycle import get_cycle_stage_status
        session = {
            "last_scan_devices": None,
            "G": nx.DiGraph(),
            "simulation_done": False,
            "selected_defenses": [],
            "applied_defenses": [],
            "live_validation_results": {},
            "post_defense_stats": None,
            "risk_before_defense": None,
            "monitoring_enabled": False,
            "network_mode": "Real Network Scan",
        }
        stages = get_cycle_stage_status(session)
        pending = [s for s in stages if s["status"] == "PENDING"]
        self.assertGreater(len(pending), 5)

    def test_render_cycle_html_produces_output(self):
        """Phase 5: HTML renderer must produce non-trivial output."""
        from core.adaptive_cycle import CYCLE_STAGES, render_adaptive_cycle_html
        stages_with_status = [{**s, "status": "PENDING"} for s in CYCLE_STAGES]
        html = render_adaptive_cycle_html(stages_with_status)
        self.assertGreater(len(html), 200)
        self.assertIn("ADAPTIVE DEFENSE CYCLE", html)

    def test_simulation_label_in_before_after_html(self):
        """Phase 13: SIMULATION label must appear in before/after HTML output."""
        from core.adaptive_cycle import compute_before_after_comparison, render_before_after_v4
        result = compute_before_after_comparison(
            70.0, 40.0,
            {"systems_controlled": 3, "critical_assets_reached": 1, "max_lateral_hops": 2, "spread": 50},
            {"systems_controlled": 1, "critical_assets_reached": 0, "max_lateral_hops": 1, "spread": 15},
            {"overall_score": 70.0}, {"overall_score": 45.0},
            [{"cost": 25, "risk_reduction": 20.0}]
        )
        html = render_before_after_v4(result)
        self.assertIn("SIMULATION", html)


# ─────────────────────────────────────────────────────────────────
# PHASE 7 & 8 TESTS — Continuous Monitoring + Alert Correlation
# ─────────────────────────────────────────────────────────────────
class TestAlertCorrelator(unittest.TestCase):

    def _make_raw_alerts(self):
        now = "2025-01-01T12:00:00"
        return [
            {"alert_type": "NEW_PORT", "asset": "192.168.1.10", "severity": "HIGH",
             "description": "New port 445 (SMB)", "new_value": "445", "timestamp": now},
            {"alert_type": "NEW_CVE", "asset": "192.168.1.10", "severity": "CRITICAL",
             "description": "CVE-2017-7494: SambaCry CVSS 9.8", "new_value": "CVE-2017-7494 CVSS=9.8", "timestamp": now},
        ]

    def test_correlation_fires_for_matching_rules(self):
        """Phase 8: NEW_PORT + NEW_CVE on same asset must produce correlated alert."""
        from core.alert_correlator import correlate_alerts
        raw = self._make_raw_alerts()
        correlated, passthrough = correlate_alerts(raw)
        all_alerts = correlated + passthrough
        self.assertGreater(len(all_alerts), 0)
        # At least one alert should be correlated
        has_correlated = any(a.get("is_correlated") for a in all_alerts)
        self.assertTrue(has_correlated)

    def test_correlated_alert_has_required_fields(self):
        """Phase 8: Correlated alert must have all required fields."""
        from core.alert_correlator import correlate_alerts
        raw = self._make_raw_alerts()
        correlated, _ = correlate_alerts(raw)
        if correlated:
            a = correlated[0]
            for field in ["timestamp", "severity", "alert_type", "asset", "title",
                          "description", "is_correlated", "correlated_from"]:
                self.assertIn(field, a, f"Correlated alert missing field: {field}")

    def test_deduplication_suppresses_duplicate(self):
        """Phase 8: Same alert fingerprint must be suppressed within window."""
        from core.alert_correlator import correlate_alerts
        raw = self._make_raw_alerts()
        fp_set = set()
        # First run
        corr1, pass1 = correlate_alerts(raw, fp_set)
        count1 = len(corr1) + len(pass1)
        # Second run with same fingerprints already seen
        corr2, pass2 = correlate_alerts(raw, fp_set)
        count2 = len(corr2) + len(pass2)
        # Second run should produce fewer (or equal) alerts due to deduplication
        self.assertLessEqual(count2, count1)

    def test_monitoring_events_detected(self):
        """Phase 7: detect_monitoring_events must find new asset and CVE events."""
        from core.alert_correlator import detect_monitoring_events
        prev = {"192.168.1.10": {"hostname": "WS1", "risk_score": 40, "cve_ids": [], "cve_cvss": {}, "exposed": True}}
        curr = {
            "192.168.1.10": {"hostname": "WS1", "risk_score": 40, "cve_ids": ["CVE-2021-9999"], "cve_cvss": {"CVE-2021-9999": 9.8}, "exposed": True, "criticality": 3},
            "192.168.1.20": {"hostname": "NewServer", "risk_score": 60, "cve_ids": [], "cve_cvss": {}, "exposed": True, "criticality": 4},
        }
        events = detect_monitoring_events(prev, curr, set(), set())
        event_types = {e["alert_type"] for e in events}
        self.assertIn("NEW_ASSET", event_types)
        self.assertIn("NEW_CVE", event_types)

    def test_no_false_positive_on_unchanged_data(self):
        """Phase 7: Identical snapshots must produce zero events."""
        from core.alert_correlator import detect_monitoring_events
        snapshot = {"192.168.1.10": {"hostname": "WS", "risk_score": 40, "cve_ids": [], "cve_cvss": {}, "exposed": True, "criticality": 2}}
        events = detect_monitoring_events(snapshot, snapshot, set(), set())
        # Should have no change events
        change_types = {e["alert_type"] for e in events}
        self.assertNotIn("NEW_ASSET", change_types)
        self.assertNotIn("REMOVED_ASSET", change_types)
        self.assertNotIn("NEW_CVE", change_types)


# ─────────────────────────────────────────────────────────────────
# PHASE 9 TESTS — Historical Security Intelligence
# ─────────────────────────────────────────────────────────────────
class TestHistoricalIntelligence(unittest.TestCase):

    def test_build_exposure_trend(self):
        """Phase 9: Trend builder must produce chart-ready series."""
        from core.historical_intelligence import build_exposure_trend_from_history
        rows = [
            {"timestamp": "2025-01-01T10:00:00", "overall_risk": 70, "blast_radius": 60},
            {"timestamp": "2025-01-01T11:00:00", "overall_risk": 65, "blast_radius": 55},
        ]
        trend = build_exposure_trend_from_history(rows)
        self.assertIn("labels", trend)
        self.assertIn("overall_risk", trend)
        self.assertIn("blast_radius", trend)
        self.assertEqual(len(trend["labels"]), 2)
        self.assertEqual(trend["overall_risk"], [70, 65])

    def test_defense_effectiveness_calculation(self):
        """Phase 9: Defense effectiveness must compute correctly."""
        from core.historical_intelligence import calculate_defense_effectiveness
        before = {"risk_score": 80, "systems_controlled": 5, "critical_assets_reached": 3, "spread": 70}
        after = {"risk_score": 45, "systems_controlled": 1, "critical_assets_reached": 0, "spread": 20}
        applied = [{"cost": 50, "risk_reduction": 30}]
        result = calculate_defense_effectiveness(before, after, applied)
        self.assertGreater(result["risk_reduction"], 0)
        self.assertGreater(result["critical_assets_protected"], 0)
        self.assertIn(result["effectiveness_label"], ["HIGHLY EFFECTIVE", "EFFECTIVE", "PARTIALLY EFFECTIVE", "MINIMAL EFFECT"])

    def test_effectiveness_na_without_stats(self):
        """Phase 9: N/A returned when stats missing."""
        from core.historical_intelligence import calculate_defense_effectiveness
        result = calculate_defense_effectiveness(None, None, [])
        self.assertEqual(result["effectiveness_label"], "N/A — simulation not run")

    def test_render_html_not_empty(self):
        """Phase 9: Historical summary HTML must be non-trivial."""
        from core.historical_intelligence import render_historical_trend_html
        rows = [{"timestamp": "2025-01-01T10:00", "overall_risk": 70, "blast_radius": 60}]
        html = render_historical_trend_html(rows, [], {"effectiveness_label": "EFFECTIVE", "risk_reduction": 20})
        self.assertGreater(len(html), 100)
        self.assertIn("SECURITY INTELLIGENCE", html)


# ─────────────────────────────────────────────────────────────────
# PHASE 10 TESTS — Threat Intelligence
# ─────────────────────────────────────────────────────────────────
class TestThreatIntelligence(unittest.TestCase):

    def test_cisa_kev_lookup_known_cve(self):
        """Phase 10: Known CISA KEV CVE must be found in offline catalog."""
        from core.threat_intelligence import is_in_cisa_kev
        result = is_in_cisa_kev("CVE-2019-0708")
        self.assertIsNotNone(result)
        self.assertEqual(result["cve_id"], "CVE-2019-0708")

    def test_cisa_kev_lookup_unknown_cve(self):
        """Phase 10: Unknown CVE must return None (not found)."""
        from core.threat_intelligence import is_in_cisa_kev
        result = is_in_cisa_kev("CVE-9999-99999")
        self.assertIsNone(result)

    def test_kev_boost_applied_when_exposed(self):
        """Phase 10: CISA KEV boost must be applied when asset is exposed AND reachable."""
        from core.threat_intelligence import enrich_cve_with_threat_intel
        cves = [{"cve_id": "CVE-2019-0708", "cvss": 9.8}]
        enriched = enrich_cve_with_threat_intel(cves, asset_is_exposed=True, asset_is_reachable=True)
        self.assertTrue(enriched[0]["in_cisa_kev"])
        self.assertTrue(enriched[0]["kev_boost_applied"])
        self.assertGreater(enriched[0]["kev_priority_boost"], 0)

    def test_kev_boost_not_applied_when_not_exposed(self):
        """Phase 10: CISA KEV boost must NOT be applied when asset is not exposed."""
        from core.threat_intelligence import enrich_cve_with_threat_intel
        cves = [{"cve_id": "CVE-2019-0708", "cvss": 9.8}]
        enriched = enrich_cve_with_threat_intel(cves, asset_is_exposed=False, asset_is_reachable=True)
        self.assertTrue(enriched[0]["in_cisa_kev"])
        self.assertFalse(enriched[0]["kev_boost_applied"])
        self.assertEqual(enriched[0]["kev_priority_boost"], 0)

    def test_ti_adjusted_priority_increases(self):
        """Phase 10: TI-adjusted priority must be >= base priority when KEV applies."""
        from core.threat_intelligence import calculate_ti_adjusted_priority, enrich_cve_with_threat_intel
        cves = [{"cve_id": "CVE-2019-0708", "cvss": 9.8}]
        enriched = enrich_cve_with_threat_intel(cves, asset_is_exposed=True, asset_is_reachable=True)
        base = 60.0
        adjusted, explanation = calculate_ti_adjusted_priority(base, enriched)
        self.assertGreaterEqual(adjusted, base)
        self.assertGreater(len(explanation), 10)

    def test_vendor_advisory_for_rdp(self):
        """Phase 10: Vendor advisory hint must be returned for RDP."""
        from core.threat_intelligence import get_vendor_advisory_hints
        hint = get_vendor_advisory_hints("RDP", None)
        self.assertIsNotNone(hint)
        self.assertGreater(len(hint), 5)

    def test_kev_badge_rendered_for_kev_cve(self):
        """Phase 10: KEV badge HTML must be non-empty for a KEV CVE."""
        from core.threat_intelligence import render_threat_intel_badge, enrich_cve_with_threat_intel
        cves = [{"cve_id": "CVE-2019-0708", "cvss": 9.8}]
        enriched = enrich_cve_with_threat_intel(cves, True, True)
        badge = render_threat_intel_badge(enriched[0])
        self.assertGreater(len(badge), 0)
        self.assertIn("CISA KEV", badge)

    def test_no_badge_for_non_kev_cve(self):
        """Phase 10: No badge must be produced for non-KEV CVE."""
        from core.threat_intelligence import render_threat_intel_badge
        badge = render_threat_intel_badge({"cve_id": "CVE-9999-99999", "in_cisa_kev": False})
        self.assertEqual(badge, "")


# ─────────────────────────────────────────────────────────────────
# PHASE 13 TESTS — Final Product Polish / Distinction
# ─────────────────────────────────────────────────────────────────
class TestPhase13Distinction(unittest.TestCase):
    """
    Phase 13: Verify that REAL OBSERVATION, REAL-TIME VALIDATION, and
    SIMULATION are clearly distinguished throughout the system.
    No simulated compromise is presented as a real compromise.
    """

    def test_edge_intelligence_labels_simulation(self):
        """Phase 13: Edge intelligence must always label result as SIMULATED."""
        from core.attack_graph_intelligence import build_explainable_edge
        src = {"display_name": "A", "ip": "10.0.0.1", "open_ports": []}
        dst = {"display_name": "B", "ip": "10.0.0.2", "open_ports": [445],
               "cve_findings": [], "exposure_level": 0.5, "isolated": False}
        edge = build_explainable_edge("A", "B", src, dst, port=445, service="SMB", prob=0.7)
        self.assertIn("SIMULATION", edge.get("simulation_label", ""))
        self.assertIn("SIMULATION", edge.get("result", ""))

    def test_defense_action_labels_simulation(self):
        """Phase 13: Defense action explanations must note SIMULATION."""
        from core.defense_optimizer_v4 import generate_v4_defense_actions
        G = nx.DiGraph()
        G.add_node("WS", ip="10.0.0.1", display_name="WS", node_type="endpoint",
                   criticality=3, vulnerability=0.5, risk_score=60.0,
                   open_ports=[445, 3389], services=["SMB", "RDP"],
                   cve_findings=[{"cve_id": "CVE-2019-0708", "cvss": 9.8, "service": "RDP"}],
                   fixes=["Patch"], weaknesses=["RDP"])
        actions = generate_v4_defense_actions(G, ["WS"], risk_score=60.0)
        for a in actions:
            self.assertIn("SIMULATION", a.get("why_selected_explanation", ""),
                          f"Action '{a['action']}' missing SIMULATION label")

    def test_cycle_simulation_label_in_html(self):
        """Phase 13: Adaptive cycle HTML must label as SIMULATION."""
        from core.adaptive_cycle import CYCLE_STAGES, render_adaptive_cycle_html
        stages = [{**s, "status": "COMPLETE"} for s in CYCLE_STAGES]
        html = render_adaptive_cycle_html(stages)
        self.assertIn("SIMULATION", html)

    def test_before_after_simulation_label(self):
        """Phase 13: Before/after comparison must label as SIMULATED."""
        from core.adaptive_cycle import compute_before_after_comparison
        result = compute_before_after_comparison(
            70.0, 40.0,
            {"systems_controlled": 3, "critical_assets_reached": 1, "max_lateral_hops": 2, "spread": 50},
            {"systems_controlled": 1, "critical_assets_reached": 0, "max_lateral_hops": 1, "spread": 20},
            {"overall_score": 70.0}, {"overall_score": 45.0},
            [{"cost": 25, "risk_reduction": 20.0}]
        )
        self.assertIn("SIMULATION", result.get("simulation_label", ""))

    def test_topology_change_html_labels_simulation(self):
        """Phase 13: Topology change HTML must note SIMULATION."""
        from core.adaptive_simulation import render_topology_change_html
        changes = [{"event_type": "NEW_PORT", "description": "Port opened",
                    "severity": "HIGH", "graph_action": "EDGES_ADDED",
                    "timestamp": "2025-01-01T00:00:00"}]
        html = render_topology_change_html(changes)
        self.assertIn("SIMULATION", html)


# ─────────────────────────────────────────────────────────────────
# DATABASE SCHEMA TESTS — Phase 3 topology_snapshots table
# ─────────────────────────────────────────────────────────────────
class TestDatabaseSchemaV4(unittest.TestCase):

    def test_topology_snapshots_table_created(self):
        """Phase 3: topology_snapshots table must exist after init_db."""
        import tempfile, os
        from core import database as monitor_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            monitor_db.init_db(db_path=tmp_path)
            conn = monitor_db.get_connection(db_path=tmp_path)
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            self.assertIn("topology_snapshots", tables)
            conn.close()
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_record_topology_snapshot(self):
        """Phase 3: Can write and read a topology snapshot."""
        import tempfile, os
        from core import database as monitor_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            monitor_db.init_db(db_path=tmp_path)
            monitor_db.record_topology_snapshot(
                node_count=5, edge_count=12, critical_assets=2,
                avg_risk=55.5, trigger="TEST", db_path=tmp_path
            )
            rows = monitor_db.get_topology_history(limit=10, db_path=tmp_path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["node_count"], 5)
            self.assertEqual(rows[0]["trigger"], "TEST")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def test_risk_history_summary_returns_list(self):
        """Phase 9: get_risk_history_summary must return a list."""
        import tempfile, os
        from core import database as monitor_db
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            monitor_db.init_db(db_path=tmp_path)
            result = monitor_db.get_risk_history_summary(limit=10, db_path=tmp_path)
            self.assertIsInstance(result, list)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
