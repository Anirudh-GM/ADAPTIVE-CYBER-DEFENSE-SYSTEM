"""
Unit and Integration Tests for Dynamic Network Discovery & Stable Asset Identity
─────────────────────────────────────────────────────────────────────────────────
Verifies:
  1. Dynamic environment detection & target IP parsing
  2. Invariant asset_id generation across IP/DHCP changes
  3. Database tracking of previous_ips and lifecycle states (NEW, ACTIVE, IP_CHANGED, OFFLINE, RETURNED)
  4. Change detection & Alert generation for IP changes and device returns
"""

import os
import sqlite3
import tempfile
import unittest

from core.network_discovery import detect_network_environment, parse_target_ips
from core.database import generate_asset_id, record_monitoring_scan, init_db, get_live_assets
from core.change_detector import diff_scans
from core.alert_engine import generate_change_alerts, ALERT_TYPES


class TestDynamicNetworkAndAssetIdentity(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        init_db(self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    def test_01_dynamic_network_detection(self):
        env = detect_network_environment()
        self.assertIsNotNone(env.get('controller_ip'))
        self.assertIsNotNone(env.get('subnet_cidr'))
        self.assertIsNotNone(env.get('base_ip_prefix'))
        self.assertIn('.', env.get('controller_ip'))
        print(f"\n[PASS] Dynamic Environment Detected: {env['adapter_name']} -> IP: {env['controller_ip']}, Subnet: {env['subnet_cidr']}, GW: {env['gateway_ip']}")

    def test_02_target_ip_parsing(self):
        # Single IP
        self.assertEqual(parse_target_ips("192.168.0.101"), ["192.168.0.101"])
        # Host range
        self.assertEqual(parse_target_ips("10-12", "192.168.0."), ["192.168.0.10", "192.168.0.11", "192.168.0.12"])
        # CIDR
        cidr_ips = parse_target_ips("192.168.0.0/30")
        self.assertEqual(cidr_ips, ["192.168.0.1", "192.168.0.2"])
        print("\n[PASS] Target IP Parsing (Single, Range, CIDR) Verified")

    def test_03_stable_asset_id_across_dhcp_change(self):
        mac = "70:1A:B8:7D:C7:2E"
        # Asset seen initially at 192.168.0.101
        asset_id_1 = generate_asset_id(mac, "192.168.0.101", "WORKSTATION-A", "Intel", "windows")
        self.assertEqual(asset_id_1, "ASSET-701AB87DC72E")

        # Next day, DHCP reassigns IP to 192.168.0.115
        asset_id_2 = generate_asset_id(mac, "192.168.0.115", "WORKSTATION-A", "Intel", "windows")
        self.assertEqual(asset_id_2, "ASSET-701AB87DC72E")
        self.assertEqual(asset_id_1, asset_id_2)
        print("\n[PASS] Stable asset_id invariant across DHCP IP changes: " + asset_id_1)

    def test_04_dhcp_reassignment_lifecycle_and_history(self):
        mac = "70:1A:B8:7D:C7:2E"
        
        # Scan 1: Asset at 192.168.0.101
        scan1_devices = [{
            'asset_id': generate_asset_id(mac, "192.168.0.101", "WORKSTATION-A", "Intel", "windows"),
            'ip': "192.168.0.101",
            'mac': mac,
            'hostname': "WORKSTATION-A",
            'vendor': "Intel Corporate",
            'os': "windows",
            'device_type': "Workstation",
            'criticality': "MEDIUM",
            'current_risk': 35.0,
            'ports': [{'port': 135, 'protocol': 'tcp', 'service': 'RPC', 'version': None, 'banner': None}]
        }]
        changes1, snap1 = record_monitoring_scan(scan1_devices, subnet="192.168.0.0/24", duration=1.0, db_path=self.temp_db_path)
        self.assertIsNotNone(snap1)

        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT asset_id, ip_address, previous_ips, lifecycle_status FROM assets WHERE mac_address=?", (mac,))
        row = cur.fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "ASSET-701AB87DC72E")
        self.assertEqual(row[1], "192.168.0.101")
        self.assertEqual(row[3], "NEW")

        # Scan 2: DHCP changes IP to 192.168.0.115 (same physical machine / MAC)
        scan2_devices = [{
            'asset_id': generate_asset_id(mac, "192.168.0.115", "WORKSTATION-A", "Intel", "windows"),
            'ip': "192.168.0.115",
            'mac': mac,
            'hostname': "WORKSTATION-A",
            'vendor': "Intel Corporate",
            'os': "windows",
            'device_type': "Workstation",
            'criticality': "MEDIUM",
            'current_risk': 35.0,
            'ports': [{'port': 135, 'protocol': 'tcp', 'service': 'RPC', 'version': None, 'banner': None}]
        }]
        changes2, snap2 = record_monitoring_scan(scan2_devices, subnet="192.168.0.0/24", duration=1.0, db_path=self.temp_db_path)

        conn = sqlite3.connect(self.temp_db_path)
        cur = conn.cursor()
        # Verify only ONE asset row exists (no duplicates created!)
        cur.execute("SELECT COUNT(*) FROM assets WHERE mac_address=?", (mac,))
        count = cur.fetchone()[0]
        self.assertEqual(count, 1)

        # Verify previous_ips and lifecycle_status
        cur.execute("SELECT asset_id, ip_address, previous_ips, lifecycle_status FROM assets WHERE mac_address=?", (mac,))
        row2 = cur.fetchone()
        conn.close()

        self.assertEqual(row2[0], "ASSET-701AB87DC72E")
        self.assertEqual(row2[1], "192.168.0.115")
        self.assertIn("192.168.0.101", row2[2])
        self.assertEqual(row2[3], "IP_CHANGED")
        print("\n[PASS] DHCP IP Reassignment recognized: 192.168.0.101 -> 192.168.0.115. Previous IPs: " + str(row2[2]))

    def test_05_change_detector_and_alerts_for_ip_change(self):
        prev_snapshot = {
            "192.168.0.101": {
                "asset_id": "ASSET-701AB87DC72E",
                "mac": "70:1A:B8:7D:C7:2E",
                "hostname": "WORKSTATION-A",
                "vendor": "Intel",
                "os": "windows",
                "services": ["RPC"],
                "ports": [135],
                "vulnerabilities": [],
            }
        }
        current_snapshot = {
            "192.168.0.115": {
                "asset_id": "ASSET-701AB87DC72E",
                "mac": "70:1A:B8:7D:C7:2E",
                "hostname": "WORKSTATION-A",
                "vendor": "Intel",
                "os": "windows",
                "services": ["RPC"],
                "ports": [135],
                "vulnerabilities": [],
            }
        }

        diff = diff_scans(prev_snapshot, current_snapshot)
        self.assertEqual(len(diff.get('ip_changed_assets', [])), 1)
        self.assertEqual(diff['ip_changed_assets'][0]['old_ip'], "192.168.0.101")
        self.assertEqual(diff['ip_changed_assets'][0]['new_ip'], "192.168.0.115")
        self.assertEqual(len(diff.get('new_assets', [])), 0)
        self.assertEqual(len(diff.get('removed_assets', [])), 0)

        # Alert Engine Generation
        alerts = generate_change_alerts(prev_snapshot, current_snapshot, set(), set(), False, "2026-09-08T00:00:00Z")
        ip_change_alerts = [a for a in alerts if a['alert_type'] == 'IP_CHANGED']
        self.assertEqual(len(ip_change_alerts), 1)
        self.assertIn("192.168.0.101", ip_change_alerts[0]['description'])
        self.assertIn("192.168.0.115", ip_change_alerts[0]['description'])
        print("\n[PASS] Change Detector & Alert Engine correctly emitted IP_CHANGED alert: " + ip_change_alerts[0]['description'])

    def test_06_decision_based_attack_propagation_simulator(self):
        """
        Verify the Decision-Based Attack Propagation Simulator:
          1. Candidate-by-candidate evaluation
          2. Explicit decision outcomes: COMPROMISE POSSIBLE, BLOCKED, NO VALID PATH, COMPROMISE NOT POSSIBLE
          3. Propagation chaining: Newly compromised node becomes next attack source
          4. Defense blocking (isolation, VLAN segmentation)
          5. Honest handling when no valid propagation path exists
        """
        import networkx as nx
        from app import simulate_decision_based_propagation, calculate_risk

        # Build a controlled 4-node test graph
        G = nx.DiGraph()
        
        # Node A: Initial foothold (workstation)
        G.add_node("A", display_name="Workstation A", asset_id="ASSET-A", ip="192.168.0.10",
                   criticality=2, vulnerability=0.8, open_ports=[80, 445], services=["HTTP", "SMB"],
                   cve_findings=[{"cve_id": "CVE-2020-0796", "cvss": 10.0, "severity": "CRITICAL"}],
                   node_type="endpoint", compromised=False)

        # Node B: Vulnerable Server (reachable from A on port 445)
        G.add_node("B", display_name="File Server B", asset_id="ASSET-B", ip="192.168.0.20",
                   criticality=3, vulnerability=0.9, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2017-0144", "cvss": 9.8, "severity": "CRITICAL"}],
                   node_type="server", compromised=False)

        # Node C: Hardened Database (reachable from B on port 3306, but isolated)
        G.add_node("C", display_name="Database C", asset_id="ASSET-C", ip="192.168.0.30",
                   criticality=5, vulnerability=0.1, open_ports=[3306], services=["MySQL"],
                   cve_findings=[], node_type="database", compromised=False, isolated=True)

        # Node D: Isolated host with no open ports
        G.add_node("D", display_name="Printer D", asset_id="ASSET-D", ip="192.168.0.40",
                   criticality=1, vulnerability=0.0, open_ports=[], services=[],
                   cve_findings=[], node_type="endpoint", compromised=False)

        # Edges
        G.add_edge("A", "B", access_port=445, connection="SMB", mitre_code="T1210", success_prob=1.0)
        G.add_edge("B", "C", access_port=3306, connection="MySQL", mitre_code="T1021", success_prob=1.0)

        # 1. Run simulation from A without global defense
        timeline, decision_log, compromised, uncompromised, successful, blocked_failed, stats = simulate_decision_based_propagation(
            G, "A", seed=42
        )

        # A is initial compromise
        self.assertIn("A", compromised)
        self.assertEqual(decision_log[0]["decision"], "✓ COMPROMISE POSSIBLE")
        self.assertEqual(decision_log[0]["target"], "Workstation A")

        # B is evaluated from A -> Compromise possible
        b_decisions = [d for d in decision_log if d["target"] == "File Server B"]
        self.assertTrue(len(b_decisions) >= 1)
        self.assertEqual(b_decisions[0]["decision"], "✓ COMPROMISE POSSIBLE")
        self.assertIn("B", compromised)

        # C is evaluated from B -> Blocked by isolation defense
        c_decisions = [d for d in decision_log if d["target"] == "Database C"]
        self.assertTrue(len(c_decisions) >= 1)
        self.assertEqual(c_decisions[0]["decision"], "🛡 BLOCKED")
        self.assertIn("C", uncompromised)

        # D has no open ports / no valid path
        d_decisions = [d for d in decision_log if d["target"] == "Printer D"]
        self.assertTrue(len(d_decisions) >= 1)
        self.assertEqual(d_decisions[0]["decision"], "✗ NO VALID PATH")
        self.assertIn("D", uncompromised)

        # 2. Risk Calculation verification
        risk, blast = calculate_risk(G, compromised, timeline, False, stats)
        self.assertGreater(risk, 0.0)
        self.assertEqual(blast["systems_controlled"], 2)

        # 3. Test honest handling when network has zero reachable paths
        G_isolated = nx.DiGraph()
        G_isolated.add_node("Solo", display_name="Standalone Host", asset_id="ASSET-SOLO", ip="192.168.0.99",
                            criticality=2, vulnerability=0.5, open_ports=[80], services=["HTTP"],
                            cve_findings=[], node_type="endpoint", compromised=False)
        t_solo, dlog_solo, comp_solo, uncomp_solo, succ_solo, block_solo, stats_solo = simulate_decision_based_propagation(
            G_isolated, "Solo", seed=42
        )
        self.assertEqual(len(comp_solo), 1)
        self.assertEqual(len(dlog_solo), 1)
        self.assertEqual(len(succ_solo), 0)
        print("\n[PASS] Dynamic Decision-Based Attack Propagation Simulator: Evaluated candidates, verified chaining, isolation blocking, and honest containment handling.")

    def test_07_level2_live_validation_engine_and_diff(self):
        """
        Level 2: Real-time validation engine and change diffing:
          - Validates port state change detection (OPEN -> CLOSED -> SERVICE_EXPOSURE_REMOVED, DEFENSE_VERIFIED)
          - Validates new exposed port (CLOSED -> OPEN -> NEW_SERVICE_EXPOSED)
          - Validates host reachability transitions (ONLINE / OFFLINE)
        """
        from core.live_validation import diff_validation_against_discovery

        discovered_baseline = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.0.20",
                "open_ports": [445, 3389], "services": ["SMB", "RDP"]
            }
        }

        # Case 1: Live validation finds port 445 is now CLOSED (e.g. hardening defense applied)
        live_snapshot_1 = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.0.20", "reachable": True,
                "latency_ms": 1.5, "method": "tcp_syn_ping",
                "timestamp": "2026-09-09T20:00:00Z",
                "ports": {
                    445: {"port": 445, "state": "closed", "service": "SMB", "banner": None, "timestamp": "2026-09-09T20:00:00Z"},
                    3389: {"port": 3389, "state": "open", "service": "RDP", "banner": None, "timestamp": "2026-09-09T20:00:00Z"}
                }
            }
        }

        changes_1 = diff_validation_against_discovery(discovered_baseline, live_snapshot_1)
        change_types_1 = [c["change_type"] for c in changes_1]
        self.assertIn("SERVICE_EXPOSURE_REMOVED", change_types_1)
        self.assertIn("DEFENSE_VERIFIED", change_types_1)
        self.assertIn("SERVICE_STILL_EXPOSED", change_types_1)

        # Case 2: Live validation finds a new port 8080 exposed
        live_snapshot_2 = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.0.20", "reachable": True,
                "latency_ms": 1.2, "method": "tcp_syn_ping",
                "timestamp": "2026-09-09T20:05:00Z",
                "ports": {
                    445: {"port": 445, "state": "open", "service": "SMB", "banner": None, "timestamp": "2026-09-09T20:05:00Z"},
                    3389: {"port": 3389, "state": "open", "service": "RDP", "banner": None, "timestamp": "2026-09-09T20:05:00Z"},
                    8080: {"port": 8080, "state": "open", "service": "HTTP-Proxy", "banner": "Apache", "timestamp": "2026-09-09T20:05:00Z"}
                }
            }
        }
        changes_2 = diff_validation_against_discovery(discovered_baseline, live_snapshot_2)
        change_types_2 = [c["change_type"] for c in changes_2]
        self.assertIn("NEW_SERVICE_EXPOSED", change_types_2)

        # Case 3: Target host goes offline
        live_snapshot_offline = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.0.20", "reachable": False,
                "latency_ms": None, "method": "tcp_syn_ping",
                "timestamp": "2026-09-09T20:10:00Z", "ports": {}
            }
        }
        changes_3 = diff_validation_against_discovery(discovered_baseline, live_snapshot_offline)
        change_types_3 = [c["change_type"] for c in changes_3]
        self.assertIn("HOST_OFFLINE", change_types_3)
        print("\n[PASS] Level 2 Live Validation Change Diff: Accurately detected exposure removal, defense verification, new exposure, and host offline.")

    def test_08_level2_live_validation_fed_into_propagation_simulator(self):
        """
        Level 2: Feed real-time live validation state into decision-based propagation:
          1. Host reachable + port open -> propagation condition valid (COMPROMISE POSSIBLE)
          2. Host reachable + port closed in validation -> COMPROMISE NOT POSSIBLE
          3. Host offline in validation -> NO VALID PATH
          4. Validation unavailable -> clear labeling using discovery snapshot
        """
        import networkx as nx
        from app import simulate_decision_based_propagation

        G = nx.DiGraph()
        G.add_node("A", display_name="Asset A", asset_id="ASSET-A", ip="192.168.1.10",
                   criticality=2, vulnerability=0.8, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2020-0796", "cvss": 10.0}], node_type="endpoint", compromised=False)

        G.add_node("B", display_name="Asset B", asset_id="ASSET-B", ip="192.168.1.20",
                   criticality=3, vulnerability=0.9, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2017-0144", "cvss": 9.8}], node_type="server", compromised=False)

        G.add_edge("A", "B", access_port=445, connection="SMB", mitre_code="T1210", success_prob=1.0)

        # Scenario 1: Live validation confirms TCP/445 is OPEN on Asset B
        live_val_open = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": True,
                "ports": {445: {"port": 445, "state": "open", "service": "SMB"}}
            }
        }
        _, dlog_open, comp_open, _, _, _, stats_open = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val_open
        )
        b_dec_open = [d for d in dlog_open if d["target"] == "Asset B"][0]
        self.assertEqual(b_dec_open["decision"], "✓ COMPROMISE POSSIBLE")
        self.assertTrue(b_dec_open["live_validated"])
        self.assertEqual(b_dec_open["live_port_state"], "OPEN")
        self.assertIn("B", comp_open)

        # Reset G nodes
        for n in G.nodes:
            G.nodes[n]["compromised"] = False

        # Scenario 2: Live validation confirms TCP/445 is CLOSED on Asset B (e.g. after defense hardening)
        live_val_closed = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": True,
                "ports": {445: {"port": 445, "state": "closed", "service": "SMB"}}
            }
        }
        _, dlog_closed, comp_closed, uncomp_closed, _, blocked_closed, stats_closed = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val_closed
        )
        b_dec_closed = [d for d in dlog_closed if d["target"] == "Asset B"][0]
        self.assertEqual(b_dec_closed["decision"], "✗ COMPROMISE NOT POSSIBLE")
        self.assertTrue(b_dec_closed["live_validated"])
        self.assertEqual(b_dec_closed["live_port_state"], "CLOSED")
        self.assertIn("CLOSED in real-time validation", b_dec_closed["reason"])
        self.assertIn("B", uncomp_closed)
        self.assertNotIn("B", comp_closed)

        # Reset G nodes
        for n in G.nodes:
            G.nodes[n]["compromised"] = False

        # Scenario 3: Live validation confirms Asset B is OFFLINE
        live_val_offline = {
            "ASSET-B": {
                "asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": False, "ports": {}
            }
        }
        _, dlog_off, comp_off, uncomp_off, _, _, _ = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val_offline
        )
        b_dec_off = [d for d in dlog_off if d["target"] == "Asset B"][0]
        self.assertEqual(b_dec_off["decision"], "✗ NO VALID PATH")
        self.assertIn("UNREACHABLE / OFFLINE", b_dec_off["reason"])
        self.assertIn("B", uncomp_off)

        # Reset G nodes
        for n in G.nodes:
            G.nodes[n]["compromised"] = False

        # Scenario 4: No live validation available -> honest fallback annotation
        _, dlog_none, _, _, _, _, _ = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=None
        )
        b_dec_none = [d for d in dlog_none if d["target"] == "Asset B"][0]
        self.assertFalse(b_dec_none["live_validated"])
        self.assertTrue(b_dec_none["live_snapshot_used"])
        self.assertIn("Using discovery snapshot", b_dec_none["reason"])
        print("\n[PASS] Level 2 Simulator Integration: Correctly evaluates OPEN, CLOSED, OFFLINE live states, and discovery fallback.")

    def test_09_level2_multi_hop_propagation_with_live_validation(self):
        """
        Level 2: Multi-hop propagation A -> B -> C:
          A -> B succeeds (port 445 open live), but B -> C fails because live validation confirms port 3306 is closed on C.
        """
        import networkx as nx
        from app import simulate_decision_based_propagation

        G = nx.DiGraph()
        G.add_node("A", display_name="Asset A", asset_id="ASSET-A", ip="192.168.1.10",
                   criticality=2, vulnerability=0.8, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2020-0796", "cvss": 10.0}], node_type="endpoint", compromised=False)

        G.add_node("B", display_name="Asset B", asset_id="ASSET-B", ip="192.168.1.20",
                   criticality=3, vulnerability=0.9, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2017-0144", "cvss": 9.8}], node_type="server", compromised=False)

        G.add_node("C", display_name="Asset C", asset_id="ASSET-C", ip="192.168.1.30",
                   criticality=5, vulnerability=0.8, open_ports=[3306], services=["MySQL"],
                   cve_findings=[{"cve_id": "CVE-2021-27928", "cvss": 9.8}], node_type="database", compromised=False)

        G.add_edge("A", "B", access_port=445, connection="SMB", mitre_code="T1210", success_prob=1.0)
        G.add_edge("B", "C", access_port=3306, connection="MySQL", mitre_code="T1021", success_prob=1.0)

        # B is open on 445, but C is closed on 3306 in live network validation
        live_val = {
            "ASSET-B": {"asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": True, "ports": {445: {"state": "open"}}},
            "ASSET-C": {"asset_id": "ASSET-C", "ip": "192.168.1.30", "reachable": True, "ports": {3306: {"state": "closed"}}},
        }

        timeline, decision_log, compromised, uncompromised, successful, blocked_failed, stats = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val
        )

        self.assertIn("A", compromised)
        self.assertIn("B", compromised)
        self.assertIn("C", uncompromised)
        self.assertNotIn("C", compromised)

        c_dec = [d for d in decision_log if d["target"] == "Asset C"][0]
        self.assertEqual(c_dec["decision"], "✗ COMPROMISE NOT POSSIBLE")
        self.assertIn("CLOSED in real-time validation", c_dec["reason"])
        print("\n[PASS] Level 2 Multi-Hop Propagation: Successfully chained A -> B while B -> C was correctly stopped by live-validated port closure on C.")

    def test_10_level2_before_after_defense_verification_pipeline(self):
        """
        Level 2 Before / After Defense Verification:
          1. Before Defense: TCP/445 OPEN -> Simulated Compromise Possible -> Risk: High
          2. Apply Defense: Port hardened / closed
          3. Live Re-Validation: TCP/445 CLOSED (DEFENSE_VERIFIED)
          4. Re-Simulation: Compromise Not Possible -> Risk Drops & Attack Path Removed
        """
        import networkx as nx
        from app import simulate_decision_based_propagation, calculate_risk

        G = nx.DiGraph()
        G.add_node("A", display_name="Asset A", asset_id="ASSET-A", ip="192.168.1.10",
                   criticality=2, vulnerability=0.8, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2020-0796", "cvss": 10.0}], node_type="endpoint", compromised=False)

        G.add_node("B", display_name="Asset B", asset_id="ASSET-B", ip="192.168.1.20",
                   criticality=4, vulnerability=0.9, open_ports=[445], services=["SMB"],
                   cve_findings=[{"cve_id": "CVE-2017-0144", "cvss": 9.8}], node_type="server", compromised=False)

        G.add_edge("A", "B", access_port=445, connection="SMB", mitre_code="T1210", success_prob=1.0)

        # 1. BEFORE DEFENSE
        live_val_before = {
            "ASSET-B": {"asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": True, "ports": {445: {"state": "open"}}}
        }
        t_before, d_before, comp_before, _, _, _, stats_before = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val_before
        )
        risk_before, blast_before = calculate_risk(G, comp_before, t_before, False, stats_before)
        self.assertEqual(len(comp_before), 2)
        self.assertGreater(risk_before, 50.0)

        # 2. AFTER DEFENSE (Safe port hardening applied -> live validation verifies TCP/445 CLOSED)
        for n in G.nodes:
            G.nodes[n]["compromised"] = False

        live_val_after = {
            "ASSET-B": {"asset_id": "ASSET-B", "ip": "192.168.1.20", "reachable": True, "ports": {445: {"state": "closed"}}}
        }
        t_after, d_after, comp_after, _, _, _, stats_after = simulate_decision_based_propagation(
            G, "A", seed=42, live_validation=live_val_after
        )
        risk_after, blast_after = calculate_risk(G, comp_after, t_after, False, stats_after)

        self.assertEqual(len(comp_after), 1)  # Only initial foothold A remains
        self.assertLess(risk_after, risk_before)
        risk_reduction = round(risk_before - risk_after, 1)
        self.assertGreater(risk_reduction, 0.0)
        print(f"\n[PASS] Level 2 Before/After Defense Verification: Risk dropped {risk_before} -> {risk_after} (-{risk_reduction} pts), Attack Path Removed.")


if __name__ == '__main__':
    unittest.main()

