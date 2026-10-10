"""
Unit tests for Live Validation rechecking open ports, discovering new ports,
and updating graph nodes, edge exposure, risk scores, and persistence everywhere.
"""
import unittest
import networkx as nx
from core.live_validation import validate_asset_state, PORT_SERVICE_MAP
from app import sync_live_validation_to_graph, calculate_asset_risk, calculate_overall_acds_risk

class TestLiveValidationSync(unittest.TestCase):
    def setUp(self):
        self.G = nx.DiGraph()
        # Setup a sample asset node with port 80 open initially
        self.target_ip = "127.0.0.1"
        self.target_node_id = "ASSET-127-0-0-1"
        
        self.G.add_node(
            self.target_node_id,
            ip=self.target_ip,
            host_name="test-server",
            device_type="Server",
            asset_type="Server",
            open_ports=[80],
            services=["http"],
            vulnerabilities=[],
            risk_score=40.0,
            criticality=3,
            business_criticality=3
        )

    def test_sync_live_validation_updates_ports_and_risk(self):
        # Simulate validation finding port 80 closed and port 443 & 8080 newly open
        mock_val_res = {
            "target_ip": self.target_ip,
            "is_alive": True,
            "ports_validated": [80, 443, 8080],
            "open_ports": [443, 8080],
            "closed_ports": [80],
            "new_ports_detected": [443, 8080],
            "closed_ports_detected": [80],
            "services": ["https", "http-proxy"],
            "version_map": {443: "OpenSSL/1.1.1", 8080: "Apache-Tomcat/9.0"},
            "banner_map": {443: "HTTPS server", 8080: "Apache Tomcat"},
            "status": "VALIDATED"
        }

        # Sync to graph
        result = sync_live_validation_to_graph(self.G, self.target_ip, mock_val_res)
        self.assertEqual(result.get("target_node"), self.target_node_id)
        self.assertEqual(result.get("new_ports"), [443, 8080])
        self.assertEqual(result.get("new_opened"), [443, 8080])
        self.assertEqual(result.get("new_closed"), [80])
        
        # Verify node data in graph was updated
        node_data = self.G.nodes[self.target_node_id]
        self.assertEqual(node_data["open_ports"], [443, 8080])
        self.assertIn("HTTPS", node_data["services"])
        self.assertIn("HTTP-Alt", node_data["services"])
        self.assertIn("Apache", node_data["version_map"][8080])
        
        # Verify risk was recalculated
        updated_risk = result.get("new_risk")
        self.assertIsInstance(updated_risk, float)
        self.assertGreaterEqual(updated_risk, 0.0)

    def test_apply_defense_actions_and_re_simulation(self):
        from app import apply_defense_actions, run_post_defense_re_simulation
        
        # Setup multi-node graph
        self.G.add_node("ASSET-B", ip="10.0.0.2", open_ports=[445], services=["SMB"], criticality=4, vulnerabilities=[], risk_score=75.0)
        self.G.add_edge(self.target_node_id, "ASSET-B", port=445, service="SMB")

        actions = [{
            "node": "ASSET-B",
            "type": "disable_smb",
            "action": "Disable SMB on ASSET-B",
            "cost": 15,
            "risk_reduction": 25.0,
            "description": "Disable SMB port 445"
        }]

        applied, ids_dep, seg_app = apply_defense_actions(self.G, actions)
        self.assertEqual(len(applied), 1)
        self.assertNotIn(445, self.G.nodes["ASSET-B"].get("open_ports", []))

        # Re-simulation
        re_res = run_post_defense_re_simulation(self.G, entry_node=self.target_node_id)
        self.assertIsNotNone(re_res)
        self.assertIn("risk_score_after", re_res)
        self.assertIn("blast_details_after", re_res)

if __name__ == '__main__':
    unittest.main()

