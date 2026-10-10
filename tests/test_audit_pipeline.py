"""
ACDS v2.0 Engineering Audit Pipeline Test Suite
─────────────────────────────────────────────────────────────────
Validates:
1. Network discovery and multi-adapter/VMware detection
2. Target specification parsing (single IP, ranges, CIDRs)
3. Banner grab parsing and version extraction (SSH, Apache, vsftpd, MySQL)
4. Honest uncertainty & CVE matching behavior
5. Risk score formula calculation & bounds
6. Exposure graph construction (single-asset vs multi-asset)
7. Defense optimization and Before/After verification consistency
"""

import unittest
import networkx as nx
from core.network_discovery import detect_network_environment, parse_target_ips
from app import (
    parse_version_from_banner,
    split_product_version,
    get_real_cves,
    lookup_cves_offline,
    cvss_severity_label,
    calculate_asset_risk,
    calculate_network_exposure_score,
    calculate_criticality_score,
    calculate_overall_acds_risk,
    build_dynamic_graph,
    get_defense_actions,
    greedy_defense_selection,
    apply_defense_actions,
    PORT_SERVICE_MAP,
)


class TestAuditPipeline(unittest.TestCase):

    def test_multi_adapter_discovery(self):
        """Verify network discovery detects host adapters and lists all interfaces."""
        env = detect_network_environment()
        self.assertIsNotNone(env.get('controller_ip'))
        self.assertIsNotNone(env.get('subnet_cidr'))
        self.assertIn('all_adapters', env)
        self.assertIsInstance(env['all_adapters'], list)
        for ad in env['all_adapters']:
            self.assertIn('name', ad)
            self.assertIn('ip', ad)
            self.assertIn('subnet_cidr', ad)

    def test_target_ip_parsing(self):
        """Verify target IP parser handles single IP, lists, ranges, and CIDRs."""
        # Single IP
        single = parse_target_ips("192.168.93.129")
        self.assertEqual(single, ["192.168.93.129"])

        # Comma-separated list
        comma_list = parse_target_ips("192.168.93.129, 192.168.93.130")
        self.assertEqual(comma_list, ["192.168.93.129", "192.168.93.130"])

        # CIDR notation (/29 = 6 usable hosts)
        cidr_list = parse_target_ips("192.168.93.0/29")
        self.assertEqual(len(cidr_list), 6)
        self.assertIn("192.168.93.1", cidr_list)
        self.assertIn("192.168.93.6", cidr_list)

        # Host range with base prefix
        range_list = parse_target_ips("10-15", base_prefix="192.168.93.")
        self.assertEqual(range_list, [f"192.168.93.{h}" for h in range(10, 16)])

    def test_banner_parsing_openssh(self):
        """Verify OpenSSH banner from Kali/Debian parses product and version."""
        banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"
        clean = parse_version_from_banner("SSH", banner)
        self.assertIsNotNone(clean)
        self.assertIn("OpenSSH", clean)
        self.assertIn("9.2p1", clean)

        prod, ver = split_product_version(clean)
        self.assertEqual(prod, "openssh")
        self.assertEqual(ver, "9.2p1")

    def test_banner_parsing_apache(self):
        """Verify Apache HTTP Server banner parses product and version."""
        banner = "Apache/2.4.58 (Debian)"
        clean = parse_version_from_banner("HTTP", banner)
        self.assertIsNotNone(clean)
        self.assertIn("Apache", clean)
        self.assertIn("2.4.58", clean)

        prod, ver = split_product_version(clean)
        self.assertEqual(prod, "apache")
        self.assertEqual(ver, "2.4.58")

    def test_banner_parsing_vsftpd(self):
        """Verify vsftpd banner parsing."""
        banner = "220 (vsFTPd 2.3.4)"
        clean = parse_version_from_banner("FTP", banner)
        self.assertIsNotNone(clean)
        self.assertIn("vsftpd", clean.lower())

        prod, ver = split_product_version(clean)
        self.assertEqual(prod, "vsftpd")
        self.assertEqual(ver, "2.3.4")

    def test_cve_offline_matching(self):
        """Verify offline CVE lookup succeeds for known vulnerable versions."""
        cves = lookup_cves_offline("vsftpd 2.3.4")
        self.assertTrue(len(cves) > 0)
        self.assertEqual(cves[0]["id"], "CVE-2011-2523")
        self.assertEqual(cves[0]["cvss"], 9.8)

    def test_cve_no_match_without_version(self):
        """Verify that missing/empty version evidence produces NO fabricated CVEs."""
        cves, source = get_real_cves("HTTP", None)
        self.assertEqual(cves, [])
        self.assertEqual(source, "none")

        cves, source = get_real_cves("SSH", "")
        self.assertEqual(cves, [])
        self.assertEqual(source, "none")

    def test_cvss_severity_bands(self):
        """Verify standard CVSS severity band mapping."""
        self.assertEqual(cvss_severity_label(9.8), "Critical")
        self.assertEqual(cvss_severity_label(7.5), "High")
        self.assertEqual(cvss_severity_label(5.3), "Medium")
        self.assertEqual(cvss_severity_label(2.1), "Low")
        self.assertEqual(cvss_severity_label(0.0), "None")
        self.assertEqual(cvss_severity_label(None), "Unknown")

    def test_risk_score_calculation(self):
        """Verify Asset Risk scoring weights: 40% Vuln, 20% Ports, 15% Sensitive, 15% Crit, 10% Net."""
        # 1. Zero-exposure asset with high criticality
        crit_score = calculate_criticality_score(4)  # Tier 4 High
        res = calculate_asset_risk(
            {'score': 0.0, 'state': 'NONE'},
            {'score': 20.0, 'open_port_count': 1},
            {'score': 0.0, 'detected_ports': []},
            crit_score,
            {'score': 10.0, 'basis': 'Single asset'}
        )
        self.assertIsInstance(res['score'], (int, float))
        self.assertTrue(0 <= res['score'] <= 100)
        # Even with High criticality, risk remains low if vulnerability and exposure are minimal
        self.assertIn(res['severity'], ["LOW", "MEDIUM"])

        # 2. Maximum exposure asset
        res_max = calculate_asset_risk(
            {'score': 100.0, 'state': 'CONFIRMED'},
            {'score': 100.0, 'open_port_count': 10},
            {'score': 100.0, 'detected_ports': [(3389, 'RDP')]},
            {'score': 100.0, 'level': 5},
            {'score': 100.0, 'basis': 'Maximal exposure'}
        )
        self.assertEqual(res_max['score'], 100.0)
        self.assertEqual(res_max['severity'], "CRITICAL")

    def test_single_asset_graph(self):
        """Verify single-asset scan builds a valid graph with 1 node and 0 lateral edges."""
        devices = [{
            'ip': '192.168.93.129',
            'hostname': 'kali-linux',
            'os': 'linux',
            'os_confidence': 0.9,
            'os_evidence': ['Linux banner'],
            'is_mobile': False,
            'mac': '00:50:56:C0:00:08',
            'mac_vendor': 'VMware',
            'open_ports': [22, 80],
            'services': ['SSH', 'HTTP'],
            'version_map': {'SSH': 'OpenSSH 9.2p1', 'HTTP': 'Apache 2.4.58'},
            'banner_map': {'SSH': 'SSH-2.0-OpenSSH_9.2p1', 'HTTP': 'Apache/2.4.58 (Debian)'},
            'device_type': 'Linux Web Server',
            'display_name': 'kali-linux (Linux Web Server)',
            'device_confidence': 0.9,
            'device_evidence': ['Port 80', 'Port 22'],
            'asset_id': 'ASSET-KALI-001'
        }]

        G = build_dynamic_graph(devices)
        self.assertEqual(G.number_of_nodes(), 1)
        self.assertEqual(G.number_of_edges(), 0)  # Single asset has 0 lateral paths

        node_data = list(G.nodes(data=True))[0][1]
        self.assertEqual(node_data['ip'], '192.168.93.129')
        self.assertIn('SSH', node_data['services'])
        self.assertIn('HTTP', node_data['services'])
        self.assertEqual(node_data['version_map']['SSH'], 'OpenSSH 9.2p1')
        self.assertEqual(node_data['version_map']['HTTP'], 'Apache 2.4.58')

    def test_multi_asset_graph_lateral_edges(self):
        """Verify multi-asset scan constructs legitimate lateral movement edges."""
        devices = [
            {
                'ip': '192.168.93.129',
                'hostname': 'kali-web',
                'os': 'linux',
                'os_confidence': 0.9,
                'os_evidence': [],
                'is_mobile': False,
                'mac': '00:50:56:C0:00:08',
                'mac_vendor': 'VMware',
                'open_ports': [22, 80],
                'services': ['SSH', 'HTTP'],
                'version_map': {'SSH': 'OpenSSH 9.2p1', 'HTTP': 'Apache 2.4.58'},
                'banner_map': {},
                'device_type': 'Server',
                'display_name': 'kali-web',
                'device_confidence': 0.9,
                'device_evidence': [],
                'asset_id': 'ASSET-KALI-001'
            },
            {
                'ip': '192.168.93.130',
                'hostname': 'admin-ws',
                'os': 'windows',
                'os_confidence': 0.8,
                'os_evidence': [],
                'is_mobile': False,
                'mac': '00:50:56:C0:00:09',
                'mac_vendor': 'VMware',
                'open_ports': [3389, 445],
                'services': ['RDP', 'SMB'],
                'version_map': {},
                'banner_map': {},
                'device_type': 'Workstation',
                'display_name': 'admin-ws',
                'device_confidence': 0.8,
                'device_evidence': [],
                'asset_id': 'ASSET-WS-002'
            }
        ]

        G = build_dynamic_graph(devices)
        self.assertEqual(G.number_of_nodes(), 2)
        # There should be edges toward kali-web (port 22) and toward admin-ws (port 3389, 445)
        self.assertTrue(G.number_of_edges() > 0)

    def test_defense_knapsack_and_before_after(self):
        """Verify defense actions are generated, selected by budget, and applied consistently."""
        G = nx.DiGraph()
        G.add_node("HostA", ip="192.168.1.10", open_ports=[80, 22], services=['HTTP', 'SSH'],
                   criticality=3, vulnerability=0.6, risk_score=60, isolated=False, compromised=True, role="Server")
        G.add_node("HostB", ip="192.168.1.20", open_ports=[3389], services=['RDP'],
                   criticality=4, vulnerability=0.8, risk_score=80, isolated=False, compromised=False, role="Workstation")
        G.add_edge("HostA", "HostB", service="RDP", port=3389)

        actions = get_defense_actions(G, {"HostA"}, 70.0)
        self.assertTrue(len(actions) > 0)

        # Greedy selection under budget 30
        selected, reduction, remaining = greedy_defense_selection(actions, budget=30)
        self.assertTrue(len(selected) > 0)
        self.assertTrue(reduction > 0)
        self.assertTrue(remaining >= 0)

        # Apply defenses
        applied, ids_dep, seg_app = apply_defense_actions(G, selected)
        self.assertEqual(len(applied), len(selected))


if __name__ == '__main__':
    unittest.main()
