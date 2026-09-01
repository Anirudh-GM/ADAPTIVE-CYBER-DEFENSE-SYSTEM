"""
ACDS Network Graph Builder
Constructs NetworkX DiGraph topologies for simulated SME labs, live scanned networks,
and scalable 10-20 node synthetic enterprise benchmarks.
"""

from typing import Dict, List, Optional, Tuple, Any
import networkx as nx

from acds.discovery.fingerprint import (
    calculate_criticality,
    format_device_display_name,
)
from acds.discovery.scanner import (
    assess_device_security,
    assign_role_from_services,
    get_lateral_edges_for_target,
)
from acds.vulnerability.risk import (
    calculate_asset_risk,
    calculate_criticality_score,
    calculate_network_exposure_score,
)


def _parse_device_record(device: Tuple) -> Dict[str, Any]:
    (ip, hostname, os_type, os_confidence, os_evidence, is_mobile, mac, mac_vendor_,
     open_ports, services, version_map, banner_map, device_type, display_name,
     device_confidence, device_evidence) = device
    if not display_name:
        display_name = format_device_display_name(hostname, device_type, ip)
    return {
        'ip': ip, 'hostname': hostname, 'os': os_type,
        'os_confidence': os_confidence, 'os_evidence': os_evidence or [],
        'is_mobile': is_mobile,
        'mac': mac, 'mac_vendor': mac_vendor_, 'open_ports': open_ports or [],
        'services': services or [], 'version_map': version_map or {},
        'banner_map': banner_map or {}, 'device_type': device_type,
        'device_confidence': device_confidence, 'device_evidence': device_evidence or [],
        'display_name': display_name,
    }


def build_dynamic_graph(devices: List[Tuple]) -> nx.DiGraph:
    """Build the live network graph from real scan results."""
    G = nx.DiGraph()
    node_type_map = {
        "Entry Node": "endpoint", "Server": "server",
        "Database": "database", "Workstation": "endpoint",
    }

    parsed = [_parse_device_record(d) for d in devices]
    node_names = []
    per_node_security = {}

    for rec in parsed:
        role = assign_role_from_services(rec['services'], rec['os'], rec['device_type'])
        security = assess_device_security(
            rec['services'], rec['os'], rec['device_type'], rec['open_ports'], role,
            version_map=rec['version_map'], ip=rec['ip'],
        )
        criticality = calculate_criticality(rec['device_type'], rec['services'], rec['open_ports'], rec['os'])
        per_node_security[rec['ip']] = (rec, role, security, criticality)

    total_assets = len(parsed)

    for rec in parsed:
        rec, role, security, criticality = per_node_security[rec['ip']]
        other_assets = max(0, total_assets - 1)
        network_component = calculate_network_exposure_score(len(rec['open_ports']), other_assets)
        asset_risk = calculate_asset_risk(
            security['vulnerability_component'],
            security['service_component'],
            security['sensitive_component'],
            calculate_criticality_score(criticality['level']),
            network_component,
        )

        ntype = node_type_map.get(role, "endpoint")
        node_name = f"{role}\n{rec['display_name']}"
        node_names.append(node_name)
        G.add_node(
            node_name,
            ip=rec['ip'], hostname=rec['hostname'], os=rec['os'],
            os_confidence=rec['os_confidence'], os_evidence=rec['os_evidence'],
            is_mobile=rec['is_mobile'], mac=rec['mac'], mac_vendor=rec['mac_vendor'],
            open_ports=rec['open_ports'], services=rec['services'],
            version_map=rec['version_map'], banner_map=rec['banner_map'],
            device_type=rec['device_type'], device_confidence=rec['device_confidence'],
            device_evidence=rec['device_evidence'], display_name=rec['display_name'],
            role=role, criticality=criticality['level'], criticality_label=criticality['label'],
            criticality_confidence=criticality['confidence'], criticality_evidence=criticality['evidence'],
            vulnerability=round(asset_risk['score'] / 100.0, 3), exposure_level=security['exposure_level'],
            risk_score=asset_risk['score'], risk_severity=asset_risk['severity'],
            risk_components=asset_risk['components'], asset_risk=asset_risk,
            weaknesses=security['weaknesses'], access_vectors=security['access_vectors'],
            fixes=security['fixes'], cve_findings=security['cve_findings'],
            exposure_findings=security['exposure_findings'], cve_source=security['cve_source'],
            node_type=ntype, compromised=False, priv_escalated=False, isolated=False,
        )

    for src in node_names:
        for dst in node_names:
            if src == dst:
                continue
            for edge_info in get_lateral_edges_for_target(G.nodes[dst]['open_ports']):
                G.add_edge(
                    src, dst,
                    connection=edge_info['connection'],
                    access_vector=edge_info['vector'],
                    access_port=edge_info['port'],
                    mitre_code=edge_info['mitre_code'],
                    mitre_desc=edge_info['mitre_desc'],
                    success_prob=edge_info['success_prob'],
                    reachability='POTENTIAL REACHABILITY',
                )
    return G


def build_network() -> nx.DiGraph:
    """Build standard 7-node simulated lab network topology."""
    G = nx.DiGraph()
    lab_hosts = [
        ("Firewall",    "192.168.1.1",  "Perimeter Defense", "perimeter", [443],        ['HTTPS'], {}),
        ("User-PC",     "192.168.1.10", "Workstation",       "endpoint",  [22, 445],    ['SSH', 'SMB'], {'SSH': 'OpenSSH 7.2p2'}),
        ("Admin-PC",    "192.168.1.11", "Admin Workstation", "endpoint",  [3389, 445],  ['RDP', 'SMB'], {}),
        ("Server",      "192.168.1.20", "Web/App Server",    "server",    [22, 80, 443],['SSH', 'HTTP', 'HTTPS'], {'HTTP': 'Apache 2.4.49', 'SSH': 'OpenSSH 7.2p2'}),
        ("File-Server", "192.168.1.21", "File Server",       "server",    [445, 139],   ['SMB', 'NetBIOS'], {}),
        ("Database",    "192.168.1.30", "MySQL Database",    "database",  [3306],       ['MySQL'], {'MySQL': 'MySQL 5.7.30'}),
        ("Honeypot",    "192.168.1.99", "Decoy System",      "honeypot",  [21],         ['FTP'], {'FTP': 'vsftpd 2.3.4'}),
    ]
    total_assets = len(lab_hosts)
    for name, ip, role, ntype, open_ports, services, vmap in lab_hosts:
        os_type = 'linux' if ntype in ('server', 'database', 'honeypot') else 'windows' if ntype == 'endpoint' else 'unknown'
        device_type = 'Web Server' if ntype == 'server' else 'Database Server' if ntype == 'database' else 'Windows Workstation'
        sim_role = 'Database' if ntype == 'database' else 'Server' if ntype == 'server' else 'Workstation'
        if name == 'Firewall':
            sim_role = 'Entry Node'
        security = assess_device_security(services, os_type, device_type, open_ports, sim_role, version_map=vmap, ip=ip)
        criticality = calculate_criticality(device_type, services, open_ports, os_type)
        network_component = calculate_network_exposure_score(len(open_ports), max(0, total_assets - 1))
        asset_risk = calculate_asset_risk(
            security['vulnerability_component'],
            security['service_component'],
            security['sensitive_component'],
            calculate_criticality_score(criticality['level']),
            network_component,
        )
        G.add_node(
            name, ip=ip, role=role, display_name=name, hostname=name, os=os_type,
            os_confidence=None,
            os_evidence=['Simulated lab topology — OS is a fixed demo assumption, not measured from a live host'],
            open_ports=open_ports, services=services, version_map=vmap, banner_map={},
            device_type=device_type, device_confidence=None,
            device_evidence=['Simulated lab topology — device type is a fixed demo assumption'],
            criticality=criticality['level'], criticality_label=criticality['label'],
            criticality_confidence=criticality['confidence'], criticality_evidence=criticality['evidence'],
            vulnerability=round(asset_risk['score'] / 100.0, 3), exposure_level=security['exposure_level'],
            risk_score=asset_risk['score'], risk_severity=asset_risk['severity'],
            risk_components=asset_risk['components'], asset_risk=asset_risk,
            weaknesses=security['weaknesses'], access_vectors=security['access_vectors'],
            fixes=security['fixes'], cve_findings=security['cve_findings'],
            exposure_findings=security['exposure_findings'], cve_source=security['cve_source'],
            node_type=ntype, compromised=False, priv_escalated=False, isolated=False,
        )

    edge_pairs = [
        ("Firewall", "User-PC"), ("Firewall", "Admin-PC"),
        ("User-PC", "Server"), ("User-PC", "File-Server"),
        ("Admin-PC", "Server"), ("Admin-PC", "File-Server"),
        ("Server", "Database"), ("File-Server", "Database"),
        ("Server", "Honeypot"), ("Admin-PC", "Honeypot"),
    ]
    for src, dst in edge_pairs:
        for edge_info in get_lateral_edges_for_target(G.nodes[dst]['open_ports']):
            G.add_edge(
                src, dst,
                connection=edge_info['connection'],
                access_vector=edge_info['vector'],
                access_port=edge_info['port'],
                mitre_code=edge_info['mitre_code'],
                mitre_desc=edge_info['mitre_desc'],
                success_prob=edge_info['success_prob'],
                reachability='POTENTIAL REACHABILITY',
            )
    return G


def build_synthetic_sme_network(num_nodes: int = 15) -> nx.DiGraph:
    """
    Generate a scalable 10-20 node synthetic SME enterprise network topology for benchmarking.
    Includes firewalls, DMZ web/mail servers, internal file/db servers, domain controllers,
    workstations, and honeypot traps.
    """
    G = nx.DiGraph()
    num_nodes = max(5, min(30, num_nodes))

    hosts = [
        ("Firewall", "192.168.1.1", "Perimeter Gateway", "perimeter", [443], ['HTTPS']),
        ("Web-Server", "192.168.1.20", "Public Web Server", "server", [80, 443, 22], ['HTTP', 'HTTPS', 'SSH']),
        ("Mail-Server", "192.168.1.25", "Corporate Mail", "server", [25, 143, 443], ['SMTP', 'IMAP', 'HTTPS']),
        ("DB-Primary", "192.168.1.30", "Customer Database", "database", [3306, 22], ['MySQL', 'SSH']),
        ("DB-Secondary", "192.168.1.31", "Analytics DB", "database", [5432], ['PostgreSQL']),
        ("File-Server", "192.168.1.40", "Internal Storage", "server", [445, 139], ['SMB', 'NetBIOS']),
        ("DC-Server", "192.168.1.50", "Domain Controller", "server", [135, 445, 3389], ['RPC', 'SMB', 'RDP']),
        ("Honeypot-DMZ", "192.168.1.98", "Decoy Trap DMZ", "honeypot", [21, 23], ['FTP', 'Telnet']),
        ("Honeypot-LAN", "192.168.1.99", "Decoy Trap Internal", "honeypot", [21, 445], ['FTP', 'SMB']),
    ]

    # Add workstations
    ws_count = max(2, num_nodes - len(hosts))
    for i in range(1, ws_count + 1):
        role_label = f"Admin-PC-{i}" if i == 1 else f"Workstation-{i}"
        ip_addr = f"192.168.1.{100 + i}"
        ports = [3389, 445] if i == 1 else [445, 22] if i % 2 == 0 else [445]
        services = ['RDP', 'SMB'] if i == 1 else ['SMB', 'SSH'] if i % 2 == 0 else ['SMB']
        hosts.append((role_label, ip_addr, "Corporate Endpoint", "endpoint", ports, services))

    hosts = hosts[:num_nodes]
    total_assets = len(hosts)

    for name, ip, role, ntype, open_ports, services in hosts:
        os_type = 'linux' if ntype in ('server', 'database') else 'windows' if ntype == 'endpoint' else 'unknown'
        device_type = 'Database Server' if ntype == 'database' else 'Web Server' if 'HTTP' in services else 'Windows Server' if ntype == 'server' else 'Windows Workstation'
        sim_role = 'Database' if ntype == 'database' else 'Server' if ntype == 'server' else 'Workstation'
        if name == 'Firewall':
            sim_role = 'Entry Node'

        security = assess_device_security(services, os_type, device_type, open_ports, sim_role, ip=ip)
        criticality = calculate_criticality(device_type, services, open_ports, os_type)
        network_comp = calculate_network_exposure_score(len(open_ports), max(0, total_assets - 1))
        asset_risk = calculate_asset_risk(
            security['vulnerability_component'],
            security['service_component'],
            security['sensitive_component'],
            calculate_criticality_score(criticality['level']),
            network_comp,
        )

        G.add_node(
            name, ip=ip, role=role, display_name=name, hostname=name, os=os_type,
            os_confidence=0.90, os_evidence=['Synthetic enterprise SME model'],
            open_ports=open_ports, services=services, version_map={}, banner_map={},
            device_type=device_type, device_confidence=0.90, device_evidence=['Synthetic enterprise SME model'],
            criticality=criticality['level'], criticality_label=criticality['label'],
            criticality_confidence=0.90, criticality_evidence=criticality['evidence'],
            vulnerability=round(asset_risk['score'] / 100.0, 3), exposure_level=security['exposure_level'],
            risk_score=asset_risk['score'], risk_severity=asset_risk['severity'],
            risk_components=asset_risk['components'], asset_risk=asset_risk,
            weaknesses=security['weaknesses'], access_vectors=security['access_vectors'],
            fixes=security['fixes'], cve_findings=security['cve_findings'],
            exposure_findings=security['exposure_findings'], cve_source=security['cve_source'],
            node_type=ntype, compromised=False, priv_escalated=False, isolated=False,
        )

    # Interconnect nodes with logical reachability
    all_names = list(G.nodes)
    for src in all_names:
        for dst in all_names:
            if src == dst:
                continue
            if G.nodes[src].get("node_type") == "perimeter" and G.nodes[dst].get("node_type") not in ("endpoint", "server"):
                continue
            for edge_info in get_lateral_edges_for_target(G.nodes[dst]['open_ports']):
                G.add_edge(
                    src, dst,
                    connection=edge_info['connection'],
                    access_vector=edge_info['vector'],
                    access_port=edge_info['port'],
                    mitre_code=edge_info['mitre_code'],
                    mitre_desc=edge_info['mitre_desc'],
                    success_prob=edge_info['success_prob'],
                    reachability='POTENTIAL REACHABILITY',
                )
    return G
