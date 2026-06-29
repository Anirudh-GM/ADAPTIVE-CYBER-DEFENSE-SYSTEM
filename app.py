"""
╔══════════════════════════════════════════════════════════════════╗
║         ADAPTIVE CYBER DEFENSE SYSTEM FOR SMEs                  ║
║         Cybersecurity Attack Simulation & Defense Platform       ║
╚══════════════════════════════════════════════════════════════════╝

VIRTUAL LAB MAPPING (UTM on MacBook M4 / Apple Silicon)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This system maps to a real UTM virtual lab:

  VM1 (User-PC)   → 192.168.1.10  → Entry point, simulates attacker's foothold
  VM2 (Server)    → 192.168.1.20  → Apache web server, lateral movement target
  VM3 (Database)  → 192.168.1.30  → MySQL database, high-value target

UTM Setup Steps (MacBook M4):
  1. Download UTM from https://mac.getutm.app/
  2. Download Ubuntu 22.04 ARM64 ISO from https://ubuntu.com/download/server/arm
  3. Create VM: New → Virtualize → Linux → Browse ISO
  4. Set RAM: 2048MB, CPU: 2 cores, Storage: 20GB
  5. Repeat for 3 VMs, assign static IPs via /etc/netplan
  6. Enable UTM Shared Network for inter-VM connectivity
  7. Verify: ping 192.168.1.20 from VM1

Real-world behavior mapping:
  - BFS traversal → ssh user@server (lateral movement)
  - Privilege escalation → sudo su (simulated as critical node delay)
  - Database compromise → mysqldump (data exfiltration simulation)

MITRE ATT&CK Alignment:
  T1021 - Remote Services (lateral movement via SSH)
  T1078 - Valid Accounts (credential reuse)
  T1068 - Exploitation for Privilege Escalation
  T1005 - Data from Local System (database exfiltration)
"""

import streamlit as st
import networkx as nx
import time
import random
import json
import re
import socket
import subprocess
import platform
from collections import deque
from pyvis.network import Network
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Exposed-service risk profiles (passive scan only — no exploitation)
SERVICE_RISKS = {
    21:   {'service': 'FTP',       'risk': 0.72, 'vector': 'FTP Anonymous/Credential Attack',  'mitre': ('T1021', 'Remote Services — FTP'),           'fix': 'Disable FTP or migrate to SFTP; block port 21 at firewall'},
    22:   {'service': 'SSH',       'risk': 0.58, 'vector': 'SSH Brute Force / Key Reuse',      'mitre': ('T1021.004', 'Remote Services — SSH'),       'fix': 'Disable password auth; use SSH keys; restrict SSH to admin VLAN'},
    23:   {'service': 'Telnet',    'risk': 0.85, 'vector': 'Telnet Cleartext Credential Theft','mitre': ('T1021', 'Remote Services — Telnet'),         'fix': 'Disable Telnet immediately; replace with SSH'},
    80:   {'service': 'HTTP',      'risk': 0.52, 'vector': 'Web App Exploit / Credential Theft','mitre': ('T1190', 'Exploit Public-Facing Application'), 'fix': 'Patch web apps; enforce HTTPS; deploy WAF'},
    135:  {'service': 'RPC',       'risk': 0.60, 'vector': 'RPC Enumeration / Lateral Movement','mitre': ('T1021', 'Remote Services — RPC'),            'fix': 'Block RPC from untrusted networks; restrict to domain controllers'},
    139:  {'service': 'NetBIOS',   'risk': 0.55, 'vector': 'NetBIOS Name Enumeration',         'mitre': ('T1046', 'Network Service Discovery'),        'fix': 'Disable NetBIOS over TCP/IP; segment LAN traffic'},
    443:  {'service': 'HTTPS',     'risk': 0.45, 'vector': 'Web Exploit / Session Hijack',     'mitre': ('T1190', 'Exploit Public-Facing Application'), 'fix': 'Keep TLS updated; enforce HSTS; patch web stack'},
    445:  {'service': 'SMB',       'risk': 0.68, 'vector': 'SMB Relay / Pass-the-Hash',        'mitre': ('T1021.002', 'Remote Services — SMB'),        'fix': 'Disable SMBv1; require SMB signing; segment file servers'},
    3306: {'service': 'MySQL',     'risk': 0.75, 'vector': 'Database Credential Attack',     'mitre': ('T1210', 'Exploitation of Remote Services'),  'fix': 'Bind MySQL to localhost; strong passwords; network ACLs'},
    3389: {'service': 'RDP',       'risk': 0.78, 'vector': 'RDP Brute Force / BlueKeep-class', 'mitre': ('T1021.001', 'Remote Services — RDP'),        'fix': 'Enable NLA; use VPN before RDP; enforce MFA; limit to jump hosts'},
    5432: {'service': 'PostgreSQL','risk': 0.72, 'vector': 'Database Credential Attack',     'mitre': ('T1210', 'Exploitation of Remote Services'),  'fix': 'Restrict pg_hba.conf; never expose DB to entire LAN'},
    5900: {'service': 'VNC',       'risk': 0.70, 'vector': 'VNC Remote Control Hijack',        'mitre': ('T1021.005', 'Remote Services — VNC'),        'fix': 'Tunnel VNC over VPN; require strong passwords'},
    8080: {'service': 'HTTP-Alt',  'risk': 0.55, 'vector': 'Admin Panel / Dev Server Exploit', 'mitre': ('T1190', 'Exploit Public-Facing Application'), 'fix': 'Remove dev services from production LAN; add auth'},
}

SCAN_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

# ─────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cyber Defense System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────
# DARK THEME CSS — Cyberpunk / Terminal Aesthetic
# ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap');

:root {
    --bg-primary: #050a0f;
    --bg-secondary: #0a1520;
    --bg-card: #0d1f2d;
    --bg-card-border: #1a3a5c;
    --accent-cyan: #00d4ff;
    --accent-green: #00ff88;
    --accent-red: #ff3355;
    --accent-orange: #ff8c00;
    --accent-yellow: #ffd700;
    --text-primary: #e0f4ff;
    --text-secondary: #7ab8d4;
    --text-muted: #3d6a8a;
    --font-mono: 'Share Tech Mono', monospace;
    --font-display: 'Orbitron', monospace;
    --font-body: 'Rajdhani', sans-serif;
}

html, body, [data-testid="stApp"] {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-body) !important;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #060d15 0%, #0a1a28 100%) !important;
    border-right: 1px solid var(--bg-card-border) !important;
}

[data-testid="stSidebar"] * {
    color: var(--text-primary) !important;
    font-family: var(--font-body) !important;
}

.stButton > button {
    background: linear-gradient(135deg, #003d5c 0%, #006b9e 100%) !important;
    color: var(--accent-cyan) !important;
    border: 1px solid var(--accent-cyan) !important;
    font-family: var(--font-display) !important;
    font-size: 0.75rem !important;
    letter-spacing: 2px !important;
    padding: 10px 28px !important;
    border-radius: 2px !important;
    text-transform: uppercase !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 0 15px rgba(0, 212, 255, 0.2) !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #00537a 0%, #0090cc 100%) !important;
    box-shadow: 0 0 30px rgba(0, 212, 255, 0.5) !important;
    transform: translateY(-1px) !important;
}

.stSelectbox > div > div {
    background: var(--bg-card) !important;
    border: 1px solid var(--bg-card-border) !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
}

.stSlider > div > div > div {
    background: var(--accent-cyan) !important;
}

.stMetric {
    background: var(--bg-card) !important;
    border: 1px solid var(--bg-card-border) !important;
    padding: 16px !important;
    border-radius: 4px !important;
}

.stMetric label {
    color: var(--text-secondary) !important;
    font-family: var(--font-display) !important;
    font-size: 0.65rem !important;
    letter-spacing: 2px !important;
}

.stMetric [data-testid="metric-container"] > div:nth-child(2) {
    color: var(--accent-cyan) !important;
    font-family: var(--font-display) !important;
}

h1, h2, h3 {
    font-family: var(--font-display) !important;
    color: var(--accent-cyan) !important;
    letter-spacing: 3px !important;
}

.stExpander {
    background: var(--bg-card) !important;
    border: 1px solid var(--bg-card-border) !important;
    border-radius: 4px !important;
}

.stExpander summary {
    color: var(--text-secondary) !important;
    font-family: var(--font-display) !important;
    font-size: 0.7rem !important;
    letter-spacing: 2px !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 3px; }

/* Custom component styles */
.cyber-header {
    background: linear-gradient(135deg, #050a0f 0%, #0a1520 50%, #050a0f 100%);
    border: 1px solid var(--bg-card-border);
    border-top: 3px solid var(--accent-cyan);
    padding: 20px 28px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}

.cyber-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 212, 255, 0.015) 2px,
        rgba(0, 212, 255, 0.015) 4px
    );
    pointer-events: none;
}

.cyber-title {
    font-family: 'Orbitron', monospace;
    font-size: 1.6rem;
    font-weight: 900;
    color: var(--accent-cyan);
    letter-spacing: 4px;
    text-transform: uppercase;
    text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
    margin: 0;
}

.cyber-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: var(--text-muted);
    letter-spacing: 3px;
    margin-top: 6px;
}

.node-card {
    background: var(--bg-card);
    border: 1px solid var(--bg-card-border);
    border-left: 3px solid;
    padding: 14px 16px;
    margin: 8px 0;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    line-height: 1.8;
}

.node-card.safe { border-left-color: var(--accent-green); }
.node-card.compromised { border-left-color: var(--accent-red); animation: pulse-red 1s infinite; }
.node-card.honeypot { border-left-color: var(--accent-yellow); }

@keyframes pulse-red {
    0%, 100% { border-left-color: var(--accent-red); box-shadow: 0 0 8px rgba(255, 51, 85, 0.3); }
    50% { border-left-color: #ff6680; box-shadow: 0 0 20px rgba(255, 51, 85, 0.6); }
}

.timeline-entry {
    display: flex;
    align-items: center;
    padding: 8px 12px;
    margin: 4px 0;
    background: var(--bg-card);
    border: 1px solid var(--bg-card-border);
    font-family: var(--font-mono);
    font-size: 0.75rem;
    gap: 12px;
}

.timeline-entry.active {
    border-color: var(--accent-red);
    background: rgba(255, 51, 85, 0.1);
    color: var(--accent-red);
}

.t-badge {
    background: rgba(0, 212, 255, 0.15);
    color: var(--accent-cyan);
    border: 1px solid var(--accent-cyan);
    padding: 2px 8px;
    font-size: 0.65rem;
    letter-spacing: 1px;
    min-width: 40px;
    text-align: center;
}

.defense-action {
    background: var(--bg-card);
    border: 1px solid;
    padding: 12px 16px;
    margin: 6px 0;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.defense-action.selected { border-color: var(--accent-green); background: rgba(0, 255, 136, 0.08); }
.defense-action.unselected { border-color: var(--text-muted); opacity: 0.5; }

.risk-bar-container {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--bg-card-border);
    height: 12px;
    border-radius: 2px;
    overflow: hidden;
    margin: 8px 0;
}

.risk-bar {
    height: 100%;
    transition: width 0.5s ease;
    border-radius: 2px;
}

.status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 8px;
}

.dot-safe { background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); }
.dot-compromised { background: var(--accent-red); box-shadow: 0 0 6px var(--accent-red); }
.dot-honeypot { background: var(--accent-yellow); box-shadow: 0 0 6px var(--accent-yellow); }
.dot-idle { background: var(--text-muted); }

.section-header {
    font-family: var(--font-display);
    font-size: 0.7rem;
    letter-spacing: 3px;
    color: var(--text-muted);
    text-transform: uppercase;
    border-bottom: 1px solid var(--bg-card-border);
    padding-bottom: 6px;
    margin: 20px 0 12px 0;
}

.mitre-tag {
    display: inline-block;
    background: rgba(255, 140, 0, 0.15);
    border: 1px solid var(--accent-orange);
    color: var(--accent-orange);
    font-family: var(--font-mono);
    font-size: 0.65rem;
    padding: 2px 8px;
    letter-spacing: 1px;
    margin: 2px;
}

.log-entry {
    font-family: var(--font-mono);
    font-size: 0.72rem;
    padding: 3px 0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    color: var(--text-secondary);
}

.log-entry .ts { color: var(--text-muted); margin-right: 8px; }
.log-entry .event-warn { color: var(--accent-orange); }
.log-entry .event-critical { color: var(--accent-red); }
.log-entry .event-ok { color: var(--accent-green); }

.honeypot-alert {
    background: rgba(255, 215, 0, 0.08);
    border: 1px solid var(--accent-yellow);
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--accent-yellow);
    margin: 8px 0;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# MODULE 1: NETWORK MODELING ENGINE
# ─────────────────────────────────────────────────────────────────

def build_network():
    G = nx.DiGraph()

    lab_hosts = [
        ("Firewall",    "192.168.1.1",  "Perimeter Defense",    "perimeter", [443],        ['HTTPS']),
        ("User-PC",     "192.168.1.10", "Workstation",          "endpoint",  [22, 445],    ['SSH', 'SMB']),
        ("Admin-PC",    "192.168.1.11", "Admin Workstation",    "endpoint",  [3389, 445],  ['RDP', 'SMB']),
        ("Server",      "192.168.1.20", "Web/App Server",       "server",    [22, 80, 443],['SSH', 'HTTP', 'HTTPS']),
        ("File-Server", "192.168.1.21", "File Server",          "server",    [445, 139],   ['SMB', 'NetBIOS']),
        ("Database",    "192.168.1.30", "MySQL Database",       "database",  [3306],       ['MySQL']),
        ("Honeypot",    "192.168.1.99", "Decoy System",         "honeypot",  [21],         ['FTP']),
    ]

    node_names = []
    for name, ip, role, ntype, open_ports, services in lab_hosts:
        os_type = 'linux' if ntype in ('server', 'database') else 'windows' if ntype == 'endpoint' else 'unknown'
        device_type = 'Server' if ntype == 'server' else 'Database Server' if ntype == 'database' else 'Computer'
        sim_role = 'Database' if ntype == 'database' else 'Server' if ntype == 'server' else 'Workstation'
        if name == 'Firewall':
            sim_role = 'Entry Node'
        security = assess_device_security(services, os_type, device_type, open_ports, sim_role)
        node_names.append(name)
        G.add_node(
            name,
            ip=ip,
            role=role,
            display_name=name,
            hostname=name,
            os=os_type,
            open_ports=open_ports,
            services=services,
            device_type=device_type,
            criticality=security['criticality'],
            vulnerability=security['vulnerability'],
            weaknesses=security['weaknesses'],
            access_vectors=security['access_vectors'],
            fixes=security['fixes'],
            node_type=ntype,
            compromised=False,
            priv_escalated=False,
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
            G.add_edge(src, dst, **{
                'connection': edge_info['connection'],
                'access_vector': edge_info['vector'],
                'access_port': edge_info['port'],
                'mitre_code': edge_info['mitre_code'],
                'mitre_desc': edge_info['mitre_desc'],
                'success_prob': edge_info['success_prob'],
            })

    return G


# ─────────────────────────────────────────────────────────────────
# MODULE 1B: REAL NETWORK SCAN ENGINE
# ─────────────────────────────────────────────────────────────────

def assign_role(i, os_type='unknown'):
    """
    Assign a logical role to a scanned device based on OS type and discovery index.
    OS-based intelligent assignment:
    - Linux: Likely server (Entry Node, Server, Database)
    - Windows: Likely workstation or server
    - macOS: Likely workstation
    - Unknown: Fallback to index-based assignment
    """
    if os_type == 'linux':
        # Linux systems often run servers
        if i == 0:
            return "Entry Node"
        elif i == 1:
            return "Server"
        elif i == 2:
            return "Database"
        else:
            return "Server"
    elif os_type == 'windows':
        # Windows can be workstation or server
        if i == 0:
            return "Entry Node"
        elif i == 1:
            return "Workstation"
        elif i == 2:
            return "Server"
        else:
            return "Workstation"
    elif os_type == 'macos':
        # macOS is typically workstation
        if i == 0:
            return "Entry Node"
        else:
            return "Workstation"
    else:
        # Unknown OS: fallback to index-based assignment
        if i == 0:
            return "Entry Node"
        elif i == 1:
            return "Server"
        elif i == 2:
            return "Database"
        else:
            return "Workstation"


def get_local_ip():
    """
    Automatically detect the local machine's IP address and subnet.
    Returns the base IP (e.g., "192.168.1.") for network scanning.
    Prioritizes active network adapters with default gateways.
    """
    system = platform.system()
    
    if system == "Windows":
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
            lines = output.split('\n')
            
            adapters = {}
            current_adapter = None
            
            # Parse ipconfig output to group by adapter
            for i, line in enumerate(lines):
                line = line.strip()
                if 'adapter' in line and ':' in line:
                    current_adapter = line
                    adapters[current_adapter] = {'ipv4': None, 'gateway': False}
                elif current_adapter:
                    # Mark as disconnected if explicitly stated
                    if 'Media State' in line and 'disconnected' in line.lower():
                        adapters[current_adapter]['ipv4'] = None
                        adapters[current_adapter]['gateway'] = False
                    elif 'IPv4 Address' in line or 'ipv4' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            ip = parts[-1].strip().split('(')[0].strip()
                            adapters[current_adapter]['ipv4'] = ip
                    elif 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != '' and gateway != '(none)':
                            adapters[current_adapter]['gateway'] = True
            
            # Collect all IPs from adapters that have IPv4
            all_ips = []
            for adapter, data in adapters.items():
                if data['ipv4']:
                    all_ips.append((data['ipv4'], data['gateway'], adapter))
            
            # Prioritize: gateway > no gateway
            all_ips.sort(key=lambda x: x[1], reverse=True)
            
            # Skip VMware adapters if possible (prioritize real network)
            for ip, has_gateway, adapter in all_ips:
                if not any(vm in ip for vm in ['192.168.93.', '192.168.193.', '10.0.0.']):
                    octets = ip.split('.')
                    if len(octets) == 4:
                        return f"{octets[0]}.{octets[1]}.{octets[2]}."
            
            # Fallback to first available IP
            if all_ips:
                octets = all_ips[0][0].split('.')
                if len(octets) == 4:
                    return f"{octets[0]}.{octets[1]}.{octets[2]}."
                    
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"Error detecting IP: {e}")
            pass
    else:
        try:
            result = subprocess.run(
                ["ifconfig" if system == "Darwin" else "ip", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            output = result.stdout
            # Parse IPv4 address from ifconfig/ip output
            for line in output.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    # Extract IP address
                    parts = line.split()
                    for part in parts:
                        if '.' in part and part.count('.') == 3:
                            ip = part
                            octets = ip.split('.')
                            if len(octets) == 4:
                                return f"{octets[0]}.{octets[1]}.{octets[2]}."
        except (subprocess.TimeoutExpired, OSError):
            pass
    
    # Fallback to common private network ranges
    return "192.168.1."


def _clean_hostname(name, ip):
    """Normalize a resolved hostname for display."""
    if not name:
        return None
    name = name.strip().rstrip('.')
    name = re.sub(r'\.local$', '', name, flags=re.IGNORECASE)
    if not name or name == ip or name.replace('.', '') == ip.replace('.', ''):
        return None
    return name


def resolve_hostname_ping(ip, system):
    """Resolve friendly device name via ping -a (Windows) or ping output."""
    try:
        if system == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", "-a", ip],
                capture_output=True,
                text=True,
                timeout=2,
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=2,
            )
        match = re.search(r'Pinging\s+(.+?)\s+\[', result.stdout, re.IGNORECASE)
        if match:
            return _clean_hostname(match.group(1), ip)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def resolve_hostname_netbios(ip):
    """Resolve NetBIOS/mDNS-style name via nbtstat (Windows). Good for phones on LAN."""
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=3,
        )
        for line in result.stdout.splitlines():
            match = re.match(r'\s*([A-Za-z0-9\-_ ]+?)\s+<00>\s+UNIQUE', line)
            if match:
                name = _clean_hostname(match.group(1).strip(), ip)
                if name and len(name) > 1:
                    return name.replace(' ', '-')
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return None


def resolve_hostname_dns(ip):
    """Reverse DNS lookup via socket or dig/host."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        cleaned = _clean_hostname(hostname, ip)
        if cleaned:
            return cleaned
    except (socket.herror, socket.gaierror, OSError):
        pass

    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["nslookup", ip],
                capture_output=True,
                text=True,
                timeout=3,
            )
            for line in result.stdout.split('\n'):
                if 'Name:' in line:
                    cleaned = _clean_hostname(line.split('Name:')[-1].strip(), ip)
                    if cleaned:
                        return cleaned
        else:
            for cmd in (
                ["dig", "+short", "-x", ip],
                ["host", ip],
            ):
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                    output = result.stdout.strip()
                    if cmd[0] == "dig":
                        cleaned = _clean_hostname(output.rstrip('.'), ip)
                    elif 'pointer' in output.lower():
                        cleaned = _clean_hostname(output.split('pointer')[-1].strip().rstrip('.'), ip)
                    else:
                        cleaned = None
                    if cleaned:
                        return cleaned
                except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
                    continue
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def resolve_hostname(ip):
    """
    Resolve hostname using multiple methods: ping name, NetBIOS, reverse DNS.
    Returns the best available friendly device name or None.
    """
    system = platform.system()
    for resolver in (
        lambda: resolve_hostname_ping(ip, system),
        lambda: resolve_hostname_netbios(ip) if system == "Windows" else None,
        lambda: resolve_hostname_dns(ip),
    ):
        name = resolver()
        if name:
            return name
    return None


def detect_os(ip, system):
    """
    Detect operating system using TTL analysis from ping response.
    Returns: 'windows', 'linux', 'macos', or 'unknown'
    TTL ranges: Windows (~128), Linux (~64), macOS (~255)
    """
    try:
        if system == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                capture_output=True,
                text=True,
                timeout=1
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=1
            )
        
        if result.returncode == 0:
            output = result.stdout
            # Extract TTL from ping output - more robust parsing
            for line in output.split('\n'):
                # Look for TTL in various formats
                if 'TTL=' in line or 'ttl=' in line:
                    # Format: "TTL=128" or "ttl=64"
                    for part in line.split():
                        if '=' in part and ('TTL' in part.upper() or 'ttl' in part.lower()):
                            try:
                                ttl_str = part.split('=')[1]
                                ttl = int(ttl_str)
                                # OS detection based on TTL with broader ranges
                                if ttl >= 110 and ttl <= 130:
                                    return 'windows'
                                elif ttl >= 55 and ttl <= 75:
                                    return 'linux'
                                elif ttl >= 240 and ttl <= 260:
                                    return 'macos'
                            except (ValueError, IndexError):
                                pass
                # Also check for "TTL" followed by number
                elif 'TTL' in line or 'ttl' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if 'TTL' in part.upper() or 'ttl' in part.lower():
                            # Try to get next part as number
                            if i + 1 < len(parts):
                                try:
                                    ttl = int(parts[i + 1])
                                    if ttl >= 110 and ttl <= 130:
                                        return 'windows'
                                    elif ttl >= 55 and ttl <= 75:
                                        return 'linux'
                                    elif ttl >= 240 and ttl <= 260:
                                        return 'macos'
                                except ValueError:
                                    pass
                            # Try to extract number from same part if it contains TTL
                            try:
                                ttl = int(''.join(filter(str.isdigit, part)))
                                if ttl >= 110 and ttl <= 130:
                                    return 'windows'
                                elif ttl >= 55 and ttl <= 75:
                                    return 'linux'
                                elif ttl >= 240 and ttl <= 260:
                                    return 'macos'
                            except ValueError:
                                pass
    except (subprocess.TimeoutExpired, OSError):
        pass
    
    return 'unknown'


def ping_ip(ip, system):
    """Ping a single IP address and return (ip, is_alive, ttl)"""
    try:
        if system == "Windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                capture_output=True,
                text=True,
                timeout=1
            )
        elif system == "Darwin":
            result = subprocess.run(
                ["ping", "-c", "1", "-t", "1", ip],
                capture_output=True,
                text=True,
                timeout=1
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=1
            )
        
        is_alive = result.returncode == 0
        ttl = None
        
        if is_alive:
            # Extract TTL from output
            output = result.stdout
            for line in output.split('\n'):
                if 'TTL=' in line or 'ttl=' in line:
                    for part in line.split():
                        if '=' in part and ('TTL' in part.upper() or 'ttl' in part.lower()):
                            try:
                                ttl_str = part.split('=')[1]
                                ttl = int(ttl_str)
                                break
                            except (ValueError, IndexError):
                                pass
                if ttl:
                    break
        
        return (ip, is_alive, ttl)
    except (subprocess.TimeoutExpired, OSError):
        return (ip, False, None)


def ttl_to_os(ttl):
    """Convert TTL value to OS type"""
    if ttl is None:
        return 'unknown'
    if ttl >= 110 and ttl <= 130:
        return 'windows'
    elif ttl >= 55 and ttl <= 75:
        return 'linux'
    elif ttl >= 240 and ttl <= 260:
        return 'macos'
    return 'unknown'


def assess_device_security(services, os_type, device_type, open_ports, role):
    """
    Derive vulnerability score, access vectors, weaknesses, and fixes from scan data.
    Passive assessment only — no exploitation performed.
    """
    weaknesses = []
    access_vectors = []
    fixes = []
    base_vuln = 0.20

    for port in open_ports:
        info = SERVICE_RISKS.get(port)
        if not info:
            continue
        label = f"Exposed {info['service']} (port {port}) — {info['vector']}"
        if label not in weaknesses:
            weaknesses.append(label)
        if info['vector'] not in access_vectors:
            access_vectors.append(info['vector'])
        if info['fix'] not in fixes:
            fixes.append(info['fix'])
        base_vuln = max(base_vuln, info['risk'])

    if device_type in ('Mobile Phone', 'Tablet'):
        base_vuln = max(base_vuln, 0.38)
        weaknesses.append('Mobile device on LAN — phishing / credential theft foothold')
        fixes.append('Move mobile devices to guest VLAN; enforce MDM and screen lock')

    if os_type == 'windows' and 'SMB' in services:
        base_vuln = max(base_vuln, 0.62)
        if 'Windows host with SMB exposed — domain credential relay risk' not in weaknesses:
            weaknesses.append('Windows host with SMB exposed — domain credential relay risk')
            fixes.append('Enable Windows Defender Firewall; restrict SMB to file-server subnet')

    if role == 'Database':
        base_vuln = max(base_vuln, 0.70)
        weaknesses.append('Database tier reachable from LAN — high-value target')
        fixes.append('Place database on isolated VLAN; allow only app-server IPs')

    if not weaknesses:
        weaknesses.append('Host reachable on network — baseline lateral movement target')
        fixes.append('Apply OS patches; enable host firewall; remove unnecessary services')

    criticality = 2
    if role in ('Database', 'Server') or device_type in ('Database Server', 'Server'):
        criticality = 5
    elif role == 'Entry Node':
        criticality = 3
    elif device_type in ('Mobile Phone', 'Tablet'):
        criticality = 2
    elif any(s in services for s in ('RDP', 'SSH', 'SMB')):
        criticality = 4
    elif services:
        criticality = 3

    return {
        'vulnerability': round(min(base_vuln, 0.95), 2),
        'weaknesses': weaknesses,
        'access_vectors': access_vectors,
        'fixes': fixes,
        'criticality': criticality,
    }


def get_lateral_edges_for_target(open_ports):
    """Return edge metadata for each exploitable access path to a target host."""
    edges = []
    for port in open_ports:
        info = SERVICE_RISKS.get(port)
        if info:
            edges.append({
                'port': port,
                'service': info['service'],
                'vector': info['vector'],
                'mitre_code': info['mitre'][0],
                'mitre_desc': info['mitre'][1],
                'success_prob': info['risk'],
                'connection': f"{info['service'].lower()}/{port}",
            })
    if not edges:
        edges.append({
            'port': 0,
            'service': 'LAN',
            'vector': 'Network Reachability / Credential Reuse',
            'mitre_code': 'T1078',
            'mitre_desc': 'Valid Accounts — LAN foothold spread',
            'success_prob': 0.35,
            'connection': 'lan/reachability',
        })
    return edges


def ip_in_subnet(ip, base_ip):
    """True when ip belongs to the /24 prefix implied by base_ip (e.g. 192.168.1.)."""
    prefix = base_ip if base_ip.endswith('.') else f"{base_ip}."
    return ip.startswith(prefix)


def parse_arp_table(output, subnet_prefix):
    """
    Parse arp -a / ip neigh output into {ip: mac} for the local subnet.
    """
    entries = {}
    base_ip = subnet_prefix if subnet_prefix.endswith('.') else f"{subnet_prefix}."

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('Interface') or 'Internet Address' in line:
            continue

        # Windows: 192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic
        win_match = re.match(
            r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+',
            line,
        )
        if win_match:
            ip, mac = win_match.group(1), win_match.group(2).replace('-', ':').upper()
            if ip_in_subnet(ip, base_ip) and mac != 'FF:FF:FF:FF:FF:FF':
                entries[ip] = mac
            continue

        # Linux/macOS: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        unix_match = re.search(
            r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})',
            line,
        )
        if unix_match:
            ip, mac = unix_match.group(1), unix_match.group(2).upper()
            if ip_in_subnet(ip, base_ip) and mac != 'FF:FF:FF:FF:FF:FF':
                entries[ip] = mac

    return entries


def read_arp_map(subnet_prefix):
    """Read the system ARP/neighbor table for devices on the scanned subnet."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        else:
            try:
                result = subprocess.run(
                    ["ip", "neigh", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except FileNotFoundError:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
        return parse_arp_table(result.stdout, subnet_prefix)
    except (subprocess.TimeoutExpired, OSError):
        return {}


def lookup_mac_windows(ip):
    """Look up MAC for a single IP using Get-NetNeighbor (Windows)."""
    try:
        result = subprocess.run(
            [
                "powershell", "-Command",
                f"(Get-NetNeighbor -IPAddress '{ip}' -ErrorAction SilentlyContinue | "
                "Select-Object -First 1 -ExpandProperty LinkLayerAddress)",
            ],
            capture_output=True,
            text=True,
            timeout=2,
        )
        mac = result.stdout.strip().replace('-', ':').upper()
        if re.fullmatch(r'([0-9A-F]{2}:){5}[0-9A-F]{2}', mac):
            return mac
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def is_tablet_device(hostname):
    """Detect tablets (iPad, Galaxy Tab, etc.)."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    tablet_patterns = ['ipad', 'tablet', 'tab-', 'tab_', 'sm-t', 'sm-x', 'lenovo tab', 'surface']
    return any(pattern in hostname_lower for pattern in tablet_patterns)


def is_mobile_device(hostname, ip):
    """Detect if device is mobile based on hostname patterns."""
    if is_tablet_device(hostname):
        return True
    if not hostname:
        return False

    hostname_lower = hostname.lower()
    mobile_patterns = [
        'iphone', 'ipad', 'android', 'mobile', 'phone', 'tablet',
        'samsung', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'oppo',
        'vivo', 'huawei', 'honor', 'realme', 'motorola', 'lg',
        'nokia', 'sony', 'htc', 'blackberry', 'windows-phone',
        'redmi', 'poco', 'nothing-phone',
    ]
    if any(pattern in hostname_lower for pattern in mobile_patterns):
        return True
    if "'s " in hostname_lower or "s iphone" in hostname_lower or "s ipad" in hostname_lower:
        return True
    if any(model in hostname_lower for model in ['sm-', 'rmx', 'cph', 'redmi', 'poco']):
        return True
    return False


def identify_device_type(hostname, os_type, is_mobile, services):
    """Classify a discovered device into a human-readable category."""
    if is_tablet_device(hostname):
        return "Tablet"
    if is_mobile:
        return "Mobile Phone"

    hostname_lower = (hostname or '').lower()
    router_hints = ['router', 'gateway', 'modem', 'ap-', 'wifi', 'fritz', 'tplink', 'netgear', 'asus']
    if any(h in hostname_lower for h in router_hints):
        return "Router/Gateway"
    if any(s in services for s in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return "Database Server"
    if any(s in services for s in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'SSH', 'RDP', 'DNS', 'SMB']):
        return "Server"
    if os_type == 'macos':
        return "Mac"
    if os_type in ('windows', 'linux'):
        return "Computer"
    return "Network Device"


def format_device_display_name(hostname, device_type, ip):
    """Build a readable label such as \"John's iPhone (Mobile Phone)\"."""
    if hostname and device_type:
        if device_type.lower() in hostname.lower():
            return hostname
        return f"{hostname} ({device_type})"
    if hostname:
        return hostname
    if device_type:
        return f"{device_type} @ {ip}"
    return ip


def scan_ports(ip, ports):
    """
    Scan specific ports on an IP to detect services using parallel scanning.
    Returns list of open ports.
    """
    open_ports = []
    system = platform.system()

    def check_port(port):
        try:
            if system == "Windows":
                result = subprocess.run(
                    [
                        "powershell", "-Command",
                        f"Test-NetConnection -ComputerName {ip} -Port {port} "
                        "-InformationLevel Quiet -WarningAction SilentlyContinue",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return port if result.stdout.strip() == 'True' else None
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.4)
                if sock.connect_ex((ip, port)) == 0:
                    return port
        except (subprocess.TimeoutExpired, OSError, socket.error):
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return open_ports


def detect_services(open_ports):
    """
    Identify services based on open ports.
    Returns list of service names.
    """
    port_service_map = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        135: 'RPC',
        139: 'NetBIOS',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
    }
    
    services = []
    for port in open_ports:
        if port in port_service_map:
            services.append(port_service_map[port])
    
    return services


def assign_role_from_services(services, os_type, device_type):
    """Assign simulation role from detected services and device type."""
    if any(db in services for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return 'Database'
    if any(web in services for web in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt']):
        return 'Server'
    if 'SMB' in services:
        return 'Server'
    if any(remote in services for remote in ['SSH', 'RDP', 'VNC', 'Telnet']):
        return 'Server'
    if any(email in services for email in ['SMTP', 'POP3', 'IMAP']):
        return 'Server'
    if 'DNS' in services:
        return 'Server'
    if device_type in ('Mobile Phone', 'Tablet'):
        return 'Workstation'
    if os_type in ['windows', 'linux', 'macos']:
        return 'Workstation'
    return 'Workstation'


def scan_network(base_ip=None, limit=254):
    """
    Network discovery: ping sweep, ARP/MAC lookup, hostname resolution, and device typing.
    Returns list of tuples:
    (ip, hostname, os, is_mobile, mac, open_ports, services, device_type, display_name)
    """
    if base_ip is None:
        base_ip = get_local_ip()

    system = platform.system()
    subnet_prefix = base_ip.rstrip('.')
    ips = [f"{base_ip}{i}" for i in range(1, limit + 1)]
    ping_results = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_ip, ip, system): ip for ip in ips}
        for future in as_completed(futures):
            ip, is_alive, ttl = future.result()
            if is_alive:
                ping_results[ip] = ttl

    # Step 2: Read ARP table after ping sweep (MAC addresses now cached)
    arp_map = read_arp_map(subnet_prefix)

    # Step 3: Merge ping-responsive hosts with ARP-only hosts on this subnet
    candidate_ips = set(ping_results.keys()) | set(arp_map.keys())
    candidate_ips = {ip for ip in candidate_ips if ip_in_subnet(ip, base_ip)}

    def enrich_device(ip):
        ttl = ping_results.get(ip)
        mac = arp_map.get(ip)
        if not mac and system == "Windows":
            mac = lookup_mac_windows(ip)

        hostname = resolve_hostname(ip)
        os_type = ttl_to_os(ttl)
        is_mobile = is_mobile_device(hostname, ip)
        open_ports = scan_ports(ip, SCAN_PORTS) if ip in ping_results else []
        services = detect_services(open_ports)
        device_type = identify_device_type(hostname, os_type, is_mobile, services)
        display_name = format_device_display_name(hostname, device_type, ip)

        return {
            'hostname': hostname,
            'os': os_type,
            'is_mobile': is_mobile,
            'mac': mac,
            'open_ports': open_ports,
            'services': services,
            'device_type': device_type,
            'display_name': display_name,
        }

    devices = {}
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(enrich_device, ip): ip for ip in sorted(candidate_ips)}
        for future in as_completed(futures):
            ip = futures[future]
            devices[ip] = future.result()

    return [
        (
            ip,
            data['hostname'],
            data['os'],
            data['is_mobile'],
            data['mac'],
            data['open_ports'],
            data['services'],
            data['device_type'],
            data['display_name'],
        )
        for ip, data in sorted(devices.items(), key=lambda item: tuple(map(int, item[0].split('.'))))
    ]


def _parse_device_record(device):
    """Normalize scan tuples into a consistent device dict."""
    open_ports = []
    device_type = 'Network Device'
    display_name = None
    if isinstance(device, tuple):
        if len(device) >= 9:
            ip, hostname, os_type, is_mobile, mac, open_ports, services, device_type, display_name = device[:9]
        elif len(device) == 7:
            ip, hostname, os_type, is_mobile, mac, services, device_type = device[:7]
            open_ports = []
        elif len(device) == 4:
            ip, hostname, os_type, is_mobile = device
            mac, services = None, []
        elif len(device) == 2:
            ip, hostname = device
            os_type, is_mobile, mac, services = 'unknown', False, None, []
        else:
            ip = device[0]
            hostname, os_type, is_mobile, mac, services = None, 'unknown', False, None, []
    else:
        ip = device
        hostname, os_type, is_mobile, mac, services = None, 'unknown', False, None, []

    if not display_name:
        display_name = format_device_display_name(hostname, device_type, ip)
    return {
        'ip': ip,
        'hostname': hostname,
        'os': os_type,
        'is_mobile': is_mobile,
        'mac': mac,
        'open_ports': open_ports or [],
        'services': services or [],
        'device_type': device_type,
        'display_name': display_name,
    }


def build_dynamic_graph(devices):
    """
    Build attack graph from scanned devices.
    Nodes carry assessed vulnerabilities; edges represent lateral movement via open services.
    """
    G = nx.DiGraph()
    node_type_map = {
        "Entry Node":  "endpoint",
        "Server":      "server",
        "Database":    "database",
        "Workstation": "endpoint",
    }

    parsed = [_parse_device_record(d) for d in devices]
    node_names = []

    for rec in parsed:
        role = assign_role_from_services(rec['services'], rec['os'], rec['device_type'])
        security = assess_device_security(
            rec['services'], rec['os'], rec['device_type'], rec['open_ports'], role,
        )
        ntype = node_type_map.get(role, "endpoint")
        node_name = f"{role}\n{rec['display_name']}"
        node_names.append(node_name)
        G.add_node(
            node_name,
            ip=rec['ip'],
            hostname=rec['hostname'],
            os=rec['os'],
            is_mobile=rec['is_mobile'],
            mac=rec['mac'],
            open_ports=rec['open_ports'],
            services=rec['services'],
            device_type=rec['device_type'],
            display_name=rec['display_name'],
            role=role,
            criticality=security['criticality'],
            vulnerability=security['vulnerability'],
            weaknesses=security['weaknesses'],
            access_vectors=security['access_vectors'],
            fixes=security['fixes'],
            node_type=ntype,
            compromised=False,
            priv_escalated=False,
        )

    # Flat LAN: any compromised host can attempt lateral movement to any other host
    for src in node_names:
        for dst in node_names:
            if src == dst:
                continue
            dst_ports = G.nodes[dst]['open_ports']
            for edge_info in get_lateral_edges_for_target(dst_ports):
                G.add_edge(
                    src, dst,
                    connection=edge_info['connection'],
                    access_vector=edge_info['vector'],
                    access_port=edge_info['port'],
                    mitre_code=edge_info['mitre_code'],
                    mitre_desc=edge_info['mitre_desc'],
                    success_prob=edge_info['success_prob'],
                )

    return G


# ─────────────────────────────────────────────────────────────────
# MODULE 2: ATTACK SIMULATION ENGINE
# ─────────────────────────────────────────────────────────────────

def simulate_attack(G, entry_node, seed=42):
    """
    BFS lateral movement simulation from a compromised entry point.
    Uses service-based edges and assessed vulnerabilities — no real exploitation.
    Returns timeline, compromised set, honeypot flag, and propagation stats.
    """
    random.seed(seed)
    timeline = []
    compromised = set()
    priv_escalated = set()
    attack_paths = []
    honeypot_triggered = False

    if entry_node not in G.nodes:
        return timeline, compromised, honeypot_triggered, {}

    # Compromise entry foothold
    entry_data = G.nodes[entry_node]
    compromised.add(entry_node)
    G.nodes[entry_node]["compromised"] = True
    timeline.append({
        "node": entry_node,
        "from_node": None,
        "timestep": 1,
        "mitre_code": "T1078",
        "mitre_desc": "Initial Access — foothold on entry system",
        "access_vector": "Initial compromise / phishing / stolen credentials",
        "success": True,
        "vuln": entry_data["vulnerability"],
        "criticality": entry_data["criticality"],
        "ntype": entry_data.get("node_type", "endpoint"),
        "priv_esc": False,
    })
    attack_paths.append([entry_node])

    visited = {entry_node}
    queue = deque([(entry_node, 1, [entry_node])])

    while queue:
        current_node, timestep, path = queue.popleft()
        if current_node not in compromised:
            continue

        for neighbor in G.successors(current_node):
            if neighbor in visited:
                continue

            edge = G.edges[current_node, neighbor]
            nd = G.nodes[neighbor]
            ntype = nd.get("node_type", "endpoint")

            if ntype == "honeypot":
                prob = nd["vulnerability"]
                mitre_code, mitre_desc = "T1003", "OS Credential Dumping [TRAP]"
                access_vector = edge.get("access_vector", "Honeypot probe")
            else:
                prob = min(0.95, edge.get("success_prob", 0.4) * nd["vulnerability"])
                if nd["criticality"] >= 4:
                    prob *= 0.85
                mitre_code = edge.get("mitre_code", "T1021")
                mitre_desc = edge.get("mitre_desc", "Lateral Movement")
                access_vector = edge.get("access_vector", edge.get("connection", "network"))

            success = random.random() < prob
            visited.add(neighbor)
            actual_timestep = timestep + 1
            did_priv_esc = False

            if success:
                compromised.add(neighbor)
                G.nodes[neighbor]["compromised"] = True
                new_path = path + [neighbor]
                attack_paths.append(new_path)
                queue.append((neighbor, actual_timestep, new_path))

                if nd["criticality"] >= 4 and neighbor not in priv_escalated:
                    priv_escalated.add(neighbor)
                    G.nodes[neighbor]["priv_escalated"] = True
                    did_priv_esc = True
                    timeline.append({
                        "node": neighbor,
                        "from_node": current_node,
                        "timestep": actual_timestep + 1,
                        "mitre_code": "T1068",
                        "mitre_desc": "Privilege Escalation — admin/root on high-value system",
                        "access_vector": "Credential dump / sudo / token theft",
                        "success": True,
                        "vuln": nd["vulnerability"],
                        "criticality": nd["criticality"],
                        "ntype": ntype,
                        "priv_esc": True,
                    })

                if ntype == "honeypot":
                    honeypot_triggered = True

            timeline.append({
                "node": neighbor,
                "from_node": current_node,
                "timestep": actual_timestep,
                "mitre_code": mitre_code,
                "mitre_desc": mitre_desc,
                "access_vector": access_vector,
                "success": success,
                "vuln": nd["vulnerability"],
                "criticality": nd["criticality"],
                "ntype": ntype,
                "priv_esc": did_priv_esc,
            })

    timeline.sort(key=lambda x: x["timestep"])
    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    max_hops = max((len(p) - 1 for p in attack_paths), default=0)

    stats = {
        "systems_controlled": len(real_compromised),
        "total_systems": len(real_nodes),
        "max_lateral_hops": max_hops,
        "privilege_escalations": len(priv_escalated),
        "attack_paths": attack_paths[:10],
        "reachable_from_entry": len(real_compromised),
    }

    return timeline, compromised, honeypot_triggered, stats


# ─────────────────────────────────────────────────────────────────
# MODULE 3: RISK (BLAST RADIUS) ENGINE
# ─────────────────────────────────────────────────────────────────

def calculate_risk(G, compromised_nodes, timeline, honeypot_triggered, attack_stats=None):
    W1, W2, W3 = 0.3, 0.5, 0.2

    total_nodes = len(G.nodes)
    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised_nodes if G.nodes[n].get("node_type") != "honeypot"]

    spread = len(real_compromised) / max(len(real_nodes), 1)

    all_criticality = sum(G.nodes[n]["criticality"] for n in real_nodes)
    compromised_criticality = sum(G.nodes[n]["criticality"] for n in real_compromised)
    critical_impact = compromised_criticality / max(all_criticality, 1)

    max_timestep = max((t["timestep"] for t in timeline), default=1)
    depth = max_timestep / max(total_nodes, 1)

    R = (W1 * spread) + (W2 * critical_impact) + (W3 * depth)
    risk_score = R * 100

    if honeypot_triggered:
        risk_score = min(100, risk_score + 15)

    stats = attack_stats or {}
    blast_details = {
        "spread": round(spread * 100, 1),
        "critical_impact": round(critical_impact * 100, 1),
        "depth": round(depth * 100, 1),
        "compromised_count": len(real_compromised),
        "total_real_nodes": len(real_nodes),
        "systems_controlled": stats.get("systems_controlled", len(real_compromised)),
        "max_lateral_hops": stats.get("max_lateral_hops", 0),
        "privilege_escalations": stats.get("privilege_escalations", 0),
        "attack_paths": stats.get("attack_paths", []),
    }

    return round(risk_score, 1), blast_details


# ─────────────────────────────────────────────────────────────────
# MODULE 4: DEFENSE OPTIMIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

def get_defense_actions(G, compromised_nodes, risk_score):
    """Generate prioritized remediation actions from assessed weaknesses on compromised nodes."""
    actions = []
    seen_fixes = set()

    for node in compromised_nodes:
        if G.nodes[node].get("node_type") == "honeypot":
            continue
        nd = G.nodes[node]
        crit = nd["criticality"]
        vuln = nd["vulnerability"]
        display = nd.get("display_name", node)

        for fix in nd.get("fixes", []):
            if fix in seen_fixes:
                continue
            seen_fixes.add(fix)
            fix_cost = int(12 + crit * 4)
            fix_reduction = round(vuln * crit * 3.5, 1)
            actions.append({
                "action": f"Fix: {fix[:55]}{'...' if len(fix) > 55 else ''}",
                "node": node,
                "type": "patch",
                "cost": fix_cost,
                "risk_reduction": fix_reduction,
                "efficiency": round(fix_reduction / fix_cost, 3),
                "description": f"{display} [{nd['ip']}] — {fix}",
            })

        for weakness in nd.get("weaknesses", [])[:2]:
            isolate_cost = int(18 + crit * 6)
            isolate_reduction = round(crit * 2.8, 1)
            action_key = f"Block: {weakness[:40]}"
            if action_key in seen_fixes:
                continue
            seen_fixes.add(action_key)
            actions.append({
                "action": action_key,
                "node": node,
                "type": "isolate",
                "cost": isolate_cost,
                "risk_reduction": isolate_reduction,
                "efficiency": round(isolate_reduction / isolate_cost, 3),
                "description": f"Segment or firewall {display} to block: {weakness}",
            })

        if crit >= 4:
            priv_cost = int(10 + crit * 3)
            priv_reduction = round(crit * 3.2, 1)
            actions.append({
                "action": f"Least Privilege on {display[:30]}",
                "node": node,
                "type": "privilege",
                "cost": priv_cost,
                "risk_reduction": priv_reduction,
                "efficiency": round(priv_reduction / priv_cost, 3),
                "description": f"Remove admin rights on {display}; enforce MFA and PAM",
            })

    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS / SIEM",
        "node": "ALL",
        "type": "ids",
        "cost": ids_cost,
        "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Detect lateral movement (Snort/Suricata/Wazuh) across the LAN",
    })

    segment_cost = 25
    segment_reduction = round(risk_score * 0.15, 1)
    actions.append({
        "action": "Network Segmentation (VLANs)",
        "node": "ALL",
        "type": "isolate",
        "cost": segment_cost,
        "risk_reduction": segment_reduction,
        "efficiency": round(segment_reduction / segment_cost, 3),
        "description": "Split workstations, servers, and databases into separate VLANs with ACLs",
    })

    actions.sort(key=lambda x: x["efficiency"], reverse=True)
    return actions


def greedy_defense_selection(actions, budget):
    """
    Greedy fractional knapsack selection.
    Selects actions with highest risk_reduction/cost ratio within budget.
    """
    selected = []
    remaining_budget = budget
    total_reduction = 0.0

    for action in actions:
        if action["cost"] <= remaining_budget:
            selected.append(action)
            remaining_budget -= action["cost"]
            total_reduction += action["risk_reduction"]

    return selected, round(total_reduction, 1), remaining_budget


# ─────────────────────────────────────────────────────────────────
# MODULE 5: GRAPH VISUALIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

def render_graph(G, compromised_set=None, current_node=None, show_honeypot=True):
    """
    Renders PyVis network graph with dark cyberpunk styling.
    Blue = safe, Red = compromised, Yellow = honeypot, Orange = current
    """
    if compromised_set is None:
        compromised_set = set()

    net = Network(
        height="480px",
        width="100%",
        bgcolor="#050a0f",
        font_color="#7ab8d4",
        directed=True
    )

    net.set_options("""
    {
      "nodes": {
        "borderWidth": 2,
        "shadow": { "enabled": true, "size": 15 },
        "font": { "size": 13, "face": "Share Tech Mono" }
      },
      "edges": {
        "arrows": { "to": { "enabled": true, "scaleFactor": 0.8 } },
        "color": { "color": "#1a3a5c", "highlight": "#00d4ff" },
        "smooth": { "type": "curvedCW", "roundness": 0.2 },
        "width": 1.5,
        "shadow": { "enabled": false }
      },
      "physics": {
        "enabled": true,
        "barnesHut": {
          "gravitationalConstant": -4000,
          "centralGravity": 0.4,
          "springLength": 140,
          "springConstant": 0.04,
          "damping": 0.09
        }
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100
      }
    }
    """)

    type_shapes = {
        "perimeter": "diamond",
        "endpoint":  "dot",
        "server":    "square",
        "database":  "database",
        "honeypot":  "star",
    }

    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "endpoint")
        is_compromised = node in compromised_set
        is_current = node == current_node
        is_honeypot = ntype == "honeypot"

        if not show_honeypot and is_honeypot:
            continue

        # Colors based on state
        if is_current:
            color = {"background": "#ff8c00", "border": "#ffd700", "highlight": {"background": "#ffaa33"}}
            size = 32
        elif is_compromised and is_honeypot:
            color = {"background": "#ff3355", "border": "#ffd700", "highlight": {"background": "#ff5577"}}
            size = 28
        elif is_compromised:
            color = {"background": "#6b0018", "border": "#ff3355", "highlight": {"background": "#cc0033"}}
            size = 26
        elif is_honeypot:
            color = {"background": "#3d2800", "border": "#ffd700", "highlight": {"background": "#5a3d00"}}
            size = 22
        else:
            color = {"background": "#002d4a", "border": "#00d4ff", "highlight": {"background": "#003d60"}}
            size = 22

        tooltip = (
            f"<div style='font-family:Share Tech Mono;font-size:11px;color:#e0f4ff;background:#0d1f2d;padding:8px;border:1px solid #1a3a5c'>"
            f"<b style='color:#00d4ff'>{node}</b><br>"
            f"IP: {data['ip']}<br>"
            f"Role: {data['role']}<br>"
            f"Criticality: {'★' * data['criticality']}<br>"
            f"Vulnerability: {int(data['vulnerability']*100)}%<br>"
            f"Status: {'🔴 COMPROMISED' if is_compromised else '🟡 HONEYPOT' if is_honeypot else '🟢 SECURE'}"
            f"</div>"
        )

        short_label = node.replace("-", "\n")
        # For dynamic graph nodes that already contain "\n" (Role\nIP format), use as-is
        if "\n" in node:
            short_label = node
        net.add_node(
            node,
            label=short_label,
            title=tooltip,
            color=color,
            size=size,
            shape=type_shapes.get(ntype, "dot"),
        )

    for src, dst, data in G.edges(data=True):
        if not show_honeypot and (G.nodes[src].get("node_type") == "honeypot" or G.nodes[dst].get("node_type") == "honeypot"):
            continue

        src_comp = src in compromised_set
        dst_comp = dst in compromised_set

        if src_comp and dst_comp:
            edge_color = "#ff3355"
            width = 3
        elif src_comp:
            edge_color = "#ff8c00"
            width = 2
        else:
            edge_color = "#1a3a5c"
            width = 1.5

        net.add_edge(src, dst,
                     title=data.get("connection", ""),
                     color=edge_color,
                     width=width)

    # Write to temp HTML and return path
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", dir=tempfile.gettempdir())
    net.save_graph(tmp.name)
    tmp.close()

    with open(tmp.name, "r", encoding="utf-8") as f:
        html = f.read()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass

    # Inject dark background override
    html = html.replace(
        "body {",
        "body { background-color: #050a0f !important; margin: 0; padding: 0; "
    )
    return html


# ─────────────────────────────────────────────────────────────────
# MODULE 5B: HONEYPOT ENGINE
# ─────────────────────────────────────────────────────────────────

def generate_attack_log(timeline, honeypot_triggered):
    log = []
    base_time = "09:42"

    # Simulated log entries based on timeline
    fake_services = {
        "Firewall":    ("443/tcp", "HTTPS"),
        "User-PC":     ("22/tcp",  "SSH"),
        "Admin-PC":    ("3389/tcp","RDP"),
        "Server":      ("80/tcp",  "HTTP"),
        "File-Server": ("445/tcp", "SMB"),
        "Database":    ("3306/tcp","MySQL"),
        "Honeypot":    ("21/tcp",  "FTP"),
    }

    mitre_log = {
        "T1190": "exploit_public_app",
        "T1078": "valid_account_brute",
        "T1021": "lateral_move_ssh",
        "T1005": "data_staged_exfil",
        "T1003": "credential_dump_lsass",
        "T1068": "priv_esc_sudo",
    }

    for i, entry in enumerate(timeline[:8]):
        node = entry["node"]
        port, svc = fake_services.get(node, ("*/*", "tcp"))
        action = mitre_log.get(entry.get("mitre_code", ""), "scan_probe")
        ip = "10.0.0." + str(random.randint(50, 254))
        status = "SUCCESS" if entry["success"] else "BLOCKED"
        severity = "critical" if entry["success"] else "ok"
        log.append({
            "time": f"09:{42+i:02d}:{random.randint(10,59):02d}",
            "src_ip": ip,
            "dst": node,
            "port": port,
            "action": action,
            "status": status,
            "severity": severity
        })

    if honeypot_triggered:
        log.append({
            "time": "09:50:01",
            "src_ip": "10.0.0.???",
            "dst": "Honeypot",
            "port": "21/tcp",
            "action": "HONEYPOT_TRIGGER",
            "status": "⚠ TRAP SPRUNG",
            "severity": "critical"
        })

    return log


# ─────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────

if "network_mode" not in st.session_state:
    st.session_state.network_mode = "Real Network Scan"

if "G" not in st.session_state:
    st.session_state.G = (
        build_network()
        if st.session_state.network_mode == "Simulated Lab"
        else nx.DiGraph()
    )

if "simulation_done" not in st.session_state:
    st.session_state.simulation_done = False

if "timeline" not in st.session_state:
    st.session_state.timeline = []

if "compromised" not in st.session_state:
    st.session_state.compromised = set()

if "risk_score" not in st.session_state:
    st.session_state.risk_score = 0.0

if "blast_details" not in st.session_state:
    st.session_state.blast_details = {}

if "honeypot_triggered" not in st.session_state:
    st.session_state.honeypot_triggered = False

if "defense_actions" not in st.session_state:
    st.session_state.defense_actions = []

if "selected_defenses" not in st.session_state:
    st.session_state.selected_defenses = []

if "attack_log" not in st.session_state:
    st.session_state.attack_log = []

if "attack_stats" not in st.session_state:
    st.session_state.attack_stats = {}

if "current_anim_node" not in st.session_state:
    st.session_state.current_anim_node = None


# ─────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:16px 0 8px 0'>
        <div style='font-family:Orbitron,monospace;font-size:1.1rem;color:#00d4ff;letter-spacing:3px'>🛡 ACDS</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>ADAPTIVE CYBER DEFENSE</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>SYSTEM v1.0</div>
    </div>
    <hr style='border-color:#1a3a5c;margin:8px 0 16px 0'>
    """, unsafe_allow_html=True)

    # ── MODE SELECTION ──
    st.markdown('<div class="section-header">🌐 NETWORK MODE</div>', unsafe_allow_html=True)
    network_mode = st.radio(
        "Network Mode",
        ["Simulated Lab", "Real Network Scan"],
        index=0 if st.session_state.network_mode == "Simulated Lab" else 1,
        label_visibility="collapsed",
    )

    # If mode changed, reset and rebuild graph
    if network_mode != st.session_state.network_mode:
        st.session_state.network_mode = network_mode
        st.session_state.simulation_done = False
        st.session_state.timeline = []
        st.session_state.compromised = set()
        st.session_state.risk_score = 0.0
        st.session_state.blast_details = {}
        st.session_state.honeypot_triggered = False
        st.session_state.defense_actions = []
        st.session_state.selected_defenses = []
        st.session_state.attack_log = []
        st.session_state.current_anim_node = None
        if network_mode == "Simulated Lab":
            st.session_state.G = build_network()
        else:
            st.session_state.G = nx.DiGraph()
        st.rerun()

    # ── REAL NETWORK SCAN MODE CONTROLS ──
    if network_mode == "Real Network Scan":
        st.markdown("""
        <div style='background:rgba(255,140,0,0.08);border:1px solid #ff8c00;padding:10px 12px;
             font-family:Share Tech Mono;font-size:0.65rem;color:#ff8c00;line-height:1.8;margin:8px 0'>
        ⚠ REAL NETWORK MODE<br>
        <span style='color:#3d6a8a'>
        • Discovers all LAN hosts by ping + ARP<br>
        • Scans open ports to find access paths (SSH, RDP, SMB…)<br>
        • Assesses vulnerabilities from exposed services<br>
        • Simulates lateral movement & privilege escalation<br>
        • Recommends fixes to stop attack spread
        </span>
        </div>
        """, unsafe_allow_html=True)

        auto_detect = st.checkbox("🔍 Auto-detect Base IP", value=True, help="Automatically detect your local network subnet")
        if auto_detect:
            detected_ip = get_local_ip()
            st.info(f"Detected Base IP: **{detected_ip}**")
            base_ip = None
        else:
            base_ip = st.text_input("Base IP Prefix", value="192.168.93.", help="e.g. 192.168.93.  — your VMnet8 subnet")
        scan_limit = st.slider("Scan Range (last octet up to...)", 10, 254, 200, 10)

        st.markdown("""
        <div style='background:rgba(0,212,255,0.06);border:1px solid #1a3a5c;padding:10px 12px;
             font-family:Share Tech Mono;font-size:0.62rem;color:#7ab8d4;line-height:1.8;margin:8px 0'>
        💡 VMWARE SETUP TIPS:<br>
        <span style='color:#3d6a8a'>
        • VMnet8 (NAT): use prefix <b style='color:#00d4ff'>192.168.93.</b><br>
        • Kali VM must be powered ON<br>
        • Set range to at least 200 to reach .128<br>
        • If not found: run <b style='color:#00ff88'>ping 192.168.93.128</b> in PowerShell first<br>
        • If ping fails: check VMware NAT service is running
        </span>
        </div>
        """, unsafe_allow_html=True)

        if st.button("📡  SCAN NETWORK", use_container_width=True):
            with st.spinner("Scanning network..."):
                devices = scan_network(base_ip=base_ip, limit=scan_limit)

            if not devices:
                st.warning("No active devices found. Check your network prefix or range.")
            else:
                # Reset simulation state and build dynamic graph
                st.session_state.simulation_done = False
                st.session_state.timeline = []
                st.session_state.compromised = set()
                st.session_state.risk_score = 0.0
                st.session_state.blast_details = {}
                st.session_state.honeypot_triggered = False
                st.session_state.defense_actions = []
                st.session_state.selected_defenses = []
                st.session_state.attack_log = []
                st.session_state.current_anim_node = None
                st.session_state.G = build_dynamic_graph(devices)
                st.session_state.last_scan_devices = devices
                st.success(f"Found {len(devices)} device(s). Graph updated.")
                st.rerun()

    st.markdown('<div class="section-header">⚙ SIMULATION CONTROLS</div>', unsafe_allow_html=True)

    all_nodes = list(st.session_state.G.nodes)
    if not all_nodes:
        st.warning("No devices in graph. Scan your network first (Real Network Scan mode).")
        entry_node = None
    else:
        if network_mode == "Simulated Lab":
            all_nodes = [n for n in all_nodes if st.session_state.G.nodes[n].get("node_type") != "honeypot"]
        entry_node = st.selectbox(
            "Entry Point (Initially Compromised System)",
            all_nodes,
            index=min(1, len(all_nodes) - 1),
            help="The system where the attacker first gained access (phishing, stolen laptop, etc.)",
        )

    show_honeypot = st.checkbox("Show Honeypot Node", value=True)
    animation_speed = st.slider("Animation Speed (sec/step)", 0.3, 2.0, 0.8, 0.1)

    st.markdown('<div class="section-header">💰 DEFENSE BUDGET</div>', unsafe_allow_html=True)

    # Dynamic budget range based on total action costs
    all_actions_for_budget = get_defense_actions(
        st.session_state.G,
        set(st.session_state.G.nodes) - {"Honeypot"},
        50
    )
    max_budget = sum(a["cost"] for a in all_actions_for_budget)
    if max_budget == 0:
        max_budget = 100
    budget = st.slider("Budget (units)", 0, max_budget, max_budget // 3)

    st.markdown('<div class="section-header">📡 NETWORK STATUS</div>', unsafe_allow_html=True)
    for node, data in st.session_state.G.nodes(data=True):
        status_class = "dot-compromised" if data["compromised"] else \
                       "dot-honeypot" if data.get("node_type") == "honeypot" else \
                       "dot-safe"
        label = "🔴" if data["compromised"] else "🟡" if data.get("node_type") == "honeypot" else "🟢"
        display_name = data.get('display_name') or node.replace("\n", " / ")
        st.markdown(
            f'<div style="font-family:Share Tech Mono;font-size:0.72rem;padding:3px 0;color:#7ab8d4">'
            f'<span class="status-dot {status_class}"></span>{display_name} '
            f'<span style="color:#3d6a8a">({data["ip"]})</span></div>',
            unsafe_allow_html=True
        )

    st.markdown('<hr style="border-color:#1a3a5c;margin:12px 0">', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-family:Share Tech Mono;font-size:0.6rem;color:#3d6a8a;text-align:center">'
        'FOR EDUCATIONAL USE ONLY<br>NO REAL EXPLOITS PERFORMED<br>'
        'MITRE ATT&CK ALIGNED</div>',
        unsafe_allow_html=True
    )


# ─────────────────────────────────────────────────────────────────
# MAIN LAYOUT
# ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="cyber-header">
    <div class="cyber-title">🛡 ADAPTIVE CYBER DEFENSE SYSTEM</div>
    <div class="cyber-subtitle">// NETWORK DISCOVERY • ATTACK PATH ANALYSIS • DEFENSE RECOMMENDATIONS // SME CYBERSECURITY //</div>
</div>
""", unsafe_allow_html=True)

# Show mode indicator and warning if in Real Network Scan mode
if st.session_state.network_mode == "Real Network Scan":
    st.markdown("""
    <div style='background:rgba(255,140,0,0.06);border:1px solid #ff8c00;border-left:4px solid #ff8c00;
         padding:12px 18px;font-family:Share Tech Mono;font-size:0.72rem;color:#ff8c00;
         line-height:1.9;margin-bottom:16px'>
        <b>⚠ REAL NETWORK MODE ACTIVE</b><br>
        <span style='color:#7ab8d4'>
        • Device detection via ping + ARP + port scan (no exploitation)<br>
        • Vulnerabilities derived from exposed services on each host<br>
        • Attack simulation shows lateral movement depth & systems controlled<br>
        • Use <b style='color:#ff8c00'>SCAN NETWORK</b> then pick compromised entry point
        </span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div style='background:rgba(0,212,255,0.04);border:1px solid #1a3a5c;border-left:4px solid #00d4ff;
         padding:8px 16px;font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin-bottom:16px'>
        MODE: <span style='color:#00d4ff'>SIMULATED LAB</span> &nbsp;|&nbsp; 6-NODE ENTERPRISE TOPOLOGY &nbsp;|&nbsp; MITRE ATT&CK ALIGNED
    </div>
    """, unsafe_allow_html=True)

# ── Top metrics row ──
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    total = len(st.session_state.G.nodes)
    st.metric("TOTAL NODES", total)
with m2:
    comp = len([n for n, d in st.session_state.G.nodes(data=True) if d["compromised"] and d.get("node_type") != "honeypot"])
    st.metric("COMPROMISED", comp)
with m3:
    risk_color = "🔴" if st.session_state.risk_score > 70 else "🟠" if st.session_state.risk_score > 40 else "🟢"
    st.metric("RISK SCORE", f"{risk_color} {st.session_state.risk_score}/100")
with m4:
    hp_status = "⚠ TRIGGERED" if st.session_state.honeypot_triggered else "✓ ARMED"
    st.metric("HONEYPOT", hp_status)
with m5:
    st.metric("SIMULATION", "COMPLETE" if st.session_state.simulation_done else "READY")

st.markdown('<hr style="border-color:#1a3a5c;margin:8px 0 20px 0">', unsafe_allow_html=True)

# ── Main columns: Graph (left) | Details (right) ──
col_graph, col_details = st.columns([3, 2], gap="medium")

with col_graph:
    st.markdown('<div class="section-header">🗺 NETWORK TOPOLOGY MAP</div>', unsafe_allow_html=True)

    graph_placeholder = st.empty()
    # Render initial graph
    html_graph = render_graph(
        st.session_state.G,
        compromised_set=st.session_state.compromised,
        current_node=st.session_state.current_anim_node,
        show_honeypot=show_honeypot
    )
    with graph_placeholder:
        st.components.v1.html(html_graph, height=500, scrolling=False)

    # Legend
    st.markdown("""
    <div style='display:flex;gap:20px;font-family:Share Tech Mono;font-size:0.68rem;margin-top:8px;flex-wrap:wrap'>
        <span><span style='color:#00d4ff'>■</span> SECURE</span>
        <span><span style='color:#ff3355'>■</span> COMPROMISED</span>
        <span><span style='color:#ff8c00'>■</span> ACTIVE THREAT</span>
        <span><span style='color:#ffd700'>★</span> HONEYPOT</span>
        <span><span style='color:#1a3a5c'>──</span> EDGE</span>
        <span><span style='color:#ff3355'>──</span> ATTACK PATH</span>
    </div>
    """, unsafe_allow_html=True)

    # Run simulation button
    st.markdown("<br>", unsafe_allow_html=True)
    run_col, reset_col = st.columns([2, 1])
    with run_col:
        run_btn = st.button("▶  RUN ATTACK SIMULATION", use_container_width=True)
    with reset_col:
        reset_btn = st.button("↺  RESET", use_container_width=True)

    if reset_btn:
        # Reset all state
        for node in st.session_state.G.nodes:
            st.session_state.G.nodes[node]["compromised"] = False
        st.session_state.simulation_done = False
        st.session_state.timeline = []
        st.session_state.compromised = set()
        st.session_state.risk_score = 0.0
        st.session_state.blast_details = {}
        st.session_state.honeypot_triggered = False
        st.session_state.defense_actions = []
        st.session_state.selected_defenses = []
        st.session_state.attack_log = []
        st.session_state.current_anim_node = None
        st.rerun()

with col_details:
    st.markdown('<div class="section-header">📋 NODE INTELLIGENCE</div>', unsafe_allow_html=True)

    node_panel = st.empty()

    def render_node_panel(active_node=None):
        html = ""
        for node, data in st.session_state.G.nodes(data=True):
            is_comp = data["compromised"]
            ntype = data.get("node_type", "endpoint")
            is_honey = ntype == "honeypot"
            is_active = node == active_node

            card_class = "compromised" if is_comp else "honeypot" if is_honey else "safe"
            if is_active:
                card_class = "compromised"

            status_icon = "🔴 COMPROMISED" if is_comp else "⚠ ALERT" if (is_honey and st.session_state.honeypot_triggered) else "🟡 DECOY" if is_honey else "🟢 SECURE"
            if is_active:
                status_icon = "💥 UNDER ATTACK"

            crit_stars = "★" * data["criticality"] + "☆" * (5 - data["criticality"])
            vuln_pct = int(data["vulnerability"] * 100)
            vuln_bar_color = "#ff3355" if vuln_pct > 60 else "#ff8c00" if vuln_pct > 40 else "#00ff88"
            node_color = "#ff3355" if is_comp else "#ffd700" if is_honey else "#00d4ff"

            hostname = data.get('hostname', '')
            hostname_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Hostname:</span><span style='color:#e0f4ff'>{hostname}</span></div>" if hostname else ""
            
            os_type = data.get('os', 'unknown')
            os_icon = {'windows': '🪟', 'linux': '🐧', 'macos': '🍎', 'unknown': '❓'}.get(os_type, '❓')
            os_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>OS:</span><span style='color:#e0f4ff'>{os_icon} {os_type.upper()}</span></div>"
            
            is_mobile = data.get('is_mobile', False)
            device_type = data.get('device_type', '')
            device_icon = {
                'Mobile Phone': '📱',
                'Tablet': '📱',
                'Router/Gateway': '🌐',
                'Server': '🖥️',
                'Database Server': '🗄️',
                'Computer': '💻',
                'Mac': '🍎',
                'Network Device': '🔗',
            }.get(device_type, '📱' if is_mobile else '')
            device_html = (
                f"<div style='display:flex;align-items:center;margin:4px 0'>"
                f"<span style='color:#3d6a8a;width:70px'>Device:</span>"
                f"<span style='color:#e0f4ff'>{device_icon} {device_type or ('Mobile' if is_mobile else 'Unknown')}</span>"
                f"</div>"
            ) if device_type or is_mobile else ""
            
            services = data.get('services', [])
            services_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Services:</span><span style='color:#e0f4ff'>{', '.join(services[:4])}{'...' if len(services) > 4 else ''}</span></div>" if services else ""

            vectors = data.get('access_vectors', [])
            vectors_html = (
                f"<div style='display:flex;align-items:flex-start;margin:4px 0'>"
                f"<span style='color:#3d6a8a;width:70px'>Access:</span>"
                f"<span style='color:#ff8c00'>{', '.join(vectors[:2])}{'...' if len(vectors) > 2 else ''}</span>"
                f"</div>"
            ) if vectors else ""

            weaknesses = data.get('weaknesses', [])
            weak_html = (
                f"<div style='margin:6px 0;padding:6px;background:rgba(255,51,85,0.06);border-left:2px solid #ff3355'>"
                f"<div style='color:#3d6a8a;font-size:0.62rem;margin-bottom:3px'>VULNERABILITIES</div>"
                + "".join(f"<div style='color:#ff8c00;font-size:0.65rem'>• {w[:70]}{'...' if len(w)>70 else ''}</div>" for w in weaknesses[:2])
                + "</div>"
            ) if weaknesses else ""
            
            html += f"<div class='node-card {card_class}'><div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'><span style='color:{node_color};font-family:Orbitron,monospace;font-size:0.8rem;font-weight:700'>{node}</span><span style='font-size:0.65rem;opacity:0.8'>{status_icon}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>IP:</span><span style='color:#e0f4ff'>{data['ip']}</span></div>{hostname_html}{os_html}{device_html}{services_html}{vectors_html}{weak_html}<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Role:</span><span style='color:#e0f4ff'>{data['role']}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Type:</span><span style='color:#e0f4ff'>{ntype.upper()}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Criticality:</span><span style='color:#ffd700'>{crit_stars}</span></div><div style='margin:8px 0'><div style='color:#3d6a8a;margin-bottom:4px'>Vulnerability:</div><div class='risk-bar-container'><div class='risk-bar' style='width:{vuln_pct}%;background:{vuln_bar_color}'></div></div><span style='color:{vuln_bar_color}'>{vuln_pct}%</span></div></div>"
        return html

    node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel()}</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# SIMULATION EXECUTION WITH ANIMATION
# ─────────────────────────────────────────────────────────────────

if run_btn and entry_node:
    # Reset graph state first
    for node in st.session_state.G.nodes:
        st.session_state.G.nodes[node]["compromised"] = False

    timeline, compromised, honeypot_triggered, attack_stats = simulate_attack(
        st.session_state.G, entry_node, seed=random.randint(1, 9999)
    )

    # Group timeline by timestep for animation
    steps = {}
    for entry in timeline:
        t = entry["timestep"]
        if t not in steps:
            steps[t] = []
        steps[t].append(entry)

    animated_compromised = set()
    status_text = st.empty()

    for timestep in sorted(steps.keys()):
        for entry in steps[timestep]:
            node = entry["node"]
            st.session_state.current_anim_node = node

            status_color = "#ff3355" if entry["success"] else "#00ff88"
            status_word = "COMPROMISED" if entry["success"] else "BLOCKED"
            status_text.markdown(
                f'<div style="font-family:Share Tech Mono;font-size:0.75rem;color:{status_color};'
                f'background:#0d1f2d;border:1px solid {status_color};padding:8px 14px;margin:4px 0">'
                f'[T{timestep}] {entry.get("mitre_code")} → {node}'
                f'{" ← " + entry.get("from_node", "") if entry.get("from_node") else ""}'
                f' via {entry.get("access_vector", "network")} — {status_word}</div>',
                unsafe_allow_html=True
            )

            if entry["success"]:
                animated_compromised.add(node)

            # Update graph
            updated_html = render_graph(
                st.session_state.G,
                compromised_set=animated_compromised,
                current_node=node,
                show_honeypot=show_honeypot
            )
            with graph_placeholder:
                st.components.v1.html(updated_html, height=500, scrolling=False)

            # Update node panel
            node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel(active_node=node)}</div>", unsafe_allow_html=True)

            time.sleep(animation_speed)

    # Simulation complete
    status_text.markdown(
        '<div style="font-family:Share Tech Mono;font-size:0.75rem;color:#ffd700;'
        'background:#1a1000;border:1px solid #ffd700;padding:8px 14px;margin:4px 0">'
        '[ SIMULATION COMPLETE ] All attack vectors evaluated.</div>',
        unsafe_allow_html=True
    )

    # Final state update
    st.session_state.timeline = timeline
    st.session_state.compromised = compromised
    st.session_state.honeypot_triggered = honeypot_triggered
    st.session_state.simulation_done = True
    st.session_state.current_anim_node = None

    # Risk calculation
    risk_score, blast_details = calculate_risk(
        st.session_state.G, compromised, timeline, honeypot_triggered, attack_stats
    )
    st.session_state.risk_score = risk_score
    st.session_state.blast_details = blast_details
    st.session_state.attack_stats = attack_stats

    # Defense actions
    st.session_state.defense_actions = get_defense_actions(
        st.session_state.G, compromised, risk_score
    )
    selected, total_reduction, remaining = greedy_defense_selection(
        st.session_state.defense_actions, budget
    )
    st.session_state.selected_defenses = selected

    # Attack log
    st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)

    # Final graph render
    final_html = render_graph(
        st.session_state.G,
        compromised_set=compromised,
        current_node=None,
        show_honeypot=show_honeypot
    )
    with graph_placeholder:
        st.components.v1.html(final_html, height=500, scrolling=False)
    node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel()}</div>", unsafe_allow_html=True)

    st.rerun()


# ─────────────────────────────────────────────────────────────────
# POST-SIMULATION PANELS (shown after simulation runs)
# ─────────────────────────────────────────────────────────────────

if st.session_state.simulation_done:

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)

    # ── Row: Timeline | Risk Analysis ──
    col_timeline, col_risk = st.columns([1, 1], gap="medium")

    with col_timeline:
        st.markdown('<div class="section-header">⏱ ATTACK TIMELINE</div>', unsafe_allow_html=True)

        # Group by timestep
        ts_groups = {}
        for entry in st.session_state.timeline:
            t = entry["timestep"]
            if t not in ts_groups:
                ts_groups[t] = []
            ts_groups[t].append(entry)

        for t, entries in sorted(ts_groups.items()):
            for entry in entries:
                is_success = entry["success"]
                bg_color = "rgba(255,51,85,0.1)" if is_success else "rgba(0,255,136,0.05)"
                border_color = "#ff3355" if is_success else "#00ff88"
                status_text_val = "✓ COMPROMISED" if is_success else "✗ BLOCKED"
                status_color = "#ff3355" if is_success else "#00ff88"

                st.markdown(f"""
                <div style='background:{bg_color};border:1px solid {border_color};
                     border-left:3px solid {border_color};padding:8px 12px;margin:4px 0;
                     font-family:Share Tech Mono;font-size:0.72rem;line-height:1.8'>
                    <div style='display:flex;justify-content:space-between'>
                        <span style='color:#00d4ff'>T{t}</span>
                        <span style='color:{status_color}'>{status_text_val}</span>
                    </div>
                    <div style='color:#e0f4ff;font-weight:bold'>→ {entry["node"]}</div>
                    <div style='color:#3d6a8a'>{entry.get("mitre_code","")}: {entry.get("mitre_desc","")}</div>
                    <div style='color:#ff8c00;font-size:0.65rem'>Via: {entry.get("access_vector", "network")}</div>
                    {"<div style='color:#ffd700;font-size:0.65rem'>⬆ Privilege Escalation</div>" if entry.get("priv_esc") else ""}
                    <div style='color:#7ab8d4'>Vuln: {int(entry["vuln"]*100)}% | Crit: {"★"*entry["criticality"]}</div>
                </div>
                """, unsafe_allow_html=True)

    with col_risk:
        st.markdown('<div class="section-header">📊 RISK ANALYSIS (BLAST RADIUS)</div>', unsafe_allow_html=True)

        rs = st.session_state.risk_score
        bd = st.session_state.blast_details

        # Big risk score display
        risk_color = "#ff3355" if rs > 70 else "#ff8c00" if rs > 40 else "#00ff88"
        risk_label = "CRITICAL" if rs > 70 else "HIGH" if rs > 40 else "LOW"
        st.markdown(f"""
        <div style='background:#0d1f2d;border:1px solid {risk_color};padding:20px;text-align:center;margin-bottom:16px'>
            <div style='font-family:Orbitron,monospace;font-size:2.5rem;color:{risk_color};
                        text-shadow:0 0 20px {risk_color};font-weight:900'>{rs}</div>
            <div style='font-family:Share Tech Mono;font-size:0.7rem;color:{risk_color};letter-spacing:3px'> / 100 — {risk_label} RISK</div>
            <div class="risk-bar-container" style='margin-top:12px'>
                <div class="risk-bar" style='width:{rs}%;background:linear-gradient(90deg,#003d5c,{risk_color})'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style='font-family:Share Tech Mono;font-size:0.75rem;line-height:2;background:#0a1520;
             border:1px solid #1a3a5c;padding:14px 16px'>
            <div style='color:#3d6a8a'>FORMULA: R = 0.3*spread + 0.5*critical_impact + 0.2*depth</div><br>
            <div>Spread (w1=0.3):
                <span style='color:#00d4ff;float:right'>{bd.get("spread",0)}% nodes compromised</span>
            </div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("spread",0)}%;background:#00d4ff'></div></div>
            <div>Critical Impact (w2=0.5):
                <span style='color:#ff8c00;float:right'>{bd.get("critical_impact",0)}% criticality</span>
            </div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("critical_impact",0)}%;background:#ff8c00'></div></div>
            <div>Attack Depth (w3=0.2):
                <span style='color:#ffd700;float:right'>{bd.get("depth",0)}% of network</span>
            </div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("depth",0)}%;background:#ffd700'></div></div>
            <br>
            <div>Systems Controlled: <span style='color:#ff3355;float:right'>{bd.get("systems_controlled", bd.get("compromised_count",0))} / {bd.get("total_real_nodes",0)}</span></div>
            <div>Max Lateral Hops: <span style='color:#ffd700;float:right'>{bd.get("max_lateral_hops", 0)}</span></div>
            <div>Privilege Escalations: <span style='color:#ff8c00;float:right'>{bd.get("privilege_escalations", 0)}</span></div>
            {"<div style='color:#ffd700;margin-top:8px'>⚠ HONEYPOT TRIGGERED: +15 risk penalty</div>" if st.session_state.honeypot_triggered else ""}
        </div>
        """, unsafe_allow_html=True)

        paths = bd.get("attack_paths", [])
        if paths:
            st.markdown('<div style="font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin:12px 0 6px 0">ATTACK PATHS (longest routes)</div>', unsafe_allow_html=True)
            for i, path in enumerate(paths[:5]):
                path_str = " → ".join(p.replace("\n", " / ") for p in path)
                st.markdown(
                    f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;'
                    f'padding:6px 10px;margin:3px 0;background:#060d15;border-left:2px solid #ff3355">{path_str}</div>',
                    unsafe_allow_html=True,
                )

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)

    # ── Row: Defense Optimization | Attack Log ──
    col_defense, col_log = st.columns([1, 1], gap="medium")

    with col_defense:
        st.markdown('<div class="section-header">🛡 DEFENSE OPTIMIZATION ENGINE</div>', unsafe_allow_html=True)

        st.markdown("""
        <div style='font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;
             background:#060d15;border:1px solid #1a3a5c;padding:10px;margin-bottom:12px;line-height:1.8'>
        // Greedy algorithm: rank by risk_reduction/cost ratio<br>
        // Select highest-value actions within budget constraint<br>
        // Objective: maximize risk reduction under limited resources
        </div>
        """, unsafe_allow_html=True)

        selected_defenses = st.session_state.selected_defenses
        all_actions = st.session_state.defense_actions

        total_reduction_val = sum(a["risk_reduction"] for a in selected_defenses)
        new_risk = max(0, round(st.session_state.risk_score - total_reduction_val, 1))
        spent = sum(a["cost"] for a in selected_defenses)

        st.markdown(f"""
        <div style='display:flex;gap:12px;margin-bottom:14px'>
            <div style='flex:1;background:#0d1f2d;border:1px solid #1a3a5c;padding:12px;text-align:center;font-family:Share Tech Mono;font-size:0.72rem'>
                <div style='color:#3d6a8a'>BUDGET USED</div>
                <div style='color:#ffd700;font-size:1.2rem'>{spent} / {budget}</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:12px;text-align:center;font-family:Share Tech Mono;font-size:0.72rem'>
                <div style='color:#3d6a8a'>RISK AFTER DEFENSE</div>
                <div style='color:#00ff88;font-size:1.2rem'>{new_risk} / 100</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #ff3355;padding:12px;text-align:center;font-family:Share Tech Mono;font-size:0.72rem'>
                <div style='color:#3d6a8a'>RISK REDUCTION</div>
                <div style='color:#ff3355;font-size:1.2rem'>-{min(total_reduction_val, st.session_state.risk_score):.1f}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        selected_set = {a["action"] for a in selected_defenses}

        for action in all_actions[:8]:
            is_sel = action["action"] in selected_set
            card_class = "selected" if is_sel else "unselected"
            badge = "✓ SELECTED" if is_sel else "— SKIPPED"
            badge_color = "#00ff88" if is_sel else "#3d6a8a"

            type_icons = {
                "patch": "🔧", "isolate": "🔒", "privilege": "👤", "ids": "📡"
            }
            icon = type_icons.get(action["type"], "⚙")

            st.markdown(f"""
            <div class="defense-action {card_class}">
                <div>
                    <div style='color:#e0f4ff;font-weight:bold'>{icon} {action["action"]}</div>
                    <div style='color:#3d6a8a;font-size:0.68rem;margin-top:3px'>{action["description"]}</div>
                    <div style='margin-top:4px'>
                        <span class='mitre-tag'>Cost: {action["cost"]}</span>
                        <span class='mitre-tag' style='border-color:#00ff88;color:#00ff88'>-{action["risk_reduction"]} risk</span>
                        <span class='mitre-tag' style='border-color:#00d4ff;color:#00d4ff'>eff: {action["efficiency"]}</span>
                    </div>
                </div>
                <span style='color:{badge_color};font-size:0.65rem;white-space:nowrap'>{badge}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-header">💡 RECOMMENDED SOLUTIONS</div>', unsafe_allow_html=True)
        all_fixes = []
        for node in st.session_state.compromised:
            nd = st.session_state.G.nodes.get(node, {})
            for fix in nd.get("fixes", []):
                if fix not in all_fixes:
                    all_fixes.append(fix)
        if all_fixes:
            for i, fix in enumerate(all_fixes[:8], 1):
                st.markdown(
                    f'<div style="font-family:Share Tech Mono;font-size:0.72rem;color:#7ab8d4;'
                    f'padding:8px 12px;margin:4px 0;background:#0a1520;border-left:3px solid #00ff88">'
                    f'<span style="color:#00ff88">{i}.</span> {fix}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.72rem;color:#3d6a8a">'
                'Run attack simulation to generate targeted remediation steps.</div>',
                unsafe_allow_html=True,
            )

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)

    with col_log:
        st.markdown('<div class="section-header">📟 SYSTEM EVENT LOG</div>', unsafe_allow_html=True)

        if st.session_state.honeypot_triggered:
            st.markdown("""
            <div class="honeypot-alert">
                ⚠ HONEYPOT TRIGGERED — Attacker has probed decoy system<br>
                <span style='color:#3d6a8a'>IP: 10.0.0.??? | Port: 21/tcp (FTP)<br>
                Action: Risk model updated (+15 penalty)<br>
                Recommendation: Analyze attacker TTPs for adaptive defense</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div style='background:#050a0f;border:1px solid #1a3a5c;padding:10px 12px;font-family:Share Tech Mono'>
            <div style='font-size:0.65rem;color:#3d6a8a;border-bottom:1px solid #1a3a5c;padding-bottom:6px;margin-bottom:6px'>
                TIME &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SRC_IP &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; TARGET &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ACTION &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; STATUS
            </div>
        """, unsafe_allow_html=True)

        for log in st.session_state.attack_log:
            sev = log["severity"]
            color = "#ff3355" if sev == "critical" else "#00ff88" if sev == "ok" else "#ff8c00"
            status_sym = "●" if sev == "critical" else "○"
            st.markdown(f"""
            <div style='font-size:0.68rem;padding:4px 0;border-bottom:1px solid #0a1520;color:#7ab8d4;line-height:1.6'>
                <span style='color:#3d6a8a'>{log["time"]}</span>
                <span style='margin:0 8px'>{log["src_ip"]}</span>
                <span style='color:#00d4ff'>{log["dst"]}</span>
                <span style='margin-left:8px;color:{color}'>{log["action"]}</span>
                <span style='float:right;color:{color}'>{status_sym} {log["status"]}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="section-header">🔖 MITRE ATT&CK MAPPING</div>', unsafe_allow_html=True)

        mitre_seen = {}
        for entry in st.session_state.timeline:
            if entry["success"]:
                mitre_seen[entry["mitre_code"]] = entry["mitre_desc"]

        mitre_html = ""
        for code, desc in mitre_seen.items():
            mitre_html += f'<span class="mitre-tag">{code}</span>'
        mitre_html += f"<br><br>"
        for code, desc in mitre_seen.items():
            mitre_html += f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:3px 0"><span style="color:#ff8c00">{code}</span> — {desc}</div>'

        st.markdown(
            f'<div style="background:#0d1f2d;border:1px solid #1a3a5c;padding:12px">{mitre_html}</div>',
            unsafe_allow_html=True
        )

    # ── VM Lab Reference ──
    with st.expander("🖥  VIRTUAL LAB REFERENCE  —  UTM Setup Guide (Mac M4 / Apple Silicon)"):
        st.markdown("""
        <div style='font-family:Share Tech Mono;font-size:0.75rem;line-height:2;color:#7ab8d4'>

        <div style='color:#00d4ff;font-size:0.8rem;margin-bottom:8px'>UTM VIRTUAL MACHINE CONFIGURATION</div>

        <b style='color:#ffd700'>VM1 — User-PC (192.168.1.10)</b><br>
        OS: Ubuntu 22.04 ARM64 | RAM: 2GB | CPU: 2 cores | Storage: 20GB<br>
        Services: SSH client, curl, nmap<br>
        Graph node: Entry point for attacker (phishing / credential theft simulation)<br>
        Real command: <span style='color:#00ff88'>ssh user@192.168.1.20</span> (lateral movement to Server)<br><br>

        <b style='color:#ffd700'>VM2 — Server (192.168.1.20)</b><br>
        OS: Ubuntu 22.04 ARM64 | RAM: 2GB | CPU: 2 cores | Storage: 20GB<br>
        Services: Apache2 (<span style='color:#00ff88'>sudo apt install apache2</span>), SSH<br>
        Graph node: Web/App server, lateral movement waypoint<br>
        Real command: <span style='color:#00ff88'>sudo -l</span> (privilege escalation check — T1068)<br><br>

        <b style='color:#ffd700'>VM3 — Database (192.168.1.30)</b><br>
        OS: Ubuntu 22.04 ARM64 | RAM: 2GB | CPU: 2 cores | Storage: 20GB<br>
        Services: MySQL (<span style='color:#00ff88'>sudo apt install mysql-server</span>)<br>
        Graph node: High-value data target<br>
        Real command: <span style='color:#00ff88'>mysqldump -u root -p --all-databases</span> (T1005 data exfil)<br><br>

        <b style='color:#00d4ff'>NETWORK SETUP (UTM Shared Network):</b><br>
        1. UTM → VM → Edit → Network → Shared Network (bridged)<br>
        2. On each VM: <span style='color:#00ff88'>sudo nano /etc/netplan/01-netcfg.yaml</span><br>
        3. Assign static IPs: 192.168.1.10 / .20 / .30<br>
        4. Apply: <span style='color:#00ff88'>sudo netplan apply</span><br>
        5. Verify: <span style='color:#00ff88'>ping 192.168.1.20</span> from User-PC<br>

        </div>
        """, unsafe_allow_html=True)

else:
    # Pre-simulation instructions
    if st.session_state.network_mode == "Real Network Scan":
        ready_note = (
            "1. Click <span style='color:#ff8c00'>📡 SCAN NETWORK</span> in the sidebar to discover all LAN devices<br>"
            "2. Review each node's open ports, vulnerabilities, and access paths<br>"
            "3. Select which system is <b>initially compromised</b> (attacker foothold)<br>"
            "4. Click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span> to see lateral movement<br>"
            "5. Review how many systems fall, max attack depth, and recommended fixes"
        )
    else:
        ready_note = (
            "1. Select an entry node (attacker's foothold) from the sidebar<br>"
            "2. Configure defense budget using the slider<br>"
            "3. Click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span> to begin<br>"
            "4. Watch real-time attack propagation on the network graph<br>"
            "5. Review risk analysis and defense recommendations"
        )

    st.markdown(f"""
    <div style='background:#0a1520;border:1px solid #1a3a5c;border-left:3px solid #00d4ff;
         padding:20px 24px;font-family:Share Tech Mono;font-size:0.78rem;line-height:2;
         text-align:center;margin-top:20px'>
        <div style='color:#00d4ff;font-size:0.9rem;font-family:Orbitron,monospace;letter-spacing:3px;margin-bottom:12px'>
            SYSTEM READY
        </div>
        <div style='color:#7ab8d4'>
            {ready_note}
        </div>
        <div style='color:#3d6a8a;margin-top:16px;font-size:0.65rem'>
            SIMULATION ALIGNED WITH MITRE ATT&CK FRAMEWORK<br>
            NO REAL EXPLOITS — EDUCATIONAL & RESEARCH PURPOSE ONLY
        </div>
    </div>
    """, unsafe_allow_html=True)