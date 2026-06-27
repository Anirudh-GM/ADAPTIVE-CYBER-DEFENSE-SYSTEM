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
import subprocess
import platform
from collections import deque
from pyvis.network import Network
import tempfile
import os

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

    # Node definitions: (name, ip, role, criticality 1-5, vulnerability 0-1, type)
    nodes = [
        ("Firewall",    "192.168.1.1",  "Perimeter Defense",    3, 0.25, "perimeter"),
        ("User-PC",     "192.168.1.10", "Workstation",          2, 0.70, "endpoint"),
        ("Admin-PC",    "192.168.1.11", "Admin Workstation",    4, 0.55, "endpoint"),
        ("Server",      "192.168.1.20", "Web/App Server",       4, 0.60, "server"),
        ("File-Server", "192.168.1.21", "File Server",          3, 0.45, "server"),
        ("Database",    "192.168.1.30", "MySQL Database",       5, 0.50, "database"),
        ("Honeypot",    "192.168.1.99", "Decoy System",         1, 0.95, "honeypot"),
    ]

    for name, ip, role, criticality, vuln, ntype in nodes:
        G.add_node(name,
                   ip=ip,
                   role=role,
                   criticality=criticality,
                   vulnerability=vuln,
                   node_type=ntype,
                   compromised=False)

    # Edge definitions: (src, dst, connection_type)
    edges = [
        ("Firewall",    "User-PC",      "filtered"),
        ("Firewall",    "Admin-PC",     "filtered"),
        ("User-PC",     "Server",       "http/ssh"),
        ("User-PC",     "File-Server",  "smb"),
        ("Admin-PC",    "Server",       "ssh/rdp"),
        ("Admin-PC",    "File-Server",  "smb/admin"),
        ("Server",      "Database",     "mysql"),
        ("File-Server", "Database",     "db-backup"),
        ("Server",      "Honeypot",     "snmp"),
        ("Admin-PC",    "Honeypot",     "ftp"),
    ]

    for src, dst, conn in edges:
        G.add_edge(src, dst, connection=conn)

    return G


# ─────────────────────────────────────────────────────────────────
# MODULE 1B: REAL NETWORK SCAN ENGINE
# ─────────────────────────────────────────────────────────────────

def assign_role(i):
    """
    Assign a logical role to a scanned device based on its discovery index.
    0 → Entry Node, 1 → Server, 2 → Database, others → Workstation
    """
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


def scan_network(base_ip=None, limit=254):
    """
    Ping IPs from base_ip+1 to base_ip+limit.
    Returns a list of reachable IP addresses.
    Uses correct ping flags per OS: Windows (-n/-w), macOS (-c/-t), Linux (-c/-W).
    Automatically detects base IP if not provided.
    """
    if base_ip is None:
        base_ip = get_local_ip()
    
    active = []
    system = platform.system()
    if system == "Windows":
        # -w 500 = 500ms timeout in milliseconds
        ping_cmd = lambda ip: ["ping", "-n", "1", "-w", "500", ip]
    elif system == "Darwin":
        ping_cmd = lambda ip: ["ping", "-c", "1", "-t", "1", ip]
    else:
        ping_cmd = lambda ip: ["ping", "-c", "1", "-W", "1", ip]

    for i in range(1, limit + 1):
        ip = f"{base_ip}{i}"
        try:
            result = subprocess.run(
                ping_cmd(ip),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            if result.returncode == 0:
                active.append(ip)
        except (subprocess.TimeoutExpired, OSError):
            pass
    return active


def build_dynamic_graph(devices):
    """
    Build a directed graph from a list of discovered IP addresses.
    Each device becomes a node with attributes matching the existing system structure.
    Edges form a simple chain for BFS compatibility.
    """
    G = nx.DiGraph()

    node_type_map = {
        "Entry Node":  "endpoint",
        "Server":      "server",
        "Database":    "database",
        "Workstation": "endpoint",
    }

    node_names = []
    for i, ip in enumerate(devices):
        role = assign_role(i)
        ntype = node_type_map.get(role, "endpoint")
        criticality = (i % 5) + 1
        vulnerability = round(random.uniform(0.3, 0.8), 2)
        # Node name is "Role\nIP" — displayed in graph label
        node_name = f"{role}\n{ip}"
        node_names.append(node_name)
        G.add_node(
            node_name,
            ip=ip,
            role=role,
            criticality=criticality,
            vulnerability=vulnerability,
            node_type=ntype,
            compromised=False,
        )

    # Create a simple chain: node[0] → node[1] → node[2] → ...
    # Also add cross-edges for richer connectivity where device count allows
    for i in range(len(node_names) - 1):
        G.add_edge(node_names[i], node_names[i + 1], connection="tcp/ip")

    # Add a few shortcut edges for BFS reachability (skip-one hops)
    for i in range(len(node_names) - 2):
        G.add_edge(node_names[i], node_names[i + 2], connection="tcp/ip")

    return G


# ─────────────────────────────────────────────────────────────────
# MODULE 2: ATTACK SIMULATION ENGINE
# ─────────────────────────────────────────────────────────────────

def simulate_attack(G, entry_node, seed=42):
    """
    BFS-based attack simulation.
    Returns: timeline [(node, timestep, mitre_tag, success)]
    """
    random.seed(seed)
    timeline = []
    compromised = set()
    visited = {entry_node}
    queue = deque([(entry_node, 1)])
    honeypot_triggered = False

    # MITRE ATT&CK technique mapping per node type
    mitre_map = {
        "perimeter":  ("T1190", "Exploit Public-Facing Application"),
        "endpoint":   ("T1078", "Valid Accounts / Credential Reuse"),
        "server":     ("T1021", "Remote Services / Lateral Movement"),
        "database":   ("T1005", "Data from Local System"),
        "honeypot":   ("T1003", "OS Credential Dumping [TRAP]"),
    }

    while queue:
        current_node, timestep = queue.popleft()
        node_data = G.nodes[current_node]
        vuln = node_data["vulnerability"]
        criticality = node_data["criticality"]
        ntype = node_data.get("node_type", "endpoint")

        # Determine compromise probability
        # Higher vulnerability → higher chance. Critical nodes have extra resistance.
        base_prob = vuln
        if criticality >= 4:
            base_prob *= 0.8  # hardened systems are slightly more resistant
        success = random.random() < base_prob

        mitre_code, mitre_desc = mitre_map.get(ntype, ("T1059", "Command Execution"))

        # Check honeypot
        if ntype == "honeypot" and success:
            honeypot_triggered = True

        if success:
            compromised.add(current_node)
            G.nodes[current_node]["compromised"] = True

        # Critical nodes (criticality ≥ 4) add extra time step (privilege escalation delay)
        actual_timestep = timestep
        if criticality >= 4 and success:
            actual_timestep += 1  # T1068 - privilege escalation delay

        timeline.append({
            "node": current_node,
            "timestep": actual_timestep,
            "mitre_code": mitre_code,
            "mitre_desc": mitre_desc,
            "success": success,
            "vuln": vuln,
            "criticality": criticality,
            "ntype": ntype
        })

        if success:
            for neighbor in G.successors(current_node):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, actual_timestep + 1))

    # Sort timeline by timestep
    timeline.sort(key=lambda x: x["timestep"])
    return timeline, compromised, honeypot_triggered


# ─────────────────────────────────────────────────────────────────
# MODULE 3: RISK (BLAST RADIUS) ENGINE
# ─────────────────────────────────────────────────────────────────

def calculate_risk(G, compromised_nodes, timeline, honeypot_triggered):
    W1, W2, W3 = 0.3, 0.5, 0.2

    total_nodes = len(G.nodes)
    # Exclude honeypot from spread calculation (it's a trap, not real asset)
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

    # Honeypot penalty: attacker has profiled the network
    if honeypot_triggered:
        risk_score = min(100, risk_score + 15)

    # Per-node blast radius details
    blast_details = {
        "spread": round(spread * 100, 1),
        "critical_impact": round(critical_impact * 100, 1),
        "depth": round(depth * 100, 1),
        "compromised_count": len(real_compromised),
        "total_real_nodes": len(real_nodes),
    }

    return round(risk_score, 1), blast_details


# ─────────────────────────────────────────────────────────────────
# MODULE 4: DEFENSE OPTIMIZATION ENGINE
# ─────────────────────────────────────────────────────────────────

def get_defense_actions(G, compromised_nodes, risk_score):
    actions = []

    for node in compromised_nodes:
        if G.nodes[node].get("node_type") == "honeypot":
            continue
        nd = G.nodes[node]
        crit = nd["criticality"]
        vuln = nd["vulnerability"]

        # Action 1: Patch vulnerability
        patch_cost = int(10 + crit * 5)
        patch_reduction = round(vuln * crit * 4.0, 1)
        actions.append({
            "action": f"Patch {node}",
            "node": node,
            "type": "patch",
            "cost": patch_cost,
            "risk_reduction": patch_reduction,
            "efficiency": round(patch_reduction / patch_cost, 3),
            "description": f"Apply security patches, update services on {node} [{nd['ip']}]"
        })

        # Action 2: Isolate node (only if high criticality or deep in network)
        if crit >= 3:
            isolate_cost = int(15 + crit * 8)
            outgoing = G.out_degree(node)
            isolate_reduction = round(outgoing * crit * 2.5, 1)
            actions.append({
                "action": f"Isolate {node}",
                "node": node,
                "type": "isolate",
                "cost": isolate_cost,
                "risk_reduction": isolate_reduction,
                "efficiency": round(isolate_reduction / isolate_cost, 3),
                "description": f"Network quarantine: remove all outgoing connections from {node}"
            })

        # Action 3: Reduce privileges
        if crit >= 4:
            priv_cost = int(8 + crit * 3)
            priv_reduction = round(crit * 3.0, 1)
            actions.append({
                "action": f"Reduce Privileges on {node}",
                "node": node,
                "type": "privilege",
                "cost": priv_cost,
                "risk_reduction": priv_reduction,
                "efficiency": round(priv_reduction / priv_cost, 3),
                "description": f"Remove admin rights, enforce least privilege on {node}"
            })

    # Global IDS action
    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS",
        "node": "ALL",
        "type": "ids",
        "cost": ids_cost,
        "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Deploy Intrusion Detection System (Snort/Suricata) across all nodes"
    })

    # Sort by efficiency (greedy ratio)
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
    st.session_state.network_mode = "Simulated Lab"

if "G" not in st.session_state:
    st.session_state.G = build_network()

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
        label_visibility="collapsed"
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
        st.rerun()

    # ── REAL NETWORK SCAN MODE CONTROLS ──
    if network_mode == "Real Network Scan":
        st.markdown("""
        <div style='background:rgba(255,140,0,0.08);border:1px solid #ff8c00;padding:10px 12px;
             font-family:Share Tech Mono;font-size:0.65rem;color:#ff8c00;line-height:1.8;margin:8px 0'>
        ⚠ REAL NETWORK MODE<br>
        <span style='color:#3d6a8a'>
        • Only detects reachable devices<br>
        • Roles are assigned logically<br>
        • No real vulnerability scanning<br>
        • Simulation is still safe/educational
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
                st.success(f"Found {len(devices)} device(s). Graph updated.")
                st.rerun()

    st.markdown('<div class="section-header">⚙ SIMULATION CONTROLS</div>', unsafe_allow_html=True)

    all_nodes = list(st.session_state.G.nodes)
    # For simulated lab: exclude honeypot from entry selection
    if network_mode == "Simulated Lab":
        all_nodes = [n for n in all_nodes if st.session_state.G.nodes[n].get("node_type") != "honeypot"]
    entry_node = st.selectbox("Entry Point (Attacker's Foothold)", all_nodes, index=min(1, len(all_nodes) - 1))

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
        display_name = node.replace("\n", " / ")
        st.markdown(
            f'<div style="font-family:Share Tech Mono;font-size:0.72rem;padding:3px 0;color:#7ab8d4">'
            f'<span class="status-dot {status_class}"></span>{display_name} <span style="color:#3d6a8a">({data["ip"]})</span></div>',
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
    <div class="cyber-subtitle">// ATTACK SIMULATION & DEFENSE OPTIMIZATION PLATFORM // SME CYBERSECURITY FRAMEWORK //</div>
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
        • Device detection uses ICMP ping only — no port scanning or exploitation<br>
        • Roles (Entry Node / Server / Database / Workstation) are assigned logically by discovery order<br>
        • Vulnerability scores are randomly assigned for simulation purposes — no real CVE scanning is performed<br>
        • Use the <b style='color:#ff8c00'>SCAN NETWORK</b> button in the sidebar to detect devices on your local network
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

            html += f"<div class='node-card {card_class}'><div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'><span style='color:{node_color};font-family:Orbitron,monospace;font-size:0.8rem;font-weight:700'>{node}</span><span style='font-size:0.65rem;opacity:0.8'>{status_icon}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>IP:</span><span style='color:#e0f4ff'>{data['ip']}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Role:</span><span style='color:#e0f4ff'>{data['role']}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Type:</span><span style='color:#e0f4ff'>{ntype.upper()}</span></div><div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:70px'>Criticality:</span><span style='color:#ffd700'>{crit_stars}</span></div><div style='margin:8px 0'><div style='color:#3d6a8a;margin-bottom:4px'>Vulnerability:</div><div class='risk-bar-container'><div class='risk-bar' style='width:{vuln_pct}%;background:{vuln_bar_color}'></div></div><span style='color:{vuln_bar_color}'>{vuln_pct}%</span></div></div>"
        return html

    st.components.v1.html(f"<div style='padding: 8px;'>{render_node_panel()}</div>", height=400, scrolling=False)


# ─────────────────────────────────────────────────────────────────
# SIMULATION EXECUTION WITH ANIMATION
# ─────────────────────────────────────────────────────────────────

if run_btn:
    # Reset graph state first
    for node in st.session_state.G.nodes:
        st.session_state.G.nodes[node]["compromised"] = False

    timeline, compromised, honeypot_triggered = simulate_attack(
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
                f'[T{timestep}] {entry["mitre_code"]} → {node} ({entry["mitre_desc"]}) — {status_word}</div>',
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
            st.components.v1.html(f"<div style='padding: 8px;'>{render_node_panel(active_node=node)}</div>", height=400, scrolling=False)

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
        st.session_state.G, compromised, timeline, honeypot_triggered
    )
    st.session_state.risk_score = risk_score
    st.session_state.blast_details = blast_details

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
    st.components.v1.html(f"<div style='padding: 8px;'>{render_node_panel()}</div>", height=400, scrolling=False)

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
            <div>Nodes Compromised: <span style='color:#ff3355;float:right'>{bd.get("compromised_count",0)} / {bd.get("total_real_nodes",0)}</span></div>
            {"<div style='color:#ffd700;margin-top:8px'>⚠ HONEYPOT TRIGGERED: +15 risk penalty</div>" if st.session_state.honeypot_triggered else ""}
        </div>
        """, unsafe_allow_html=True)

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
            "1. Use the sidebar to configure your IP prefix and scan range<br>"
            "2. Click <span style='color:#ff8c00'>📡 SCAN NETWORK</span> to detect devices<br>"
            "3. Select an entry node and click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span><br>"
            "4. Watch real-time propagation across discovered devices<br>"
            "5. Review risk analysis and defense recommendations"
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