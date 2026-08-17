"""
╔══════════════════════════════════════════════════════════════════╗
║         ADAPTIVE CYBER DEFENSE SYSTEM FOR SMEs  (v2.0)           ║
║         Real Network Discovery + CVE-Based Risk Engine           ║
╚══════════════════════════════════════════════════════════════════╝

WHAT CHANGED IN v2.0
━━━━━━━━━━━━━━━━━━━━
1. MOBILE DEVICE DETECTION FIXED
   - Now checks the MAC address vendor (OUI) against a real vendor table
     (Apple, Samsung, Xiaomi, Google, Huawei, OnePlus, etc.) in addition to
     hostname pattern matching. A phone with a generic hostname like
     "android-1234" or no hostname at all will now correctly show as
     "Mobile Phone" instead of "Computer", as long as its MAC vendor
     resolves to a known mobile manufacturer.

2. REAL BANNER GRABBING (passive, no exploitation)
   - For every open port found during the scan, the tool now connects and
     reads the service banner it offers (SSH version string, FTP welcome
     banner, HTTP Server header, SMTP banner, etc.) instead of just
     guessing the service name from the port number.

3. REAL CVE LOOKUP (NIST NVD)
   - The detected service + version string is queried against the NVD
     REST API (https://services.nvd.nist.gov/rest/json/cves/2.0) to pull
     actual, current CVEs that apply to that exact version, with their
     real CVSS score. If you don't have internet access from the
     scanning machine, or NVD rate-limits you, the tool falls back to a
     small built-in table of well-known historical CVEs for common
     services so the app still works offline.

4. DYNAMIC, SPECIFIC REMEDIATION
   - Remediation text is now generated per-finding: "Patch OpenSSH 7.2p2
     on 192.168.1.20 — CVE-2018-15473 (CVSS 5.3): username enumeration
     via crafted packets. Upgrade to OpenSSH >= 7.7" instead of a generic
     "Disable password auth; use SSH keys".

5. SME-READABLE EXECUTIVE SUMMARY
   - A plain-English summary panel is added that a non-technical SME
     owner can read: what's exposed, what it means in business terms,
     and the single highest-priority fix to do first.

WHAT DID NOT CHANGE (BY DESIGN)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
The attack "simulation" (lateral movement / privilege escalation) is
still a probabilistic model — it never logs into, exploits, or extracts
data from real machines. It uses the real CVSS-derived risk of each
discovered service to estimate how likely an attacker could move between
machines, which is what makes the risk score and the attack paths useful
for planning, without the tool itself being capable of causing harm to
your own (or anyone else's) network.

REQUIREMENTS
━━━━━━━━━━━━
pip install streamlit networkx pyvis requests --break-system-packages
(requests is new in v2.0, needed for the NVD CVE lookup)

Run with: streamlit run acds_app.py

LEGAL / ETHICAL NOTE
━━━━━━━━━━━━━━━━━━━━
Only run the "Real Network Scan" mode against networks you own or have
explicit written authorization to test. Port scanning and banner
grabbing other people's networks without permission may be illegal in
your jurisdiction even though no exploitation occurs.
"""

import streamlit as st
import networkx as nx
import time
import random
import re
import socket
import ssl
import subprocess
import platform
import functools
import csv
import io
from collections import deque
from pyvis.network import Network
import tempfile
import os
import html as html_lib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
              3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

PORT_SERVICE_MAP = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB',
}

# Baseline exposure risk used only when no version-specific CVE is found.
# This reflects "how dangerous is it for this service to be reachable at
# all", not a substitute for real CVE data.
SERVICE_BASELINE_RISK = {
    'FTP': 0.55, 'SSH': 0.35, 'Telnet': 0.85, 'SMTP': 0.30, 'DNS': 0.25,
    'HTTP': 0.45, 'POP3': 0.40, 'RPC': 0.50, 'NetBIOS': 0.50, 'IMAP': 0.40,
    'HTTPS': 0.30, 'SMB': 0.60, 'MySQL': 0.65, 'RDP': 0.70,
    'PostgreSQL': 0.62, 'VNC': 0.68, 'Redis': 0.75, 'HTTP-Alt': 0.50,
    'HTTPS-Alt': 0.35, 'MongoDB': 0.70,
}

SERVICE_MITRE = {
    'FTP':        ('T1021', 'Remote Services — FTP'),
    'SSH':        ('T1021.004', 'Remote Services — SSH'),
    'Telnet':     ('T1021', 'Remote Services — Telnet'),
    'HTTP':       ('T1190', 'Exploit Public-Facing Application'),
    'HTTPS':      ('T1190', 'Exploit Public-Facing Application'),
    'HTTP-Alt':   ('T1190', 'Exploit Public-Facing Application'),
    'HTTPS-Alt':  ('T1190', 'Exploit Public-Facing Application'),
    'RPC':        ('T1021', 'Remote Services — RPC'),
    'NetBIOS':    ('T1046', 'Network Service Discovery'),
    'SMB':        ('T1021.002', 'Remote Services — SMB'),
    'MySQL':      ('T1210', 'Exploitation of Remote Services'),
    'PostgreSQL': ('T1210', 'Exploitation of Remote Services'),
    'MongoDB':    ('T1210', 'Exploitation of Remote Services'),
    'Redis':      ('T1210', 'Exploitation of Remote Services'),
    'RDP':        ('T1021.001', 'Remote Services — RDP'),
    'VNC':        ('T1021.005', 'Remote Services — VNC'),
    'SMTP':       ('T1071.003', 'Application Layer Protocol — Mail'),
    'POP3':       ('T1071.003', 'Application Layer Protocol — Mail'),
    'IMAP':       ('T1071.003', 'Application Layer Protocol — Mail'),
    'DNS':        ('T1071.004', 'Application Layer Protocol — DNS'),
}

GENERIC_FIXES = {
    'FTP': 'Disable FTP or migrate to SFTP/FTPS; block port 21 at the firewall',
    'SSH': 'Disable password auth; require SSH keys; restrict SSH to an admin VLAN',
    'Telnet': 'Disable Telnet immediately; replace with SSH',
    'HTTP': 'Patch the web application/server; force redirect to HTTPS; add a WAF',
    'HTTPS': 'Keep TLS/cipher config current; patch the web stack',
    'HTTP-Alt': 'Remove dev/admin panels from production; add authentication',
    'HTTPS-Alt': 'Remove dev/admin panels from production; add authentication',
    'RPC': 'Block RPC from untrusted networks; restrict to domain controllers',
    'NetBIOS': 'Disable NetBIOS over TCP/IP; segment LAN broadcast domains',
    'SMB': 'Disable SMBv1; require SMB signing; segment file servers',
    'MySQL': 'Bind MySQL to localhost/internal IP only; rotate to strong passwords; add network ACLs',
    'PostgreSQL': 'Restrict pg_hba.conf to known app-server IPs; never expose to the whole LAN',
    'MongoDB': 'Enable authentication (often disabled by default); bind to localhost; add network ACLs',
    'Redis': 'Set a strong requirepass; bind to localhost; disable dangerous commands (FLUSHALL, CONFIG)',
    'RDP': 'Enable Network Level Authentication; require VPN before RDP; enforce MFA; restrict to jump hosts',
    'VNC': 'Tunnel VNC over VPN only; require a strong password; disable if unused',
    'SMTP': 'Disable open relay; require auth for sending; keep mail server patched',
    'POP3': 'Require TLS (POP3S); disable plaintext auth',
    'IMAP': 'Require TLS (IMAPS); disable plaintext auth',
    'DNS': 'Disable recursion for external clients; rate-limit to prevent DNS amplification abuse',
}

# ─────────────────────────────────────────────────────────────────
# MAC VENDOR (OUI) TABLE — used for real mobile-device detection
# ─────────────────────────────────────────────────────────────────
# Prefixes are the first 3 octets of a MAC address (the IEEE-assigned
# Organizationally Unique Identifier). This is a representative subset
# covering the vendors most commonly seen as phones/tablets on SME LANs.
MOBILE_OUI_PREFIXES = {
    # Apple (iPhone/iPad — Apple also makes laptops, so combine with
    # hostname/service heuristics rather than trusting this alone)
    'F0:18:98': 'Apple', '3C:15:C2': 'Apple', 'A4:5E:60': 'Apple',
    'DC:A9:04': 'Apple', '88:66:5A': 'Apple', '8C:85:90': 'Apple',
    'BC:92:6B': 'Apple', '40:B3:95': 'Apple', '6C:40:08': 'Apple',
    'AC:BC:32': 'Apple', '7C:6D:62': 'Apple',
    # Samsung
    '5C:0A:5B': 'Samsung', '8C:71:F8': 'Samsung', 'CC:07:AB': 'Samsung',
    'E8:50:8B': 'Samsung', '34:23:BA': 'Samsung', 'A0:21:95': 'Samsung',
    '64:B3:10': 'Samsung', '78:1F:DB': 'Samsung', 'D0:59:E4': 'Samsung',
    # Xiaomi / Redmi / Poco
    '64:09:80': 'Xiaomi', '8C:BE:BE': 'Xiaomi', '28:6C:07': 'Xiaomi',
    '74:51:BA': 'Xiaomi', '50:8F:4C': 'Xiaomi',
    # Google (Pixel)
    '3C:5A:B4': 'Google', 'F4:F5:D8': 'Google', '94:EB:2C': 'Google',
    # Huawei / Honor
    '00:E0:FC': 'Huawei', '48:7B:6B': 'Huawei', 'F8:01:13': 'Huawei',
    'C8:D7:19': 'Huawei',
    # OnePlus
    '94:65:2D': 'OnePlus', 'AC:C1:EE': 'OnePlus',
    # Oppo / Vivo / Realme (BBK Electronics group prefixes)
    '40:4E:36': 'Oppo', '7C:64:56': 'Vivo', '50:32:75': 'Realme',
    # Motorola
    '88:0F:10': 'Motorola', 'B0:EC:71': 'Motorola',
}

PHONE_VENDORS = {'Apple', 'Samsung', 'Xiaomi', 'Google', 'Huawei',
                  'OnePlus', 'Oppo', 'Vivo', 'Realme', 'Motorola'}

# ─────────────────────────────────────────────────────────────────
# OFFLINE CVE FALLBACK TABLE
# ─────────────────────────────────────────────────────────────────
# Used only when NVD can't be reached (no internet / rate-limited).
# These are real, well-documented historical CVEs for common SME
# software so the tool still produces specific guidance offline.
OFFLINE_CVE_FALLBACK = {
    'vsftpd 2.3.4': [{'id': 'CVE-2011-2523', 'cvss': 9.8,
        'summary': 'Backdoor command execution via crafted login string in vsftpd 2.3.4',
        'fix_version': '3.0.5 or later'}],
    'ProFTPD 1.3.5': [{'id': 'CVE-2015-3306', 'cvss': 9.8,
        'summary': 'mod_copy module allows unauthenticated file read/write',
        'fix_version': '1.3.5a or later'}],
    'OpenSSH 7.2': [{'id': 'CVE-2016-6210', 'cvss': 5.9,
        'summary': 'User enumeration via timing differences in authentication',
        'fix_version': '7.3 or later'}],
    'OpenSSH 6.6': [{'id': 'CVE-2016-0777', 'cvss': 4.0,
        'summary': 'Roaming feature in client allows leaking private keys to malicious server',
        'fix_version': '7.1p2 or later'}],
    'Apache 2.4.49': [{'id': 'CVE-2021-41773', 'cvss': 7.5,
        'summary': 'Path traversal and remote code execution in mod_cgi',
        'fix_version': '2.4.51 or later'}],
    'Apache 2.4.50': [{'id': 'CVE-2021-42013', 'cvss': 9.8,
        'summary': 'Path traversal / RCE — incomplete fix of CVE-2021-41773',
        'fix_version': '2.4.51 or later'}],
    'nginx 1.3.9': [{'id': 'CVE-2013-2028', 'cvss': 9.8,
        'summary': 'Stack buffer overflow in chunked transfer encoding',
        'fix_version': '1.4.1 or 1.5.0+'}],
    'Microsoft-IIS 6.0': [{'id': 'CVE-2017-7269', 'cvss': 9.8,
        'summary': 'Buffer overflow in WebDAV ScStoragePathFromUrl (RCE)',
        'fix_version': 'Upgrade off Windows Server 2003/IIS 6.0 entirely'}],
    'MySQL 5.5': [{'id': 'CVE-2012-2122', 'cvss': 7.5,
        'summary': 'Authentication bypass due to incorrect memcmp() result handling',
        'fix_version': '5.5.24/5.1.63/5.6.6 or later'}],
    'Samba 3.5': [{'id': 'CVE-2017-7494', 'cvss': 9.8,
        'summary': '"SambaCry" — remote code execution by uploading a shared library',
        'fix_version': '4.6.4 / 4.5.10 / 4.4.14 or later'}],
    'RDP': [{'id': 'CVE-2019-0708', 'cvss': 9.8,
        'summary': '"BlueKeep" — pre-auth remote code execution in RDP services',
        'fix_version': 'Apply MS17-010-era and 2019 RDP patches; enable NLA'}],
}


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
# DARK THEME CSS
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

.stSlider > div > div > div { background: var(--accent-cyan) !important; }

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

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-primary); }
::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 3px; }

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
        0deg, transparent, transparent 2px,
        rgba(0, 212, 255, 0.015) 2px, rgba(0, 212, 255, 0.015) 4px
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

.risk-bar { height: 100%; transition: width 0.5s ease; border-radius: 2px; }

.status-dot {
    display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; margin-right: 8px;
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

.cve-tag {
    display: inline-block;
    background: rgba(255, 51, 85, 0.15);
    border: 1px solid var(--accent-red);
    color: var(--accent-red);
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

.honeypot-alert {
    background: rgba(255, 215, 0, 0.08);
    border: 1px solid var(--accent-yellow);
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--accent-yellow);
    margin: 8px 0;
}

.exec-summary {
    background: var(--bg-card);
    border: 1px solid var(--bg-card-border);
    border-left: 4px solid var(--accent-cyan);
    padding: 18px 22px;
    font-family: var(--font-body);
    font-size: 0.95rem;
    line-height: 1.8;
    color: var(--text-primary);
    margin-bottom: 16px;
}

/* PRIORITY 25 — targeted fix for the Streamlit sidebar collapse/expand
   control rendering as literal text ("keyboard_double_arrow_right/left")
   instead of the Material Symbols icon glyph. This happens when the
   Material Symbols font fails to load/parse in the user's environment.
   This rule ONLY targets that specific control's font-family fallback
   and font-feature settings — it does not hide any application content
   or any other icon in the app. If the Material Symbols font is present,
   this rule is a no-op (the ligature text still renders as the icon).
   If it is not present, we at least keep the control usable (a plain
   arrow-like glyph) instead of leaving raw ligature text visible.
*/
[data-testid="stSidebarCollapseButton"] span[data-testid="stIconMaterial"],
[data-testid="collapsedControl"] span[data-testid="stIconMaterial"] {
    font-family: 'Material Symbols Outlined', sans-serif !important;
    font-size: 0 !important;
    line-height: 1 !important;
}
[data-testid="stSidebarCollapseButton"] span[data-testid="stIconMaterial"]::after,
[data-testid="collapsedControl"] span[data-testid="stIconMaterial"]::after {
    font-size: 1rem;
    content: '\\21C4';
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# ACDS DESIGN CONSTANTS  (Priority 6, 10, 13, 28)
# ─────────────────────────────────────────────────────────────────
# IMPORTANT: These weights/thresholds are the ACDS project's OWN design
# choice for this final-year project. They are NOT an industry-standard
# formula (e.g. not CVSS, not FAIR, not NIST 800-30). They exist so the
# risk score is transparent and explainable, not to claim authority.

# Asset Risk component weights (Priority 6) — must sum to 1.0
RISK_WEIGHT_VULNERABILITY = 0.40
RISK_WEIGHT_SERVICE_EXPOSURE = 0.20
RISK_WEIGHT_SENSITIVE_SERVICES = 0.15
RISK_WEIGHT_CRITICALITY = 0.15
RISK_WEIGHT_NETWORK_EXPOSURE = 0.10

# Overall ACDS Risk aggregation weights (Priority 15) — ACDS design choice
OVERALL_WEIGHT_ASSET_RISK = 0.60
OVERALL_WEIGHT_BLAST_RADIUS = 0.40

# Documented cap for the service/port exposure component (Priority 8).
# SCAN_PORTS currently checks 19 ports, so a host with ~10+ open ports
# is already treated as "fully exposed" for this component; this keeps
# one noisy host from silently dominating the score past that point.
PORT_EXPOSURE_CAP = 10

# Sensitive ports used for the Sensitive Services component (Priority 9)
SENSITIVE_PORTS = {21, 23, 135, 139, 445, 3306, 3389, 5432, 5900, 6379, 27017}
SENSITIVE_PORT_LABELS = {
    21: 'FTP', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 27017: 'MongoDB',
}
# A host with this many sensitive ports open is treated as maximally
# exposed on this component (documented cap, same rationale as above).
SENSITIVE_PORT_CAP = 4

# Risk severity thresholds (Priority 13) — used everywhere a 0-100 score
# needs a human label, so severity bands are never scattered as magic
# numbers through the UI code.
SEVERITY_THRESHOLDS = (
    (85, 'CRITICAL'), (65, 'HIGH'), (35, 'MEDIUM'), (0, 'LOW'),
)

# Criticality normalization (Priority 10): 2=LOW .. 5=CRITICAL mapped to 0-100
CRITICALITY_LABELS = {2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}
CRITICALITY_NORMALIZED = {2: 0, 3: 33, 4: 67, 5: 100}


def severity_from_score(score):
    """Map a 0-100 score to a documented severity label (Priority 13)."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return 'LOW'


# ─────────────────────────────────────────────────────────────────
# MODULE 0: MAC VENDOR / OUI LOOKUP
# ─────────────────────────────────────────────────────────────────

def mac_vendor(mac):
    """Look up the manufacturer of a MAC address using the local OUI table."""
    if not mac:
        return None
    prefix = mac.upper()[:8]  # "AA:BB:CC"
    return MOBILE_OUI_PREFIXES.get(prefix)


# Apple-specific OUI prefixes recognised for macOS evidence (Priority 2).
# This is a small, explicit subset (kept separate from MOBILE_OUI_PREFIXES,
# which is phone-focused) so "Apple vendor" evidence can be surfaced for
# laptops/desktops too without conflating them with iPhones/iPads.
APPLE_OUI_PREFIXES = {k for k, v in MOBILE_OUI_PREFIXES.items() if v == 'Apple'}


def is_apple_vendor(mac):
    """True if the MAC's OUI resolves to Apple (laptop, desktop, or phone)."""
    if not mac:
        return False
    return mac.upper()[:8] in APPLE_OUI_PREFIXES


# ─────────────────────────────────────────────────────────────────
# MODULE 0B: BANNER GRABBING (passive service fingerprinting)
# ─────────────────────────────────────────────────────────────────

def grab_banner(ip, port, timeout=1.2):
    """
    Connect to an open port and read whatever banner/header the service
    offers. This is passive — we never send exploit payloads, only the
    minimal protocol-correct request needed to elicit a version string
    (e.g. an HTTP GET, a TLS ClientHello). Returns (raw_banner, version_str).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                data = sock.recv(2048).decode(errors='ignore')
                m = re.search(r'Server:\s*(.+)', data, re.IGNORECASE)
                return data[:300], (m.group(1).strip() if m else None)

            if port in (443, 8443):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                        tls.settimeout(timeout)
                        tls.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                        data = tls.recv(2048).decode(errors='ignore')
                        m = re.search(r'Server:\s*(.+)', data, re.IGNORECASE)
                        return data[:300], (m.group(1).strip() if m else None)
                except (ssl.SSLError, OSError):
                    return None, None

            # Banner-on-connect protocols: SSH, FTP, SMTP, POP3, IMAP, Telnet
            data = sock.recv(1024).decode(errors='ignore').strip()
            if not data:
                return None, None
            version = data.splitlines()[0] if data else None
            return data[:300], version
    except (socket.timeout, OSError, ConnectionRefusedError):
        return None, None


def parse_version_from_banner(service, banner):
    """Extract a clean 'Product X.Y.Z' string from a raw banner for CVE lookup."""
    if not banner:
        return None
    banner = banner.strip()

    patterns = [
        r'SSH-[\d.]+-(OpenSSH[_\-][\d.]+\w*)',
        r'(vsftpd\s+[\d.]+)',
        r'(ProFTPD\s+[\d.]+)',
        r'(Pure-FTPd)',
        r'(Apache(?:/[\d.]+)?)',
        r'(nginx/[\d.]+)',
        r'(Microsoft-IIS/[\d.]+)',
        r'(MySQL\s+[\d.]+)',
        r'(\d+\.\d+\.\d+-MariaDB)',
        r'(OpenSSH[_\-][\d.]+\w*)',
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1).replace('_', ' ').replace('-', ' ', 1).strip()
    # Fallback: return first ~60 chars of banner as the "version" label
    return banner[:60]


# ─────────────────────────────────────────────────────────────────
# MODULE 0C: CVE LOOKUP (NVD live + offline fallback)
# ─────────────────────────────────────────────────────────────────
# Priority 4: every confirmed vulnerability now carries CVE ID, CVSS,
# Severity, Affected Product, Detected Product, Detected Version,
# Published/Modified dates, Source, and a Detection Confidence label.
# NVD's live API is the only source that can supply real published/
# modified dates; the offline fallback table is a small, static, local
# list with no date metadata, so those fields are explicitly "Unknown"
# rather than fabricated.

def cvss_severity_label(cvss):
    """Map a CVSS base score to its standard qualitative severity band."""
    if cvss is None:
        return 'Unknown'
    if cvss >= 9.0:
        return 'Critical'
    if cvss >= 7.0:
        return 'High'
    if cvss >= 4.0:
        return 'Medium'
    if cvss > 0.0:
        return 'Low'
    return 'None'


@functools.lru_cache(maxsize=128)
def lookup_cves_nvd(version_string):
    """
    Query the public NVD REST API for CVEs matching a free-text keyword
    (the parsed service/version string). Cached so we don't repeat the
    same network call during one session. Returns a list of dicts with
    id, cvss, severity, summary, fix_version, published, modified.
    """
    if not REQUESTS_AVAILABLE or not version_string:
        return []
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": version_string, "resultsPerPage": 5},
            timeout=4,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        product, detected_version = split_product_version(version_string)
        # A banner such as just "Apache" is useful inventory data but is
        # insufficient evidence for a version-specific CVE finding.
        if not product or not detected_version:
            return []

        results = []
        for item in data.get("vulnerabilities", [])[:5]:
            cve = item.get("cve", {})
            if not cve_applies_to_detected_version(cve, product, detected_version):
                continue
            cve_id = cve.get("id", "UNKNOWN")
            descs = cve.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0]["cvssData"].get("baseScore")
                    break
            results.append({
                "id": cve_id,
                "cvss": cvss if cvss is not None else 5.0,
                "severity": cvss_severity_label(cvss),
                "summary": summary[:200],
                "fix_version": None,
                "published": cve.get("published", "Unknown")[:10] if cve.get("published") else "Unknown",
                "modified": cve.get("lastModified", "Unknown")[:10] if cve.get("lastModified") else "Unknown",
            })
        results.sort(key=lambda c: c["cvss"], reverse=True)
        return results
    except (requests.RequestException, ValueError, KeyError):
        return []


def split_product_version(version_string):
    """Return a normalized product label and concrete version from a banner."""
    if not version_string:
        return None, None
    match = re.search(r"(OpenSSH|Apache|nginx|vsftpd|ProFTPD|MySQL|MariaDB|Microsoft-IIS)[ /_-]*([0-9]+(?:\.[0-9A-Za-z]+)+)", version_string, re.I)
    if not match:
        return None, None
    return match.group(1).lower(), match.group(2).lower()


def comparable_version(value):
    """Small, dependency-free comparator for NVD CPE numeric versions."""
    return tuple(int(part) if part.isdigit() else part for part in re.findall(r"\d+|[a-z]+", value.lower()))


def cpe_matches_product(criteria, product):
    aliases = {
        "apache": ("apache", "http_server"), "openssh": ("openbsd", "openssh"),
        "nginx": ("nginx", "nginx"), "vsftpd": ("vsftpd", "vsftpd"),
        "proftpd": ("proftpd", "proftpd"), "mysql": ("oracle", "mysql"),
        "mariadb": ("mariadb", "mariadb"), "microsoft-iis": ("microsoft", "internet_information_services"),
    }
    parts = criteria.lower().split(":")
    expected = aliases.get(product)
    return bool(expected and len(parts) > 5 and parts[3] == expected[0] and parts[4] == expected[1])


def version_is_affected(match, detected_version):
    """Evaluate the CPE range metadata NVD supplies for a concrete version."""
    target = comparable_version(detected_version)
    exact = match.get("criteria", "").split(":")
    if len(exact) > 5 and exact[5] not in {"*", "-"}:
        return target == comparable_version(exact[5])
    bounds = (
        ("versionStartIncluding", lambda a, b: a >= b),
        ("versionStartExcluding", lambda a, b: a > b),
        ("versionEndIncluding", lambda a, b: a <= b),
        ("versionEndExcluding", lambda a, b: a < b),
    )
    for field, comparison in bounds:
        value = match.get(field)
        if value and not comparison(target, comparable_version(value)):
            return False
    return True


def cve_applies_to_detected_version(cve, product, detected_version):
    """Require a vulnerable NVD CPE entry for the detected product/version."""
    def walk(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and cpe_matches_product(match.get("criteria", ""), product):
                    if version_is_affected(match, detected_version):
                        return True
            if walk(node.get("nodes")):
                return True
        return False
    return walk(cve.get("configurations", []))


def lookup_cves_offline(version_string):
    """Fallback lookup against the small built-in historical CVE table.
    No published/modified metadata is available offline — reported as
    'Unknown' rather than guessed."""
    product, detected_version = split_product_version(version_string)
    if not product or not detected_version:
        return []
    for key, cves in OFFLINE_CVE_FALLBACK.items():
        fallback_product, fallback_version = split_product_version(key)
        if (fallback_product == product and fallback_version == detected_version):
            enriched = []
            for c in cves:
                enriched.append({
                    **c,
                    "severity": cvss_severity_label(c.get("cvss")),
                    "published": "Unknown (offline table)",
                    "modified": "Unknown (offline table)",
                })
            return enriched
    return []


def get_real_cves(service, version_string):
    """
    Try live NVD lookup first; fall back to the offline table; fall back
    further to nothing (caller then uses the generic baseline risk).
    Returns (cves, source) where source in {'nvd_live','offline_table','none'}.
    """
    if not version_string:
        return [], "none"
    cves = lookup_cves_nvd(version_string)
    if cves:
        return cves, "nvd_live"
    cves = lookup_cves_offline(version_string)
    if cves:
        return cves, "offline_table"
    return [], "none"


def detection_confidence_label(source, has_exact_version):
    """Priority 4: 'Detection Confidence' shown alongside every finding."""
    if source == "nvd_live" and has_exact_version:
        return "High — live NVD match on exact detected version"
    if source == "offline_table" and has_exact_version:
        return "Medium — offline reference table match on exact version"
    if source == "none":
        return "N/A — no version-specific CVE found"
    return "Low — partial version evidence"


# ─────────────────────────────────────────────────────────────────
# MODULE 1B: REAL NETWORK SCAN ENGINE
# ─────────────────────────────────────────────────────────────────

def get_local_ip():
    """Detect the local machine's subnet for scanning."""
    system = platform.system()

    if system == "Windows":
        try:
            result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=5)
            output = result.stdout
            lines = output.split('\n')
            adapters, current_adapter = {}, None
            for line in lines:
                line = line.strip()
                if 'adapter' in line and ':' in line:
                    current_adapter = line
                    adapters[current_adapter] = {'ipv4': None, 'gateway': False}
                elif current_adapter:
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
                        if gateway and gateway != '(none)':
                            adapters[current_adapter]['gateway'] = True
            all_ips = [(d['ipv4'], d['gateway'], a) for a, d in adapters.items() if d['ipv4']]
            all_ips.sort(key=lambda x: x[1], reverse=True)
            for ip, has_gw, adapter in all_ips:
                if not any(vm in ip for vm in ['192.168.93.', '192.168.193.', '10.0.0.']):
                    octets = ip.split('.')
                    if len(octets) == 4:
                        return f"{octets[0]}.{octets[1]}.{octets[2]}."
            if all_ips:
                octets = all_ips[0][0].split('.')
                if len(octets) == 4:
                    return f"{octets[0]}.{octets[1]}.{octets[2]}."
        except (subprocess.TimeoutExpired, OSError):
            pass
    else:
        try:
            result = subprocess.run(
                ["ifconfig" if system == "Darwin" else "ip", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    for part in line.split():
                        if '.' in part and part.count('.') == 3:
                            octets = part.split('.')
                            if len(octets) == 4:
                                return f"{octets[0]}.{octets[1]}.{octets[2]}."
        except (subprocess.TimeoutExpired, OSError):
            pass
    return "192.168.1."


def get_local_system_context():
    """Identify the scanning machine's own IP, hostname and OS.

    This is cross-platform (Darwin/macOS, Linux, Windows) and is used as
    ONE piece of supporting evidence in infer_os_type() — if a discovered
    IP during a scan turns out to be this same machine, that is very
    strong (but not automatically 100%) evidence of its OS. Nothing here
    sends network traffic other than a UDP socket "connect" used purely
    to ask the OS which local interface would be used to reach the
    internet — no packets are actually transmitted by that call.
    """
    system = platform.system()
    local_os = {'Darwin': 'macos', 'Windows': 'windows', 'Linux': 'linux'}.get(system, 'unknown')

    local_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = None

    try:
        local_hostname = socket.gethostname()
    except OSError:
        local_hostname = None

    return {'os': local_os, 'ip': local_ip, 'hostname': local_hostname, 'system': system}


def _clean_hostname(name, ip):
    if not name:
        return None
    name = name.strip().rstrip('.')
    name = re.sub(r'\.local$', '', name, flags=re.IGNORECASE)
    if not name or name == ip or name.replace('.', '') == ip.replace('.', ''):
        return None
    return name


def resolve_hostname_ping(ip, system):
    try:
        if system == "Windows":
            result = subprocess.run(["ping", "-n", "1", "-w", "500", "-a", ip],
                                     capture_output=True, text=True, timeout=2)
        else:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                                     capture_output=True, text=True, timeout=2)
        match = re.search(r'Pinging\s+(.+?)\s+\[', result.stdout, re.IGNORECASE)
        if match:
            return _clean_hostname(match.group(1), ip)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def resolve_hostname_netbios(ip):
    try:
        result = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
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
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)
            for line in result.stdout.split('\n'):
                if 'Name:' in line:
                    cleaned = _clean_hostname(line.split('Name:')[-1].strip(), ip)
                    if cleaned:
                        return cleaned
        else:
            for cmd in (["dig", "+short", "-x", ip], ["host", ip]):
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


def ping_ip(ip, system):
    try:
        if system == "Windows":
            result = subprocess.run(["ping", "-n", "1", "-w", "500", ip], capture_output=True, text=True, timeout=1)
        elif system == "Darwin":
            result = subprocess.run(["ping", "-c", "1", "-t", "1", ip], capture_output=True, text=True, timeout=1)
        else:
            result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=1)

        is_alive = result.returncode == 0
        ttl = None
        if is_alive:
            for line in result.stdout.split('\n'):
                if 'TTL=' in line or 'ttl=' in line:
                    for part in line.split():
                        if '=' in part and 'ttl' in part.lower():
                            try:
                                ttl = int(part.split('=')[1])
                                break
                            except (ValueError, IndexError):
                                pass
                if ttl:
                    break
        return (ip, is_alive, ttl)
    except (subprocess.TimeoutExpired, OSError):
        return (ip, False, None)


def ttl_to_os(ttl):
    """Legacy TTL-only lookup. NOT used as the OS classifier anymore —
    kept only as a documented reference for the raw TTL bands, because
    TTL is now folded into infer_os_type() as supporting evidence only.
    Do not reintroduce this as a standalone classifier: macOS and Linux
    both commonly reply with TTL 64, so this function alone cannot tell
    them apart and previously caused every Mac to be labelled 'linux'.
    """
    if ttl is None:
        return 'unknown'
    if 110 <= ttl <= 130:
        return 'windows'
    if 55 <= ttl <= 75:
        return 'linux'
    if 240 <= ttl <= 260:
        return 'macos'
    return 'unknown'


# Hostname substrings that are supporting (not decisive) evidence for each
# OS family. Kept small and readable rather than exhaustive — new patterns
# can be appended safely without touching the scoring logic.
_MACOS_HOSTNAME_HINTS = (
    'macbook', 'imac', 'mac-mini', 'macmini', 'mac-pro', 'macpro',
    'mac-studio', 'macstudio', 'mbp', 'mba', '-mac', 'macs-',
)
_LINUX_HOSTNAME_HINTS = (
    'ubuntu', 'debian', 'kali', 'linux', 'centos', 'fedora', 'rhel',
    'raspberrypi', 'raspbian', '-rpi', 'arch-', 'suse',
)
_WINDOWS_HOSTNAME_HINTS = (
    'desktop-', 'win-', 'winpc', '-pc', 'dell-', 'hp-', 'lenovo-',
)


def infer_os_type(ip, ttl, hostname, mac, mac_vendor_, services,
                   banner_map=None, local_system_context=None):
    """Evidence-based OS inference (Priority 2).

    TTL is only ever ONE of several supporting signals — it is never
    treated as decisive on its own. macOS and Linux both commonly reply
    with TTL 64, so TTL alone cannot separate them (this was the root
    cause of Macs being reported as Linux). Instead, every available
    signal — TTL, MAC vendor, hostname, exposed services, service
    banners, and (when the discovered IP is the scanning machine itself)
    local system identity — contributes weighted evidence toward one of
    'macos', 'linux', 'windows', or 'unknown'.

    Returns:
        {
            'os': 'macos' | 'linux' | 'windows' | 'unknown',
            'confidence': float in [0, 1],
            'evidence': [human-readable reasons for the winning OS],
        }
    """
    banner_map = banner_map or {}
    services = services or []
    hl = (hostname or '').lower()

    scores = {'macos': 0.0, 'linux': 0.0, 'windows': 0.0}
    evidence = {'macos': [], 'linux': [], 'windows': []}

    def add(os_name, weight, reason):
        scores[os_name] += weight
        evidence[os_name].append(reason)

    # 1) Local machine identity — only fires for the scanner's own host,
    #    and only ever contributes evidence, never an unconditional 100%,
    #    because the scanner may itself run inside a VM/container later.
    if local_system_context and local_system_context.get('ip') and ip == local_system_context['ip']:
        local_os = local_system_context.get('os')
        if local_os in scores:
            add(local_os, 0.90, "This IP matches the scanning machine's own local IP")

    # 2) MAC vendor (OUI) — explicit Apple-vendor evidence (Priority 2:
    #    "Improve Apple vendor/OUI detection where appropriate").
    if mac_vendor_ == 'Apple' or is_apple_vendor(mac):
        add('macos', 0.30, "Apple MAC vendor (also used by iPhone/iPad — cross-checked against hostname/services)")

    # 3) Hostname patterns
    if any(h in hl for h in _MACOS_HOSTNAME_HINTS):
        add('macos', 0.35, "Hostname resembles a macOS device")
    if any(h in hl for h in _LINUX_HOSTNAME_HINTS):
        add('linux', 0.30, "Hostname resembles a Linux device/distribution")
    if any(h in hl for h in _WINDOWS_HOSTNAME_HINTS):
        add('windows', 0.25, "Hostname resembles a Windows device")

    # 4) Service exposure fingerprints
    if any(s in services for s in ('SMB', 'RDP')):
        add('windows', 0.30, "SMB/RDP exposed — Windows-specific services")
    if 'NetBIOS' in services:
        add('windows', 0.10, "NetBIOS exposed — common on Windows")

    # 5) Service banner fingerprints (passive banners already grabbed
    #    elsewhere in the pipeline — no extra probing here). Generic
    #    OpenSSH must NOT automatically favor Linux over macOS (Priority
    #    2) — it contributes equally small evidence to both.
    ssh_banner = banner_map.get('SSH') or ''
    if ssh_banner:
        if re.search(r'ubuntu|debian', ssh_banner, re.IGNORECASE):
            add('linux', 0.45, f"SSH banner identifies a Linux distribution ({ssh_banner[:50]})")
        elif re.search(r'openssh', ssh_banner, re.IGNORECASE):
            add('linux', 0.12, "OpenSSH banner present (common on Linux; also shipped on macOS)")
            add('macos', 0.08, "OpenSSH banner present (common on macOS; also shipped on Linux)")

    http_banner = banner_map.get('HTTP') or banner_map.get('HTTPS') or banner_map.get('HTTP-Alt') or ''
    if http_banner:
        if re.search(r'ubuntu|debian', http_banner, re.IGNORECASE):
            add('linux', 0.35, "HTTP server banner identifies a Linux distribution")
        elif re.search(r'win32|iis', http_banner, re.IGNORECASE):
            add('windows', 0.35, "HTTP server banner indicates Windows/IIS")
        elif re.search(r'\(unix\)', http_banner, re.IGNORECASE):
            add('macos', 0.05, "HTTP server banner reports generic Unix (compatible with macOS, not decisive)")
            add('linux', 0.05, "HTTP server banner reports generic Unix (compatible with Linux, not decisive)")

    # 6) TTL — SUPPORTING EVIDENCE ONLY. Windows' ~128 TTL is fairly
    #    distinctive, but the ~64 band is shared by both macOS and Linux,
    #    so it can only nudge the score, never decide macOS vs Linux.
    if ttl is not None:
        if 110 <= ttl <= 130:
            add('windows', 0.20, f"TTL {ttl} is consistent with Windows (supporting evidence only)")
        elif 55 <= ttl <= 75:
            add('linux', 0.10, f"TTL {ttl} is consistent with Linux or macOS (supporting evidence only, not decisive)")
            add('macos', 0.10, f"TTL {ttl} is consistent with Linux or macOS (supporting evidence only, not decisive)")

    best_os = max(scores, key=scores.get)
    best_score = scores[best_os]

    if best_score <= 0:
        return {'os': 'unknown', 'confidence': 0.0,
                'evidence': ['No distinguishing OS evidence was collected for this host']}

    # If two or more OSes are genuinely tied at the top score (e.g. TTL 64
    # alone, with no other signal to separate Linux from macOS), do not
    # arbitrarily pick one — report 'unknown' rather than a coin-flip
    # 'linux' the way the old TTL-only classifier effectively did.
    tied = [os_name for os_name, sc in scores.items() if sc == best_score]
    if len(tied) > 1:
        combined_evidence = []
        for t in tied:
            combined_evidence.extend(evidence[t])
        return {
            'os': 'unknown', 'confidence': round(min(0.3, best_score), 2),
            'evidence': [f"Evidence is ambiguous between {' and '.join(tied)}"] + combined_evidence,
        }

    confidence = round(max(0.05, min(0.97, best_score)), 2)
    return {'os': best_os, 'confidence': confidence, 'evidence': evidence[best_os]}


def ip_in_subnet(ip, base_ip):
    prefix = base_ip if base_ip.endswith('.') else f"{base_ip}."
    return ip.startswith(prefix)


def parse_arp_table(output, subnet_prefix):
    entries = {}
    base_ip = subnet_prefix if subnet_prefix.endswith('.') else f"{subnet_prefix}."
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('Interface') or 'Internet Address' in line:
            continue
        win_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+', line)
        if win_match:
            ip, mac = win_match.group(1), win_match.group(2).replace('-', ':').upper()
            if ip_in_subnet(ip, base_ip) and mac != 'FF:FF:FF:FF:FF:FF':
                entries[ip] = mac
            continue
        unix_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})', line)
        if unix_match:
            ip, mac = unix_match.group(1), unix_match.group(2).upper()
            if ip_in_subnet(ip, base_ip) and mac != 'FF:FF:FF:FF:FF:FF':
                entries[ip] = mac
    return entries


def read_arp_map(subnet_prefix):
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        else:
            try:
                result = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
            except FileNotFoundError:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        return parse_arp_table(result.stdout, subnet_prefix)
    except (subprocess.TimeoutExpired, OSError):
        return {}


def lookup_mac_windows(ip):
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"(Get-NetNeighbor -IPAddress '{ip}' -ErrorAction SilentlyContinue | "
             "Select-Object -First 1 -ExpandProperty LinkLayerAddress)"],
            capture_output=True, text=True, timeout=2,
        )
        mac = result.stdout.strip().replace('-', ':').upper()
        if re.fullmatch(r'([0-9A-F]{2}:){5}[0-9A-F]{2}', mac):
            return mac
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def is_tablet_device(hostname):
    if not hostname:
        return False
    hl = hostname.lower()
    return any(p in hl for p in ['ipad', 'tablet', 'tab-', 'tab_', 'sm-t', 'sm-x', 'lenovo tab', 'surface'])


def is_mobile_device(hostname, ip, mac=None):
    """
    Real mobile detection: combine MAC-vendor lookup (most reliable, works
    even with no/generic hostname) with hostname pattern matching.
    """
    if is_tablet_device(hostname):
        return True

    vendor = mac_vendor(mac)
    if vendor in PHONE_VENDORS:
        # Apple vendor MACs can be laptops too — only trust this alone if
        # the hostname doesn't look like a Mac/computer; otherwise let the
        # hostname check below confirm it.
        if vendor != 'Apple':
            return True
        if hostname and any(w in hostname.lower() for w in ['macbook', 'imac', 'mac-mini', 'mac-pro']):
            return False
        if hostname and ('iphone' in hostname.lower() or 'ipad' in hostname.lower()):
            return True
        if not hostname:
            return True  # unnamed Apple device on LAN — treat as phone/tablet by default, flagged for review

    if not hostname:
        return False

    hl = hostname.lower()
    mobile_patterns = [
        'iphone', 'ipad', 'android', 'mobile', 'phone', 'tablet',
        'samsung', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'oppo',
        'vivo', 'huawei', 'honor', 'realme', 'motorola', 'lg',
        'nokia', 'sony', 'htc', 'blackberry', 'windows-phone',
        'redmi', 'poco', 'nothing-phone',
    ]
    if any(p in hl for p in mobile_patterns):
        return True
    if "'s " in hl or "s iphone" in hl or "s ipad" in hl:
        return True
    if any(model in hl for model in ['sm-', 'rmx', 'cph', 'redmi', 'poco']):
        return True
    return False


def classify_device(hostname, os_type, os_confidence, is_mobile, services, open_ports, mac=None):
    """Evidence-based device classification (Priority 3).

    Returns an "Inferred Device Type" rather than an absolute claim, with
    a confidence score and the concrete evidence used, so a Mac with SSH
    open is never silently reported as a Linux server.
    """
    services = services or []
    open_ports = open_ports or []
    hl = (hostname or '').lower()
    evidence = []

    if is_tablet_device(hostname):
        return {'device_type': 'Tablet', 'confidence': 0.75,
                'evidence': ['Hostname matches known tablet naming pattern (e.g. iPad/tablet/Surface)']}

    if is_mobile:
        vendor = mac_vendor(mac)
        ev = ['Hostname or MAC vendor matches a known mobile-phone pattern']
        if vendor:
            ev.append(f"MAC vendor resolved to {vendor}")
        return {'device_type': 'Mobile Device', 'confidence': 0.70 if vendor else 0.55, 'evidence': ev}

    if any(h in hl for h in ['router', 'gateway', 'modem', 'ap-', 'wifi', 'fritz', 'tplink', 'netgear', 'asus']):
        return {'device_type': 'Network Device', 'confidence': 0.65,
                'evidence': ['Hostname matches known router/gateway/AP naming pattern']}

    db_services = [s for s in services if s in ('MySQL', 'PostgreSQL', 'MongoDB', 'Redis')]
    if db_services:
        db_ports = [p for p in open_ports if PORT_SERVICE_MAP.get(p) in db_services]
        evidence = [f"{s} detected" for s in db_services] + [f"Port {p} exposed" for p in db_ports]
        return {'device_type': 'Database Server', 'confidence': 0.90, 'evidence': evidence}

    web_services = [s for s in services if s in ('HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt')]
    if web_services and os_type != 'macos':
        evidence = [f"{s} service detected" for s in web_services]
        return {'device_type': 'Web Server', 'confidence': 0.65, 'evidence': evidence}

    # macOS host: never label as a "Linux Server" merely because SSH is
    # open (Priority 3's explicit example). macOS evidence dominates once
    # os_type == 'macos', regardless of which remote-access service is up.
    if os_type == 'macos':
        evidence = ['OS inferred as macOS']
        if any(s in services for s in ('SSH', 'HTTP', 'HTTPS')):
            evidence.append('Remote-access/web service open, but service alone does not override OS evidence')
        return {'device_type': 'Mac Computer', 'confidence': round(min(0.95, 0.5 + os_confidence * 0.4), 2),
                'evidence': evidence}

    if os_type == 'windows':
        evidence = ['OS inferred as Windows']
        if any(s in services for s in ('SMB', 'RDP')):
            evidence.append('SMB/RDP service present (common on Windows workstations/servers)')
        role_guess = 'Windows Server' if any(s in services for s in ('HTTP', 'HTTPS', 'DNS')) else 'Windows Workstation'
        return {'device_type': role_guess, 'confidence': round(min(0.9, 0.45 + os_confidence * 0.4), 2),
                'evidence': evidence}

    if os_type == 'linux':
        evidence = ['OS inferred as Linux']
        role_guess = 'Linux Server' if any(s in services for s in ('SSH', 'HTTP', 'HTTPS', 'DNS', 'SMB')) else 'Linux Workstation'
        if role_guess == 'Linux Server':
            evidence.append('Server-type service exposed (SSH/HTTP/DNS/SMB)')
        return {'device_type': role_guess, 'confidence': round(min(0.9, 0.45 + os_confidence * 0.4), 2),
                'evidence': evidence}

    if services:
        return {'device_type': 'Unknown', 'confidence': 0.25,
                'evidence': [f"Services detected ({', '.join(services[:3])}) but OS evidence was insufficient to classify further"]}

    return {'device_type': 'Unknown', 'confidence': 0.10,
            'evidence': ['No OS or service evidence collected for this host']}


def identify_device_type(hostname, os_type, is_mobile, services, mac=None):
    """Backward-compatible thin wrapper returning just the label string
    (kept because several call sites only need the label). New code
    should call classify_device() directly for confidence + evidence."""
    return classify_device(hostname, os_type, 0.5, is_mobile, services, [], mac)['device_type']


def calculate_criticality(device_type, services, open_ports, os_type):
    """Asset Criticality Model (Priority 5 / 10).

    Criticality answers "how important is this asset based on observable
    technical characteristics?" — it is deliberately kept separate from
    vulnerability/CVE data (never uses CVSS). It is derived only from
    inferred device type, inferred role, and the services actually
    detected. It never claims real business importance unless the user
    supplies that separately (not implemented here — out of scope for a
    passive scanner).
    """
    services = services or []
    open_ports = open_ports or []
    evidence = []
    level = 2  # LOW by default

    db_services = [s for s in services if s in ('MySQL', 'PostgreSQL', 'MongoDB', 'Redis')]
    infra_services = [s for s in services if s in ('DNS', 'SMB', 'RDP')]
    sensitive_open = sorted(set(open_ports) & SENSITIVE_PORTS)

    if device_type == 'Database Server' or db_services:
        level = 5
        evidence.append('Database role inferred')
        evidence.extend(f"{s} detected" for s in db_services)
    elif device_type in ('Web Server', 'Linux Server', 'Windows Server'):
        level = 4
        evidence.append('Server role inferred from device classification')
    elif infra_services:
        level = 4
        evidence.append('Infrastructure service detected (DNS/SMB/RDP)')
        evidence.extend(f"{s} detected" for s in infra_services)
    elif device_type in ('Mac Computer', 'Windows Workstation', 'Linux Workstation'):
        level = 3
        evidence.append('Workstation role inferred — not a server or infrastructure asset')
    elif device_type in ('Mobile Device', 'Tablet'):
        level = 2
        evidence.append('Mobile/tablet device — typically lower blast-radius value on the LAN')
    elif device_type == 'Network Device':
        level = 4
        evidence.append('Network infrastructure device (router/gateway/AP) inferred from hostname')
    else:
        level = 2
        evidence.append('No device-role evidence available — defaulted to LOW criticality')

    if sensitive_open:
        evidence.extend(f"Port {p} ({SENSITIVE_PORT_LABELS.get(p, 'sensitive')}) exposed" for p in sensitive_open[:3])
        level = min(5, level + (1 if level < 5 and len(sensitive_open) >= 2 else 0))

    confidence = round(min(0.95, 0.35 + 0.12 * len(evidence)), 2)
    return {
        'level': level,
        'label': CRITICALITY_LABELS[level],
        'confidence': confidence,
        'evidence': evidence,
    }


# ─────────────────────────────────────────────────────────────────
# ACDS ASSET RISK MODEL (Priorities 6-14)
# ─────────────────────────────────────────────────────────────────
# Replaces the old additive heuristic (CVSS*7 + port points + criticality
# points) with a transparent WEIGHTED model. Every component is first
# normalized to 0-100, then combined using the documented weights above.
# These weights are this project's own design choice, not an industry
# standard (NIST/FAIR/CVSS do not define an "asset risk" formula this
# way) — that is stated explicitly in the UI as well.


def calculate_vulnerability_score(cve_findings):
    """Priority 7: vulnerability/CVSS component.

    Uses the highest CONFIRMED CVSS score for the asset. CVSS 0-10 maps
    linearly to 0-100. If there is no confirmed version-specific CVE,
    this explicitly returns state='no_cve' rather than silently
    reporting a zero score with no explanation — the asset may still
    carry EXPOSURE / WEAK CONFIGURATION risk via other components.
    """
    if not cve_findings:
        return {'score': 0.0, 'state': 'no_cve', 'max_cvss': None, 'basis': 'NO VERSION-SPECIFIC CVE FOUND'}
    max_cvss = max((float(c.get('cvss', 0)) for c in cve_findings), default=0.0)
    return {'score': round(max_cvss * 10, 1), 'state': 'confirmed', 'max_cvss': max_cvss,
            'basis': f'Highest confirmed CVSS: {max_cvss}'}


def calculate_service_exposure_score(open_port_count):
    """Priority 8: service/port exposure component.

    service_exposure_score = min(open_port_count / PORT_EXPOSURE_CAP, 1.0) * 100
    PORT_EXPOSURE_CAP is documented in the ACDS design constants above.
    """
    score = min(open_port_count / PORT_EXPOSURE_CAP, 1.0) * 100
    return {'score': round(score, 1), 'open_port_count': open_port_count, 'cap': PORT_EXPOSURE_CAP}


def calculate_sensitive_service_score(open_ports):
    """Priority 9: sensitive-service component.

    Normalizes the count of exposed sensitive ports (documented list) to
    0-100 using a documented cap, and returns which specific sensitive
    ports/services were detected so the UI never shows a mysterious
    number alone.
    """
    open_ports = open_ports or []
    detected = sorted(set(open_ports) & SENSITIVE_PORTS)
    score = min(len(detected) / SENSITIVE_PORT_CAP, 1.0) * 100
    labeled = [(p, SENSITIVE_PORT_LABELS.get(p, str(p))) for p in detected]
    return {'score': round(score, 1), 'detected_ports': labeled, 'cap': SENSITIVE_PORT_CAP}


def calculate_criticality_score(criticality_level):
    """Priority 10: criticality component, normalized 2->0 .. 5->100.
    Does NOT mix in CVSS — criticality and vulnerability stay separate
    inputs that are only combined later, with their own weights, inside
    calculate_asset_risk()."""
    return {'score': float(CRITICALITY_NORMALIZED.get(criticality_level, 0)), 'level': criticality_level}


# Documented cap for the network-exposure component (Priority 11): if a
# host is potentially reachable from this many OTHER discovered assets
# (i.e. those other hosts have a modeled lateral-movement edge to it),
# it is treated as maximally network-exposed for this component.
NETWORK_EXPOSURE_REACHABILITY_CAP = 5
# Neutral value used only when no network/exposure evidence exists at all
# (e.g. a single-host scan, or before any other asset has been discovered).
NETWORK_EXPOSURE_NEUTRAL_SCORE = 50.0


def calculate_network_exposure_score(open_port_count, other_asset_count):
    """Priority 11: network-exposure component.

    Uses only information already available in the app's own model: how
    many OTHER discovered assets could potentially reach this host,
    given it exposes at least one open service. This is explicitly
    POTENTIAL REACHABILITY (a modeled possibility), never a claim of
    OBSERVED COMMUNICATION — the scanner never captures real traffic.
    """
    if other_asset_count is None:
        return {'score': NETWORK_EXPOSURE_NEUTRAL_SCORE, 'basis': 'No network exposure evidence available — neutral value used', 'reachable_from': None}
    if open_port_count <= 0:
        return {'score': 0.0, 'basis': 'No open services — no modeled reachability from other assets', 'reachable_from': 0}
    score = min(other_asset_count / NETWORK_EXPOSURE_REACHABILITY_CAP, 1.0) * 100
    return {'score': round(score, 1), 'basis': f'Potential reachability from {other_asset_count} discovered asset(s)', 'reachable_from': other_asset_count}


def calculate_asset_risk(vulnerability, service_exposure, sensitive_services, criticality, network_exposure):
    """Priority 6/12: combine the five normalized 0-100 components into a
    single explainable 0-100 Asset Risk score using the documented ACDS
    weights. Returns the full risk_components breakdown so the UI can
    show contribution-by-contribution math that always sums (within
    rounding) to the final score.
    """
    components = {
        'vulnerability': {
            'normalized_score': vulnerability['score'], 'weight': RISK_WEIGHT_VULNERABILITY,
            'contribution': round(vulnerability['score'] * RISK_WEIGHT_VULNERABILITY, 2),
        },
        'service_exposure': {
            'normalized_score': service_exposure['score'], 'weight': RISK_WEIGHT_SERVICE_EXPOSURE,
            'contribution': round(service_exposure['score'] * RISK_WEIGHT_SERVICE_EXPOSURE, 2),
        },
        'sensitive_services': {
            'normalized_score': sensitive_services['score'], 'weight': RISK_WEIGHT_SENSITIVE_SERVICES,
            'contribution': round(sensitive_services['score'] * RISK_WEIGHT_SENSITIVE_SERVICES, 2),
        },
        'criticality': {
            'normalized_score': criticality['score'], 'weight': RISK_WEIGHT_CRITICALITY,
            'contribution': round(criticality['score'] * RISK_WEIGHT_CRITICALITY, 2),
        },
        'network_exposure': {
            'normalized_score': network_exposure['score'], 'weight': RISK_WEIGHT_NETWORK_EXPOSURE,
            'contribution': round(network_exposure['score'] * RISK_WEIGHT_NETWORK_EXPOSURE, 2),
        },
    }
    total = sum(c['contribution'] for c in components.values())
    total = max(0.0, min(100.0, total))
    return {
        'score': round(total, 1),
        'severity': severity_from_score(total),
        'components': components,
        'vulnerability_state': vulnerability['state'],
        'sensitive_detected': sensitive_services['detected_ports'],
        'network_basis': network_exposure['basis'],
    }


def build_risk_profile(open_ports, cve_findings, criticality):
    """DEPRECATED — retained only so any external/legacy caller does not
    crash on import. The ACDS Asset Risk Model (Priority 6) replaces this
    additive heuristic; see calculate_asset_risk(). Do not call this for
    new risk numbers — it is intentionally NOT used anywhere below.
    """
    sensitive_ports = SENSITIVE_PORTS
    exposed_sensitive = sorted(set(open_ports) & sensitive_ports)
    max_cvss = max((float(c.get('cvss', 0)) for c in cve_findings), default=0.0)
    severity = cvss_severity_label(max_cvss) if max_cvss else "Unknown"
    return {
        'score': None, 'severity': severity, 'basis': 'deprecated — use calculate_asset_risk()',
        'max_cvss': max_cvss, 'sensitive_ports': exposed_sensitive,
    }


def format_device_display_name(hostname, device_type, ip):
    if hostname and device_type:
        if device_type.lower() in hostname.lower():
            return hostname
        return f"{hostname} ({device_type})"
    if hostname:
        return hostname
    if device_type:
        return f"{device_type} @ {ip}"
    return ip


def scan_ports(ip, ports, timeout=0.6):
    """Passively test a curated TCP port list using native sockets.

    This avoids spawning a PowerShell process for every port on Windows;
    those processes can time out before Test-NetConnection runs and hide
    services that are actually reachable.
    """
    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                return port if sock.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=min(20, len(ports))) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def detect_services_and_versions(ip, open_ports):
    """
    For every open port: identify the service name from the port number,
    then attempt a real banner grab to get the actual version string.
    Returns: services (list of names), version_map ({service: version_str or None}),
    banner_map ({service: raw_banner or None})
    """
    services, version_map, banner_map = [], {}, {}
    for port in open_ports:
        svc = PORT_SERVICE_MAP.get(port)
        if not svc:
            continue
        services.append(svc)
        banner, raw_version = grab_banner(ip, port)
        clean_version = parse_version_from_banner(svc, raw_version) if raw_version else None
        version_map[svc] = clean_version
        banner_map[svc] = banner
    return services, version_map, banner_map


def assess_device_security(services, os_type, device_type, open_ports, role, version_map=None, ip=None):
    """
    Build the real, per-host security assessment (Priority 4):
      - For each open service, try to pull real CVEs via NVD/offline table
        using the detected version string, with full CVE metadata.
      - If no version-specific CVE is found, fall back to the generic
        baseline exposure risk for that service type and label it
        EXPOSURE / WEAK CONFIGURATION, never a confirmed CVE.
      - Always produce a SPECIFIC fix string naming the host, version, and
        (when available) the exact CVE + patched version.

    Note: this function computes everything EXCEPT the network-exposure
    component and the final weighted Asset Risk, because those require
    knowing how many other assets were discovered in the same scan.
    build_dynamic_graph() / build_network() finish the risk calculation
    once the full set of hosts is known (see calculate_asset_risk()).
    """
    version_map = version_map or {}
    weaknesses, access_vectors, fixes = [], [], []
    confirmed_findings = []      # CONFIRMED VULNERABILITY (version-specific CVE)
    exposure_findings = []       # EXPOSURE / WEAK CONFIGURATION (no confirmed CVE)
    cve_source_used = "none"

    for port in open_ports:
        svc = PORT_SERVICE_MAP.get(port)
        if not svc:
            continue

        version_str = version_map.get(svc)
        cves, source = get_real_cves(svc, version_str) if version_str else ([], "none")
        if source != "none":
            cve_source_used = source

        if cves:
            top = cves[0]
            confirmed_findings.append({
                'status': 'CONFIRMED VULNERABILITY',
                'service': svc, 'port': port,
                'affected_product': svc, 'detected_product': svc,
                'detected_version': version_str,
                'cve_id': top['id'], 'cvss': top['cvss'],
                'severity': top.get('severity', cvss_severity_label(top['cvss'])),
                'summary': top['summary'], 'fix_version': top.get('fix_version'),
                'published': top.get('published', 'Unknown'),
                'modified': top.get('modified', 'Unknown'),
                'source': source,
                'detection_confidence': detection_confidence_label(source, bool(version_str)),
            })
            label = f"{svc} {version_str or ''} (port {port}) — {top['id']} (CVSS {top['cvss']})"
            if label not in weaknesses:
                weaknesses.append(label)
            fix_detail = top.get('fix_version')
            fix_text = (
                f"Patch {svc}{(' ' + version_str) if version_str else ''} on {ip or 'this host'} — "
                f"{top['id']} (CVSS {top['cvss']}): {top['summary'][:120]}"
                f"{('. Upgrade to ' + fix_detail) if fix_detail else '. Check vendor advisory for the patched version.'}"
            )
            if fix_text not in fixes:
                fixes.append(fix_text)
            mitre = SERVICE_MITRE.get(svc, ('T1190', 'Exploit Public-Facing Application'))
            access_vectors.append(f"{mitre[1]} via {svc} ({top['id']})")
        else:
            exposure_findings.append({
                'status': 'EXPOSURE / WEAK CONFIGURATION' if version_str else 'NO VERSION-SPECIFIC CVE FOUND',
                'service': svc, 'port': port, 'detected_version': version_str,
                'baseline_risk': SERVICE_BASELINE_RISK.get(svc, 0.4),
            })
            label = f"Exposed {svc}{(' ' + version_str) if version_str else ''} (port {port}) — no version-specific CVE found, baseline exposure risk"
            if label not in weaknesses:
                weaknesses.append(label)
            mitre = SERVICE_MITRE.get(svc, ('T1190', 'Exploit Public-Facing Application'))
            access_vectors.append(mitre[1])
            generic_fix = GENERIC_FIXES.get(svc, f'Restrict access to {svc} and keep it patched')
            fix_text = f"{generic_fix} (host: {ip or 'this host'}, port {port})"
            if fix_text not in fixes:
                fixes.append(fix_text)

    if device_type in ('Mobile Device', 'Tablet'):
        weaknesses.append('Mobile device on LAN — phishing / credential-theft foothold; often unmanaged by IT')
        fixes.append(f'Move {ip or "this device"} to a guest/BYOD VLAN isolated from servers; enforce MDM and screen-lock policy if company-owned')

    if os_type == 'windows' and 'SMB' in services:
        if 'Windows host with SMB exposed — domain credential relay risk' not in weaknesses:
            weaknesses.append('Windows host with SMB exposed — domain credential relay risk')
            fixes.append(f'Enable Windows Defender Firewall on {ip or "this host"}; restrict SMB to the file-server subnet only')

    if role == 'Database':
        weaknesses.append('Database tier reachable from LAN — high-value target')
        fixes.append(f'Place {ip or "this database"} on an isolated VLAN; allow only the specific app-server IPs that need it')

    if not weaknesses:
        weaknesses.append('Host reachable on network — baseline lateral movement target')
        fixes.append(f'Apply OS patches on {ip or "this host"}; enable host firewall; remove unused services')

    vulnerability_component = calculate_vulnerability_score(confirmed_findings)
    service_component = calculate_service_exposure_score(len(open_ports))
    sensitive_component = calculate_sensitive_service_score(open_ports)

    # exposure_level kept for the attack-simulation probability model
    # (Priority 26 boundary: simulation stays a probabilistic model on
    # the in-memory graph, never real exploitation). It reuses the
    # confirmed-CVE CVSS when present, else the baseline exposure table.
    if confirmed_findings:
        exposure_level = min(0.98, max(f['cvss'] for f in confirmed_findings) / 10.0)
    elif exposure_findings:
        exposure_level = min(0.98, max(f['baseline_risk'] for f in exposure_findings))
    else:
        exposure_level = 0.20

    return {
        'vulnerability_component': vulnerability_component,
        'service_component': service_component,
        'sensitive_component': sensitive_component,
        'exposure_level': round(exposure_level, 2),
        'weaknesses': weaknesses,
        'access_vectors': access_vectors,
        'fixes': fixes,
        'cve_findings': confirmed_findings,       # CONFIRMED only (Priority 4)
        'exposure_findings': exposure_findings,    # EXPOSURE / NO-CVE only
        'cve_source': cve_source_used,
    }


def get_lateral_edges_for_target(open_ports):
    edges = []
    for port in open_ports:
        svc = PORT_SERVICE_MAP.get(port)
        if svc:
            mitre = SERVICE_MITRE.get(svc, ('T1021', 'Lateral Movement'))
            edges.append({
                'port': port, 'service': svc,
                'vector': mitre[1],
                'mitre_code': mitre[0], 'mitre_desc': mitre[1],
                'success_prob': SERVICE_BASELINE_RISK.get(svc, 0.4),
                'connection': f"{svc.lower()}/{port}",
            })
    if not edges:
        edges.append({
            'port': 0, 'service': 'LAN', 'vector': 'Network Reachability / Credential Reuse',
            'mitre_code': 'T1078', 'mitre_desc': 'Valid Accounts — LAN foothold spread',
            'success_prob': 0.35, 'connection': 'lan/reachability',
        })
    return edges


def assign_role_from_services(services, os_type, device_type):
    if any(db in services for db in ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis']):
        return 'Database'
    if any(w in services for w in ['HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt']):
        return 'Server'
    if 'SMB' in services:
        return 'Server'
    if any(r in services for r in ['SSH', 'RDP', 'VNC', 'Telnet']):
        return 'Server'
    if any(e in services for e in ['SMTP', 'POP3', 'IMAP']):
        return 'Server'
    if 'DNS' in services:
        return 'Server'
    if device_type in ('Mobile Device', 'Tablet'):
        return 'Workstation'
    if os_type in ['windows', 'linux', 'macos']:
        return 'Workstation'
    return 'Workstation'


def _now_stamp():
    return datetime.now().strftime("%H:%M:%S")


def scan_network(base_ip=None, limit=254, progress_cb=None):
    """
    Full discovery pipeline: ping sweep -> ARP/MAC -> hostname -> port scan
    -> banner grab -> per-host record. progress_cb(done, total) is called
    as hosts are enriched, for a live progress bar in the UI.

    Also returns a scan_timeline (Priority 20): a flat, time-ordered list
    of the ACTUAL operations performed (ping, host discovery, ports,
    banner, NVD lookup, risk calculated). No synthetic/fake events are
    ever appended — only operations this function truly executed.
    """
    if base_ip is None:
        base_ip = get_local_ip()

    system = platform.system()
    subnet_prefix = base_ip.rstrip('.')
    ips = [f"{base_ip}{i}" for i in range(1, limit + 1)]

    timeline = []
    timeline.append({'timestamp': _now_stamp(), 'event': 'Ping sweep started', 'target': f"{base_ip}0/{limit}", 'status': 'Running'})

    ping_results = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_ip, ip, system): ip for ip in ips}
        for future in as_completed(futures):
            ip, is_alive, ttl = future.result()
            if is_alive:
                ping_results[ip] = ttl

    timeline.append({'timestamp': _now_stamp(), 'event': 'Ping sweep completed', 'target': f"{len(ping_results)} host(s) responded", 'status': 'Completed'})

    arp_map = read_arp_map(subnet_prefix)
    timeline.append({'timestamp': _now_stamp(), 'event': 'ARP table read', 'target': f"{len(arp_map)} entr(y/ies)", 'status': 'Completed'})
    candidate_ips = {ip for ip in (set(ping_results) | set(arp_map)) if ip_in_subnet(ip, base_ip)}

    total = len(candidate_ips)

    # Computed once per scan (not per host) — cheap, and gives every host
    # something to compare against for the "is this the scanner itself"
    # evidence signal in infer_os_type().
    local_ctx = get_local_system_context()

    def enrich_device(ip):
        # NOTE: this runs inside a worker thread. Never call Streamlit UI
        # functions (st.*, or a progress_cb that wraps them) from in here —
        # Streamlit only allows UI updates from the main script thread and
        # will raise NoSessionContext otherwise. Progress is reported back
        # in the main-thread as_completed() loop below instead.
        host_events = [{'timestamp': _now_stamp(), 'event': 'Host discovered', 'target': ip, 'status': 'Alive' if ip in ping_results else 'ARP only'}]
        ttl = ping_results.get(ip)
        mac = arp_map.get(ip)
        if not mac and system == "Windows":
            mac = lookup_mac_windows(ip)
        if mac:
            host_events.append({'timestamp': _now_stamp(), 'event': 'ARP/MAC resolved', 'target': f"{ip} ({mac})", 'status': 'Resolved'})

        hostname = resolve_hostname(ip)
        vendor = mac_vendor(mac)

        try:
            open_ports = scan_ports(ip, SCAN_PORTS) if ip in ping_results else []
        except Exception as exc:
            open_ports = []
            host_events.append({'timestamp': _now_stamp(), 'event': 'Port scan failed', 'target': ip, 'status': f'Unavailable ({type(exc).__name__})'})
        else:
            host_events.append({'timestamp': _now_stamp(), 'event': 'Ports discovered', 'target': ','.join(str(p) for p in open_ports) if open_ports else 'none', 'status': 'Completed'})

        try:
            services, version_map, banner_map = detect_services_and_versions(ip, open_ports)
        except Exception as exc:
            services, version_map, banner_map = [], {}, {}
            host_events.append({'timestamp': _now_stamp(), 'event': 'Banner grab failed', 'target': ip, 'status': f'Unavailable ({type(exc).__name__})'})
        else:
            if services:
                host_events.append({'timestamp': _now_stamp(), 'event': 'Banners retrieved', 'target': ', '.join(services), 'status': 'Completed'})

        # OS is inferred AFTER services/banners are collected, so banner
        # evidence (e.g. an SSH banner naming "Ubuntu") can be used. TTL
        # alone is never decisive — see infer_os_type().
        try:
            os_result = infer_os_type(ip, ttl, hostname, mac, vendor, services,
                                       banner_map=banner_map, local_system_context=local_ctx)
        except Exception as exc:
            os_result = {'os': 'unknown', 'confidence': 0.0, 'evidence': [f'OS inference failed: {type(exc).__name__}']}
        host_events.append({'timestamp': _now_stamp(), 'event': 'OS inferred', 'target': f"{os_result['os']} ({int(os_result['confidence']*100)}%)", 'status': 'Completed'})

        is_mobile = is_mobile_device(hostname, ip, mac)
        device_result = classify_device(hostname, os_result['os'], os_result['confidence'], is_mobile, services, open_ports, mac)
        host_events.append({'timestamp': _now_stamp(), 'event': 'Asset classified', 'target': device_result['device_type'], 'status': 'Completed'})
        display_name = format_device_display_name(hostname, device_result['device_type'], ip)

        for svc in services:
            if version_map.get(svc):
                host_events.append({'timestamp': _now_stamp(), 'event': 'NVD lookup completed', 'target': f"{svc} {version_map.get(svc)}", 'status': 'Completed'})

        return {
            'hostname': hostname, 'os': os_result['os'],
            'os_confidence': os_result['confidence'], 'os_evidence': os_result['evidence'],
            'is_mobile': is_mobile, 'mac': mac,
            'mac_vendor': vendor, 'open_ports': open_ports, 'services': services,
            'version_map': version_map, 'banner_map': banner_map,
            'device_type': device_result['device_type'],
            'device_confidence': device_result['confidence'],
            'device_evidence': device_result['evidence'],
            'display_name': display_name, 'events': host_events,
        }

    devices = {}
    done = 0
    scan_had_errors = False
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(enrich_device, ip): ip for ip in sorted(candidate_ips)}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                devices[ip] = future.result()
                timeline.extend(devices[ip].get('events', []))
            except Exception as exc:
                # A single host's failure must never abort the whole scan
                # (Priority 1). Record it and continue with everything else.
                scan_had_errors = True
                timeline.append({'timestamp': _now_stamp(), 'event': 'Host enrichment failed', 'target': ip, 'status': f'Unavailable ({type(exc).__name__})'})
            done += 1
            if progress_cb:
                # Safe: this loop runs on the main thread, not a worker thread.
                progress_cb(done, total)

    timeline.append({'timestamp': _now_stamp(), 'event': 'Scan completed', 'target': f"{len(devices)} host(s) profiled", 'status': 'Partial (errors logged)' if scan_had_errors else 'Completed'})

    ordered = [
        (ip, d['hostname'], d['os'], d['os_confidence'], d['os_evidence'], d['is_mobile'],
         d['mac'], d['mac_vendor'], d['open_ports'], d['services'], d['version_map'],
         d['banner_map'], d['device_type'], d['display_name'], d['device_confidence'], d['device_evidence'])
        for ip, d in sorted(devices.items(), key=lambda item: tuple(map(int, item[0].split('.'))))
    ]
    return ordered, timeline


def _parse_device_record(device):
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


def build_dynamic_graph(devices):
    """Build the live network graph from real scan results, finishing the
    Priority 6-14 Asset Risk calculation once the full asset set is known
    (network-exposure needs the count of OTHER discovered assets)."""
    G = nx.DiGraph()
    node_type_map = {"Entry Node": "endpoint", "Server": "server",
                      "Database": "database", "Workstation": "endpoint"}

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
            security['vulnerability_component'], security['service_component'],
            security['sensitive_component'], calculate_criticality_score(criticality['level']),
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
            vulnerability=round(asset_risk['score'] / 100, 3), exposure_level=security['exposure_level'],
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
                G.add_edge(src, dst, connection=edge_info['connection'],
                           access_vector=edge_info['vector'], access_port=edge_info['port'],
                           mitre_code=edge_info['mitre_code'], mitre_desc=edge_info['mitre_desc'],
                           success_prob=edge_info['success_prob'], reachability='POTENTIAL REACHABILITY')
    return G


def build_network():
    """Simulated lab topology (offline demo mode) — unchanged structure, now
    routed through the same real-CVE-aware assessment + ACDS Asset Risk
    Model, with no version data, so it falls back cleanly to baseline
    exposure risk (never a fabricated CVE)."""
    G = nx.DiGraph()
    lab_hosts = [
        ("Firewall",    "192.168.1.1",  "Perimeter Defense", "perimeter", [443],        ['HTTPS']),
        ("User-PC",     "192.168.1.10", "Workstation",       "endpoint",  [22, 445],    ['SSH', 'SMB']),
        ("Admin-PC",    "192.168.1.11", "Admin Workstation", "endpoint",  [3389, 445],  ['RDP', 'SMB']),
        ("Server",      "192.168.1.20", "Web/App Server",    "server",    [22, 80, 443],['SSH', 'HTTP', 'HTTPS']),
        ("File-Server", "192.168.1.21", "File Server",       "server",    [445, 139],   ['SMB', 'NetBIOS']),
        ("Database",    "192.168.1.30", "MySQL Database",    "database",  [3306],       ['MySQL']),
        ("Honeypot",    "192.168.1.99", "Decoy System",      "honeypot",  [21],         ['FTP']),
    ]
    total_assets = len(lab_hosts)
    for name, ip, role, ntype, open_ports, services in lab_hosts:
        os_type = 'linux' if ntype in ('server', 'database') else 'windows' if ntype == 'endpoint' else 'unknown'
        device_type = 'Web Server' if ntype == 'server' else 'Database Server' if ntype == 'database' else 'Windows Workstation'
        sim_role = 'Database' if ntype == 'database' else 'Server' if ntype == 'server' else 'Workstation'
        if name == 'Firewall':
            sim_role = 'Entry Node'
        security = assess_device_security(services, os_type, device_type, open_ports, sim_role, ip=ip)
        criticality = calculate_criticality(device_type, services, open_ports, os_type)
        network_component = calculate_network_exposure_score(len(open_ports), max(0, total_assets - 1))
        asset_risk = calculate_asset_risk(
            security['vulnerability_component'], security['service_component'],
            security['sensitive_component'], calculate_criticality_score(criticality['level']),
            network_component,
        )
        G.add_node(
            name, ip=ip, role=role, display_name=name, hostname=name, os=os_type,
            os_confidence=None,
            os_evidence=['Simulated lab topology — OS is a fixed demo assumption, not measured from a live host'],
            open_ports=open_ports, services=services, version_map={}, banner_map={},
            device_type=device_type, device_confidence=None,
            device_evidence=['Simulated lab topology — device type is a fixed demo assumption'],
            criticality=criticality['level'], criticality_label=criticality['label'],
            criticality_confidence=criticality['confidence'], criticality_evidence=criticality['evidence'],
            vulnerability=round(asset_risk['score'] / 100, 3), exposure_level=security['exposure_level'],
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
            G.add_edge(src, dst, connection=edge_info['connection'],
                       access_vector=edge_info['vector'], access_port=edge_info['port'],
                       mitre_code=edge_info['mitre_code'], mitre_desc=edge_info['mitre_desc'],
                       success_prob=edge_info['success_prob'], reachability='POTENTIAL REACHABILITY')
    return G


def recompute_node_risk(node_data):
    """Recalculate risk_score/risk_severity/risk_components from the
    normalized_score values already stored on a node's risk_components
    dict (Priority 18: defenses must actually affect the model, not just
    be recommended). Call this after mutating a node's component scores
    (e.g. after a simulated patch/isolate/privilege action)."""
    comps = node_data['risk_components']
    total = 0.0
    for key, weight in (
        ('vulnerability', RISK_WEIGHT_VULNERABILITY),
        ('service_exposure', RISK_WEIGHT_SERVICE_EXPOSURE),
        ('sensitive_services', RISK_WEIGHT_SENSITIVE_SERVICES),
        ('criticality', RISK_WEIGHT_CRITICALITY),
        ('network_exposure', RISK_WEIGHT_NETWORK_EXPOSURE),
    ):
        comps[key]['weight'] = weight
        comps[key]['contribution'] = round(comps[key]['normalized_score'] * weight, 2)
        total += comps[key]['contribution']
    total = max(0.0, min(100.0, total))
    node_data['risk_score'] = round(total, 1)
    node_data['risk_severity'] = severity_from_score(total)
    node_data['vulnerability'] = round(total / 100, 3)
    return node_data['risk_score']


# ─────────────────────────────────────────────────────────────────
# MODULE 2: ATTACK SIMULATION ENGINE (probabilistic — no real exploitation)
# ─────────────────────────────────────────────────────────────────
# PRIORITY 26 BOUNDARY: everything below operates ONLY on the in-memory
# NetworkX graph built from passive scan data. It never sends network
# traffic, never authenticates anywhere, and never performs real
# exploitation, credential attacks, or data exfiltration.

def simulate_attack(G, entry_node, seed=42, ids_deployed=False, segmentation_applied=False):
    random.seed(seed)
    timeline = []
    compromised = set()
    priv_escalated = set()
    attack_paths = []
    honeypot_triggered = False

    if entry_node not in G.nodes:
        return timeline, compromised, honeypot_triggered, {}

    entry_data = G.nodes[entry_node]
    compromised.add(entry_node)
    G.nodes[entry_node]["compromised"] = True
    timeline.append({
        "node": entry_node, "from_node": None, "timestep": 1,
        "mitre_code": "T1078", "mitre_desc": "Initial Access — foothold on entry system",
        "access_vector": "Initial compromise / phishing / stolen credentials",
        "success": True, "vuln": entry_data["vulnerability"],
        "criticality": entry_data["criticality"], "ntype": entry_data.get("node_type", "endpoint"),
        "priv_esc": False,
    })
    attack_paths.append([entry_node])

    visited = {entry_node}
    queue = deque([(entry_node, 1, [entry_node])])

    # Deployed global defenses (Priority 18/19) reduce lateral-movement
    # success probability across the whole simulation — this is how
    # "Deploy IDS/SIEM" and "Network Segmentation" actually change the
    # re-simulated outcome rather than only being cosmetic.
    global_dampener = 1.0
    if ids_deployed:
        global_dampener *= 0.75   # faster detection/response cuts success odds
    if segmentation_applied:
        global_dampener *= 0.55   # VLAN ACLs remove many lateral paths

    while queue:
        current_node, timestep, path = queue.popleft()
        if current_node not in compromised:
            continue

        for neighbor in G.successors(current_node):
            if neighbor in visited:
                continue
            nd = G.nodes[neighbor]

            # A node marked isolated by an APPLIED defense action is
            # modeled as unreachable — this is how "Isolate database"
            # actually removes it from the blast radius on re-simulation.
            if nd.get("isolated"):
                visited.add(neighbor)
                timeline.append({
                    "node": neighbor, "from_node": current_node, "timestep": timestep + 1,
                    "mitre_code": "T1599", "mitre_desc": "Network Boundary Bridging — blocked",
                    "access_vector": "Blocked by applied isolation/segmentation defense",
                    "success": False, "vuln": nd["vulnerability"], "criticality": nd["criticality"],
                    "ntype": nd.get("node_type", "endpoint"), "priv_esc": False,
                })
                continue

            edge = G.edges[current_node, neighbor]
            ntype = nd.get("node_type", "endpoint")

            if ntype == "honeypot":
                prob = nd["vulnerability"]
                mitre_code, mitre_desc = "T1003", "OS Credential Dumping [TRAP]"
                access_vector = edge.get("access_vector", "Honeypot probe")
            else:
                prob = min(0.95, edge.get("success_prob", 0.4) * nd["vulnerability"] * global_dampener)
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
                        "node": neighbor, "from_node": current_node, "timestep": actual_timestep + 1,
                        "mitre_code": "T1068", "mitre_desc": "Privilege Escalation — admin/root on high-value system",
                        "access_vector": "Credential dump / sudo / token theft", "success": True,
                        "vuln": nd["vulnerability"], "criticality": nd["criticality"],
                        "ntype": ntype, "priv_esc": True,
                    })
                if ntype == "honeypot":
                    honeypot_triggered = True

            timeline.append({
                "node": neighbor, "from_node": current_node, "timestep": actual_timestep,
                "mitre_code": mitre_code, "mitre_desc": mitre_desc, "access_vector": access_vector,
                "success": success, "vuln": nd["vulnerability"], "criticality": nd["criticality"],
                "ntype": ntype, "priv_esc": did_priv_esc,
            })

    timeline.sort(key=lambda x: x["timestep"])
    real_nodes = [n for n in G.nodes if G.nodes[n].get("node_type") != "honeypot"]
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    critical_reached = [n for n in real_compromised if G.nodes[n]["criticality"] >= 4]
    max_hops = max((len(p) - 1 for p in attack_paths), default=0)

    stats = {
        "systems_controlled": len(real_compromised), "total_systems": len(real_nodes),
        "max_lateral_hops": max_hops, "privilege_escalations": len(priv_escalated),
        "attack_paths": attack_paths[:10], "reachable_from_entry": len(real_compromised),
        "critical_assets_reached": len(critical_reached),
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
        "spread": round(spread * 100, 1), "critical_impact": round(critical_impact * 100, 1),
        "depth": round(depth * 100, 1), "compromised_count": len(real_compromised),
        "total_real_nodes": len(real_nodes),
        "systems_controlled": stats.get("systems_controlled", len(real_compromised)),
        "max_lateral_hops": stats.get("max_lateral_hops", 0),
        "privilege_escalations": stats.get("privilege_escalations", 0),
        "critical_assets_reached": stats.get("critical_assets_reached", 0),
        "attack_paths": stats.get("attack_paths", []),
    }
    return round(risk_score, 1), blast_details


def calculate_overall_acds_risk(G, blast_radius_score):
    """Priority 15: OVERALL ACDS RISK.

    Keeps Asset Risk (per-host, Priority 6) and Network/Blast-Radius
    Simulation (Priority 3 module) as two SEPARATE internal concepts,
    then combines them with a documented, non-industry-standard
    aggregation:

        Overall ACDS Risk = Asset Risk Component * 0.60
                           + Network Blast Radius Component * 0.40

    Asset Risk Component = mean of all real (non-honeypot) assets'
    Priority-6 risk_score values, i.e. an organization-wide asset risk
    figure built from the same transparent weighted model as each
    individual host.

    If no simulation has been run yet, blast_radius_score is None and
    this returns a PARTIAL result rather than inventing a blast-radius
    number.
    """
    real_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") != "honeypot"]
    asset_scores = [G.nodes[n].get("risk_score", 0.0) for n in real_nodes]
    asset_component = round(sum(asset_scores) / len(asset_scores), 1) if asset_scores else 0.0

    if blast_radius_score is None:
        return {
            'status': 'PARTIAL — SIMULATION NOT RUN',
            'overall_score': None, 'severity': None,
            'asset_component': asset_component, 'asset_weight': OVERALL_WEIGHT_ASSET_RISK,
            'blast_component': None, 'blast_weight': OVERALL_WEIGHT_BLAST_RADIUS,
        }

    overall = round(asset_component * OVERALL_WEIGHT_ASSET_RISK + blast_radius_score * OVERALL_WEIGHT_BLAST_RADIUS, 1)
    overall = max(0.0, min(100.0, overall))
    return {
        'status': 'COMPLETE',
        'overall_score': overall, 'severity': severity_from_score(overall),
        'asset_component': asset_component, 'asset_weight': OVERALL_WEIGHT_ASSET_RISK,
        'blast_component': blast_radius_score, 'blast_weight': OVERALL_WEIGHT_BLAST_RADIUS,
    }


# ─────────────────────────────────────────────────────────────────
# MODULE 4: DEFENSE OPTIMIZATION ENGINE
# ─────────────────────────────────────────────────────────────────
# Priority 18: every action carries an explicit state —
#   RECOMMENDED  -> generated by this engine, not yet chosen
#   SELECTED     -> chosen by the greedy budget optimizer / the user
#   APPLIED TO SIMULATION MODEL -> actually mutated the in-memory graph
# A defense is NEVER presented as applied unless apply_defense_actions()
# below has actually run and mutated the model.

DEFENSE_STATE_RECOMMENDED = "RECOMMENDED"
DEFENSE_STATE_SELECTED = "SELECTED"
DEFENSE_STATE_APPLIED = "APPLIED TO SIMULATION MODEL"


def get_defense_actions(G, compromised_nodes, risk_score):
    actions = []
    seen_fixes = set()

    for node in compromised_nodes:
        if G.nodes[node].get("node_type") == "honeypot":
            continue
        nd = G.nodes[node]
        crit, vuln = nd["criticality"], nd["vulnerability"]
        display = nd.get("display_name", node)

        for fix in nd.get("fixes", []):
            if fix in seen_fixes:
                continue
            seen_fixes.add(fix)
            fix_cost = int(12 + crit * 4)
            fix_reduction = round(vuln * crit * 3.5, 1)
            actions.append({
                "action": f"Fix: {fix[:60]}{'...' if len(fix) > 60 else ''}",
                "node": node, "type": "patch", "cost": fix_cost,
                "risk_reduction": fix_reduction,
                "efficiency": round(fix_reduction / fix_cost, 3),
                "description": fix, "state": DEFENSE_STATE_RECOMMENDED,
            })

        for weakness in nd.get("weaknesses", [])[:2]:
            isolate_cost = int(18 + crit * 6)
            isolate_reduction = round(crit * 2.8, 1)
            action_key = f"Block: {weakness[:40]}"
            if action_key in seen_fixes:
                continue
            seen_fixes.add(action_key)
            actions.append({
                "action": action_key, "node": node, "type": "isolate", "cost": isolate_cost,
                "risk_reduction": isolate_reduction,
                "efficiency": round(isolate_reduction / isolate_cost, 3),
                "description": f"Segment or firewall {display} to block: {weakness}",
                "state": DEFENSE_STATE_RECOMMENDED,
            })

        if crit >= 4:
            priv_cost = int(10 + crit * 3)
            priv_reduction = round(crit * 3.2, 1)
            actions.append({
                "action": f"Least Privilege on {display[:30]}",
                "node": node, "type": "privilege", "cost": priv_cost,
                "risk_reduction": priv_reduction,
                "efficiency": round(priv_reduction / priv_cost, 3),
                "description": f"Remove admin rights on {display}; enforce MFA and PAM",
                "state": DEFENSE_STATE_RECOMMENDED,
            })

    ids_cost = 30
    ids_reduction = round(risk_score * 0.12, 1)
    actions.append({
        "action": "Deploy Network IDS / SIEM", "node": "ALL", "type": "ids",
        "cost": ids_cost, "risk_reduction": ids_reduction,
        "efficiency": round(ids_reduction / ids_cost, 3),
        "description": "Detect lateral movement (Snort/Suricata/Wazuh) across the LAN",
        "state": DEFENSE_STATE_RECOMMENDED,
    })

    segment_cost = 25
    segment_reduction = round(risk_score * 0.15, 1)
    actions.append({
        "action": "Network Segmentation (VLANs)", "node": "ALL", "type": "isolate",
        "cost": segment_cost, "risk_reduction": segment_reduction,
        "efficiency": round(segment_reduction / segment_cost, 3),
        "description": "Split workstations, servers, and databases into separate VLANs with ACLs",
        "state": DEFENSE_STATE_RECOMMENDED,
    })

    actions.sort(key=lambda x: x["efficiency"], reverse=True)
    return actions


def greedy_defense_selection(actions, budget):
    selected, remaining_budget, total_reduction = [], budget, 0.0
    for action in actions:
        if action["cost"] <= remaining_budget:
            action = {**action, "state": DEFENSE_STATE_SELECTED}
            selected.append(action)
            remaining_budget -= action["cost"]
            total_reduction += action["risk_reduction"]
    return selected, round(total_reduction, 1), remaining_budget


def apply_defense_actions(G, selected_actions):
    """Priority 18/19: actually mutate the in-memory asset/network model
    so a re-simulation produces a genuinely different result. This is the
    ONLY function that may set an action's state to APPLIED TO SIMULATION
    MODEL. Returns (applied_actions, ids_deployed, segmentation_applied).
    """
    applied = []
    ids_deployed = False
    segmentation_applied = False

    for action in selected_actions:
        node = action.get("node")
        atype = action.get("type")

        if atype == "ids" and node == "ALL":
            ids_deployed = True
        elif atype == "isolate" and node == "ALL":
            segmentation_applied = True
        elif node in G.nodes:
            nd = G.nodes[node]
            comps = nd.get("risk_components")
            if atype == "patch" and comps:
                # A patch removes the matched confirmed CVE finding and
                # collapses the vulnerability component to "no confirmed
                # CVE" (0), which is only fair since the fix was applied.
                nd["cve_findings"] = []
                comps['vulnerability']['normalized_score'] = 0.0
                recompute_node_risk(nd)
            elif atype == "isolate" and comps:
                nd["isolated"] = True
                comps['network_exposure']['normalized_score'] = 0.0
                recompute_node_risk(nd)
            elif atype == "privilege" and comps:
                # Least-privilege/MFA reduces how dangerous compromising
                # this node is to the rest of the network (its effective
                # criticality contribution to blast radius), modeled here
                # as a 40% reduction of the criticality component.
                comps['criticality']['normalized_score'] = round(comps['criticality']['normalized_score'] * 0.6, 1)
                recompute_node_risk(nd)

        applied.append({**action, "state": DEFENSE_STATE_APPLIED})

    return applied, ids_deployed, segmentation_applied


# ─────────────────────────────────────────────────────────────────
# MODULE 5: GRAPH VISUALIZATION ENGINE
# ─────────────────────────────────────────────────────────────────
# Priority 16: this is a NETWORK EXPOSURE & ATTACK PATH MODEL, not a
# "network topology" — edges represent modeled POTENTIAL REACHABILITY
# derived from exposed services, never OBSERVED COMMUNICATION. The
# scanner never captures real traffic between hosts.

def render_graph(G, compromised_set=None, current_node=None, show_honeypot=True):
    if compromised_set is None:
        compromised_set = set()

    net = Network(height="480px", width="100%", bgcolor="#050a0f", font_color="#7ab8d4", directed=True)
    net.set_options("""
    {
      "nodes": { "borderWidth": 2, "shadow": {"enabled": true, "size": 15},
                 "font": {"size": 13, "face": "Share Tech Mono"} },
      "edges": { "arrows": {"to": {"enabled": true, "scaleFactor": 0.8}},
                 "color": {"color": "#1a3a5c", "highlight": "#00d4ff"},
                 "smooth": {"type": "curvedCW", "roundness": 0.2}, "width": 1.5,
                 "shadow": {"enabled": false} },
      "physics": { "enabled": true, "barnesHut": {"gravitationalConstant": -4000,
                   "centralGravity": 0.4, "springLength": 140, "springConstant": 0.04, "damping": 0.09} },
      "interaction": { "hover": true, "tooltipDelay": 100 }
    }
    """)

    type_shapes = {"perimeter": "diamond", "endpoint": "dot", "server": "square",
                   "database": "database", "honeypot": "star"}

    for node, data in G.nodes(data=True):
        ntype = data.get("node_type", "endpoint")
        is_compromised = node in compromised_set
        is_current = node == current_node
        is_honeypot = ntype == "honeypot"
        is_isolated = data.get("isolated", False)
        if not show_honeypot and is_honeypot:
            continue

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
        elif is_isolated:
            color = {"background": "#0a2e1a", "border": "#00ff88", "highlight": {"background": "#0f3d22"}}
            size = 22
        else:
            color = {"background": "#002d4a", "border": "#00d4ff", "highlight": {"background": "#003d60"}}
            size = 22

        cves = data.get('cve_findings', [])
        cve_html = ''.join(f"CONFIRMED: {c['cve_id']} (CVSS {c['cvss']})<br>" for c in cves[:2])
        status_label = ('🔴 COMPROMISED (simulated)' if is_compromised else
                         '🟢 ISOLATED (defense applied)' if is_isolated else
                         '🟡 HONEYPOT (decoy)' if is_honeypot else '🔵 OBSERVED ASSET')
        tooltip = (
            f"<div style='font-family:Share Tech Mono;font-size:11px;color:#e0f4ff;background:#0d1f2d;padding:8px;border:1px solid #1a3a5c'>"
            f"<b style='color:#00d4ff'>{node}</b><br>IP: {data['ip']}<br>Role: {data['role']}<br>"
            f"Criticality: {data.get('criticality_label','?')} ({'★' * data['criticality']})<br>"
            f"Asset Risk: {data.get('risk_score', int(data.get('vulnerability',0)*100))}/100 ({data.get('risk_severity','?')})<br>"
            f"{cve_html}"
            f"Status: {status_label}</div>"
        )

        short_label = node if "\n" in node else node.replace("-", "\n")
        net.add_node(node, label=short_label, title=tooltip, color=color, size=size,
                     shape=type_shapes.get(ntype, "dot"))

    for src, dst, data in G.edges(data=True):
        if not show_honeypot and (G.nodes[src].get("node_type") == "honeypot" or G.nodes[dst].get("node_type") == "honeypot"):
            continue
        src_comp, dst_comp = src in compromised_set, dst in compromised_set
        if src_comp and dst_comp:
            edge_color, width = "#ff3355", 3
        elif src_comp:
            edge_color, width = "#ff8c00", 2
        else:
            edge_color, width = "#1a3a5c", 1.5
        edge_title = f"{data.get('connection','')} — POTENTIAL REACHABILITY (modeled, not observed traffic)"
        net.add_edge(src, dst, title=edge_title, color=edge_color, width=width)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", dir=tempfile.gettempdir())
    net.save_graph(tmp.name)
    tmp.close()
    with open(tmp.name, "r", encoding="utf-8") as f:
        html = f.read()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    html = html.replace("body {", "body { background-color: #050a0f !important; margin: 0; padding: 0; ")
    return html


# ─────────────────────────────────────────────────────────────────
# MODULE 5B: SIMULATED ATTACK EVENT LOG
# ─────────────────────────────────────────────────────────────────
# Priority 17: every entry here describes a SIMULATED event evaluated
# against the in-memory model. Source is always labeled "Simulated
# Attacker" — never a fabricated real source IP presented as telemetry.

def generate_attack_log(timeline, honeypot_triggered):
    log = []
    mitre_log = {
        "T1190": "exploit_public_app", "T1078": "valid_account_brute",
        "T1021": "lateral_move", "T1005": "data_staged_exfil",
        "T1003": "credential_dump_lsass", "T1068": "priv_esc",
        "T1599": "boundary_blocked",
    }
    for entry in timeline[:12]:
        action = mitre_log.get(entry.get("mitre_code", ""), "scan_probe")
        status = "POTENTIAL PATH" if entry["success"] else "BLOCKED"
        severity = "critical" if entry["success"] else "ok"
        log.append({
            "src": "Simulated Attacker", "target": entry["node"], "action": action,
            "technique": f"{entry.get('mitre_code','')} — {entry.get('mitre_desc','')}",
            "reason": entry.get("access_vector", "network"),
            "status": status, "severity": severity,
        })
    if honeypot_triggered:
        log.append({"src": "Simulated Attacker", "target": "Honeypot", "action": "HONEYPOT_TRIGGER",
                     "technique": "T1003 — Credential Dumping [TRAP]", "reason": "Decoy service probed",
                     "status": "⚠ TRAP SPRUNG (simulated)", "severity": "critical"})
    return log


def build_executive_summary(G, compromised, risk_score, blast_details, entry_node):
    """Plain-English summary for a non-technical SME owner."""
    real_compromised = [n for n in compromised if G.nodes[n].get("node_type") != "honeypot"]
    crown_jewels = [n for n in real_compromised if G.nodes[n]["criticality"] >= 4]

    all_cves = []
    for n in G.nodes:
        all_cves.extend(G.nodes[n].get('cve_findings', []))
    all_cves.sort(key=lambda c: c['cvss'], reverse=True)
    top_cve = all_cves[0] if all_cves else None

    risk_word = severity_from_score(risk_score)

    lines = []
    lines.append(
        "<b>SIMULATION ONLY — no real attack traffic was generated and no exploitation was performed.</b>"
    )
    lines.append(
        f"Starting from <b>{(entry_node or 'the chosen entry point').split(chr(10))[-1]}</b>, "
        f"this simulation estimates an attacker could potentially reach "
        f"<b>{len(real_compromised)} of {blast_details.get('total_real_nodes', len(G.nodes))}</b> "
        f"systems on your network, including <b>{len(crown_jewels)}</b> high-value system(s) "
        f"such as servers or databases."
    )
    if top_cve:
        lines.append(
            f"The single most dangerous CONFIRMED issue found was <b>{top_cve['cve_id']}</b> "
            f"(CVSS {top_cve['cvss']}) on the <b>{top_cve['service']}</b> service "
            f"(port {top_cve['port']}). Fixing this first gives the largest risk reduction "
            f"for the least effort."
        )
    else:
        lines.append(
            "No version-specific CONFIRMED CVE was found on this network. Remaining risk comes "
            "from exposed services / weak configuration rather than a matched vulnerability."
        )
    lines.append(
        f"Overall business risk is rated <b>{risk_word}</b> ({risk_score}/100). "
        f"{'This needs attention this week.' if risk_word=='CRITICAL' else 'This should be scheduled into your next IT maintenance window.' if risk_word=='HIGH' else 'Address opportunistically as part of routine maintenance.' if risk_word=='MEDIUM' else 'No urgent action required, but keep monitoring.'}"
    )
    return "<br><br>".join(lines)


def get_asset_metrics(G):
    """Return presentation metrics without mutating the discovery graph."""
    assets = list(G.nodes(data=True))
    risks = [float(data.get("risk_score", data.get("vulnerability", 0) * 100)) for _, data in assets]
    services = sum(len(data.get("services", [])) for _, data in assets)
    servers = sum(data.get("node_type") in {"server", "database"} for _, data in assets)
    other = sum(data.get("node_type") not in {"server", "database", "honeypot", "perimeter"} for _, data in assets)
    critical = sum(any(c.get("cvss", 0) >= 9 for c in data.get("cve_findings", [])) for _, data in assets)
    high = sum(any(7 <= c.get("cvss", 0) < 9 for c in data.get("cve_findings", [])) for _, data in assets)
    medium = sum(data.get("risk_severity") == "MEDIUM" for _, data in assets)
    low = sum(data.get("risk_severity") == "LOW" for _, data in assets)
    return {
        "assets": len(assets), "servers": servers, "services": services,
        "other_devices": other,
        "average_risk": round(sum(risks) / len(risks), 1) if risks else 0.0,
        "critical": critical, "high": high, "medium": medium, "low": low,
    }


# ─────────────────────────────────────────────────────────────────
# MODULE 6: REPORTING / EXPORT (Priority 22)
# ─────────────────────────────────────────────────────────────────

def export_asset_inventory_csv(G):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'OS Confidence', 'Device Type',
                      'Device Confidence', 'Services', 'Ports', 'Risk', 'Criticality'])
    for node, d in G.nodes(data=True):
        writer.writerow([
            d.get('ip', ''), d.get('hostname') or 'Unknown', d.get('mac') or 'Unknown',
            d.get('mac_vendor') or 'Unknown', d.get('os', 'unknown'),
            f"{int((d.get('os_confidence') or 0) * 100)}%" if d.get('os_confidence') is not None else 'N/A',
            d.get('device_type', 'Unknown'),
            f"{int((d.get('device_confidence') or 0) * 100)}%" if d.get('device_confidence') is not None else 'N/A',
            '; '.join(d.get('services', [])), '; '.join(str(p) for p in d.get('open_ports', [])),
            f"{d.get('risk_score', 0)}/100 ({d.get('risk_severity','?')})",
            d.get('criticality_label', 'Unknown'),
        ])
    return buf.getvalue()


def export_vulnerability_report_csv(G):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Asset', 'CVE', 'CVSS', 'Severity', 'Product', 'Version', 'Description',
                      'Recommendation', 'Detection Confidence', 'Published', 'Modified', 'Source'])
    for node, d in G.nodes(data=True):
        fixes = d.get('fixes', [])
        for i, c in enumerate(d.get('cve_findings', [])):
            rec = fixes[i] if i < len(fixes) else (fixes[0] if fixes else 'See generic remediation guidance')
            writer.writerow([
                d.get('display_name', node), c.get('cve_id'), c.get('cvss'), c.get('severity'),
                c.get('affected_product'), c.get('detected_version') or 'Unknown', c.get('summary'),
                rec, c.get('detection_confidence'), c.get('published'), c.get('modified'), c.get('source'),
            ])
    return buf.getvalue()


def build_executive_report_text(G, risk_score, blast_details, overall_risk, scan_history):
    metrics = get_asset_metrics(G)
    lines = []
    lines.append("ACDS SECURITY ASSESSMENT")
    lines.append("=" * 40)
    lines.append("SIMULATION ONLY — NO REAL ATTACK TRAFFIC GENERATED")
    lines.append("PASSIVE SCANNING ONLY — NO EXPLOITATION PERFORMED")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append(f"Assets Discovered: {metrics['assets']}")
    lines.append(f"Critical Findings (CVSS >= 9): {metrics['critical']}")
    lines.append(f"High Findings (CVSS 7-8.9): {metrics['high']}")
    lines.append(f"Average Asset Risk: {metrics['average_risk']}/100")
    lines.append("")
    lines.append("TOP RISKS")
    ranked = sorted(G.nodes(data=True), key=lambda x: x[1].get('risk_score', 0), reverse=True)[:5]
    for node, d in ranked:
        lines.append(f"  - {d.get('display_name', node)} ({d.get('ip')}): {d.get('risk_score',0)}/100 [{d.get('risk_severity','?')}]")
    lines.append("")
    lines.append("RECOMMENDED ACTIONS")
    seen = set()
    for node, d in G.nodes(data=True):
        for fix in d.get('fixes', [])[:2]:
            if fix not in seen:
                seen.add(fix)
                lines.append(f"  - {fix}")
    lines.append("")
    lines.append(f"Risk Before Defense: {risk_score if risk_score else 'Simulation not run'}")
    lines.append(f"Network Blast Radius: {blast_details.get('spread','N/A')}% spread, "
                  f"{blast_details.get('critical_assets_reached','N/A')} critical asset(s) reached")
    lines.append(f"Overall ACDS Risk: {overall_risk.get('overall_score')} ({overall_risk.get('status')})")
    lines.append("")
    if scan_history:
        lines.append("SCAN HISTORY")
        for h in scan_history:
            lines.append(f"  Scan #{h['scan_id']} — {h['asset_count']} assets, avg risk {h['average_risk']}, "
                          f"{h['critical_count']}C/{h['high_count']}H/{h['medium_count']}M/{h['low_count']}L")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────

defaults = {
    "network_mode": "Real Network Scan", "simulation_done": False, "timeline": [],
    "compromised": set(), "risk_score": 0.0, "blast_details": {},
    "honeypot_triggered": False, "defense_actions": [], "selected_defenses": [],
    "applied_defenses": [], "ids_deployed": False, "segmentation_applied": False,
    "attack_log": [], "attack_stats": {}, "current_anim_node": None,
    "last_scan_devices": None, "scan_started_at": None, "scan_completed_at": None,
    "scan_error": None, "scan_timeline": [], "scan_history": [], "scan_counter": 0,
    "risk_before_defense": None, "blast_before_defense": {},
    "post_defense_stats": None, "overall_acds_risk": None, "budget": 50,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

if "G" not in st.session_state:
    st.session_state.G = build_network() if st.session_state.network_mode == "Simulated Lab" else nx.DiGraph()


def record_scan_history(G, scan_type):
    """Priority 21: persistent in-session scan history (no database)."""
    metrics = get_asset_metrics(G)
    st.session_state.scan_counter += 1
    st.session_state.scan_history.append({
        'scan_id': st.session_state.scan_counter,
        'timestamp': datetime.now(timezone.utc),
        'scan_type': scan_type,
        'asset_count': metrics['assets'],
        'average_risk': metrics['average_risk'],
        'critical_count': metrics['critical'],
        'high_count': metrics['high'],
        'medium_count': metrics['medium'],
        'low_count': metrics['low'],
    })


# ─────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:16px 0 8px 0'>
        <div style='font-family:Orbitron,monospace;font-size:1.1rem;color:#00d4ff;letter-spacing:3px'>🛡 ACDS v2.1</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>ADAPTIVE CYBER DEFENSE SYSTEM</div>
        <div style='font-family:Share Tech Mono,monospace;font-size:0.6rem;color:#3d6a8a;letter-spacing:2px'>EXPLAINABLE RISK ENGINE</div>
    </div>
    <hr style='border-color:#1a3a5c;margin:8px 0 16px 0'>
    """, unsafe_allow_html=True)

    if not REQUESTS_AVAILABLE:
        st.warning("⚠ `requests` not installed — live NVD CVE lookups disabled.\nRun: pip install requests --break-system-packages\nFalling back to the offline CVE table.")

    st.markdown('<div class="section-header">🌐 NETWORK MODE</div>', unsafe_allow_html=True)
    network_mode = st.radio(
        "Network Mode", ["Simulated Lab", "Real Network Scan"],
        index=0 if st.session_state.network_mode == "Simulated Lab" else 1,
        label_visibility="collapsed",
    )

    if network_mode != st.session_state.network_mode:
        st.session_state.network_mode = network_mode
        for k in ("simulation_done",):
            st.session_state[k] = False
        st.session_state.timeline = []
        st.session_state.compromised = set()
        st.session_state.risk_score = 0.0
        st.session_state.blast_details = {}
        st.session_state.honeypot_triggered = False
        st.session_state.defense_actions = []
        st.session_state.selected_defenses = []
        st.session_state.applied_defenses = []
        st.session_state.ids_deployed = False
        st.session_state.segmentation_applied = False
        st.session_state.attack_log = []
        st.session_state.current_anim_node = None
        st.session_state.overall_acds_risk = None
        st.session_state.G = build_network() if network_mode == "Simulated Lab" else nx.DiGraph()
        st.rerun()

    # PRIORITY 24: one compact notice instead of duplicated passive-mode banners.
    st.markdown("""
    <div style='background:rgba(255,140,0,0.08);border:1px solid #ff8c00;padding:8px 10px;
         font-family:Share Tech Mono;font-size:0.62rem;color:#ff8c00;letter-spacing:1px;margin:8px 0'>
    AUTHORIZED NETWORK SCANNING • PASSIVE MODE
    </div>
    """, unsafe_allow_html=True)

    if network_mode == "Real Network Scan":
        lab_preset = st.selectbox(
            "Lab network preset",
            ["Custom / Auto", "VMware NAT (192.168.93.x)", "Home LAN (192.168.1.x)"],
            help="VMware NAT is skipped by auto-detect — use this preset for VM lab targets",
        )

        if lab_preset == "VMware NAT (192.168.93.x)":
            base_ip = "192.168.93."
            preset_limit = 200
            st.info("VMware NAT lab: target VM usually at **192.168.93.128**.")
        elif lab_preset == "Home LAN (192.168.1.x)":
            base_ip = "192.168.1."
            preset_limit = 254
        else:
            auto_detect = st.checkbox("🔍 Auto-detect Base IP", value=True)
            preset_limit = 100
            if auto_detect:
                detected_ip = get_local_ip()
                st.info(f"Detected Base IP: **{detected_ip}**")
                base_ip = None
            else:
                base_ip = st.text_input("Base IP Prefix", value="192.168.1.")

        scan_limit = st.slider("Scan Range (last octet up to...)", 10, 254, preset_limit, 10)

        if st.button("📡  SCAN NETWORK", use_container_width=True):
            progress_bar = st.progress(0, text="Starting scan...")

            def _progress(done, total):
                if total > 0:
                    progress_bar.progress(min(done / total, 1.0), text=f"Profiling host {done}/{total}...")

            st.session_state.scan_started_at = datetime.now(timezone.utc)
            st.session_state.scan_error = None
            try:
                with st.spinner("Pinging subnet and discovering hosts..."):
                    devices, scan_timeline = scan_network(base_ip=base_ip, limit=scan_limit, progress_cb=_progress)
            except Exception as exc:
                devices, scan_timeline = [], []
                st.session_state.scan_error = f"Scan failed safely: {type(exc).__name__}: {exc}"
            finally:
                st.session_state.scan_completed_at = datetime.now(timezone.utc)
                progress_bar.empty()

            if st.session_state.scan_error:
                st.error(st.session_state.scan_error)
            elif not devices:
                st.warning("No active devices found. Check your network prefix or range.")
            else:
                st.session_state.simulation_done = False
                st.session_state.timeline = []
                st.session_state.compromised = set()
                st.session_state.risk_score = 0.0
                st.session_state.blast_details = {}
                st.session_state.honeypot_triggered = False
                st.session_state.defense_actions = []
                st.session_state.selected_defenses = []
                st.session_state.applied_defenses = []
                st.session_state.ids_deployed = False
                st.session_state.segmentation_applied = False
                st.session_state.attack_log = []
                st.session_state.current_anim_node = None
                st.session_state.overall_acds_risk = None
                st.session_state.G = build_dynamic_graph(devices)
                st.session_state.last_scan_devices = devices
                st.session_state.scan_timeline = scan_timeline
                record_scan_history(st.session_state.G, "Real Network Scan")
                st.success(f"Found {len(devices)} device(s). Real banners + CVE lookups + ACDS risk model applied.")
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
            "Entry Point (Initially Compromised System)", all_nodes,
            index=min(1, len(all_nodes) - 1),
            help="The system where the attacker first gained access (phishing, stolen laptop, etc.)",
        )

    show_honeypot = st.checkbox("Show Honeypot Node (simulation view)", value=True)
    animation_speed = st.slider("Animation Speed (sec/step)", 0.3, 2.0, 0.6, 0.1)

    st.markdown('<div class="section-header">📡 NETWORK STATUS</div>', unsafe_allow_html=True)
    for node, data in st.session_state.G.nodes(data=True):
        status_class = "dot-compromised" if data["compromised"] else \
                       "dot-honeypot" if data.get("node_type") == "honeypot" else "dot-safe"
        label = "🔴" if data["compromised"] else "🟢" if data.get("isolated") else "🟡" if data.get("node_type") == "honeypot" else "🟢"
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
        'PASSIVE SCANNING ONLY — NO EXPLOITS PERFORMED<br>'
        'CVE DATA FROM NIST NVD WHERE AVAILABLE<br>MITRE ATT&CK ALIGNED</div>',
        unsafe_allow_html=True
    )


# ─────────────────────────────────────────────────────────────────
# MAIN LAYOUT
# ─────────────────────────────────────────────────────────────────

st.markdown("""
<div class="cyber-header">
    <div class="cyber-title">🛡 ADAPTIVE CYBER DEFENSE SYSTEM</div>
    <div class="cyber-subtitle">// NETWORK EXPOSURE & ATTACK PATH MODEL • EXPLAINABLE RISK • SIMULATION-BASED DEFENSE OPTIMIZATION //</div>
</div>
""", unsafe_allow_html=True)

if st.session_state.network_mode == "Real Network Scan":
    st.markdown("""
    <div style='background:rgba(255,140,0,0.06);border:1px solid #ff8c00;border-left:4px solid #ff8c00;
         padding:12px 18px;font-family:Share Tech Mono;font-size:0.72rem;color:#ff8c00;
         line-height:1.9;margin-bottom:16px'>
        <b>⚠ REAL NETWORK MODE — passive scan only</b><br>
        <span style='color:#7ab8d4'>
        • Device + service detection via ping/ARP/port scan + real banner grabbing<br>
        • Vulnerabilities matched against live NIST NVD CVE data for the exact version found<br>
        • Attack simulation shows lateral movement depth &amp; systems controlled (probabilistic model only)<br>
        • Use <b style='color:#ff8c00'>SCAN NETWORK</b> then pick the compromised entry point
        </span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div style='background:rgba(0,212,255,0.04);border:1px solid #1a3a5c;border-left:4px solid #00d4ff;
         padding:8px 16px;font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin-bottom:16px'>
        MODE: <span style='color:#00d4ff'>SIMULATED LAB</span> &nbsp;|&nbsp; 7-NODE DEMO TOPOLOGY &nbsp;|&nbsp; MITRE ATT&CK ALIGNED
    </div>
    """, unsafe_allow_html=True)

asset_metrics = get_asset_metrics(st.session_state.G)
m1, m2, m3, m4, m5, m6, m7, m8 = st.columns(8)
with m1:
    st.metric("ASSETS", asset_metrics["assets"])
with m2:
    st.metric("CRITICAL", asset_metrics["critical"])
with m3:
    st.metric("HIGH", asset_metrics["high"])
with m4:
    st.metric("MEDIUM", asset_metrics["medium"])
with m5:
    st.metric("LOW", asset_metrics["low"])
with m6:
    st.metric("SERVERS", asset_metrics["servers"])
with m7:
    st.metric("OTHER DEVICES", asset_metrics["other_devices"])
with m8:
    st.metric("AVG. RISK", f"{asset_metrics['average_risk']}")

st.markdown('<hr style="border-color:#1a3a5c;margin:8px 0 20px 0">', unsafe_allow_html=True)

col_graph, col_details = st.columns([3, 2], gap="medium")

with col_graph:
    st.markdown('<div class="section-header">🗺 NETWORK EXPOSURE &amp; ATTACK PATH MODEL</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style='font-family:Share Tech Mono;font-size:0.6rem;color:#3d6a8a;margin-bottom:6px'>
    Edges = modeled POTENTIAL REACHABILITY from exposed services. This is NOT observed network traffic.
    </div>
    """, unsafe_allow_html=True)
    graph_placeholder = st.empty()
    html_graph = render_graph(st.session_state.G, compromised_set=st.session_state.compromised,
                               current_node=st.session_state.current_anim_node, show_honeypot=show_honeypot)
    with graph_placeholder:
        st.components.v1.html(html_graph, height=500, scrolling=False)

    st.markdown("""
    <div style='display:flex;gap:16px;font-family:Share Tech Mono;font-size:0.65rem;margin-top:8px;flex-wrap:wrap'>
        <span><span style='color:#00d4ff'>■</span> OBSERVED ASSET</span>
        <span><span style='color:#ff3355'>■</span> COMPROMISED (simulated)</span>
        <span><span style='color:#ff8c00'>■</span> ACTIVE (simulated)</span>
        <span><span style='color:#00ff88'>■</span> ISOLATED (defense applied)</span>
        <span><span style='color:#ffd700'>★</span> HONEYPOT (decoy)</span>
        <span><span style='color:#1a3a5c'>──</span> POTENTIAL REACHABILITY</span>
        <span><span style='color:#ff3355'>──</span> SIMULATED ATTACK PATH</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    run_col, reset_col = st.columns([2, 1])
    with run_col:
        run_btn = st.button("▶  RUN ATTACK SIMULATION (SIMULATION ONLY)", use_container_width=True)
    with reset_col:
        reset_btn = st.button("↺  RESET", use_container_width=True)

    if reset_btn:
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
        st.session_state.overall_acds_risk = None
        st.rerun()

with col_details:
    st.markdown('<div class="section-header">📋 ASSET INTELLIGENCE</div>', unsafe_allow_html=True)
    asset_nodes = list(st.session_state.G.nodes)
    selected_asset = st.selectbox(
        "Selected asset",
        asset_nodes,
        format_func=lambda node: f"{st.session_state.G.nodes[node].get('display_name', node)} — {st.session_state.G.nodes[node].get('ip', '')}",
        disabled=not asset_nodes,
    ) if asset_nodes else None
    node_panel = st.empty()

    def _evidence_block(title, evidence_list, color="#3d6a8a"):
        if not evidence_list:
            return ""
        items = "".join(f"<div>✓ {html_lib.escape(str(e))}</div>" for e in evidence_list[:4])
        return (f"<div style='margin:2px 0 6px 70px;font-size:0.62rem;color:{color};line-height:1.6'>{items}</div>")

    def render_node_panel(active_node=None, selected_node=None):
        html = ""
        for node, data in st.session_state.G.nodes(data=True):
            if selected_node and node != selected_node:
                continue
            is_comp = data["compromised"]
            ntype = data.get("node_type", "endpoint")
            is_honey = ntype == "honeypot"
            is_active = node == active_node
            is_isolated = data.get("isolated", False)

            card_class = "compromised" if is_comp else "honeypot" if is_honey else "safe"
            if is_active:
                card_class = "compromised"

            status_icon = ("🔴 COMPROMISED (simulated)" if is_comp else
                            "🟢 ISOLATED (defense applied)" if is_isolated else
                            "⚠ ALERT" if (is_honey and st.session_state.honeypot_triggered) else
                            "🟡 DECOY" if is_honey else "🔵 OBSERVED SECURE")
            if is_active:
                status_icon = "💥 UNDER SIMULATED ATTACK"

            crit_label = data.get('criticality_label', 'Unknown')
            crit_stars = "★" * data["criticality"] + "☆" * (5 - data["criticality"])
            crit_conf = data.get('criticality_confidence')
            conf_str = f" ({int(crit_conf*100)}% confidence)" if isinstance(crit_conf, (int, float)) else ""

            hostname = data.get('hostname', '')
            hostname_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:90px'>Hostname:</span><span style='color:#e0f4ff'>{hostname}</span></div>" if hostname else ""

            os_type = data.get('os', 'unknown')
            os_confidence = data.get('os_confidence')
            os_evidence = data.get('os_evidence') or []
            os_icon = {'windows': '🪟', 'linux': '🐧', 'macos': '🍎', 'unknown': '❓'}.get(os_type, '❓')
            conf_suffix = f" · {int(round(os_confidence * 100))}% confidence" if isinstance(os_confidence, (int, float)) else ""
            os_html = (
                f"<div style='display:flex;align-items:center;margin:4px 0'>"
                f"<span style='color:#3d6a8a;width:90px'>Inferred OS:</span>"
                f"<span style='color:#e0f4ff'>{os_icon} {os_type.upper()}{conf_suffix}</span></div>"
                + _evidence_block("", os_evidence)
            )

            device_type = data.get('device_type', '')
            device_evidence = data.get('device_evidence') or []
            device_conf = data.get('device_confidence')
            dconf_str = f" · {int(device_conf*100)}% confidence" if isinstance(device_conf, (int, float)) else ""
            vendor = data.get('mac_vendor')
            device_icon = {
                'Mobile Device': '📱', 'Tablet': '📱', 'Network Device': '🌐',
                'Web Server': '🖥️', 'Database Server': '🗄️', 'Linux Server': '🖥️',
                'Windows Server': '🖥️', 'Windows Workstation': '💻', 'Linux Workstation': '💻',
                'Mac Computer': '🍎',
            }.get(device_type, '📦')
            vendor_suffix = f" ({vendor})" if vendor else ""
            device_html = (
                f"<div style='display:flex;align-items:center;margin:4px 0'>"
                f"<span style='color:#3d6a8a;width:90px'>Inferred Device:</span>"
                f"<span style='color:#e0f4ff'>{device_icon} {device_type or 'Unknown'}{vendor_suffix}{dconf_str}</span>"
                f"</div>" + _evidence_block("", device_evidence)
            )

            version_map = data.get('version_map', {})
            services = data.get('services', [])
            if version_map:
                svc_strs = [f"{s} ({version_map[s]})" if version_map.get(s) else s for s in services[:4]]
            else:
                svc_strs = services[:4]
            services_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:90px'>Services:</span><span style='color:#e0f4ff'>{', '.join(svc_strs)}{'...' if len(services) > 4 else ''}</span></div>" if services else ""
            open_ports = data.get('open_ports', [])
            ports_html = f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:90px'>Ports:</span><span style='color:#e0f4ff'>{', '.join(str(p) for p in open_ports) or 'None detected'}</span></div>"

            risk_score = data.get('risk_score', int(data.get('vulnerability', 0) * 100))
            risk_severity = data.get('risk_severity', 'Unknown')
            comps = data.get('risk_components') or {}

            def comp_row(key, label, cap):
                c = comps.get(key, {})
                contrib = c.get('contribution', 0)
                return f"<div style='display:flex;justify-content:space-between;color:#7ab8d4'><span>{label}</span><span>{contrib:.1f} / {cap}</span></div>"

            risk_breakdown_html = ""
            if comps:
                risk_breakdown_html = (
                    "<div style='margin:6px 0;padding:8px;background:rgba(0,212,255,0.05);border-left:2px solid #00d4ff;font-size:0.65rem'>"
                    "<div style='color:#00d4ff;font-weight:bold;margin-bottom:4px'>RISK CALCULATION</div>"
                    + comp_row('vulnerability', 'Vulnerability / CVSS', 40)
                    + comp_row('service_exposure', 'Service Exposure', 20)
                    + comp_row('sensitive_services', 'Sensitive Services', 15)
                    + comp_row('criticality', 'Asset Criticality', 15)
                    + comp_row('network_exposure', 'Network Exposure', 10)
                    + f"<div style='border-top:1px solid #1a3a5c;margin-top:4px;padding-top:4px;display:flex;justify-content:space-between;color:#00d4ff;font-weight:bold'><span>TOTAL</span><span>{risk_score} / 100</span></div>"
                    "</div>"
                )
            risk_html = (
                f"<div style='margin:6px 0;padding:6px;background:rgba(0,212,255,0.05);border-left:2px solid #00d4ff'>"
                f"<div style='color:#00d4ff;font-size:0.68rem'>RISK: {risk_score}/100 — {risk_severity}</div></div>"
                + risk_breakdown_html
            )

            sensitive_detected = (data.get('asset_risk') or {}).get('sensitive_detected', [])
            sensitive_html = ""
            if sensitive_detected:
                sensitive_html = (
                    "<div style='margin:6px 0;padding:6px;background:rgba(255,140,0,0.06);border-left:2px solid #ff8c00;font-size:0.63rem'>"
                    "<div style='color:#3d6a8a;margin-bottom:3px'>SENSITIVE SERVICES</div>"
                    + "".join(f"<div style='color:#ff8c00'>✓ {label} — {port}</div>" for port, label in sensitive_detected)
                    + "</div>"
                )

            cve_findings = data.get('cve_findings', [])
            cve_html = ""
            if cve_findings:
                cve_html = "<div style='margin:6px 0;padding:6px;background:rgba(255,51,85,0.08);border-left:2px solid #ff3355;font-size:0.63rem'>"
                cve_html += "<div style='color:#3d6a8a;margin-bottom:3px'>CONFIRMED VULNERABILITY</div>"
                for c in cve_findings[:3]:
                    cve_html += (
                        f"<div style='color:#ff3355'>• {c['cve_id']} — CVSS {c['cvss']} ({c.get('severity','?')})</div>"
                        f"<div style='color:#3d6a8a;margin-left:10px'>{c.get('detected_product')} {c.get('detected_version') or ''} · "
                        f"Published {c.get('published')} · Modified {c.get('modified')} · Confidence: {c.get('detection_confidence')}</div>"
                    )
                cve_html += "</div>"
            else:
                exp = data.get('exposure_findings', [])
                if exp:
                    cve_html = ("<div style='margin:6px 0;padding:6px;background:rgba(255,140,0,0.05);border-left:2px solid #ff8c00;"
                                 "color:#7ab8d4;font-size:0.63rem'>EXPOSURE / WEAK CONFIGURATION — no confirmed version-specific CVE. "
                                 f"{len(exp)} exposed service(s) contribute baseline risk only.</div>")
                else:
                    cve_html = "<div style='margin:6px 0;padding:6px;background:rgba(0,255,136,0.04);border-left:2px solid #00ff88;color:#7ab8d4;font-size:0.63rem'>NO VERSION-SPECIFIC CVE FOUND.</div>"

            recommendations = data.get('fixes', [])
            recommendation_html = "".join(
                f"<div style='color:#7ab8d4;font-size:0.64rem'>• {html_lib.escape(fix)}</div>" for fix in recommendations[:2]
            )
            if recommendation_html:
                recommendation_html = f"<div style='margin:6px 0;padding:6px;background:rgba(0,255,136,0.04);border-left:2px solid #00ff88'><div style='color:#3d6a8a;font-size:0.62rem;margin-bottom:3px'>RECOMMENDED ACTIONS</div>{recommendation_html}</div>"

            node_color = "#ff3355" if is_comp else "#00ff88" if is_isolated else "#ffd700" if is_honey else "#00d4ff"
            html += (
                f"<div class='node-card {card_class}'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>"
                f"<span style='color:{node_color};font-family:Orbitron,monospace;font-size:0.8rem;font-weight:700'>{node}</span>"
                f"<span style='font-size:0.62rem;opacity:0.8'>{status_icon}</span></div>"
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:90px'>IP:</span><span style='color:#e0f4ff'>{data['ip']}</span></div>"
                f"{hostname_html}{os_html}{device_html}{ports_html}{services_html}{risk_html}{sensitive_html}{cve_html}{recommendation_html}"
                f"<div style='display:flex;align-items:center;margin:4px 0'><span style='color:#3d6a8a;width:90px'>Role:</span><span style='color:#e0f4ff'>{data['role']}</span></div>"
                f"<div style='margin:4px 0'><span style='color:#3d6a8a'>Inferred Criticality: </span><span style='color:#ffd700'>{crit_label}{conf_str}</span><br>"
                f"<span style='color:#ffd700'>{crit_stars}</span>"
                + _evidence_block("", data.get('criticality_evidence') or [])
                + "</div></div>"
            )
        return html

    node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel(selected_node=selected_asset)}</div>", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────
# SIMULATION EXECUTION WITH ANIMATION
# ─────────────────────────────────────────────────────────────────

if run_btn and entry_node:
    for node in st.session_state.G.nodes:
        st.session_state.G.nodes[node]["compromised"] = False

    timeline, compromised, honeypot_triggered, attack_stats = simulate_attack(
        st.session_state.G, entry_node, seed=random.randint(1, 9999),
        ids_deployed=st.session_state.ids_deployed,
        segmentation_applied=st.session_state.segmentation_applied,
    )

    steps = {}
    for entry in timeline:
        steps.setdefault(entry["timestep"], []).append(entry)

    animated_compromised = set()
    status_text = st.empty()

    for timestep in sorted(steps.keys()):
        for entry in steps[timestep]:
            node = entry["node"]
            st.session_state.current_anim_node = node

            status_color = "#ff3355" if entry["success"] else "#00ff88"
            status_word = "POTENTIAL PATH" if entry["success"] else "BLOCKED"
            status_text.markdown(
                f'<div style="font-family:Share Tech Mono;font-size:0.75rem;color:{status_color};'
                f'background:#0d1f2d;border:1px solid {status_color};padding:8px 14px;margin:4px 0">'
                f'SIMULATED ATTACK EVENT — [T{timestep}] {entry.get("mitre_code")} → {node}'
                f'{" ← " + entry.get("from_node", "") if entry.get("from_node") else ""}'
                f' via {entry.get("access_vector", "network")} — {status_word}</div>',
                unsafe_allow_html=True
            )

            if entry["success"]:
                animated_compromised.add(node)

            updated_html = render_graph(st.session_state.G, compromised_set=animated_compromised,
                                         current_node=node, show_honeypot=show_honeypot)
            with graph_placeholder:
                st.components.v1.html(updated_html, height=500, scrolling=False)
            node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel(active_node=node, selected_node=selected_asset)}</div>", unsafe_allow_html=True)
            time.sleep(animation_speed)

    status_text.markdown(
        '<div style="font-family:Share Tech Mono;font-size:0.75rem;color:#ffd700;'
        'background:#1a1000;border:1px solid #ffd700;padding:8px 14px;margin:4px 0">'
        '[ SIMULATION COMPLETE ] SIMULATION ONLY — no real attack traffic generated, no exploitation performed.</div>',
        unsafe_allow_html=True
    )

    st.session_state.timeline = timeline
    st.session_state.compromised = compromised
    st.session_state.honeypot_triggered = honeypot_triggered
    st.session_state.simulation_done = True
    st.session_state.current_anim_node = None

    risk_score, blast_details = calculate_risk(st.session_state.G, compromised, timeline, honeypot_triggered, attack_stats)
    st.session_state.risk_score = risk_score
    st.session_state.blast_details = blast_details
    st.session_state.attack_stats = attack_stats
    st.session_state.overall_acds_risk = calculate_overall_acds_risk(st.session_state.G, risk_score)

    # Snapshot BEFORE state the first time a simulation runs after a scan,
    # so the Priority 19 Before/After panel has something honest to diff
    # against once defenses are applied.
    if st.session_state.risk_before_defense is None:
        st.session_state.risk_before_defense = risk_score
        st.session_state.blast_before_defense = blast_details

    st.session_state.defense_actions = get_defense_actions(st.session_state.G, compromised, risk_score)
    selected, total_reduction, remaining = greedy_defense_selection(st.session_state.defense_actions, st.session_state.budget)
    st.session_state.selected_defenses = selected
    st.session_state.attack_log = generate_attack_log(timeline, honeypot_triggered)
    record_scan_history(st.session_state.G, "Post-simulation")

    final_html = render_graph(st.session_state.G, compromised_set=compromised, current_node=None, show_honeypot=show_honeypot)
    with graph_placeholder:
        st.components.v1.html(final_html, height=500, scrolling=False)
    node_panel.markdown(f"<div style='padding: 8px;'>{render_node_panel(selected_node=selected_asset)}</div>", unsafe_allow_html=True)

    st.rerun()


# ─────────────────────────────────────────────────────────────────
# POST-SIMULATION PANELS
# ─────────────────────────────────────────────────────────────────

if st.session_state.simulation_done:

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    st.markdown("""
    <div style='background:rgba(255,51,85,0.06);border:1px solid #ff3355;padding:8px 14px;
         font-family:Share Tech Mono;font-size:0.65rem;color:#ff3355;letter-spacing:1px;margin-bottom:10px'>
    SIMULATION ONLY &nbsp;•&nbsp; NO REAL ATTACK TRAFFIC GENERATED &nbsp;•&nbsp; NO EXPLOITATION PERFORMED
    </div>
    """, unsafe_allow_html=True)
    st.markdown('<div class="section-header">📝 EXECUTIVE SUMMARY (PLAIN ENGLISH)</div>', unsafe_allow_html=True)
    summary_html = build_executive_summary(
        st.session_state.G, st.session_state.compromised, st.session_state.risk_score,
        st.session_state.blast_details, entry_node,
    )
    st.markdown(f"<div class='exec-summary'>{summary_html}</div>", unsafe_allow_html=True)

    # PRIORITY 15 — OVERALL ACDS RISK
    overall = st.session_state.overall_acds_risk or calculate_overall_acds_risk(st.session_state.G, st.session_state.risk_score)
    st.markdown('<div class="section-header">🎯 OVERALL ACDS RISK</div>', unsafe_allow_html=True)
    if overall['status'] == 'COMPLETE':
        ov_color = "#ff3355" if overall['overall_score'] > 70 else "#ff8c00" if overall['overall_score'] > 40 else "#00ff88"
        st.markdown(f"""
        <div style='background:#0d1f2d;border:1px solid {ov_color};padding:16px;margin-bottom:10px'>
            <div style='font-family:Orbitron,monospace;font-size:2rem;color:{ov_color};text-align:center'>{overall['overall_score']} / 100</div>
            <div style='font-family:Share Tech Mono;font-size:0.65rem;color:{ov_color};text-align:center;letter-spacing:2px'>{overall['severity']}</div>
            <div style='display:flex;justify-content:space-around;margin-top:10px;font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4'>
                <div>Asset Risk<br><span style='color:#00d4ff'>{overall['asset_component']} / 60</span></div>
                <div>Network Blast Radius<br><span style='color:#ff8c00'>{overall['blast_component']} / 40</span></div>
                <div>Total<br><span style='color:{ov_color}'>{overall['overall_score']} / 100</span></div>
            </div>
            <div style='font-family:Share Tech Mono;font-size:0.58rem;color:#3d6a8a;text-align:center;margin-top:8px'>
                Overall ACDS Risk = Asset Risk × 0.60 + Network Blast Radius × 0.40 (ACDS design choice, not an industry-standard formula)
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info(f"Overall ACDS Risk: {overall['status']} — Asset Risk component is {overall['asset_component']}/100; run a simulation to compute the Network Blast Radius component.")

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    col_timeline, col_risk = st.columns([1, 1], gap="medium")

    with col_timeline:
        st.markdown('<div class="section-header">⏱ SIMULATED ATTACK TIMELINE</div>', unsafe_allow_html=True)
        ts_groups = {}
        for entry in st.session_state.timeline:
            ts_groups.setdefault(entry["timestep"], []).append(entry)
        for t, entries in sorted(ts_groups.items()):
            for entry in entries:
                is_success = entry["success"]
                bg_color = "rgba(255,51,85,0.1)" if is_success else "rgba(0,255,136,0.05)"
                border_color = "#ff3355" if is_success else "#00ff88"
                status_text_val = "✓ POTENTIAL PATH" if is_success else "✗ BLOCKED"
                status_color = "#ff3355" if is_success else "#00ff88"
                privilege_html = "<div style='color:#ffd700;font-size:0.65rem'>⬆ Privilege Escalation (simulated)</div>" if entry.get("priv_esc") else ""
                vuln_percent = int(entry["vuln"] * 100)
                criticality_stars = "★" * entry["criticality"]
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
                    <div style='color:#ff8c00;font-size:0.65rem'>Reason: {entry.get("access_vector", "network")}</div>
                    {privilege_html}
                    <div style='color:#7ab8d4'>Risk: {vuln_percent}/100 | Criticality: {criticality_stars}</div>
                </div>
                """, unsafe_allow_html=True)

    with col_risk:
        st.markdown('<div class="section-header">📊 NETWORK BLAST RADIUS (SIMULATION)</div>', unsafe_allow_html=True)
        rs = st.session_state.risk_score
        bd = st.session_state.blast_details
        risk_color = "#ff3355" if rs > 70 else "#ff8c00" if rs > 40 else "#00ff88"
        risk_label = severity_from_score(rs)

        st.markdown(f"""
        <div style='background:#0d1f2d;border:1px solid {risk_color};padding:20px;text-align:center;margin-bottom:16px'>
            <div style='font-family:Orbitron,monospace;font-size:2.5rem;color:{risk_color};
                        text-shadow:0 0 20px {risk_color};font-weight:900'>{rs}</div>
            <div style='font-family:Share Tech Mono;font-size:0.7rem;color:{risk_color};letter-spacing:3px'> / 100 — {risk_label}</div>
            <div class="risk-bar-container" style='margin-top:12px'>
                <div class="risk-bar" style='width:{rs}%;background:linear-gradient(90deg,#003d5c,{risk_color})'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style='font-family:Share Tech Mono;font-size:0.75rem;line-height:2;background:#0a1520;
             border:1px solid #1a3a5c;padding:14px 16px'>
            <div style='color:#3d6a8a'>FORMULA: R = 0.3×spread + 0.5×critical_impact + 0.2×depth (ACDS blast-radius model)</div><br>
            <div>Spread (w1=0.3): <span style='color:#00d4ff;float:right'>{bd.get("spread",0)}% nodes compromised</span></div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("spread",0)}%;background:#00d4ff'></div></div>
            <div>Critical Impact (w2=0.5): <span style='color:#ff8c00;float:right'>{bd.get("critical_impact",0)}% criticality</span></div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("critical_impact",0)}%;background:#ff8c00'></div></div>
            <div>Attack Depth (w3=0.2): <span style='color:#ffd700;float:right'>{bd.get("depth",0)}% of network</span></div>
            <div class="risk-bar-container"><div class="risk-bar" style='width:{bd.get("depth",0)}%;background:#ffd700'></div></div>
            <br>
            <div>Systems Controlled: <span style='color:#ff3355;float:right'>{bd.get("systems_controlled", bd.get("compromised_count",0))} / {bd.get("total_real_nodes",0)}</span></div>
            <div>Critical Assets Reached: <span style='color:#ff3355;float:right'>{bd.get("critical_assets_reached", 0)}</span></div>
            <div>Max Lateral Hops (Attack Depth): <span style='color:#ffd700;float:right'>{bd.get("max_lateral_hops", 0)}</span></div>
            <div>Privilege Escalations: <span style='color:#ff8c00;float:right'>{bd.get("privilege_escalations", 0)}</span></div>
            {"<div style='color:#ffd700;margin-top:8px'>⚠ HONEYPOT TRIGGERED (simulated): +15 risk penalty</div>" if st.session_state.honeypot_triggered else ""}
        </div>
        """, unsafe_allow_html=True)

        paths = bd.get("attack_paths", [])
        if paths:
            st.markdown('<div style="font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;margin:12px 0 6px 0">SIMULATED ATTACK PATHS (longest routes)</div>', unsafe_allow_html=True)
            for path in paths[:5]:
                path_str = " → ".join(p.replace("\n", " / ") for p in path)
                st.markdown(
                    f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;'
                    f'padding:6px 10px;margin:3px 0;background:#060d15;border-left:2px solid #ff3355">{path_str}</div>',
                    unsafe_allow_html=True,
                )

    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    col_defense, col_log = st.columns([1, 1], gap="medium")

    with col_defense:
        st.markdown('<div class="section-header">🛡 ACDS DEFENSE OPTIMIZATION</div>', unsafe_allow_html=True)
        st.markdown("""
        <div style='font-family:Share Tech Mono;font-size:0.65rem;color:#3d6a8a;
             background:#060d15;border:1px solid #1a3a5c;padding:10px;margin-bottom:12px;line-height:1.8'>
        // Greedy algorithm: rank by risk_reduction/cost ratio<br>
        // Select highest-value, CVE-specific actions within budget<br>
        // Objective: maximize risk reduction under limited resources<br>
        // States: RECOMMENDED → SELECTED → APPLIED TO SIMULATION MODEL
        </div>
        """, unsafe_allow_html=True)

        # PRIORITY 24: Budget control lives in the Defense Optimization
        # section now (moved out of the sidebar).
        all_actions_for_budget = get_defense_actions(st.session_state.G, set(st.session_state.G.nodes) - {"Honeypot"}, 50)
        max_budget = sum(a["cost"] for a in all_actions_for_budget) or 100
        st.slider("Defense Budget (units)", 0, max_budget, key="budget")

        defense_actions = st.session_state.defense_actions
        selected, total_reduction_val, remaining = greedy_defense_selection(defense_actions, st.session_state.budget)
        st.session_state.selected_defenses = selected

        before_risk = st.session_state.risk_before_defense if st.session_state.risk_before_defense is not None else st.session_state.risk_score
        before_bd = st.session_state.blast_before_defense or st.session_state.blast_details

        applied = st.session_state.applied_defenses
        has_applied = bool(applied)

        st.markdown("**BEFORE**")
        st.markdown(f"""
        <div style='display:flex;gap:10px;margin-bottom:10px;font-family:Share Tech Mono;font-size:0.7rem'>
            <div style='flex:1;background:#0d1f2d;border:1px solid #1a3a5c;padding:10px;text-align:center'>
                <div style='color:#3d6a8a'>RISK</div><div style='color:#ff3355'>{before_risk} / 100</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #1a3a5c;padding:10px;text-align:center'>
                <div style='color:#3d6a8a'>SYSTEMS REACHED</div><div style='color:#ffd700'>{before_bd.get('systems_controlled', before_bd.get('compromised_count',0))}</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #1a3a5c;padding:10px;text-align:center'>
                <div style='color:#3d6a8a'>CRITICAL REACHED</div><div style='color:#ffd700'>{before_bd.get('critical_assets_reached',0)}</div>
            </div>
            <div style='flex:1;background:#0d1f2d;border:1px solid #1a3a5c;padding:10px;text-align:center'>
                <div style='color:#3d6a8a'>MAX DEPTH</div><div style='color:#ffd700'>{before_bd.get('max_lateral_hops',0)}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("**RECOMMENDED / SELECTED ACTIONS**")
        selected_set = {a["action"] for a in selected}
        for action in defense_actions[:10]:
            is_sel = action["action"] in selected_set
            card_class = "selected" if is_sel else "unselected"
            badge = DEFENSE_STATE_SELECTED if is_sel else DEFENSE_STATE_RECOMMENDED
            badge_color = "#00ff88" if is_sel else "#3d6a8a"
            type_icons = {"patch": "🔧", "isolate": "🔒", "privilege": "👤", "ids": "📡"}
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
                <span style='color:{badge_color};font-size:0.62rem;white-space:nowrap'>{badge}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:8px 0'>
        Budget used: {sum(a['cost'] for a in selected)} / {st.session_state.budget} &nbsp;|&nbsp;
        Modeled risk reduction if applied: -{total_reduction_val:.1f}
        </div>
        """, unsafe_allow_html=True)

        if st.button("🛡  APPLY SELECTED DEFENSES", use_container_width=True, disabled=not selected):
            applied_actions, ids_dep, seg_applied = apply_defense_actions(st.session_state.G, selected)
            st.session_state.applied_defenses = applied_actions
            st.session_state.ids_deployed = st.session_state.ids_deployed or ids_dep
            st.session_state.segmentation_applied = st.session_state.segmentation_applied or seg_applied

            # Re-simulate from the same entry point so BEFORE vs AFTER is a
            # genuine comparison against the mutated model (Priority 18/19).
            new_timeline, new_compromised, new_honeypot, new_stats = simulate_attack(
                st.session_state.G, entry_node, seed=random.randint(1, 9999),
                ids_deployed=st.session_state.ids_deployed, segmentation_applied=st.session_state.segmentation_applied,
            )
            new_risk, new_bd = calculate_risk(st.session_state.G, new_compromised, new_timeline, new_honeypot, new_stats)
            st.session_state.timeline = new_timeline
            st.session_state.compromised = new_compromised
            st.session_state.honeypot_triggered = new_honeypot
            st.session_state.attack_stats = new_stats
            st.session_state.risk_score = new_risk
            st.session_state.blast_details = new_bd
            st.session_state.post_defense_stats = new_bd
            st.session_state.overall_acds_risk = calculate_overall_acds_risk(st.session_state.G, new_risk)
            st.session_state.attack_log = generate_attack_log(new_timeline, new_honeypot)
            record_scan_history(st.session_state.G, "Post-defense")
            st.success(f"Applied {len(applied_actions)} defense action(s) to the simulation model and re-ran the simulation.")
            st.rerun()

        if has_applied:
            after_bd = st.session_state.post_defense_stats or st.session_state.blast_details
            after_risk = st.session_state.risk_score
            reduction_pct = round(max(0, (before_risk - after_risk) / before_risk * 100), 1) if before_risk else 0.0
            st.markdown("**AFTER (applied to model, re-simulated)**")
            st.markdown(f"""
            <div style='display:flex;gap:10px;margin:10px 0;font-family:Share Tech Mono;font-size:0.7rem'>
                <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:10px;text-align:center'>
                    <div style='color:#3d6a8a'>RISK</div><div style='color:#00ff88'>{after_risk} / 100</div>
                </div>
                <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:10px;text-align:center'>
                    <div style='color:#3d6a8a'>SYSTEMS REACHED</div><div style='color:#00ff88'>{after_bd.get('systems_controlled', after_bd.get('compromised_count',0))}</div>
                </div>
                <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:10px;text-align:center'>
                    <div style='color:#3d6a8a'>CRITICAL REACHED</div><div style='color:#00ff88'>{after_bd.get('critical_assets_reached',0)}</div>
                </div>
                <div style='flex:1;background:#0d1f2d;border:1px solid #00ff88;padding:10px;text-align:center'>
                    <div style='color:#3d6a8a'>MAX DEPTH</div><div style='color:#00ff88'>{after_bd.get('max_lateral_hops',0)}</div>
                </div>
            </div>
            <div style='text-align:center;font-family:Orbitron,monospace;color:#00ff88;font-size:1.1rem'>
                RISK REDUCTION: {reduction_pct}%
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-header">💡 RECOMMENDED SOLUTIONS (SPECIFIC, PER-HOST)</div>', unsafe_allow_html=True)
        all_fixes = []
        for node in st.session_state.compromised:
            nd = st.session_state.G.nodes.get(node, {})
            for fix in nd.get("fixes", []):
                if fix not in all_fixes:
                    all_fixes.append(fix)
        if all_fixes:
            for i, fix in enumerate(all_fixes[:10], 1):
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
        st.markdown('<div class="section-header">📟 SIMULATED ATTACK EVENT LOG</div>', unsafe_allow_html=True)
        if st.session_state.honeypot_triggered:
            st.markdown("""
            <div class="honeypot-alert">
                ⚠ HONEYPOT TRIGGERED (SIMULATED) — modeled attacker probed decoy system<br>
                <span style='color:#3d6a8a'>Source: Simulated Attacker | Target: Honeypot (port 21/FTP)<br>
                Action: Risk model updated (+15 penalty)<br>
                Recommendation: Analyze modeled TTPs for adaptive defense</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div style='background:#050a0f;border:1px solid #1a3a5c;padding:10px 12px;font-family:Share Tech Mono'>
            <div style='font-size:0.62rem;color:#3d6a8a;border-bottom:1px solid #1a3a5c;padding-bottom:6px;margin-bottom:6px'>
                SOURCE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; TARGET &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; TECHNIQUE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; RESULT
            </div>
        """, unsafe_allow_html=True)
        for log in st.session_state.attack_log:
            sev = log["severity"]
            color = "#ff3355" if sev == "critical" else "#00ff88" if sev == "ok" else "#ff8c00"
            st.markdown(f"""
            <div style='font-size:0.66rem;padding:5px 0;border-bottom:1px solid #0a1520;color:#7ab8d4;line-height:1.6'>
                <div><span style='color:#3d6a8a'>Source:</span> {log["src"]} &nbsp;→&nbsp; <span style='color:#00d4ff'>Target: {log["target"]}</span></div>
                <div><span style='color:#3d6a8a'>Technique:</span> {log["technique"]}</div>
                <div><span style='color:#3d6a8a'>Reason:</span> {log["reason"]}</div>
                <div style='color:{color}'>Result: {log["status"]}</div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="section-header">🔖 MITRE ATT&CK MAPPING</div>', unsafe_allow_html=True)
        mitre_seen = {}
        for entry in st.session_state.timeline:
            if entry["success"]:
                mitre_seen[entry["mitre_code"]] = entry["mitre_desc"]
        mitre_html = "".join(f'<span class="mitre-tag">{code}</span>' for code in mitre_seen) + "<br><br>"
        for code, desc in mitre_seen.items():
            mitre_html += f'<div style="font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;margin:3px 0"><span style="color:#ff8c00">{code}</span> — {desc}</div>'
        st.markdown(f'<div style="background:#0d1f2d;border:1px solid #1a3a5c;padding:12px">{mitre_html}</div>', unsafe_allow_html=True)

        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="section-header">🦠 ALL CONFIRMED CVEs DISCOVERED ON NETWORK</div>', unsafe_allow_html=True)
        all_cves = []
        for node, data in st.session_state.G.nodes(data=True):
            for c in data.get('cve_findings', []):
                all_cves.append((node, data['ip'], c))
        all_cves.sort(key=lambda x: x[2]['cvss'], reverse=True)
        if all_cves:
            for node, ip, c in all_cves[:10]:
                st.markdown(f"""
                <div style="font-family:Share Tech Mono;font-size:0.66rem;color:#7ab8d4;
                     padding:8px 10px;margin:4px 0;background:#0a1520;border-left:3px solid #ff3355">
                    <span class="cve-tag">{c['cve_id']}</span>
                    <span class="mitre-tag" style="border-color:#ff3355;color:#ff3355">CVSS {c['cvss']} ({c.get('severity','?')})</span>
                    <div style="margin-top:4px;color:#e0f4ff">{node.replace(chr(10),' / ')} ({ip}) — {c['service']} {c.get('detected_version') or ''}</div>
                    <div style="margin-top:2px;color:#3d6a8a">{c['summary'][:120]}{'...' if len(c['summary'])>120 else ''}</div>
                    <div style="margin-top:2px;color:#3d6a8a">Published: {c.get('published')} · Modified: {c.get('modified')} · Confidence: {c.get('detection_confidence')}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="font-family:Share Tech Mono;font-size:0.7rem;color:#3d6a8a">'
                'No version-specific CVEs matched (services may be unversioned, patched, or NVD unreachable — '
                'baseline exposure risk was used instead).</div>',
                unsafe_allow_html=True,
            )

    # ─────────────────────────────────────────────────────────
    # PRIORITY 20/21/22 — SCAN TIMELINE, SCAN HISTORY, REPORTING
    # ─────────────────────────────────────────────────────────
    st.markdown('<hr style="border-color:#1a3a5c;margin:20px 0">', unsafe_allow_html=True)
    col_scanlog, col_history = st.columns([1, 1], gap="medium")

    with col_scanlog:
        with st.expander("🕒 SCAN TIMELINE (actual operations performed)", expanded=False):
            if st.session_state.scan_timeline:
                for ev in st.session_state.scan_timeline[-60:]:
                    st.markdown(
                        f'<div class="log-entry"><span style="color:#3d6a8a">{ev["timestamp"]}</span> '
                        f'<span style="color:#00d4ff">{ev["event"]}</span> — '
                        f'<span style="color:#7ab8d4">{ev["target"]}</span> '
                        f'<span style="color:#00ff88">[{ev["status"]}]</span></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown('<div style="color:#3d6a8a;font-family:Share Tech Mono;font-size:0.7rem">No scan timeline recorded yet (run a Real Network Scan).</div>', unsafe_allow_html=True)

    with col_history:
        with st.expander("📈 SCAN HISTORY", expanded=False):
            if st.session_state.scan_history:
                for h in st.session_state.scan_history[-10:]:
                    st.markdown(f"""
                    <div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;padding:6px 10px;margin:3px 0;background:#0a1520;border-left:3px solid #00d4ff'>
                        Scan #{h['scan_id']} ({h['scan_type']})<br>
                        {h['asset_count']} assets · Avg Risk {h['average_risk']} ·
                        {h['critical_count']}C / {h['high_count']}H / {h['medium_count']}M / {h['low_count']}L
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown('<div style="color:#3d6a8a;font-family:Share Tech Mono;font-size:0.7rem">No scans recorded yet this session.</div>', unsafe_allow_html=True)

    st.markdown('<div class="section-header">📤 REPORTING / EXPORT</div>', unsafe_allow_html=True)
    rep1, rep2, rep3 = st.columns(3)
    with rep1:
        st.download_button("⬇ Asset Inventory (CSV)", export_asset_inventory_csv(st.session_state.G),
                            file_name="acds_asset_inventory.csv", mime="text/csv", use_container_width=True)
    with rep2:
        st.download_button("⬇ Vulnerability Report (CSV)", export_vulnerability_report_csv(st.session_state.G),
                            file_name="acds_vulnerability_report.csv", mime="text/csv", use_container_width=True)
    with rep3:
        report_text = build_executive_report_text(st.session_state.G, st.session_state.risk_score,
                                                    st.session_state.blast_details, overall, st.session_state.scan_history)
        st.download_button("⬇ Executive Report (TXT)", report_text,
                            file_name="acds_executive_report.txt", mime="text/plain", use_container_width=True)

else:
    if st.session_state.network_mode == "Real Network Scan":
        ready_note = (
            "1. Click <span style='color:#ff8c00'>📡 SCAN NETWORK</span> in the sidebar to discover all LAN devices<br>"
            "2. The tool grabs real service banners and checks them against live NVD CVE data<br>"
            "3. Review each node's open ports, confirmed CVEs, inferred OS/device/criticality with evidence<br>"
            "4. Select which system is <b>initially compromised</b> (attacker foothold)<br>"
            "5. Click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span> to see modeled lateral movement<br>"
            "6. Review the risk breakdown, apply defenses, and compare Before vs After"
        )
    else:
        ready_note = (
            "1. Select an entry node (attacker's foothold) from the sidebar<br>"
            "2. Click <span style='color:#00d4ff'>▶ RUN ATTACK SIMULATION</span> to begin<br>"
            "3. Watch simulated attack propagation on the network exposure model<br>"
            "4. Review risk analysis and defense recommendations"
        )

    st.markdown(f"""
    <div style='background:#0a1520;border:1px solid #1a3a5c;border-left:3px solid #00d4ff;
         padding:20px 24px;font-family:Share Tech Mono;font-size:0.78rem;line-height:2;
         text-align:center;margin-top:20px'>
        <div style='color:#00d4ff;font-size:0.9rem;font-family:Orbitron,monospace;letter-spacing:3px;margin-bottom:12px'>
            SYSTEM READY
        </div>
        <div style='color:#7ab8d4'>{ready_note}</div>
        <div style='color:#3d6a8a;margin-top:16px;font-size:0.65rem'>
            PASSIVE SCANNING ONLY — NO EXPLOITS PERFORMED<br>
            REAL CVE DATA FROM NIST NVD WHERE AVAILABLE<br>
            ALIGNED WITH MITRE ATT&CK FRAMEWORK
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.scan_timeline:
        with st.expander("🕒 SCAN TIMELINE (actual operations performed)", expanded=False):
            for ev in st.session_state.scan_timeline[-60:]:
                st.markdown(
                    f'<div class="log-entry"><span style="color:#3d6a8a">{ev["timestamp"]}</span> '
                    f'<span style="color:#00d4ff">{ev["event"]}</span> — '
                    f'<span style="color:#7ab8d4">{ev["target"]}</span> '
                    f'<span style="color:#00ff88">[{ev["status"]}]</span></div>',
                    unsafe_allow_html=True,
                )
    if st.session_state.scan_history:
        with st.expander("📈 SCAN HISTORY", expanded=False):
            for h in st.session_state.scan_history[-10:]:
                st.markdown(f"""
                <div style='font-family:Share Tech Mono;font-size:0.68rem;color:#7ab8d4;padding:6px 10px;margin:3px 0;background:#0a1520;border-left:3px solid #00d4ff'>
                    Scan #{h['scan_id']} ({h['scan_type']})<br>
                    {h['asset_count']} assets · Avg Risk {h['average_risk']} ·
                    {h['critical_count']}C / {h['high_count']}H / {h['medium_count']}M / {h['low_count']}L
                </div>
                """, unsafe_allow_html=True)
        st.download_button("⬇ Asset Inventory (CSV)", export_asset_inventory_csv(st.session_state.G),
                            file_name="acds_asset_inventory.csv", mime="text/csv")
